"""Validated execution input and versioned persistence contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from importlib.resources import files
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal

from jsonschema import Draft202012Validator, FormatChecker


class State(StrEnum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"


TERMINAL = {State.COMPLETED, State.FAILED, State.CANCELLED, State.INTERRUPTED}


class WorkerCleanupError(RuntimeError):
    """Owned process tree could not be observed empty after bounded cleanup."""


def sdk_succeeded(outcome: dict[str, Any] | None) -> bool:
    """Pinned SDK reports completed; None is documented compatibility with older CLI."""
    return bool(
        outcome
        and outcome.get("subtype") == "success"
        and outcome.get("is_error") is False
        and outcome.get("terminal_reason") in (None, "completed")
    )


TRANSITIONS = {
    State.CREATED: {State.VALIDATING, State.CANCELLED, State.INTERRUPTED},
    State.VALIDATING: {State.RUNNING, State.FAILED, State.CANCELLED, State.INTERRUPTED},
    State.RUNNING: TERMINAL,
}


def transition(current: State, target: State) -> None:
    if target not in TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid lifecycle transition {current} -> {target}")


@dataclass(frozen=True)
class Limits:
    max_turns: int
    max_budget_usd: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        for name, maximum in (("max_turns", 1000), ("timeout_seconds", 3600)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in 1..{maximum}")
        if not isinstance(self.max_budget_usd, str):
            raise ValueError("max_budget_usd must be a decimal string")
        try:
            budget = Decimal(self.max_budget_usd)
        except InvalidOperation as error:
            raise ValueError("max_budget_usd must be finite and positive") from error
        if not budget.is_finite() or not Decimal("0") < budget <= Decimal("100"):
            raise ValueError("max_budget_usd must be finite and in (0, 100]")


@dataclass(frozen=True)
class ExecutionRequest:
    kind: Literal["task", "scenario"]
    instructions: str
    workspace: Path
    limits: Limits
    scenario_id: str | None = None
    model: str | None = None
    live_authorized: bool = False
    agent_name: str = "text-only-v1"
    auth_mode: Literal["subscription", "api"] = "subscription"
    allow_existing_login: bool = False
    login_config_dir: str | None = None

    def __post_init__(self) -> None:
        if (
            self.auth_mode not in {"subscription", "api"}
            or type(self.allow_existing_login) is not bool
        ):
            raise ValueError("Unknown auth mode or invalid login-reuse consent")
        if self.login_config_dir is not None and not isinstance(self.login_config_dir, str):
            raise ValueError("Native login directory must be an explicit path string")
        if self.agent_name not in {"text-only-v1", "read-only-v1"}:
            raise ValueError("Unknown agent profile")
        if self.kind not in {"task", "scenario"}:
            raise ValueError("Unknown execution kind")
        if not isinstance(self.instructions, str) or not self.instructions.strip():
            raise ValueError("Nonempty task instructions are required")
        if len(self.instructions.encode("utf-8")) > 256_000:
            raise ValueError("Task instructions exceed 256 KB")
        if (self.kind == "scenario") != bool(self.scenario_id):
            raise ValueError("Only scenarios require a scenario_id")


def safe_relative(value: str) -> str:
    """Validate a portable artifact/reference path, never a native absolute path."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("Expected a safe relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or ":" in value:
        raise ValueError("Absolute or drive paths are forbidden")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Noncanonical relative path")
    return value


def validate_document(name: str, document: dict[str, Any]) -> None:
    schema = json.loads(files("agent_runtime.schemas").joinpath(f"{name}.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = next(validator.iter_errors(document), None)
    if error:
        # Avoid including untrusted instance values in diagnostics.
        raise ValueError(f"Invalid {name} document at {'.'.join(map(str, error.path)) or '<root>'}")
    if name == "run":
        Limits(
            **{
                key: document["limits"][key]
                for key in ("max_turns", "max_budget_usd", "timeout_seconds")
            }
        )
        for field in ("resumes_run_id", "retry_of_run_id"):
            if document.get(field) == document["run_id"]:
                raise ValueError("A run cannot reference itself as a previous attempt")
        for field in ("instructions_ref", "result_ref", "artifacts_ref"):
            if document.get(field) is not None:
                safe_relative(document[field])
        if document["status"] == "COMPLETED":
            if document["error"] is not None:
                raise ValueError("COMPLETED cannot contain an execution error")
            outcome = document["sdk_outcome"]
            local = (
                document["kind"] == "scenario"
                and document["provider"]["name"] == "local-validation"
                and document["configuration"].get("execution_mode") == "offline"
                and outcome is None
            )
            if not local and not sdk_succeeded(outcome):
                raise ValueError("COMPLETED requires a successful native outcome")
            if document["validation"]["status"] != "passed":
                raise ValueError("COMPLETED requires passed validation")
    if name == "artifacts":
        for artifact in document["artifacts"]:
            safe_relative(artifact["path"])
