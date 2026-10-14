"""Explicit-root configuration; credentials are never part of public configuration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from agent_runtime.tasks.models import Limits


@dataclass(frozen=True)
class Configuration:
    root: Path
    data_dir: Path
    workspace_root: Path
    max_turns: int | None
    max_budget_usd: str | None
    console_host: str
    console_port: int
    provider: str = "claude"
    auth_mode: str = "subscription"
    login_config_dir: str | None = None

    @classmethod
    def load(
        cls, root: Path, environment: Mapping[str, str], overrides: Mapping[str, Any] | None = None
    ) -> Configuration:
        root = root.resolve(strict=True)
        overrides = overrides or {}

        def value(key: str, variable: str, default: Any = None) -> Any:
            chosen = overrides.get(key)
            return chosen if chosen is not None else environment.get(variable, default)

        def path(key: str, variable: str, default: str) -> Path:
            result = Path(value(key, variable, default)).expanduser()
            return (result if result.is_absolute() else root / result).resolve()

        def integer(raw: Any, name: str) -> int:
            try:
                return int(raw)
            except (ValueError, TypeError) as error:
                raise ValueError(f"{name} must be an integer") from error

        data = path("data_dir", "CAS_DATA_DIR", "data")
        workspace = path("workspace_root", "CAS_RUNTIME_WORKSPACE_DIR", str(data / "workspaces"))
        if data == root or (data.is_relative_to(root) and not data.is_relative_to(root / "data")):
            raise ValueError("CAS data must be under root/data or an explicit external directory")
        if not workspace.is_relative_to(data) or workspace == data:
            raise ValueError("Workspace root must be below the CAS data directory")
        host = value("console_host", "CAS_CONSOLE_HOST", "127.0.0.1")
        port = integer(value("console_port", "CAS_CONSOLE_PORT", "8765"), "Console port")
        provider = value("provider", "CAS_RUNTIME_PROVIDER", "claude")
        if host != "127.0.0.1" or not 1 <= port <= 65535:
            raise ValueError("Console requires 127.0.0.1 and port 1..65535")
        if provider != "claude":
            raise ValueError("Only provider claude is implemented")
        auth_mode = value("auth_mode", "CAS_AUTH_MODE", "subscription")
        if auth_mode not in {"subscription", "api"}:
            raise ValueError("Auth mode must be subscription or api")
        login_config = value(
            "login_config_dir", "CAS_NATIVE_CONFIG_DIR", environment.get("CLAUDE_CONFIG_DIR")
        )
        if login_config is not None:
            chosen = Path(login_config).expanduser()
            if not chosen.is_absolute():
                raise ValueError("Native login directory must be absolute and outside CAS")
            chosen = chosen.resolve()
            if chosen.is_relative_to(root) or chosen.is_relative_to(data):
                raise ValueError("Native login directory must remain outside CAS and its data")
            login_config = str(chosen)
        elif auth_mode == "subscription" and (
            environment.get("USERPROFILE") or environment.get("HOME")
        ):
            derived = (
                Path(environment.get("USERPROFILE") or environment.get("HOME") or Path.home())
                / ".claude"
            ).resolve()
            if derived.is_relative_to(root) or derived.is_relative_to(data):
                raise ValueError("Default native login store must remain outside CAS and data")
        turns = value("max_turns", "CAS_RUNTIME_MAX_TURNS")
        budget = value("max_budget_usd", "CAS_RUNTIME_MAX_BUDGET_USD")
        if turns is not None:
            turns = integer(turns, "Max turns")
        if turns is not None and budget is not None:
            Limits(turns, str(budget), 120)
        return cls(
            root,
            data,
            workspace,
            turns,
            None if budget is None else str(budget),
            host,
            port,
            provider,
            auth_mode,
            login_config,
        )

    def live_limits(
        self,
        requested_turns: int | None = None,
        requested_budget: str | None = None,
        timeout_seconds: int = 120,
    ) -> Limits:
        if self.max_turns is None or self.max_budget_usd is None:
            raise ValueError("Live execution requires explicit max turns and budget")
        limits = Limits(
            requested_turns if requested_turns is not None else self.max_turns,
            requested_budget if requested_budget is not None else self.max_budget_usd,
            timeout_seconds,
        )
        if limits.max_turns > self.max_turns or Decimal(limits.max_budget_usd) > Decimal(
            self.max_budget_usd
        ):
            raise ValueError("Task limits exceed the operator policy ceiling")
        return limits

    def public(self) -> dict[str, Any]:
        return {
            key: str(value) if isinstance(value, Path) else value
            for key, value in asdict(self).items()
        }
