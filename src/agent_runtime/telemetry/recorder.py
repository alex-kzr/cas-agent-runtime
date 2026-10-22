"""Atomic run snapshots, bounded events and process-owned execution locking."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_runtime.tasks import analysis_privacy
from agent_runtime.tasks.models import (
    TERMINAL,
    ExecutionRequest,
    State,
    transition,
    validate_document,
)

SENSITIVE = re.compile(
    r"(?:secret|password|credential|api[_-]?key|authorization|access[_-]?token)", re.I
)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def redact(
    value: Any,
    secrets: tuple[str, ...] | list[str] = (),
    depth: int = 0,
    _budget: list[int] | None = None,
) -> Any:
    budget = [32_768] if _budget is None else _budget
    if budget[0] <= 0:
        return {"truncated": True, "reason": "total-size"}
    if depth > 8:
        return {"truncated": True, "reason": "depth"}
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:128]:
            if budget[0] <= 0:
                result["_truncated"] = True
                break
            key = str(key)[:256]
            sensitive = SENSITIVE.search(key)
            key = redact(key, secrets, depth + 1, budget)
            if not isinstance(key, str):
                result["_truncated"] = True
                break
            result[key] = "[REDACTED]" if sensitive else redact(item, secrets, depth + 1, budget)
        if len(value) > 128:
            result["_truncated"] = True
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for item in value[:128]:
            if budget[0] <= 0:
                result.append({"truncated": True, "reason": "total-size"})
                break
            result.append(redact(item, secrets, depth + 1, budget))
        return result + ([{"truncated": True}] if len(value) > 128 else [])
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"\b(?:sk-ant-|ghp_|github_pat_)[A-Za-z0-9_-]{16,}", "[REDACTED]", value)
        limit = min(16_384, budget[0])
        encoded = value.encode("utf-8")
        budget[0] -= min(len(encoded), limit)
        return (
            value
            if len(encoded) <= limit
            else encoded[:limit].decode("utf-8", errors="ignore") + "[TRUNCATED]"
        )
    if value is None or type(value) in {int, bool}:
        return value
    if isinstance(value, float):
        import math

        return value if math.isfinite(value) else None
    return redact(str(value), secrets, depth + 1, budget)


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".cas-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class RunLock:
    """Kernel releases this lock on process exit; do not unlink the shared lock inode."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.stream = None

    def __enter__(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.stream = (self.data_dir / ".execution.lock").open("a+b")
        self.stream.seek(0, 2)
        if self.stream.tell() == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.stream.close()
            raise RuntimeError("Another CAS execution owns this data directory") from error
        return self

    def __exit__(self, *_):
        if self.stream:
            self.stream.close()


class Recorder:
    # Analysis runs project every event/document through an allowlist before any write.
    private = False
    # Optional write budgets (mean-review scope only). Class defaults keep Recorder.__new__
    # instances, as the private worker builds them, and every existing caller unbounded as before.
    event_limit = None  # absolute ceiling for seq: the event numbered above it is not written
    event_limit_code = None  # numeric reason reported when event_limit is reached
    journal_limit = None  # ceiling for the bytes appended to events.jsonl by this instance
    _journal_bytes = 0

    def __init__(
        self, data_dir: Path, request: ExecutionRequest, secrets=(), *, local: bool = False
    ):
        self.private = analysis_privacy.enabled(request.scenario_id)
        self.data_dir = data_dir
        self.secrets = tuple(secrets)
        self.run_id = request.run_id or str(uuid4())
        self.directory = data_dir / "runs" / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)
        self.seq = 0
        self.task_id = (request.task_id or str(uuid4())) if request.kind == "task" else None
        source_id = self.task_id or self.run_id
        instructions_ref = f"tasks/{source_id}/task.json"
        self.record = {
            "schema_version": 1,
            "run_id": self.run_id,
            "kind": request.kind,
            "task_id": self.task_id,
            "scenario_id": request.scenario_id,
            "status": "CREATED",
            "created_at": now(),
            "updated_at": now(),
            "started_at": None,
            "ended_at": None,
            "provider": {
                "name": "claude",
                "sdk_package": "claude-agent-sdk",
                "sdk_version": version("claude-agent-sdk"),
                "cli_version": None,
                "requested_model": request.model,
                "resolved_model": None,
                "os": platform.system(),
                "python": platform.python_version(),
            },
            "instructions_ref": instructions_ref,
            "configuration": {
                "agent": request.agent_name,
                "auth_mode": request.auth_mode,
                "session_status": "not-checked",
                "api_fallback": "disabled",
                "live_authorized": request.live_authorized,
                "existing_login_authorized": request.allow_existing_login,
            },
            "workspace": str(request.workspace),
            "limits": asdict(request.limits),
            "session_id": None,
            "resumes_run_id": request.resumes_run_id,
            "retry_of_run_id": None,
            "validation": {"status": "pending", "validator_version": "1", "checks": []},
            "sdk_outcome": None,
            "result_ref": None,
            "artifacts_ref": None,
            "error": None,
            "evidence_status": "partial",
            "usage": {"sdk": None, "application": None},
        }
        if local:
            if request.kind != "scenario":
                raise ValueError("Local validation is available only for explicit scenarios")
            self.record["provider"].update(
                name="local-validation", sdk_package=None, sdk_version=None
            )
            self.record["configuration"] = {"execution_mode": "offline", "agent": "none"}
        source = self.clean_document(
            {
                "schema_version": 1,
                "task_id": self.task_id,
                "instructions": request.instructions,
                "agent": {"name": request.agent_name},
                "workspace": str(request.workspace),
                "limits": asdict(request.limits),
                "kind": request.kind,
                "scenario_id": request.scenario_id,
                "instructions_sha256": hashlib.sha256(
                    request.instructions.encode("utf-8")
                ).hexdigest(),
                "instructions_size_bytes": len(request.instructions.encode("utf-8")),
                "instructions_truncated": len(request.instructions.encode("utf-8")) > 16_384,
            }
        )
        if self.private:
            source = analysis_privacy.task_source(source)
        validate_document("task", source)
        atomic_json(data_dir / instructions_ref, source)
        self.save()
        self.event("run.created", {"kind": request.kind})

    def clean(self, value: Any) -> Any:
        return redact(value, self.secrets)

    def clean_document(self, value: dict[str, Any]) -> dict[str, Any]:
        """Keep the trusted schema skeleton; bound/redact each untrusted value separately."""
        if self.private:
            value = analysis_privacy.document(value)
        result = {key: self.clean(item) for key, item in value.items()}
        for field in ("provider", "usage"):
            if isinstance(value.get(field), dict):
                result[field] = {key: self.clean(item) for key, item in value[field].items()}
        return result

    def save(self) -> None:
        clean = self.clean_document(self.record)
        validate_document("run", clean)
        atomic_json(self.directory / "run.json", clean)

    def event(self, event_type: str, payload: dict[str, Any], source: str = "application") -> None:
        if self.private:
            payload = analysis_privacy.event(event_type, payload)
        if self.event_limit is not None and self.seq >= self.event_limit:
            # Checked before anything is serialized or written; numeric reason only.
            from agent_runtime.tasks import review_profile

            code = self.event_limit_code or review_profile.PARENT_EVENTS
            raise review_profile.BudgetExceeded(code)
        self.seq += 1
        event = {
            "schema_version": 1,
            "run_id": self.run_id,
            "seq": self.seq,
            "timestamp": now(),
            "source": source,
            "type": event_type,
            "session_id": self.record["session_id"],
            "parent_event_seq": None,
            "correlation_id": None,
            "payload": self.clean(payload),
            "redaction": {"applied": True, "fields": []},
        }
        validate_document("event", event)
        encoded = json.dumps(event, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > 65_536:
            event["payload"] = {
                "truncated": True,
                "original_size_bytes": len(encoded.encode("utf-8")),
            }
            encoded = json.dumps(event, ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8")) + 1
        if self.journal_limit is not None and self._journal_bytes + size > self.journal_limit:
            from agent_runtime.tasks import review_profile

            self.seq -= 1  # nothing was written for this event
            raise review_profile.BudgetExceeded(review_profile.WORKER_JOURNAL)
        with (self.directory / "events.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._journal_bytes += size

    def transition(self, target: State) -> None:
        current = State(self.record["status"])
        transition(current, target)
        updated = dict(self.record, status=target.value, updated_at=now())
        if target == State.RUNNING:
            updated["started_at"] = now()
        if target in TERMINAL:
            updated["ended_at"] = now()
        # Write the transition event first; a failed metadata replacement remains partial.
        self.event("run.transition", {"from": current.value, "to": target.value})
        previous = self.record
        self.record = updated
        try:
            self.save()
        except BaseException:
            self.record = previous
            raise


def read_events(path: Path, max_bytes: int = 4_000_000) -> tuple[list[dict], list[str]]:
    if not path.is_file():
        return [], ["Events unavailable"]
    warnings = []
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        warnings.append("Event read truncated at size limit")
        raw = raw[:max_bytes]
    lines = raw.splitlines(keepends=True)
    events = []
    for index, line in enumerate(lines):
        if not line.endswith(b"\n"):
            warnings.append(f"Incomplete final event line {index + 1}")
            break
        try:
            event = json.loads(line)
            validate_document("event", event)
        except (ValueError, UnicodeError):
            warnings.append(f"Invalid event line {index + 1}")
            continue
        events.append(event)
    return events, warnings


def reconcile(data_dir: Path, *, locked: bool = False) -> list[str]:
    if not locked:
        with RunLock(data_dir):
            return reconcile(data_dir, locked=True)
    changed = []
    for path in (data_dir / "runs").glob("*/run.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            validate_document("run", record)
        except (ValueError, OSError):
            continue
        if State(record["status"]) in TERMINAL:
            continue
        record["error"] = {
            "category": "interrupted",
            "code": "process_lost",
            "message": "Previous CAS writer is no longer active; effects may remain",
            "retryable": False,
            "evidence_refs": [],
            "last_status": record["status"],
        }
        record.update(
            status="INTERRUPTED", updated_at=now(), ended_at=now(), evidence_status="partial"
        )
        atomic_json(path, record)
        changed.append(record["run_id"])
    return changed
