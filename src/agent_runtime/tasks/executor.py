"""One application execution path; test doubles are injected only through Python tests."""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_runtime.tasks.models import ExecutionRequest, State, sdk_succeeded, validate_document
from agent_runtime.telemetry.recorder import Recorder, RunLock, atomic_json, reconcile


@dataclass(frozen=True)
class NativeResult:
    text: str | None
    outcome: dict[str, Any] | None
    session_id: str | None
    usage: dict[str, Any] | None
    source: str = "sdk"
    checks: list[dict[str, Any]] | None = None
    application_usage: dict[str, Any] | None = None


class Executor:
    def __init__(self, data_dir: Path, client, *, secrets=(), workspace_root: Path | None = None):
        self.data_dir, self.client, self.secrets = data_dir, client, secrets
        self.workspace_root = (workspace_root or data_dir / "workspaces").resolve()

    async def execute(self, request: ExecutionRequest) -> dict[str, Any]:
        with RunLock(self.data_dir):
            reconcile(self.data_dir, locked=True)
            recorder = Recorder(
                self.data_dir,
                request,
                self.secrets,
                local=getattr(self.client, "local_validation", False),
            )
            started = time.monotonic()
            summary = None
            artifact_ids = []
            target = State.FAILED
            stage = "validation"
            try:
                recorder.transition(State.VALIDATING)
                workspace = request.workspace.resolve()
                if workspace == self.workspace_root or not workspace.is_relative_to(
                    self.workspace_root
                ):
                    raise ValueError("Workspace must be below the approved workspace root")
                request.workspace.mkdir(parents=True, exist_ok=True)
                if not request.workspace.is_dir():
                    raise ValueError("Workspace is not a directory")
                recorder.transition(State.RUNNING)
                stage = "sdk"
                async with asyncio.timeout(request.limits.timeout_seconds):
                    native = await self.client.run(request, recorder)
                stage = "persistence"
                recorder.record["session_id"] = native.session_id
                recorder.record["sdk_outcome"] = native.outcome
                recorder.record["usage"]["sdk"] = native.usage
                recorder.record["usage"]["application"] = native.application_usage
                summary = recorder.clean(native.text)
                passed = isinstance(summary, str) and bool(summary.strip())
                recorder.record["validation"] = {
                    "status": "passed" if passed else "failed",
                    "validator_version": "text-nonempty-v1",
                    "checks": [{"id": "nonempty-result", "passed": passed}],
                }
                recorder.event("validation.result", recorder.record["validation"], "validator")
                native_success = (
                    native.source == "application"
                    and request.kind == "scenario"
                    and native.outcome is None
                    and recorder.record["provider"]["name"] == "local-validation"
                ) or sdk_succeeded(native.outcome)
                assertions_passed = not native.checks or all(
                    check.get("outcome") == "pass" for check in native.checks
                )
                if native_success and passed and assertions_passed:
                    target = State.COMPLETED
                    # Preserve native outcomes without translating failed terminal reasons.
                else:
                    recorder.record["error"] = self.error(
                        "sdk" if not native_success else "validation",
                        "native_failure" if not native_success else "acceptance_failed",
                        "Execution did not meet acceptance",
                    )
                if passed:
                    artifact_id = str(uuid4())
                    relative = f"{artifact_id}/result.txt"
                    path = self.data_dir / "artifacts" / recorder.run_id / relative
                    path.parent.mkdir(parents=True, exist_ok=False)
                    content = summary.encode("utf-8")
                    path.write_bytes(content)
                    artifact_ids = [artifact_id]
                    manifest = {
                        "schema_version": 1,
                        "run_id": recorder.run_id,
                        "artifacts": [
                            {
                                "artifact_id": artifact_id,
                                "path": relative,
                                "media_type": "text/plain",
                                "size_bytes": len(content),
                                "sha256": hashlib.sha256(content).hexdigest(),
                                "producer": "agent-runtime",
                                "sensitivity": "normal",
                            }
                        ],
                    }
                    validate_document("artifacts", manifest)
                    atomic_json(recorder.directory / "artifacts.json", manifest)
                    recorder.record["artifacts_ref"] = f"runs/{recorder.run_id}/artifacts.json"
                    recorder.event("artifact.registered", {"artifact_id": artifact_id})
                recorder.record["evidence_status"] = "complete"
                if request.kind == "scenario":
                    checks = native.checks or [
                        {
                            "id": "accepted-result",
                            "expected": True,
                            "observed": native_success and passed,
                            "outcome": "pass" if native_success and passed else "fail",
                            "evidence_refs": [f"runs/{recorder.run_id}/events.jsonl"],
                        }
                    ]
                    assertions = {
                        "schema_version": 1,
                        "run_id": recorder.run_id,
                        "scenario_id": request.scenario_id,
                        "scenario_version": "1",
                        "outcome": "pass"
                        if all(c["outcome"] == "pass" for c in checks)
                        else "fail",
                        "prerequisites": [],
                        "checks": checks,
                    }
                    validate_document("assertions", assertions)
                    atomic_json(recorder.directory / "assertions.json", assertions)
            except TimeoutError:
                target = State.INTERRUPTED
                recorder.record["error"] = self.error(
                    "timeout", "wall_timeout", "Wall timeout; external cleanup unverified"
                )
            except asyncio.CancelledError:
                target = State.INTERRUPTED
                recorder.record["error"] = self.error(
                    "interrupted", "operator_interrupt", "Interrupted; external cleanup unverified"
                )
            except Exception as error:
                target = State.FAILED
                recorder.record["evidence_status"] = "partial"
                recorder.record["error"] = self.error(
                    stage, type(error).__name__, recorder.clean(str(error))
                )
            recorder.record["usage"]["application"] = {
                **(recorder.record["usage"]["application"] or {}),
                "duration_ms": round((time.monotonic() - started) * 1000),
            }
            if recorder.record["error"]:
                recorder.event("error", recorder.record["error"])
            result = recorder.clean_document(
                {
                    "schema_version": 1,
                    "run_id": recorder.run_id,
                    "summary": summary,
                    "sdk_outcome": recorder.record["sdk_outcome"],
                    "validation": recorder.record["validation"],
                    "artifact_ids": artifact_ids,
                    "usage": recorder.record["usage"],
                    "error": recorder.record["error"],
                }
            )
            validate_document("result", result)
            atomic_json(recorder.directory / "result.json", result)
            recorder.record["result_ref"] = f"runs/{recorder.run_id}/result.json"
            recorder.transition(target)
            return recorder.clean_document(recorder.record)

    @staticmethod
    def error(category: str, code: str, message: str) -> dict[str, Any]:
        return {
            "category": category,
            "code": code,
            "message": message,
            "retryable": False,
            "evidence_refs": [],
        }
