"""Parent-side ownership of the direct SDK adapter; no alternate execution engine."""

import asyncio
import json
import sys
from dataclasses import asdict

from agent_runtime.providers.claude.auth import auth_environment, require_auth
from agent_runtime.providers.claude.supervision import OwnedProcess
from agent_runtime.tasks import analysis_privacy, review_profile
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import WorkerCleanupError, sdk_succeeded, validate_document
from agent_runtime.telemetry.recorder import read_events


class SupervisedClaudeAdapter:
    def __init__(self, environment, profile=None):
        self.environment = dict(environment)
        self.profile = profile

    async def run(self, request, recorder):
        profile = self.profile
        require_auth(request, self.environment)
        # Test-only variants are refused earlier (adapter) and later (transport), never here.
        if profile is not None and (
            request.model != profile.model
            or request.limits != profile.limits()
            or request.instructions != profile.query_text
        ):
            raise PermissionError("Request differs from the bounded review profile")
        directory = recorder.directory / "worker"
        directory.mkdir(exist_ok=False)
        values = asdict(request)
        values["workspace"] = str(request.workspace)
        body = {
            "request": values,
            "record": recorder.clean_document(recorder.record),
            "seq": recorder.seq,
            "directory": str(directory),
        }
        if profile is not None:
            body["profile"] = profile.to_payload()
        payload = json.dumps(body).encode("utf-8")
        if profile is not None and len(payload) > profile.max_input_bytes:
            raise review_profile.BudgetExceeded(review_profile.OUTGOING_BYTES)
        environment = auth_environment(
            request, self.environment, directory / "sdk-state", forbidden_roots=(recorder.data_dir,)
        )
        owner = OwnedProcess() if profile is None else OwnedProcess(profile.cleanup_seconds)
        code = None
        failed = False
        import_error = None
        try:
            code = await owner.run(
                [sys.executable, "-I", "-m", "agent_runtime.providers.claude.worker"],
                payload,
                environment,
            )
        except (TimeoutError, asyncio.CancelledError):
            failed = True
            raise
        except Exception as exception:
            failed = True
            if not owner.cleanup["tree_empty"]:
                owner.cleanup["failure_type"] = type(exception).__name__
                raise WorkerCleanupError(
                    "SDK worker failure with unconfirmed cleanup"
                ) from exception
            raise
        except BaseException:
            failed = True
            raise
        finally:
            cleanup = owner.cleanup
            recorder.record["usage"]["application"] = {
                **(recorder.record["usage"]["application"] or {}),
                "cleanup": cleanup,
            }
            # Worker has a private journal. The parent alone writes canonical state;
            # import only after observed tree exit, never race a potentially live writer.
            if cleanup["tree_empty"]:
                try:
                    self.import_evidence(directory, recorder, profile)
                except (ValueError, OSError) as exception:
                    import_error = exception
                    recorder.event(
                        "process.evidence_warning", {"warning": "Worker evidence import failed"}
                    )
            recorder.event("process.cleanup", cleanup, "application")
            if import_error is not None and not failed:
                if isinstance(import_error, review_profile.BudgetExceeded):
                    raise review_profile.BudgetExceeded(import_error.code) from None
                raise ValueError("Worker evidence import failed") from import_error
        if not owner.cleanup["tree_empty"]:
            raise WorkerCleanupError("SDK worker cleanup could not be observed; no retry")
        path = directory / "response.json"
        limit = profile.max_response_bytes if profile is not None else 1_000_000
        if not path.is_file() or path.stat().st_size > limit:
            raise RuntimeError("SDK worker ended without a bounded response")
        response = json.loads(path.read_text(encoding="utf-8"))
        if code != 0 or response.get("error") or not isinstance(response.get("result"), dict):
            raise RuntimeError("SDK worker failed; inspect retained partial native evidence")
        native = dict(response["result"])
        if getattr(recorder, "private", False) is True:
            # Independent parent-side projection: never trust the worker file as already safe.
            fields = {
                name: native.get(name)
                for name in ("text", "outcome", "session_id", "usage", "application_usage")
            }
            native = analysis_privacy.worker_result(
                NativeResult(**fields), request.instructions, profile
            )
        if request.scenario_id == "sdk.fundamentals":
            checks = native.get("checks")
            if (
                not isinstance(checks, list)
                or len(checks) != 2
                or {item.get("id") for item in checks if isinstance(item, dict)}
                != {"exact-baseline-marker", "native-success"}
            ):
                raise ValueError("SDK baseline worker response lacks mandatory assertions")
            expected = {
                "exact-baseline-marker": (native.get("text") or "").strip()
                == "CAS_SDK_BASELINE_OK",
                "native-success": sdk_succeeded(native.get("outcome")),
            }
            if any(
                item.get("outcome") != ("pass" if expected[item["id"]] else "fail")
                for item in checks
            ):
                raise ValueError("SDK baseline worker assertions contradict the response")
        native["application_usage"] = {
            **(native.get("application_usage") or {}),
            "cleanup": owner.cleanup,
        }
        return NativeResult(**native)

    @staticmethod
    def import_evidence(directory, recorder, profile=None):
        snapshot = directory / "run.json"
        if snapshot.is_file() and snapshot.stat().st_size <= 1_000_000:
            record = json.loads(snapshot.read_text(encoding="utf-8"))
            validate_document("run", record)
            if record["run_id"] != recorder.run_id:
                raise ValueError("Worker evidence identity mismatch")
            for name in ("provider", "session_id", "sdk_outcome", "configuration"):
                recorder.record[name] = record[name]
            cleanup = recorder.record["usage"]["application"]["cleanup"]
            recorder.record["usage"] = record["usage"]
            recorder.record["usage"]["application"] = {
                **(recorder.record["usage"]["application"] or {}),
                "cleanup": cleanup,
            }
        journal = directory / "events.jsonl"
        if profile is not None and journal.is_file():
            # The worker's own budget is re-checked here; its file is never trusted as bounded.
            if journal.stat().st_size > profile.worker_journal_bytes:
                raise review_profile.BudgetExceeded(review_profile.WORKER_JOURNAL)
        events, warnings = read_events(
            journal, profile.parent_import_bytes if profile is not None else 4_000_000
        )
        if profile is not None and len(events) > profile.worker_events:
            raise review_profile.BudgetExceeded(review_profile.WORKER_EVENTS)
        for event in events:
            if event["run_id"] != recorder.run_id or event["seq"] != recorder.seq + 1:
                raise ValueError("Worker event identity/order mismatch")
            # Reuse canonical redaction/envelope validation and contiguous sequencing.
            recorder.event(
                event["type"],
                {**event["payload"], "worker_timestamp": event["timestamp"]},
                event["source"],
            )
        if warnings:
            recorder.event("process.evidence_warning", {"warnings": warnings}, "application")
            raise ValueError("Worker event journal is incomplete or exceeds bounded limits")
