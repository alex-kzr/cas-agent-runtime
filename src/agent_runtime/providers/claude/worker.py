"""Private fixed SDK worker. Never a second executor or selectable fake provider."""

import asyncio
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path


def bounded_result(result, recorder, instructions=None, profile=None):
    if result is None:
        return None
    if getattr(recorder, "private", False) is True:
        # Analysis: only a validated source-grounded report or no text reaches disk.
        from agent_runtime.tasks import analysis_privacy

        return analysis_privacy.worker_result(result, instructions, profile)
    values = {key: recorder.clean(value) for key, value in asdict(result).items()}
    if result.checks is not None:
        values["checks"] = [recorder.clean_document(check) for check in result.checks]
    return values


def main():
    # Ownership handshake first: do not import/construct SDK before the parent has
    # contained this process (Windows Job Object/Linux PID namespace) and released stdin.
    raw = sys.stdin.buffer.read(1_000_001)
    return run_payload(raw)


def run_payload(raw):
    if not raw or len(raw) > 1_000_000:
        return 2
    payload = json.loads(raw)
    from agent_runtime.providers.claude.auth import require_auth
    from agent_runtime.providers.claude.client import ClaudeAdapter
    from agent_runtime.tasks import review_profile, vs_review_profile
    from agent_runtime.tasks.models import ExecutionRequest, Limits
    from agent_runtime.telemetry.recorder import Recorder, atomic_json

    values = payload["request"]
    values["limits"] = Limits(**values["limits"])
    values["workspace"] = Path(values["workspace"])
    request = ExecutionRequest(**values)
    from agent_runtime.tasks import analysis_privacy

    # Scope identity comes from ONE typed profile; the worker re-derives every bound from it and
    # trusts nothing else in the payload (no arbitrary runtime limits).
    profile = None
    if payload.get("profile") is not None:
        profile = review_profile.from_payload(payload["profile"])
        if profile.profile_id == vs_review_profile.PROFILE_ID:
            # The VS payload is manifest-only: rebuild the verified bytes from the request itself
            # against the fixed names, sizes, hashes and query identity. Anything else fails here,
            # before auth or any SDK construction.
            try:
                profile = profile.bind_query(request.instructions)
            except ValueError:
                return 2
        if (
            request.scenario_id != analysis_privacy.SCENARIO
            or request.model != profile.model
            or request.limits != profile.limits()
            or request.instructions != profile.query_text
            or request.agent_name != "text-only-v1"
            or len(raw) > profile.max_input_bytes
        ):
            return 2
    require_auth(request, os.environ)
    directory = Path(payload["directory"])
    recorder = Recorder.__new__(Recorder)
    recorder.data_dir = directory.parent.parent.parent
    recorder.directory = directory
    recorder.record = payload["record"]
    recorder.run_id = recorder.record["run_id"]
    recorder.task_id = recorder.record["task_id"]
    recorder.seq = payload["seq"]
    recorder.secrets = (os.environ["ANTHROPIC_API_KEY"],) if request.auth_mode == "api" else ()
    recorder.private = analysis_privacy.enabled(request.scenario_id)
    if profile is not None:
        # Worker journal budget: events and bytes, written before any growth.
        recorder.event_limit = recorder.seq + profile.worker_events
        recorder.event_limit_code = review_profile.WORKER_EVENTS
        recorder.journal_limit = profile.worker_journal_bytes
    result = None
    error = None
    try:
        result = asyncio.run(ClaudeAdapter(os.environ, profile).run(request, recorder))
    except Exception as exception:
        # Analysis: exception text may carry provider content; keep the type name only.
        error = {
            "type": type(exception).__name__,
            "message": analysis_privacy.WITHHELD
            if recorder.private
            else recorder.clean(str(exception)),
        }
    finally:
        recorder.save()
        atomic_json(
            directory / "response.json",
            {
                "result": bounded_result(result, recorder, request.instructions, profile),
                "error": error,
            },
        )
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
