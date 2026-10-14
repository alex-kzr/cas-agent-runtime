"""Private fixed SDK worker. Never a second executor or selectable fake provider."""

import asyncio
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path


def bounded_result(result, recorder):
    if result is None:
        return None
    values = {key: recorder.clean(value) for key, value in asdict(result).items()}
    if result.checks is not None:
        values["checks"] = [recorder.clean_document(check) for check in result.checks]
    return values


def main():
    # Ownership handshake first: do not import/construct SDK before the parent has
    # assigned this process to its non-breakaway Job Object and released stdin.
    raw = sys.stdin.buffer.read(1_000_001)
    if not raw or len(raw) > 1_000_000:
        return 2
    payload = json.loads(raw)
    from agent_runtime.providers.claude.auth import require_auth
    from agent_runtime.providers.claude.client import ClaudeAdapter
    from agent_runtime.tasks.models import ExecutionRequest, Limits
    from agent_runtime.telemetry.recorder import Recorder, atomic_json

    values = payload["request"]
    values["limits"] = Limits(**values["limits"])
    values["workspace"] = Path(values["workspace"])
    request = ExecutionRequest(**values)
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
    result = None
    error = None
    try:
        result = asyncio.run(ClaudeAdapter(os.environ).run(request, recorder))
    except Exception as exception:
        error = {"type": type(exception).__name__, "message": recorder.clean(str(exception))}
    finally:
        recorder.save()
        atomic_json(
            directory / "response.json",
            {"result": bounded_result(result, recorder), "error": error},
        )
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
