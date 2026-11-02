"""One ordinary text-only task in fresh nonroot Linux PID1. Input is data, not code."""

import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path

PRIVATE = re.compile(
    r'''(?i)(sk-ant-[\w-]{12,}|\bbearer\s+\S{12,}|-----BEGIN [\w ]*PRIVATE KEY|(?:access_?token|refresh_?token|client_?secret|password)["']?\s*[:=]|https?://\S*(?:oauth|[?&]code=|[?&]token=|/auth/))'''
)
SECRET_VALUE = re.compile(
    r'''(?i)(sk-ant-[\w-]{12,}|\bbearer\s+\S{12,}|-----BEGIN [\w ]*PRIVATE KEY[\s\S]*?-----END [\w ]*PRIVATE KEY-----|(?:access_?token|refresh_?token|client_?secret|password)["']?\s*[:=][ \t]*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)|https?://\S*(?:oauth|[?&]code=|[?&]token=|/auth/)\S*)'''
)


def identity(value):
    return (
        hashlib.sha256(value.encode()).hexdigest()
        if isinstance(value, str) and re.fullmatch("[A-Za-z0-9_-]{1,128}", value)
        else None
    )


def summary(task):
    return dict(
        scope="cas-working-task-v1",
        stage=task["stage"],
        run_id=task["run_id"],
        result="FAIL",
        query_count=1,
        native_success=False,
        text="",
        session_hash=None,
        tree_empty=False,
        auth_profile_shared=True,
        context_isolation="NOT_PROVED",
        failure_code="WORK_EXCEPTION",
    )


def selected_text(text):
    if not isinstance(text, str) or not text.strip():
        return ''
    text = SECRET_VALUE.sub('[REDACTED]', text)
    if PRIVATE.search(text):
        return ''
    encoded = text.encode('utf-8')
    if len(encoded) <= 4096:
        return text
    suffix = '\n[Result truncated]'
    return encoded[:4096 - len(suffix.encode('utf-8'))].decode('utf-8', errors='ignore') + suffix


def task_data(path=Path("/cas-task.json")):
    from uuid import UUID

    path = Path(path)
    if path.stat().st_size > 8192:
        raise ValueError("TASK_INVALID")
    d = json.loads(path.read_text(encoding="utf-8"))
    if (
        set(d) != {"stage", "run_id", "task_id", "prompt"}
        or d["stage"] not in {"first", "second"}
        or any(str(UUID(d[k])) != d[k] for k in ["run_id", "task_id"])
        or not isinstance(d["prompt"], str)
        or not 1 <= len(d["prompt"].encode("utf-8")) <= 2048
        or PRIVATE.search(d["prompt"])
    ):
        raise ValueError("TASK_INVALID")
    return d


async def execute(executor, request, data, task):
    from agent_runtime.tasks.models import sdk_succeeded

    r = await executor.execute(request)
    d = summary(task)
    cleanup = (r.get("usage", {}).get("application") or {}).get("cleanup", {})
    d["tree_empty"] = (
        cleanup.get("tree_empty") is True and cleanup.get("mechanism") == "linux-pid-namespace"
    )
    d["session_hash"] = identity(r.get("session_id"))
    d["native_success"] = r.get("status") == "COMPLETED" and sdk_succeeded(r.get("sdk_outcome"))
    path = data / "runs" / task["run_id"] / "result.json"
    if d["native_success"] and path.is_file() and path.stat().st_size <= 1048576:
        text = json.loads(path.read_text()).get("summary")
        d['text'] = selected_text(text)
    good = (
        d["native_success"]
        and d["tree_empty"]
        and bool(d["text"].strip())
        and d["session_hash"] is not None
    )
    d["result"] = "PASS" if good else "FAIL"
    d["failure_code"] = None if good else "EXECUTION_NOT_ACCEPTED"
    return d


def wait_go():
    import select

    until = time.monotonic() + 20
    body = b""
    while len(body) < 8 and time.monotonic() < until:
        if not select.select([0], [], [], max(0, until - time.monotonic()))[0]:
            break
        part = os.read(0, 8 - len(body))
        if not part:
            break
        body += part
        if b"\n" in body:
            break
    if body != b"GO\n":
        raise ValueError("GO_REQUIRED")


def main():
    if (
        sys.platform != "linux"
        or os.getpid() != 1
        or os.getuid() != 10001
        or os.environ.get("CAS_PHASE1_ACTIVATION") != "one-approved-finite-working-session"
    ):
        raise ValueError("DEDICATED_PID1_REQUIRED")
    if any(
        r.split()[1] == "00000000"
        for r in Path("/proc/net/route").read_text().splitlines()[1:]
        if r.split()
    ):
        raise ValueError("NO_DEFAULT_ROUTE")
    wait_go()
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(
        dict(
            PATH="/usr/local/bin:/usr/bin:/bin",
            LANG="C.UTF-8",
            HOME="/home/cas",
            CLAUDE_CONFIG_DIR="/home/cas/.claude",
            CAS_DATA_DIR="/var/lib/cas",
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONUNBUFFERED="1",
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
            DISABLE_AUTOUPDATER="1",
        )
    )
    info = Path("/home/cas").stat()
    capacity = os.statvfs("/home/cas")
    lines = [
        s
        for s in Path("/proc/self/mountinfo").read_text().splitlines()
        if s.split()[4] == "/home/cas"
    ]
    if (
        len(lines) != 1
        or " - tmpfs " not in lines[0]
        or info.st_uid != 10001
        or stat.S_IMODE(info.st_mode) != 0o700
        or capacity.f_frsize * capacity.f_blocks != 67108864
    ):
        raise ValueError("PROFILE_GUARD")
    flags = set(lines[0].split()[5].split(",")) | set(
        lines[0].split(" - ", 1)[1].split()[2].split(",")
    )
    if not {"nosuid", "nodev", "noexec"}.issubset(flags):
        raise ValueError("PROFILE_GUARD")

    def stop(n, frame):
        raise SystemExit(128 + n)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter
    from agent_runtime.tasks.executor import Executor
    from agent_runtime.tasks.models import ExecutionRequest, Limits

    task = task_data()
    data = Path("/var/lib/cas")
    if (data / "runs").exists():
        raise ValueError("ONE_EXECUTION")
    request = ExecutionRequest(
        "task",
        task["prompt"],
        data / "workspaces" / task["run_id"],
        Limits(1, "0.05", 30),
        model="claude-haiku-4-5-20251001",
        live_authorized=True,
        auth_mode="subscription",
        allow_existing_login=True,
        login_config_dir="/home/cas/.claude",
        run_id=task["run_id"],
        task_id=task["task_id"],
    )
    result = asyncio.run(
        execute(
            Executor(
                data, SupervisedClaudeAdapter(dict(os.environ)), workspace_root=data / "workspaces"
            ),
            request,
            data,
            task,
        )
    )
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(1) from None  # no native/profile exception or transcript export
