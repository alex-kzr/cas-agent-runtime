"""Future private official login and bounded tmpfs holder; no secret output capture."""

import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

OWNER = "cas-working-session-87ae135e-46ea-4ed8-88ac-90b8ab348a2b"
PROFILE = "/home/cas/.claude"
CANCELLED = False
LOGOUT_ALLOWED = False


def profile_mount_ok(mountinfo, *, capacity, uid, mode):
    lines = [
        line
        for line in mountinfo.splitlines()
        if len(line.split()) > 5 and line.split()[4] == "/home/cas"
    ]
    if len(lines) != 1:
        raise ValueError("One home mount required")
    left, right = lines[0].split(" - ", 1)
    flags = set(left.split()[5].split(",")) | set(right.split()[2].split(","))
    if (
        right.split()[0] != "tmpfs"
        or not {"nosuid", "nodev", "noexec"}.issubset(flags)
        or capacity != 67108864
        or uid != 10001
        or mode != 0o700
    ):
        raise ValueError("Bounded private tmpfs profile required")


def check_profile():
    home = Path("/home/cas")
    value = home.stat()
    stats = os.statvfs(home)
    if home.is_symlink():
        raise ValueError("Symlink home forbidden")
    profile_mount_ok(
        Path("/proc/self/mountinfo").read_text(),
        capacity=stats.f_frsize * stats.f_blocks,
        uid=value.st_uid,
        mode=stat.S_IMODE(value.st_mode),
    )


def cleanup(namespace, seconds=5):
    deadline = time.monotonic() + seconds
    while True:
        namespace.terminate()
        namespace.reap()
        if not namespace.members():
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Auth tree cleanup unconfirmed")
        time.sleep(0.02)


def environment():
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": "/home/cas",
        "CLAUDE_CONFIG_DIR": PROFILE,
        "XDG_CONFIG_HOME": "/home/cas/.config",
        "CAS_DATA_DIR": "/var/lib/cas",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
        "CLAUDE_CODE_MAX_RETRIES": "0",
        "CLAUDE_CODE_RETRY_WATCHDOG": "0",
        "API_TIMEOUT_MS": "8000",
    }


def copy_local_auth(source, target):
    with source.open('rb') as incoming:
        data = incoming.read(65537)
    if not data or len(data) > 65536:
        raise ValueError('Invalid local credentials')
    with target.open('xb') as outgoing:
        if outgoing.write(data) != len(data):
            raise OSError('Incomplete local credentials copy')


def login_workflow(
    namespace,
    cli,
    status_call,
    env,
    *,
    cancelled=lambda: CANCELLED,
    clock=time.monotonic,
    sleep=time.sleep,
):
    child = None
    try:
        child = subprocess.Popen(
            [
                str(cli),
                "--setting-sources",
                "",
                "--settings",
                '{"forceLoginMethod":"claudeai","disableClaudeAiConnectors":true}',
                "auth",
                "login",
            ],
            env=env,
            stdin=None,
            stdout=None,
            stderr=None,
            shell=False,
        )
        deadline = clock() + 280
        while child.poll() is None:
            if cancelled() or clock() >= deadline:
                raise RuntimeError("Login cancelled/timeout")
            sleep(0.02)
        if child.returncode != 0 or cancelled():
            raise RuntimeError("Login failed")
    finally:
        try:
            if child is not None and child.poll() is None:
                namespace.terminate()
                child.wait(timeout=2)
        finally:
            cleanup(namespace)
    try:
        status_call()  # Existing strict status; raw response stays in private RAM.
    finally:
        cleanup(namespace)


def logout_if_allowed(namespace, cli, env, allowed):
    if not allowed:
        return False  # Never mutate profile while a work writer may remain alive.
    try:
        result = subprocess.run(
            [str(cli), "--setting-sources", "", "auth", "logout"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Official logout unconfirmed")
    finally:
        cleanup(namespace, seconds=1)
    return True


def main():
    global CANCELLED
    if (
        sys.platform != "linux"
        or os.getpid() != 1
        or os.getuid() != 10001
        or os.environ.get("CAS_PHASE1_ACTIVATION") != "one-approved-finite-working-session"
    ):
        raise RuntimeError("Dedicated activated Linux PID1 required")
    started = time.monotonic()

    def stop(number, frame):
        global CANCELLED
        CANCELLED = True  # Repeated signals never interrupt cleanup.

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def allow_logout(number, frame):
        global LOGOUT_ALLOWED
        LOGOUT_ALLOWED = True

    signal.signal(signal.SIGUSR1, allow_logout)
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(environment())
    check_profile()
    for name in (PROFILE, "/home/cas/.config", "/var/lib/cas"):
        Path(name).mkdir(parents=True, exist_ok=True)
    from agent_runtime.providers.claude.linux_namespace import LinuxNamespace

    namespace = LinuxNamespace()  # One finite auth workflow, never reused for SDK.
    from agent_runtime.providers.claude.auth import native_cli, subscription_status

    request = SimpleNamespace(
        live_authorized=True, allow_existing_login=True, auth_mode="subscription"
    )
    local_source = Path('/cas-local-auth')
    local_mode = local_source.is_file()
    if local_mode:
        # Copy into the private tmpfs; never mutate or log the host file.
        copy_local_auth(local_source, Path(PROFILE) / '.credentials.json')
    else:
        login_workflow(namespace, native_cli(), lambda: subscription_status(request, dict(os.environ)), dict(os.environ))
    if CANCELLED:
        raise RuntimeError("Cancelled before READY")
    check_profile()
    secret = Path(PROFILE) / ".credentials.json"
    value = secret.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != 10001
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
        or not 0 < value.st_size <= 65536
    ):
        raise RuntimeError("Unexpected native credential file; contents not opened/copied")
    import importlib.util

    definition = importlib.util.spec_from_file_location("ready_wire", "/cas-ready-wire.py")
    ready_wire = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(ready_wire)
    ready_wire.publish()
    print(
        "CAS_LOGIN_READY. Detach now with Ctrl-P then Ctrl-Q; do not stop this container.",
        flush=True,
    )
    while not CANCELLED and time.monotonic() - started < 380:
        time.sleep(0.1)
    if local_mode:
        return 0 if CANCELLED and LOGOUT_ALLOWED else 1
    if not logout_if_allowed(namespace, native_cli(), dict(os.environ), LOGOUT_ALLOWED):
        return 1
    return 0 if CANCELLED else 1  # Natural holder expiry is not a successful workflow.


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("CAS_LOGIN_FAILED; no replay. No credential details are recorded.", flush=True)
        raise SystemExit(1) from None
