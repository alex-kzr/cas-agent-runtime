"""Fixed marker only. No credentials, auth imports, subprocess, socket or diagnostics."""

import os
import stat
import time
from pathlib import Path

PATH = Path("/var/lib/cas/auth-ready.json")
OWNER = "cas-working-session-87ae135e-46ea-4ed8-88ac-90b8ab348a2b"
MARKER = ("CAS_READY_V1:" + OWNER + "\n").encode("ascii")
TOKEN = b"CAS_READY_V1_OK\n"


def publish():
    fd = os.open(PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, MARKER) != len(MARKER):
            raise RuntimeError("fixed-marker-write")
        os.fsync(fd)
    finally:
        os.close(fd)


def check():
    os.environ.clear()
    if os.getuid() != 10001 or os.getgid() != 10001:
        return False
    fd = os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 10001
            and info.st_gid == 10001
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_size == len(MARKER)
        ):
            return False
        return os.read(fd, len(MARKER) + 1) == MARKER
    finally:
        os.close(fd)


def main():
    deadline = time.monotonic() + 4
    ok = False
    while True:
        try:
            ok = check()
        except FileNotFoundError:
            ok = False
        except BaseException:
            break
        if ok or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    if ok:
        try:
            if os.write(1, TOKEN) != len(TOKEN):
                return 1
        except BaseException:
            return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
