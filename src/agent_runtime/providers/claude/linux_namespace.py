"""One execution per dedicated Linux PID namespace; never a process-group claim.

CAS must be namespace init (PID 1), with a matching private procfs and no other
processes at acquisition. The container runtime owns the outer boundary. No
container exec, shared PID namespace, init shim or concurrent owners are allowed.
"""

import os
import signal
import sys
from pathlib import Path

_acquired = False


class LinuxNamespace:
    def __init__(self):
        global _acquired
        if sys.platform != "linux" or os.getpid() != 1:
            raise RuntimeError("Linux supervision requires CAS as PID 1 in a dedicated container")
        if _acquired:
            raise RuntimeError("Only one owned execution is allowed per container")
        self.proc = Path("/proc")
        if (self.proc / "self/ns/pid").readlink() != (self.proc / "1/ns/pid").readlink():
            raise RuntimeError("procfs does not match the supervisor PID namespace")
        # A host procfs mounted over /proc must not grant a namespace-wide kill.
        status = (self.proc / "self/status").read_text()
        nspid = next((line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:")), [])
        if nspid != ["1"] or self.members():
            raise RuntimeError("A fresh dedicated PID namespace and matching procfs are required")
        # All descendants inherit the unprivileged UID and cannot gain privilege.
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        if os.geteuid() == 0 or fields.get("NoNewPrivs", "").strip() != "1":
            raise RuntimeError("Linux containment requires non-root and no-new-privileges")
        if int(fields.get("CapEff", "0").strip(), 16) != 0 or int(fields.get("CapBnd", "0").strip(), 16) != 0:
            raise RuntimeError("Linux containment requires all capabilities dropped")
        _acquired = True  # Deliberately never released: a second run needs a fresh container.

    def members(self):
        return [int(path.name) for path in self.proc.iterdir() if path.name.isdecimal() and path.name != "1"]

    def terminate(self):
        # Linux kill(-1) reaches all signalable members of this PID namespace,
        # including double forks/setsid descendants, excluding caller and PID 1.
        # Namespace ownership is acquired BEFORE any worker input is released.
        try:
            os.kill(-1, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def reap(self):
        # Call only after asyncio has reaped its direct worker, to avoid stealing
        # that wait status. Orphaned grandchildren are adopted by namespace init.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
