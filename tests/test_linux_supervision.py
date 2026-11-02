import asyncio
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from agent_runtime.providers.claude import linux_namespace as namespace
from agent_runtime.providers.claude.supervision import OwnedProcess


class NamespaceTests(unittest.TestCase):
    def status(self, **overrides):
        return "\n".join(f"{k}:\t{v}" for k, v in ({"NSpid": "1", "NoNewPrivs": "1", "CapEff": "00000000", "CapBnd": "00000000"} | overrides).items())

    def acquire(self, status=None, pid=1, uid=10001, members=(), matched=True):
        with (
            patch.object(namespace, "_acquired", False),
            patch.object(namespace.sys, "platform", "linux"),
            patch.object(namespace.os, "getpid", return_value=pid),
            patch.object(namespace.os, "geteuid", return_value=uid, create=True),
            patch.object(Path, "readlink", side_effect=[Path("pid:[123]"), Path("pid:[123]" if matched else "pid:[456]")]),
            patch.object(Path, "read_text", return_value=status or self.status()),
            patch.object(namespace.LinuxNamespace, "members", return_value=list(members)),
        ):
            boundary = namespace.LinuxNamespace()
            with self.assertRaises(RuntimeError):
                namespace.LinuxNamespace()
            return boundary

    def test_accepts_only_fresh_unprivileged_namespace_and_refuses_reuse(self):
        self.acquire()

    def test_rejects_host_init_shim_shared_procfs_privileges_and_existing_processes(self):
        for args in ({"pid": 42}, {"uid": 0}, {"members": [9]}, {"matched": False}, {"status": self.status(NSpid="90 1")}, {"status": self.status(NoNewPrivs="0")}, {"status": self.status(CapEff="1")}, {"status": self.status(CapBnd="1")}):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                self.acquire(**args)

    def test_terminate_is_namespace_wide_never_a_process_group(self):
        with patch.object(namespace.os, "kill") as kill, patch.object(namespace.signal, "SIGKILL", 9, create=True):
            namespace.LinuxNamespace.__new__(namespace.LinuxNamespace).terminate()
        self.assertEqual(kill.call_args.args[0], -1)


class LinuxRunTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, *, sink_failure=False, spawn_delay=False, fail_boundary=False):
        process = MagicMock()
        process.returncode = 17
        process.stdin.drain = AsyncMock()
        process.wait = AsyncMock(return_value=17)
        process.stderr.read = AsyncMock(side_effect=[b"synthetic", b""])
        boundary = MagicMock()
        boundary.members.side_effect = [[123], []]

        async def spawn(*args, **kwargs):
            if spawn_delay:
                await asyncio.sleep(0.05)
            return process

        owner = OwnedProcess()
        def sink(chunk):
            if sink_failure:
                raise ValueError("sink")
        with (
            patch("agent_runtime.providers.claude.supervision.sys.platform", "linux"),
            patch("agent_runtime.providers.claude.linux_supervision.LinuxNamespace", side_effect=RuntimeError("boundary") if fail_boundary else lambda: boundary),
            patch("asyncio.create_subprocess_exec", side_effect=spawn) as create,
        ):
            if fail_boundary:
                with self.assertRaises(RuntimeError):
                    await owner.run(["fixed-worker"], b"x", {}, stderr_sink=sink)
                create.assert_not_called()
                self.assertFalse(owner.cleanup["tree_empty"])
                return
            task = asyncio.create_task(owner.run(["fixed-worker"], b"x", {}, stderr_sink=sink))
            if spawn_delay:
                await asyncio.sleep(0.01)
                task.cancel()
            if spawn_delay:
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(owner.released)
                process.stdin.write.assert_not_called()
            elif sink_failure:
                with self.assertRaisesRegex(RuntimeError, "Stderr sink failed"):
                    await task
            else:
                self.assertEqual(await task, 17)
                process.stdin.write.assert_called_once_with(b"x")
            self.assertTrue(owner.cleanup["tree_empty"])
            boundary.terminate.assert_called()
            boundary.reap.assert_called()

    async def test_normal_nonzero_and_stderr_drain_after_cleanup(self):
        await self.exercise()

    async def test_cancellation_during_spawn_never_releases_input(self):
        await self.exercise(spawn_delay=True)

    async def test_boundary_failure_never_spawns(self):
        await self.exercise(fail_boundary=True)

    async def test_stderr_sink_failure_visible_after_cleanup(self):
        await self.exercise(sink_failure=True)

    async def test_cleanup_timeout_or_query_or_kill_failure_cannot_claim_empty_tree(self):
        for failure in ("timeout", "query", "kill"):
            owner = OwnedProcess(0.03)
            process = MagicMock()
            process.returncode = 0
            process.stdin.drain = AsyncMock()
            process.wait = AsyncMock(return_value=0)
            boundary = MagicMock()
            boundary.members.return_value = [123]
            if failure == "query":
                boundary.members.side_effect = OSError("synthetic query failure")
            if failure == "kill":
                boundary.terminate.side_effect = OSError("synthetic kill failure")
            with (
                self.subTest(failure=failure),
                patch("agent_runtime.providers.claude.supervision.sys.platform", "linux"),
                patch("agent_runtime.providers.claude.linux_supervision.LinuxNamespace", return_value=boundary),
                patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
            ):
                try:
                    await owner.run(["fixed-worker"], b"x", {})
                except OSError:
                    self.assertEqual(failure, "kill")
                self.assertFalse(owner.cleanup["tree_empty"])

    async def test_repeated_cancellation_waits_for_cleanup_and_preserves_cancel(self):
        owner = OwnedProcess(0.5)
        process = MagicMock()
        process.returncode = None
        process.stdin.drain = AsyncMock()
        cleanup_wait = asyncio.Event()
        cleanup_started = asyncio.Event()

        async def wait():
            cleanup_started.set()
            await cleanup_wait.wait()
            process.returncode = -9

        process.wait = wait
        boundary = MagicMock()
        boundary.members.side_effect = [[123], []]
        with (
            patch("agent_runtime.providers.claude.supervision.sys.platform", "linux"),
            patch("agent_runtime.providers.claude.linux_supervision.LinuxNamespace", return_value=boundary),
            patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)),
        ):
            task = asyncio.create_task(owner.run(["fixed-worker"], b"x", {}))
            while not owner.released:
                await asyncio.sleep(0)
            task.cancel()
            await cleanup_started.wait()
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            cleanup_wait.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(owner.cleanup["tree_empty"])
