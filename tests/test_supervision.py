import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.supervision import OwnedProcess


@unittest.skipUnless(os.name == "nt", "Windows Job Object containment")
class SupervisionTests(unittest.IsolatedAsyncioTestCase):
    def assert_owned_fixture_pid_exited(self, pid):
        import ctypes
        from ctypes import wintypes as w

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.OpenProcess.argtypes, api.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
        api.WaitForSingleObject.argtypes, api.WaitForSingleObject.restype = (
            [w.HANDLE, w.DWORD],
            w.DWORD,
        )
        api.CloseHandle.argtypes = [w.HANDLE]
        handle = api.OpenProcess(0x100000, False, pid)
        if handle:
            try:
                self.assertEqual(
                    api.WaitForSingleObject(handle, 0), 0, "Owned fixture descendant is still alive"
                )
            finally:
                api.CloseHandle(handle)

    async def test_deadline_kills_worker_and_descendant_but_not_unrelated_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant.json"
            code = (
                "import sys,subprocess,time,json,pathlib;sys.stdin.buffer.read();"
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)']);"
                f"pathlib.Path({str(marker)!r}).write_text(json.dumps(p.pid));"
                "time.sleep(90)"
            )
            unrelated = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "import time;time.sleep(90)"
            )
            owner = OwnedProcess()
            started = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):
                    async with asyncio.timeout(2):
                        await owner.run([sys.executable, "-c", code], b"synthetic", {})
                self.assertTrue(marker.is_file())
                self.assertTrue(owner.cleanup["tree_empty"])
                self.assertTrue(owner.cleanup["forced"])
                self.assert_owned_fixture_pid_exited(json.loads(marker.read_text()))
                self.assertIsNone(unrelated.returncode)
                self.assertLess(time.monotonic() - started, 7)
            finally:
                unrelated.kill()
                await asyncio.wait_for(unrelated.wait(), 3)

    async def test_normal_worker_exit_still_cleans_leftover_descendant(self):
        code = (
            "import sys,subprocess;sys.stdin.buffer.read();"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(90)'])"
        )
        owner = OwnedProcess()
        async with asyncio.timeout(5):
            result = await owner.run([sys.executable, "-c", code], b"synthetic", {})
        self.assertEqual(result, 0)
        self.assertTrue(owner.cleanup["tree_empty"])

    async def test_cancelled_worker_is_reaped_with_bounded_cleanup(self):
        owner = OwnedProcess()
        task = asyncio.create_task(
            owner.run(
                [sys.executable, "-c", "import sys,time;sys.stdin.buffer.read();time.sleep(90)"],
                b"synthetic",
                {},
            )
        )
        while owner.process is None or not owner.released:
            await asyncio.sleep(0.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        self.assertTrue(owner.cleanup["tree_empty"])

    async def test_nonzero_worker_exit_is_visible_and_cleanup_is_recorded(self):
        owner = OwnedProcess()
        result = await owner.run(
            [sys.executable, "-c", "import sys;sys.stdin.read();sys.exit(17)"], b"x", {}
        )
        self.assertEqual(result, 17)
        self.assertTrue(owner.cleanup["tree_empty"])

    async def test_cancellation_during_spawn_reaps_waiting_worker(self):
        create = asyncio.create_subprocess_exec

        async def delayed(*args, **kwargs):
            await asyncio.sleep(0.1)
            return await create(*args, **kwargs)

        owner = OwnedProcess()
        with patch("asyncio.create_subprocess_exec", delayed):
            task = asyncio.create_task(
                owner.run(
                    [sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
                    b"synthetic",
                    {},
                )
            )
            await asyncio.sleep(0.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        self.assertIsNotNone(owner.process.returncode)
        self.assertTrue(owner.cleanup["tree_empty"])

    async def test_assignment_failure_never_releases_worker_input(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected.txt"
            code = f"import sys,pathlib;sys.stdin.buffer.read();pathlib.Path({str(marker)!r}).write_text('bad')"
            owner = OwnedProcess()
            with patch(
                "agent_runtime.providers.claude.windows_job.WindowsJob.assign",
                side_effect=OSError("synthetic denial"),
            ):
                with self.assertRaises(OSError):
                    await owner.run([sys.executable, "-c", code], b"synthetic", {})
            self.assertFalse(marker.exists())
            self.assertTrue(owner.cleanup["tree_empty"])

    async def test_delayed_assignment_contains_venv_launcher_descendants(self):
        from agent_runtime.providers.claude.windows_job import WindowsJob

        assign = WindowsJob.assign

        def delayed(job, pid):
            time.sleep(0.2)
            return assign(job, pid)

        with patch.object(WindowsJob, "assign", delayed):
            await self.test_deadline_kills_worker_and_descendant_but_not_unrelated_child()

    async def test_double_assignment_and_query_failure_reaps_unreleased_worker(self):
        owner = OwnedProcess()
        with (
            patch(
                "agent_runtime.providers.claude.windows_job.WindowsJob.assign",
                side_effect=OSError("synthetic assign"),
            ),
            patch(
                "agent_runtime.providers.claude.windows_job.WindowsJob.active",
                side_effect=OSError("synthetic query"),
            ),
        ):
            with self.assertRaises(OSError):
                await owner.run([sys.executable, "-c", "import sys;sys.stdin.read()"], b"x", {})
        await asyncio.wait_for(owner.process.wait(), 3)
        self.assertIsNotNone(owner.process.returncode)


class HandoffTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(
        self,
        *,
        timeout=False,
        corrupt=False,
        uncertain=False,
        baseline=False,
        large=False,
        drop_checks=False,
        operational_error=False,
        journal=None,
    ):

        from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter
        from agent_runtime.tasks.executor import Executor, NativeResult
        from agent_runtime.tasks.models import ExecutionRequest, Limits
        from agent_runtime.telemetry.recorder import Recorder, atomic_json

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "scenario" if baseline else "task",
                "synthetic",
                root / "workspaces/one",
                Limits(1, "0.10", 5),
                live_authorized=True,
                auth_mode="api",
                scenario_id="sdk.fundamentals" if baseline else None,
            )

            class FixtureOwner:
                cleanup = {
                    "mechanism": "test-double",
                    "tree_empty": not uncertain,
                    "forced": timeout,
                }

                async def run(self, command, payload, environment):
                    values = json.loads(payload)
                    self.assertion = "synthetic-key" not in payload.decode()
                    if not self.assertion:
                        raise AssertionError("Key leaked into worker input")
                    recorder = Recorder.__new__(Recorder)
                    recorder.directory = Path(values["directory"])
                    recorder.record = values["record"]
                    recorder.run_id = recorder.record["run_id"]
                    recorder.seq = values["seq"]
                    recorder.secrets = ("synthetic-key",)
                    recorder.record["session_id"] = "synthetic-session"
                    recorder.record["sdk_outcome"] = {
                        "subtype": "success",
                        "is_error": False,
                        "terminal_reason": "completed",
                    }
                    recorder.record["usage"]["sdk"] = {"total_cost_usd": 0.001}
                    recorder.event("sdk.message", {"message": "synthetic-key"}, "sdk")
                    recorder.save()
                    if journal == "missing":
                        (recorder.directory / "events.jsonl").unlink()
                    elif journal == "partial":
                        with (recorder.directory / "events.jsonl").open("ab") as stream:
                            stream.write(b'{"partial":')
                    if corrupt:
                        (recorder.directory / "run.json").write_text("invalid json")
                    if operational_error:
                        raise OSError("synthetic worker failure")
                    if timeout:
                        raise TimeoutError("synthetic deadline")
                    native = NativeResult(
                        "wrong " * 10000 if large else "synthetic answer",
                        recorder.record["sdk_outcome"],
                        "synthetic-session",
                        recorder.record["usage"]["sdk"],
                        checks=[
                            {
                                "id": "exact-baseline-marker",
                                "expected": "CAS_SDK_BASELINE_OK",
                                "observed": "wrong " * 10000,
                                "outcome": "fail",
                                "evidence_refs": [],
                            },
                            {
                                "id": "native-success",
                                "expected": True,
                                "observed": True,
                                "outcome": "pass",
                                "evidence_refs": [],
                            },
                        ]
                        if baseline
                        else None,
                    )
                    from agent_runtime.providers.claude.worker import bounded_result

                    result = bounded_result(native, recorder)
                    if drop_checks:
                        result.pop("checks", None)
                    atomic_json(
                        recorder.directory / "response.json", {"result": result, "error": None}
                    )
                    return 0

            with patch("agent_runtime.providers.claude.supervised.OwnedProcess", FixtureOwner):
                run = await Executor(
                    root,
                    SupervisedClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-key"}),
                    secrets=("synthetic-key",),
                ).execute(request)
            events = (root / "runs" / run["run_id"] / "events.jsonl").read_text()
            self.assertNotIn("synthetic-key", events)
            return run, [json.loads(line) for line in events.splitlines()]

    async def test_success_preserves_cleanup_and_native_evidence(self):
        run, events = await self.exercise()
        self.assertEqual(run["status"], "COMPLETED")
        self.assertTrue(run["usage"]["application"]["cleanup"]["tree_empty"])
        self.assertEqual([event["seq"] for event in events], list(range(1, len(events) + 1)))
        self.assertEqual(run["session_id"], "synthetic-session")

    async def test_timeout_preserves_partial_observed_usage(self):
        run, _ = await self.exercise(timeout=True)
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["category"], "timeout")
        self.assertEqual(run["usage"]["sdk"]["total_cost_usd"], 0.001)
        self.assertTrue(run["usage"]["application"]["cleanup"]["tree_empty"])

    async def test_corrupt_handoff_cannot_hide_original_timeout(self):
        run, events = await self.exercise(timeout=True, corrupt=True)
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["category"], "timeout")
        self.assertTrue(any(event["type"] == "process.evidence_warning" for event in events))

    async def test_unknown_cleanup_is_interrupted_even_without_timeout(self):
        run, _ = await self.exercise(uncertain=True)
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["code"], "cleanup_unconfirmed")

    async def test_large_baseline_cannot_drop_assertions_or_pass(self):
        run, _ = await self.exercise(baseline=True, large=True)
        self.assertEqual(run["status"], "FAILED")

    async def test_missing_baseline_checks_reject_instead_of_defaulting(self):
        run, _ = await self.exercise(baseline=True, drop_checks=True)
        self.assertEqual(run["status"], "FAILED")

    async def test_operational_error_with_unknown_cleanup_is_interrupted(self):
        run, _ = await self.exercise(uncertain=True, operational_error=True)
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["code"], "cleanup_unconfirmed")

    async def test_success_response_cannot_promote_incomplete_worker_journal(self):
        for journal in ("missing", "partial"):
            with self.subTest(journal=journal):
                run, _ = await self.exercise(journal=journal)
                self.assertEqual(run["status"], "FAILED")
                self.assertEqual(run["evidence_status"], "partial")
