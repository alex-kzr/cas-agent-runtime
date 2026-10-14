import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.tasks.coding import CodingWorkspace


class CodingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspaces" / "fixture"
        CodingWorkspace.create(self.workspace)
        self.coding = CodingWorkspace(self.workspace, self.root / "evidence")

    async def test_fixed_command_baseline_fails_then_patch_passes(self):
        baseline = await self.coding.test()
        self.assertNotEqual(baseline["exit_code"], 0)
        self.coding.write("calc.py", "def add(a, b):\n    return a + b\n")
        result = await self.coding.test()
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["cleanup"]["tree_empty"])
        report = self.coding.capture()
        self.assertTrue(report["changed"])
        self.assertIn("+    return a + b", (self.root / "evidence" / "changes.diff").read_text())

    async def test_path_and_code_fail_closed(self):
        for path in ("../calc.py", "C:/calc.py", "calc.py:stream", "tests.py", ".git/config"):
            with self.assertRaises(ValueError):
                self.coding.write(path, "def add(a, b):\n    return a + b\n")
        for source in (
            "import os",
            'def add(a,b):\n return __import__("os")',
            "def add(a,b):\n while True: pass",
        ):
            with self.assertRaises(ValueError):
                self.coding.write("calc.py", source)

    async def test_extra_file_and_changed_test_result_rejected(self):
        (self.workspace / "extra.py").write_text("pass")
        with self.assertRaises(ValueError):
            self.coding.capture()
        (self.workspace / "extra.py").unlink()
        self.coding.write("calc.py", "def add(a, b):\n    return a + b\n")
        await self.coding.test()
        self.coding.write("calc.py", "def add(a, b):\n    return a - b\n")
        self.assertFalse(self.coding.capture()["tests_passed"])

    async def test_saved_report_contains_only_fixture_data(self):
        await self.coding.test()
        self.coding.capture()
        report = json.loads((self.root / "evidence" / "coding.json").read_text())
        self.assertEqual(report["schema_version"], 1)
        self.assertFalse(report["tests_passed"])

    async def test_missing_or_invalid_worker_output_cannot_pass_acceptance(self):
        coding = self.coding

        class FakeOwner:
            cleanup = {"tree_empty": True}

            async def run(self, command, payload, environment):
                return 0

        with patch("agent_runtime.tasks.coding.OwnedProcess", FakeOwner):
            with self.assertRaises(ValueError):
                await coding.test()
        self.assertFalse(coding.capture()["tests_passed"])

    async def test_concurrent_write_and_second_test_are_rejected(self):
        import asyncio

        coding = self.coding
        entered = asyncio.Event()
        release = asyncio.Event()

        class FakeOwner:
            cleanup = {"tree_empty": True}

            async def run(self, command, payload, environment):
                entered.set()
                await release.wait()
                return 0

        with patch("agent_runtime.tasks.coding.OwnedProcess", FakeOwner):
            pending = asyncio.create_task(coding.test())
            await entered.wait()
            with self.assertRaises(ValueError):
                coding.write("calc.py", "def add(a,b):\n return a + b\n")
            with self.assertRaises(ValueError):
                await coding.test()
            release.set()
            with self.assertRaises(ValueError):
                await pending

    async def test_corrupt_mismatched_and_empty_checks_never_pass(self):
        from agent_runtime.tasks.coding import digest

        coding = self.coding
        for index, bad in enumerate(
            [
                "{",
                json.dumps({"exit_code": 0, "source_sha256": "wrong", "checks": []}),
                json.dumps(
                    {"exit_code": 0, "source_sha256": digest(coding.read("calc.py")), "checks": []}
                ),
            ]
        ):
            coding.invocations = 0

            class FakeOwner:
                cleanup = {"tree_empty": True}

                async def run(self, command, payload, environment, content=bad):
                    target = Path(json.loads(payload)["output"])
                    target.write_text(content)
                    return 0

            with (
                self.subTest(index=index),
                patch("agent_runtime.tasks.coding.OwnedProcess", FakeOwner),
            ):
                with self.assertRaises((ValueError, KeyError)):
                    await coding.test()
            self.assertFalse(coding.capture()["tests_passed"])

    async def test_executor_timeout_keeps_partial_artifacts_and_owned_cleanup(self):
        import sys

        from agent_runtime.providers.claude.supervision import OwnedProcess
        from agent_runtime.tasks.executor import Executor
        from agent_runtime.tasks.models import ExecutionRequest, Limits

        class WaitingFixture:
            async def run(self, request, recorder):
                owner = OwnedProcess()
                try:
                    await owner.run(
                        [
                            sys.executable,
                            "-I",
                            "-c",
                            "import sys,time;sys.stdin.buffer.read();time.sleep(30)",
                        ],
                        b"fixture",
                        {},
                    )
                finally:
                    recorder.record["usage"]["application"] = {"cleanup": owner.cleanup}

        request = ExecutionRequest(
            "task",
            "synthetic timeout test",
            self.workspace,
            Limits(2, "0.10", 1),
            agent_name="coding-fixture-v1",
        )
        run = await Executor(self.root, WaitingFixture()).execute(request)
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["category"], "timeout")
        self.assertTrue(run["usage"]["application"]["cleanup"]["tree_empty"])
        self.assertTrue((self.root / run["artifacts_ref"]).is_file())
