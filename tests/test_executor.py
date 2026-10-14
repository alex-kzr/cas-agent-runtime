import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.tasks.executor import Executor, NativeResult
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import atomic_json


class FixtureClient:
    """Explicit test double; never selectable as a production CLI provider."""

    def __init__(self, text="verified fixture output", error=False, delay=0):
        self.text, self.error, self.delay = text, error, delay
        self.calls = 0

    async def run(self, request, recorder):
        self.calls += 1
        recorder.event("sdk.message", {"fixture": True}, "sdk")
        await asyncio.sleep(self.delay)
        return NativeResult(
            self.text,
            {
                "subtype": "error_during_execution" if self.error else "success",
                "is_error": self.error,
                "terminal_reason": None,
            },
            "fixture-session",
            {"total_cost_usd": None},
        )


class ExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def request(self, kind="task", timeout=5):
        return ExecutionRequest(
            kind,
            "explicit fixture request",
            self.root / "workspaces/one",
            Limits(2, "0.10", timeout),
            "offline-contracts" if kind == "scenario" else None,
        )

    async def test_task_and_scenario_use_same_executor(self):
        client = FixtureClient()
        executor = Executor(self.root, client)
        task = await executor.execute(self.request())
        scenario = await executor.execute(self.request("scenario"))
        self.assertEqual(client.calls, 2)
        for run in (task, scenario):
            self.assertEqual(run["status"], "COMPLETED")
            self.assertEqual(run["validation"]["status"], "passed")
            self.assertTrue((self.root / run["result_ref"]).is_file())
            self.assertTrue((self.root / run["artifacts_ref"]).is_file())

    async def test_native_error_and_failed_validation_never_succeed(self):
        for client in (FixtureClient(error=True), FixtureClient(text="")):
            run = await Executor(self.root, client).execute(self.request())
            self.assertEqual(run["status"], "FAILED")
            self.assertIsNotNone(run["error"])

    async def test_exception_persisted_without_secret(self):
        class Broken:
            async def run(self, request, recorder):
                raise RuntimeError("TEST-PRIVATE-MARKER")

        run = await Executor(self.root, Broken(), secrets=["TEST-PRIVATE-MARKER"]).execute(
            self.request()
        )
        self.assertEqual(run["status"], "FAILED")
        for file in (self.root / "runs" / run["run_id"]).glob("*.json*"):
            self.assertNotIn("TEST-PRIVATE-MARKER", file.read_text())

    async def test_timeout_records_uncertain_cleanup_as_interrupted(self):
        run = await Executor(self.root, FixtureClient(delay=2)).execute(self.request(timeout=1))
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["category"], "timeout")

    async def test_no_implicit_retry(self):
        client = FixtureClient(error=True)
        await Executor(self.root, client).execute(self.request())
        self.assertEqual(client.calls, 1)

    async def test_artifact_persistence_error_after_sdk_success_is_failed(self):
        with patch(
            "agent_runtime.tasks.executor.Path.write_bytes",
            side_effect=OSError("fixture disk failure"),
        ):
            run = await Executor(self.root, FixtureClient()).execute(self.request())
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(run["error"]["category"], "persistence")
        self.assertEqual(run["evidence_status"], "partial")

    async def test_assertion_persistence_error_after_success_is_failed(self):
        def write(path, document):
            if path.name == "assertions.json":
                raise OSError("fixture assertion disk failure")
            return atomic_json(path, document)

        with patch("agent_runtime.tasks.executor.atomic_json", side_effect=write):
            run = await Executor(self.root, FixtureClient()).execute(self.request("scenario"))
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(run["error"]["category"], "persistence")

    async def test_failed_assertion_prevents_completed_scenario(self):
        class FailedCheck:
            async def run(self, request, recorder):
                return NativeResult(
                    "output",
                    {"subtype": "success", "is_error": False, "terminal_reason": None},
                    None,
                    None,
                    checks=[
                        {
                            "id": "check",
                            "expected": True,
                            "observed": False,
                            "outcome": "fail",
                            "evidence_refs": [],
                        }
                    ],
                )

        run = await Executor(self.root, FailedCheck()).execute(self.request("scenario"))
        self.assertEqual(run["status"], "FAILED")

    async def test_workspace_escape_is_rejected_before_client(self):
        client = FixtureClient()
        request = ExecutionRequest("task", "fixture", self.root / "outside", Limits(2, "0.1", 5))
        run = await Executor(self.root, client).execute(request)
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(client.calls, 0)
        self.assertFalse(request.workspace.exists())

    async def test_large_usage_retains_required_result_fields(self):
        class Large:
            async def run(self, request, recorder):
                return NativeResult(
                    "a" * 20000,
                    {"subtype": "success", "is_error": False, "terminal_reason": None},
                    None,
                    {"a": "x" * 16000, "b": "y" * 16000},
                )

        run = await Executor(self.root, Large()).execute(self.request())
        self.assertEqual(run["status"], "COMPLETED")
        result = json.loads((self.root / run["result_ref"]).read_text())
        self.assertIn("error", result)
        self.assertIn("application", result["usage"])

    async def test_results_use_contract(self):
        run = await Executor(self.root, FixtureClient()).execute(self.request())
        result = json.loads((self.root / run["result_ref"]).read_text())
        self.assertEqual(result["run_id"], run["run_id"])
