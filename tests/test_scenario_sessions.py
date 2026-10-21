"""Selectable SES-01 negatives: mock streams only, never live SDK capability evidence."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from claude_agent_sdk import SystemMessage
from test_session_contract import MockStream, result

from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.tasks.control import TaskControl
from agent_runtime.tasks.executor import Executor
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import read_events, reconcile

CASES = {
    "missing-session": "SES-01-missing-session-local",
    "sid-mismatch": "SES-01-sid-mismatch-local",
    "no-replay": "SES-01-no-replay-local",
}


class SessionScenarioTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Fail closed if a fixture accidentally reaches an actual process or native status.
        for target in (
            "subprocess.Popen",
            "agent_runtime.providers.claude.client.subscription_status",
        ):
            guard = patch(target, side_effect=AssertionError("Offline session fixture boundary"))
            guard.start()
            self.addCleanup(guard.stop)
        self.factory = patch("agent_runtime.providers.claude.client.ClaudeSDKClient")
        self.client = self.factory.start()
        self.addCleanup(self.factory.stop)
        self.adapter = ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
        self.executor = Executor(self.root, self.adapter)

    async def execute(self, case, messages, previous=None):
        stream = MockStream(messages)
        self.client.return_value = stream
        request = ExecutionRequest(
            "scenario",
            "Synthetic session contract only; no native query",
            self.root / "workspaces/one",
            Limits(1, "0.02", 5),
            CASES[case],
            live_authorized=True,  # Adapter validation only; SDK client is a test double.
            auth_mode="api",
            resumes_run_id=previous["run_id"] if previous else None,
            resume_session_id=previous["session_id"] if previous else None,
        )
        run = await self.executor.execute(request)
        directory = self.root / "runs" / run["run_id"]
        events, warnings = read_events(directory / "events.jsonl")
        self.assertEqual(warnings, [])
        self.assertEqual(stream.queries, 1)
        self.assertEqual(sum(e["type"] == "sdk.query_started" for e in events), 1)
        return run, stream

    async def baseline(self, case):
        run, _ = await self.execute(
            case, [SystemMessage("init", {"session_id": "expected-session"}), result()]
        )
        self.assertEqual(run["status"], "COMPLETED")
        source = self.root / "runs" / run["run_id"] / "run.json"
        return run, source, hashlib.sha256(source.read_bytes()).hexdigest()

    def assert_negative(self, case, run, previous, source, digest, code):
        self.assertEqual(run["scenario_id"], CASES[case])
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(run["evidence_status"], "partial")
        self.assertEqual(run["error"]["code"], code)
        self.assertFalse(run["error"]["retryable"])
        self.assertEqual(run["resumes_run_id"], previous["run_id"])
        self.assertNotEqual(run["run_id"], previous["run_id"])
        self.assertIsNone(run["task_id"])  # Scenario records use scenario_id, not task_id.
        self.assertIsNone(previous["task_id"])
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.client.call_count, 2)  # Baseline plus one failed attempt.

    async def test_missing_session(self):
        """SES-01-missing-session-local: missing native store is simulated, never read."""
        for messages in ([RuntimeError("synthetic missing native session")], []):
            with self.subTest(empty_stream=not messages):
                self.client.reset_mock()
                previous, source, digest = await self.baseline("missing-session")
                run, _ = await self.execute("missing-session", messages, previous)
                self.assert_negative(
                    "missing-session", run, previous, source, digest, "RuntimeError"
                )
                self.assertIsNone(run["sdk_outcome"])
                options = self.client.call_args.kwargs["options"]
                self.assertEqual(options.resume, "expected-session")
                self.assertFalse(options.continue_conversation)
                self.assertFalse(options.fork_session)

    async def test_sid_mismatch(self):
        """SES-01-sid-mismatch-local: reject both unexpected init and result SID."""
        for at_result in (False, True):
            with self.subTest(at_result=at_result):
                self.client.reset_mock()
                previous, source, digest = await self.baseline("sid-mismatch")
                terminal = result("wrong-session" if at_result else "expected-session")
                terminal.total_cost_usd = 0.004
                messages = [
                    SystemMessage(
                        "init", {"session_id": "expected-session" if at_result else "wrong-session"}
                    ),
                    terminal,
                ]
                run, _ = await self.execute("sid-mismatch", messages, previous)
                self.assert_negative("sid-mismatch", run, previous, source, digest, "ValueError")
                if at_result:
                    self.assertEqual(run["sdk_outcome"]["subtype"], "success")
                    self.assertEqual(run["usage"]["sdk"]["total_cost_usd"], 0.004)
                    self.assertEqual(run["session_id"], "expected-session")
                self.assertNotEqual(run["session_id"], "wrong-session")

    async def test_no_replay_failed_run_after_reconcile(self):
        """SES-01-no-replay-local: reopening the executor never resubmits a failed turn."""
        previous, source, digest = await self.baseline("no-replay")
        run, stream = await self.execute(
            "no-replay", [RuntimeError("synthetic missing native session")], previous
        )
        self.assert_negative("no-replay", run, previous, source, digest, "RuntimeError")
        failed = self.root / "runs" / run["run_id"] / "run.json"
        saved = failed.read_bytes()
        self.assertEqual(reconcile(self.root), [])
        Executor(self.root, self.adapter)
        self.assertEqual(failed.read_bytes(), saved)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.client.call_count, 2)
        self.assertEqual(stream.queries, 1)


class SessionNoReplayControlTests(unittest.TestCase):
    def test_consumed_claim_after_controller_restart(self):
        """SES-01-no-replay-local: reuse the existing interrupted-start controller fixture."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch(
                "agent_runtime.providers.claude.supervised.SupervisedClaudeAdapter"
            ) as adapter:
                control = TaskControl(root, adapter_factory=adapter)
                try:
                    task = control.create()
                    marker = control.directory / f"{task['task_id']}.started"
                    marker.write_text(str(uuid4()), encoding="utf-8")
                    original = marker.read_bytes()
                finally:
                    control.close()
                restarted = TaskControl(root, adapter_factory=adapter)
                try:
                    self.assertEqual(restarted.load(task["task_id"])["status"], "INTERRUPTED")
                    with self.assertRaises(ValueError):
                        restarted.start(task["task_id"], allow_live=True, allow_existing_login=True)
                    self.assertEqual(marker.read_bytes(), original)
                    self.assertEqual(list((root / "runs").glob("*/run.json")), [])
                    adapter.assert_not_called()
                finally:
                    restarted.close()


if __name__ == "__main__":
    unittest.main()
