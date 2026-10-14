import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path

from agent_runtime.tasks.coding import CodingWorkspace
from agent_runtime.tasks.control import TaskControl
from agent_runtime.tasks.executor import NativeResult


class ScriptedCoding:
    """Test-only injection. No SDK/native/auth call; never a CLI-selectable provider."""

    requests = []
    delay = 0

    async def run(self, request, recorder):
        self.requests.append(request)
        recorder.record["configuration"]["scripted_test_only"] = True
        recorder.record["session_id"] = "scripted-session"
        recorder.record["usage"]["application"] = {
            "cleanup": {"tree_empty": True, "mechanism": "scripted"}
        }
        await asyncio.sleep(self.delay)
        coding = CodingWorkspace(request.workspace, recorder.directory / "coding")
        coding.write("calc.py", "def add(a, b):\n    return a + b\n")
        await coding.test()
        return NativeResult(
            "Scripted fixture result; not SDK evidence",
            {"subtype": "success", "is_error": False, "terminal_reason": "completed"},
            "scripted-session",
            None,
            application_usage={"cleanup": {"tree_empty": True, "mechanism": "scripted"}},
        )


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        ScriptedCoding.requests = []
        ScriptedCoding.delay = 0
        self.control = TaskControl(self.root, adapter_factory=ScriptedCoding)
        self.addCleanup(lambda: self.control.close() if not self.control.closing else None)

    def wait(self):
        self.control.thread.join(10)
        self.assertFalse(self.control.thread.is_alive())

    def test_consent_duplicate_start_and_verified_artifacts(self):
        job = self.control.create()
        with self.assertRaises(ValueError):
            self.control.start(job["task_id"])
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        with self.assertRaises(ValueError):
            self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        run = json.loads((self.root / "runs" / started["run_id"] / "run.json").read_text())
        self.assertEqual(run["status"], "COMPLETED")
        artifacts = json.loads((self.root / run["artifacts_ref"]).read_text())["artifacts"]
        self.assertTrue(any(item["path"].endswith("changes.diff") for item in artifacts))
        self.assertEqual(run["validation"]["validator_version"], "coding-fixture-v1")

    def test_stop_preserves_run_and_never_replays(self):
        ScriptedCoding.delay = 5
        job = self.control.create()
        self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        deadline = time.monotonic() + 3
        while not ScriptedCoding.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        self.control.stop(job["task_id"])
        self.wait()
        self.assertEqual(self.control.load(job["task_id"])["status"], "CANCELLED")
        self.assertEqual(len(ScriptedCoding.requests), 1)

    def test_restart_requires_new_draft_and_fresh_consent(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        self.control.close()
        self.control = TaskControl(self.root, adapter_factory=ScriptedCoding)
        resumed = self.control.create(resumes_run_id=started["run_id"])
        self.assertEqual(len(ScriptedCoding.requests), 1)
        with self.assertRaises(ValueError):
            self.control.start(resumed["task_id"])
        new = self.control.start(resumed["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        self.assertNotEqual(new["run_id"], started["run_id"])
        request = ScriptedCoding.requests[-1]
        self.assertEqual(request.resume_session_id, "scripted-session")
        self.assertEqual(request.resumes_run_id, started["run_id"])
        self.assertEqual(self.control.load(resumed["task_id"])["status"], "COMPLETED")

    def test_missing_session_or_changed_workspace_refuses_continuation(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        self.control.workspace(job).joinpath("calc.py").write_text("def add(a,b):\n return a - b\n")
        with self.assertRaises(ValueError):
            self.control.create(resumes_run_id=started["run_id"])

    def test_second_controller_cannot_reconcile_active_owner(self):
        with self.assertRaises(RuntimeError):
            TaskControl(self.root, adapter_factory=ScriptedCoding)

    def test_capacity_refuses_new_draft_before_it_disappears(self):
        from unittest.mock import patch

        with patch.object(self.control, "list", return_value=[{}] * 100):
            with self.assertRaises(ValueError):
                self.control.create()
        self.assertEqual(self.control.list(), [])

    def test_changed_workspace_is_rechecked_at_start_not_only_prepare(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        resumed = self.control.create(resumes_run_id=started["run_id"])
        self.control.workspace(resumed).joinpath("calc.py").write_text(
            "def add(a,b):\n return a - b\n"
        )
        with self.assertRaises(ValueError):
            self.control.start(resumed["task_id"], allow_live=True, allow_existing_login=True)
        self.assertEqual(len(ScriptedCoding.requests), 1)

    def test_missing_native_session_refuses_without_fresh_query(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        path = self.root / "runs" / started["run_id"] / "run.json"
        record = json.loads(path.read_text())
        record["session_id"] = None
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            self.control.create(resumes_run_id=started["run_id"])
        self.assertEqual(len(ScriptedCoding.requests), 1)

    def test_restart_marks_stale_task_interrupted_without_running_adapter(self):
        job = self.control.create()
        job["status"] = "STARTING"
        self.control.save(job)
        self.control.close()
        self.control = TaskControl(self.root, adapter_factory=ScriptedCoding)
        self.assertEqual(self.control.load(job["task_id"])["status"], "INTERRUPTED")
        self.assertEqual(ScriptedCoding.requests, [])

    def test_restart_recovers_completed_canonical_status_without_replay(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        stale = self.control.load(job["task_id"])
        stale["status"] = "RUNNING"
        self.control.save(stale)
        self.control.close()
        self.control = TaskControl(self.root, adapter_factory=ScriptedCoding)
        recovered = self.control.load(job["task_id"])
        self.assertEqual(recovered["status"], "COMPLETED")
        self.assertEqual(recovered["recovery"]["reason"], "canonical-terminal")
        self.assertEqual(len(ScriptedCoding.requests), 1)
        self.assertEqual(recovered["run_id"], started["run_id"])

    def test_consumed_claim_is_not_a_new_draft_after_restart(self):
        from uuid import uuid4

        job = self.control.create()
        (self.control.directory / f"{job['task_id']}.started").write_text(str(uuid4()))
        self.control.close()
        self.control = TaskControl(self.root, adapter_factory=ScriptedCoding)
        self.assertEqual(self.control.load(job["task_id"])["status"], "INTERRUPTED")
        with self.assertRaises(ValueError):
            self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.assertEqual(ScriptedCoding.requests, [])

    def test_eligibility_is_read_only_and_explicitly_not_native_verified(self):
        job = self.control.create()
        self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        before = {
            file.relative_to(self.root).as_posix(): file.read_bytes()
            for file in self.root.rglob("*")
            if file.is_file() and file.name != ".execution.lock"
        }
        status = self.control.list()[0]["continuation"]
        self.assertTrue(status["eligible"])
        self.assertFalse(status["native_history_verified"])
        after = {
            file.relative_to(self.root).as_posix(): file.read_bytes()
            for file in self.root.rglob("*")
            if file.is_file() and file.name != ".execution.lock"
        }
        self.assertEqual(before, after)

    def test_unknown_cleanup_disables_continuation_with_reason(self):
        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        path = self.root / "runs" / started["run_id"] / "run.json"
        record = json.loads(path.read_text())
        record["usage"]["application"]["cleanup"]["tree_empty"] = False
        path.write_text(json.dumps(record))
        status = self.control.list()[0]["continuation"]
        self.assertFalse(status["eligible"])
        self.assertEqual(status["code"], "cleanup-unconfirmed")

    def test_corrupt_source_refuses_eligibility_without_breaking_list(self):
        job = self.control.create()
        self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        self.control.workspace(job).joinpath("calc.py").write_text("def add(")
        status = self.control.list()[0]["continuation"]
        self.assertFalse(status["eligible"])
        self.assertEqual(status["code"], "missing-or-invalid-evidence")
        self.assertEqual(self.control.create()["status"], "DRAFT")

    def test_malformed_cleanup_and_foreign_task_identity_are_ineligible(self):
        from uuid import uuid4

        job = self.control.create()
        started = self.control.start(job["task_id"], allow_live=True, allow_existing_login=True)
        self.wait()
        path = self.root / "runs" / started["run_id"] / "run.json"
        record = json.loads(path.read_text())
        for invalid in (True, {"tree_empty": "true"}, {"tree_empty": 1}):
            record["usage"]["application"]["cleanup"] = invalid
            path.write_text(json.dumps(record))
            self.assertEqual(self.control.list()[0]["continuation"]["code"], "cleanup-unconfirmed")
        record["usage"]["application"]["cleanup"] = {"tree_empty": True}
        record["task_id"] = str(uuid4())
        path.write_text(json.dumps(record))
        self.assertEqual(self.control.list()[0]["continuation"]["code"], "identity-mismatch")
