import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.tasks.models import ExecutionRequest, Limits, State, validate_document
from agent_runtime.telemetry.recorder import Recorder, RunLock, read_events, reconcile


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def request(self):
        return ExecutionRequest("task", "test", self.root / "workspace", Limits(2, "0.10", 5))

    def test_redaction_sequence_and_atomic_metadata(self):
        writer = Recorder(self.root, self.request(), secrets=["TEST-PRIVATE-MARKER"])
        writer.event("sdk.message", {"text": "TEST-PRIVATE-MARKER", "api_key": "hidden"}, "sdk")
        writer.transition(State.VALIDATING)
        text = (writer.directory / "events.jsonl").read_text()
        self.assertNotIn("TEST-PRIVATE-MARKER", text)
        self.assertNotIn("hidden", text)
        events, warnings = read_events(writer.directory / "events.jsonl")
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        self.assertEqual(warnings, [])
        self.assertEqual(
            json.loads((writer.directory / "run.json").read_text())["status"], "VALIDATING"
        )

    def test_partial_final_event_is_visible(self):
        writer = Recorder(self.root, self.request())
        with (writer.directory / "events.jsonl").open("a") as stream:
            stream.write('{"incomplete":')
        events, warnings = read_events(writer.directory / "events.jsonl")
        self.assertGreater(len(events), 0)
        self.assertTrue(warnings)

    def test_scenario_source_record_validates(self):
        request = ExecutionRequest(
            "scenario", "fixture", self.root / "workspace", Limits(2, "0.1", 5), "offline-contracts"
        )
        writer = Recorder(self.root, request)
        source = json.loads((self.root / writer.record["instructions_ref"]).read_text())
        validate_document("task", source)

    def test_secret_in_dict_key_and_total_event_size(self):
        writer = Recorder(self.root, self.request(), secrets=["PRIVATE-MARKER"])
        writer.event(
            "sdk.message",
            {"PRIVATE-MARKER": "value", "huge": ["x" * 16000 for _ in range(128)]},
            "sdk",
        )
        lines = (writer.directory / "events.jsonl").read_bytes().splitlines()
        self.assertNotIn(b"PRIVATE-MARKER", lines[-1])
        self.assertLessEqual(len(lines[-1]), 65536)
        self.assertIn(b"truncated", lines[-1].lower())

    def test_non_analysis_events_keep_their_full_payload(self):
        writer = Recorder(self.root, self.request())
        self.assertFalse(writer.private)
        writer.event("sdk.message", {"message": {"result": "PLAIN-RESULT"}}, "sdk")
        text = (writer.directory / "events.jsonl").read_text()
        self.assertIn("PLAIN-RESULT", text)
        source = json.loads((self.root / writer.record["instructions_ref"]).read_text())
        self.assertEqual(source["instructions"], "test")

    def test_analysis_recorder_projects_events_and_withholds_instructions(self):
        request = ExecutionRequest(
            "scenario",
            "SNAPSHOT-TEXT",
            self.root / "workspace",
            Limits(1, "0.02", 5),
            "sdk.repository-analysis",
        )
        writer = Recorder(self.root, request)
        self.assertTrue(writer.private)
        writer.event("sdk.message", {"message_type": "ResultMessage", "message": {"result": "X"}})
        writer.record["sdk_outcome"] = {
            "subtype": "success",
            "is_error": False,
            "terminal_reason": "q r",
        }
        writer.save()
        writer.event("error", {"category": "sdk", "code": "E", "message": "RAW-ERROR-TEXT"})
        combined = (
            (writer.directory / "events.jsonl").read_text()
            + (self.root / writer.record["instructions_ref"]).read_text()
            + (writer.directory / "run.json").read_text()
        )
        for raw in ("SNAPSHOT-TEXT", "RAW-ERROR-TEXT", '"result"'):
            self.assertNotIn(raw, combined)
        run = json.loads((writer.directory / "run.json").read_text())
        self.assertEqual(run["sdk_outcome"]["terminal_reason"], "other")

    def test_global_lock_rejects_concurrent_execution(self):
        with RunLock(self.root):
            with self.assertRaises(RuntimeError), RunLock(self.root):
                pass

    def test_reconciliation_preserves_previous_phase(self):
        writer = Recorder(self.root, self.request())
        writer.transition(State.VALIDATING)
        writer.transition(State.RUNNING)
        changed = reconcile(self.root)
        self.assertEqual(changed, [writer.run_id])
        run = json.loads((writer.directory / "run.json").read_text())
        self.assertEqual(run["status"], "INTERRUPTED")
        self.assertEqual(run["error"]["code"], "process_lost")
        self.assertEqual(run["error"]["last_status"], "RUNNING")

    def test_actual_writer_crash_releases_lock_and_preserves_history(self):
        script = """
import os, sys
from pathlib import Path
from agent_runtime.tasks.models import ExecutionRequest, Limits, State
from agent_runtime.telemetry.recorder import Recorder, RunLock
root = Path(sys.argv[1])
with RunLock(root):
    writer = Recorder(root, ExecutionRequest("task", "fixture crash", root / "workspaces/child", Limits(2, "0.1", 5)))
    writer.transition(State.VALIDATING)
    writer.transition(State.RUNNING)
    print(writer.run_id, flush=True)
    os._exit(17)
"""
        child = subprocess.run(
            [sys.executable, "-c", script, str(self.root)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(child.returncode, 17, child.stderr)
        run_id = child.stdout.strip()
        self.assertEqual(reconcile(self.root), [run_id])
        events, warnings = read_events(self.root / "runs" / run_id / "events.jsonl")
        self.assertFalse(warnings)
        self.assertEqual(events[-1]["payload"]["to"], "RUNNING")

    def test_persistence_error_does_not_overwrite_previous_summary(self):
        writer = Recorder(self.root, self.request())
        with patch("agent_runtime.telemetry.recorder.os.replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                writer.transition(State.VALIDATING)
        self.assertEqual(
            json.loads((writer.directory / "run.json").read_text())["status"], "CREATED"
        )
