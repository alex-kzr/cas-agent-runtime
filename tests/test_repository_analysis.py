"""Read-only facts are checked against source, not merely nonempty model text."""

import asyncio
import copy
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from agent_runtime.tasks.repository_analysis import (
    SAMPLE,
    AnalysisControl,
    expected_fixture_output,
    validate_report,
)


class AnalysisFactsTests(unittest.TestCase):
    def test_source_grounded_facts_and_semantic_rejection(self):
        value = expected_fixture_output()
        self.assertEqual(len(validate_report(value, SAMPLE)), 3)
        for change in ("expression", "path", "line", "hash", "missing", "duplicate"):
            wrong = copy.deepcopy(value)
            if change == "expression":
                wrong["claims"][1]["value"] = "price + quantity"
            elif change == "path":
                wrong["claims"][1]["file"] = "../secret.txt"
            elif change == "line":
                wrong["claims"][1]["line"] = True
            elif change == "hash":
                wrong["claims"][1]["sha256"] = "0" * 64
            elif change == "missing":
                wrong["claims"].pop()
            else:
                wrong["claims"][1] = wrong["claims"][0]
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_report(wrong, SAMPLE)


class AnalysisLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "data"
        self.control = AnalysisControl(self.root)
        self.addCleanup(lambda: self.control.close())

    def completed(self):
        job = self.control.create("tiny-shop", "overview")
        self.control.start(job["job_id"])
        self.control.thread.join(5)
        self.assertFalse(self.control.thread.is_alive())
        return self.control.load(job["job_id"])

    def test_real_executor_persisted_report_sources_export_and_no_replay(self):
        job = self.completed()
        self.assertEqual(job["status"], "COMPLETED")
        report = self.control.report(job["job_id"])
        record = self.control.canonical(job)
        self.assertEqual(record["provider"]["name"], "local-validation")
        self.assertIsNone(record["sdk_outcome"])
        self.assertEqual(report["model_requests"], 0)
        self.assertEqual(record["configuration"]["model_requests"], 0)
        assertions = json.loads(
            (self.root / "runs" / job["run_id"] / "assertions.json").read_text()
        )
        self.assertEqual(assertions["checks"][0]["id"], "source-grounded-report")
        self.assertEqual(assertions["outcome"], "pass")
        with zipfile.ZipFile(io.BytesIO(self.control.bundle(job["job_id"]))) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {"report.md", "report.json", "files/README.md", "files/inventory.py"},
            )
            self.assertEqual(archive.read("files/inventory.py").decode(), SAMPLE["inventory.py"])
            self.assertIn(b"files/inventory.py#L1", archive.read("report.md"))
        self.control.close()
        self.control = AnalysisControl(self.root)
        self.assertEqual(self.control.report(job["job_id"]), report)
        with self.assertRaises(ValueError):
            self.control.start(job["job_id"])
        self.assertEqual(len(list((self.root / "runs").iterdir())), 1)

    def test_invalid_semantics_never_exports_accepted_report(self):
        async def wrong(source, question):
            value = expected_fixture_output()
            value["claims"][1]["value"] = "price - quantity"
            return value

        self.control.producer = wrong
        job = self.completed()
        self.assertEqual(job["status"], "FAILED")
        with self.assertRaises(ValueError):
            self.control.report(job["job_id"])

    def assert_failed_before_execution(self, job_id, producer_calls):
        self.control.thread.join(5)
        self.assertFalse(self.control.thread.is_alive())
        job = self.control.load(job_id)
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["error"], "Local analysis failed; no replay")
        self.assertIsNone(job["report"])
        self.assertIsNone(self.control.active)
        self.assertIsNone(self.control.loop)
        self.assertIsNone(self.control.execution)
        self.assertEqual(producer_calls, [])
        self.assertFalse((self.root / "runs").exists() and any((self.root / "runs").iterdir()))
        with self.assertRaises(ValueError):
            self.control.report(job_id)
        self.assertTrue((self.control.directory / (job_id + ".started")).exists())
        with self.assertRaises(ValueError):
            self.control.start(job_id)

    def test_event_loop_construction_failure_is_terminal_and_clears_ownership(self):
        calls = []

        async def producer(source, question):
            calls.append(question)
            return expected_fixture_output()

        self.control.producer = producer
        job = self.control.create("tiny-shop", "overview")
        with patch(
            "agent_runtime.tasks.repository_analysis.asyncio.new_event_loop",
            side_effect=PermissionError("synthetic"),
        ):
            self.control.start(job["job_id"])
            self.control.thread.join(5)
        self.assert_failed_before_execution(job["job_id"], calls)
        self.assertNotIn("synthetic", json.dumps(self.control.load(job["job_id"])))

    def test_close_failure_still_clears_ownership(self):
        calls = []

        async def producer(source, question):
            calls.append(question)
            return expected_fixture_output()

        class FakeLoop:
            closed = 0

            def create_task(self, coroutine):
                coroutine.close()
                raise RuntimeError("synthetic")

            def close(self):
                FakeLoop.closed += 1
                raise OSError("synthetic")

        self.control.producer = producer
        job = self.control.create("tiny-shop", "overview")
        with patch(
            "agent_runtime.tasks.repository_analysis.asyncio.new_event_loop",
            return_value=FakeLoop(),
        ):
            self.control.start(job["job_id"])
            self.control.thread.join(5)
        self.assertEqual(FakeLoop.closed, 1)
        self.assert_failed_before_execution(job["job_id"], calls)

    def test_stop_keeps_local_cancel_and_no_native_claim(self):
        entered = threading.Event()

        async def wait(source, question):
            entered.set()
            await asyncio.Future()

        self.control.producer = wait
        job = self.control.create("tiny-shop", "overview")
        self.control.start(job["job_id"])
        self.assertTrue(entered.wait(3))
        self.control.stop(job["job_id"])
        self.control.thread.join(5)
        record = self.control.canonical(self.control.load(job["job_id"]))
        self.assertEqual(record["status"], "CANCELLED")
        self.assertEqual(record["error"]["code"], "operator_interrupt")
        self.assertTrue(record["usage"]["application"]["cleanup"]["tree_empty"])
        self.assertEqual(record["provider"]["name"], "local-validation")
        self.assertNotIn("native_cancellation_verified", record["configuration"])
        with self.assertRaises(ValueError):
            self.control.report(job["job_id"])

    def test_source_mutation_and_hardlink_rejected(self):
        job = self.control.create("tiny-shop", "functions")
        file = self.control.workspace / "inventory.py"
        file.write_text("def evil(): return 0\n")
        with self.assertRaises(ValueError):
            self.control.start(job["job_id"])
        file.write_bytes(SAMPLE["inventory.py"].encode("utf-8"))
        alias = self.control.workspace / "alias.py"
        os.link(file, alias)
        with self.assertRaises(ValueError):
            self.control.start(job["job_id"])
        alias.unlink()
        self.control.start(job["job_id"])
        self.control.thread.join(5)
        snapshot = self.control.directory / job["job_id"] / "files/inventory.py"
        snapshot.write_text("tampered")
        with self.assertRaises(ValueError):
            self.control.bundle(job["job_id"])

    def test_restart_recovers_stale_control_and_consumed_draft_without_replay(self):
        job = self.completed()
        job.update(status="RUNNING", report=None)
        self.control.save(job)
        draft = self.control.create("tiny-shop", "overview")
        (self.control.directory / (draft["job_id"] + ".started")).write_text(str(uuid4()))
        self.control.close()
        self.control = AnalysisControl(self.root)
        self.assertEqual(self.control.load(job["job_id"])["status"], "COMPLETED")
        self.assertEqual(len(self.control.report(job["job_id"])["report"]["claims"]), 3)
        self.assertEqual(self.control.load(draft["job_id"])["status"], "INTERRUPTED")
        self.assertEqual(len(list((self.root / "runs").iterdir())), 1)

    def test_foreign_data_and_unknown_repository_question_refused(self):
        other = Path(self.temp.name) / "foreign"
        other.mkdir()
        with self.assertRaises(ValueError):
            AnalysisControl(other)
        for repository, question in (("../secret", "overview"), ("tiny-shop", "run a shell")):
            with self.assertRaises(ValueError):
                self.control.create(repository, question)

    def test_lost_canonical_writer_reconciles_without_replay(self):
        from agent_runtime.telemetry.recorder import atomic_json

        job = self.completed()
        record = self.control.canonical(job)
        record.update(status="RUNNING", ended_at=None, evidence_status="partial")
        atomic_json(self.root / "runs" / job["run_id"] / "run.json", record)
        job.update(status="RUNNING")
        self.control.save(job)
        self.control.close()
        self.control = AnalysisControl(self.root)
        recovered = self.control.load(job["job_id"])
        self.assertEqual(recovered["status"], "INTERRUPTED")
        self.assertEqual(self.control.canonical(recovered)["error"]["code"], "process_lost")
        self.assertEqual(len(list((self.root / "runs").iterdir())), 1)
        with self.assertRaises(ValueError):
            self.control.start(job["job_id"])

    def test_corrupt_control_and_foreign_canonical_are_refused(self):
        from agent_runtime.telemetry.recorder import atomic_json

        job = self.completed()
        record = self.control.canonical(job)
        record["scenario_id"] = "platform.foreign"
        atomic_json(self.root / "runs" / job["run_id"] / "run.json", record)
        with self.assertRaises(ValueError):
            self.control.report(job["job_id"])
        path = self.control.directory / (job["job_id"] + ".json")
        path.write_text("[]")
        with self.assertRaises(ValueError):
            self.control.load(job["job_id"])

    def test_offline_execution_never_spawns_native_process(self):
        with patch(
            "subprocess.Popen", side_effect=AssertionError("No child/native process permitted")
        ):
            self.assertEqual(self.completed()["status"], "COMPLETED")
