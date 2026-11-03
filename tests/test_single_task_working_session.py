"""One/two finite-task source regression; no SDK/Docker/socket/native execution."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_working_lifecycle import LifecycleTests
from test_working_sessions import FakeBackend, report

from agent_runtime.providers.claude import working_backend
from agent_runtime.tasks.working_sessions import WorkingSessions
from agent_runtime.telemetry.recorder import atomic_json


class PlannedBackend(FakeBackend):
    def approval(self, d, digest, approved=False):
        return super().approval(d, digest, approved) | {"synthetic_only_not_production": True}

    def run(self, bundle, d, approval):
        assert approval["synthetic_only_not_production"] is True
        self.calls += 1
        if self.callback:
            self.callback(bundle, d)
        if self.mode == "lost":
            raise RuntimeError("SYNTHETIC_PRIVATE_FAILURE")
        cancel = (bundle / "cancel.request.json").exists()
        return dict(
            completed=not cancel,
            cleanup_confirmed=self.mode != "unclean",
            cancelled=cancel,
            stages=[] if cancel else [report(d, i) for i in range(len(d["tasks"]))],
            code=None,
        )


class CardinalityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("CAS_TEST_TMP"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = PlannedBackend()
        self.store = WorkingSessions(self.root, backend=self.backend, root=self.root)

    def prepared(self, count=1):
        sid = self.store.create("Synthetic planned tasks")["session_id"]
        for i in range(count):
            self.store.add(sid, title=str(i), prompt="Synthetic task " + str(i))
        return self.store.prepare(sid)

    def execute(self, d, approval=None):
        p = self.root / "synthetic-not-production.json"
        atomic_json(p, approval or self.backend.approval(d, d["plan_hash"], True))
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
            patch("sys.stderr.isatty", return_value=True),
        ):
            return self.store.run(d["session_id"], p, allow_live=True)

    def test_one_real_task_only_and_scope_is_exact(self):
        d = self.prepared()
        bundle = self.store.bundle(d)
        self.assertTrue((bundle / "first.json").is_file())
        self.assertFalse((bundle / "second.json").exists())
        manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertNotIn("second.json", {r["path"] for r in manifest["files"]})
        scope = self.store.scope(d["session_id"])
        self.assertEqual(
            (
                scope["max_sdk_prompts"],
                scope["aggregate_estimate_usd"],
                scope["max_results_utf8_total"],
                scope["containers_total"],
            ),
            (1, "0.05", 4096, 3),
        )
        self.assertEqual(
            (scope["main_seconds"], scope["cleanup_seconds"], scope["total_docker_operations"]),
            (420, 45, 112),
        )
        done = self.execute(d)
        self.assertEqual(
            (done["status"], done["cleanup"], len(done["results"])), ("COMPLETED", "CONFIRMED", 1)
        )
        self.assertEqual(self.backend.calls, 1)
        with self.assertRaisesRegex(ValueError, "NO_REPLAY"):
            self.execute(d)
        self.assertEqual(self.store.get(d["session_id"])["results"], done["results"])

    def test_two_task_scope_and_native_session_uniqueness_retained(self):
        d = self.prepared(2)
        scope = self.store.scope(d["session_id"])
        self.assertEqual(
            (
                scope["max_sdk_prompts"],
                scope["aggregate_estimate_usd"],
                scope["max_results_utf8_total"],
                scope["containers_total"],
            ),
            (2, "0.10", 8192, 4),
        )
        done = self.execute(d)
        self.assertEqual(done["status"], "COMPLETED")
        done["results"][1]["session_hash"] = done["results"][0]["session_hash"]
        self.store.save(done)
        with self.assertRaisesRegex(ValueError, "INVALID_WORKING_SESSION_RECORD"):
            self.store.get(d["session_id"])

    def test_zero_three_and_duplicate_identity_fail_closed(self):
        sid = self.store.create()["session_id"]
        with self.assertRaisesRegex(ValueError, "ONE_OR_TWO_DRAFT_TASKS_REQUIRED"):
            self.store.prepare(sid)
        self.assertFalse(self.store.bundle(self.store.load(sid)).exists())
        d = self.prepared(2)
        with self.assertRaises(ValueError):
            self.store.add(d["session_id"], title="3", prompt="Synthetic")
        for tasks in ([], [{}, {}, {}]):
            with self.assertRaises(ValueError):
                working_backend.task_stages({"tasks": tasks})
        invalid = self.store.load(d["session_id"])
        invalid["tasks"][1]["task_id"] = invalid["tasks"][0]["task_id"]
        self.store.save(invalid)
        with self.assertRaises(ValueError):
            self.store.get(d["session_id"])
        self.assertEqual(self.backend.calls, 0)

    def test_single_rejects_unplanned_second_projection_and_missing_hash(self):
        d = self.prepared()
        first = report(d, 0)
        with self.assertRaisesRegex(ValueError, "INVALID_WORKING_SESSION_STAGES"):
            self.backend.project_stages({"first": first, "second": first}, d)
        with self.assertRaises(ValueError):
            self.store.merge_results(self.store.load(d["session_id"]), [first, first])
        self.assertFalse(working_backend.complete_results(d, [first | {"session_hash": None}]))

    def test_count_or_prompt_tamper_and_wrong_matching_approval_are_denied(self):
        d = self.prepared()
        bad = self.backend.approval(d, d["plan_hash"], True) | {"manifest_sha256": "0" * 64}
        with self.assertRaises(PermissionError):
            self.execute(d, bad)
        self.assertFalse(self.store._claim(d).exists())
        row = self.store.load(d["session_id"])
        row["tasks"][0]["prompt"] = "Changed synthetic input"
        self.store.save(row)
        with self.assertRaises(ValueError):
            self.execute(row)
        self.assertFalse(self.store._claim(d).exists())
        self.assertEqual(self.backend.calls, 0)

    def test_frozen_one_to_two_count_tamper_denied_without_claim(self):
        from uuid import uuid4

        d = self.prepared()
        row = self.store.load(d["session_id"])
        row["tasks"].append(
            dict(
                task_id=str(uuid4()),
                run_id=str(uuid4()),
                title="Added",
                prompt="Unplanned synthetic task",
            )
        )
        self.store.save(row)
        with self.assertRaises(ValueError):
            self.execute(row)
        self.assertFalse(self.store._claim(row).exists())
        self.assertEqual(self.backend.calls, 0)

    def test_cli_and_direct_console_bridge_prepare_single_without_run(self):
        from agent_console.working_sessions import WorkingSessionBridge

        from agent_runtime.cli import main

        def call(*args):
            out = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
                rc = main(["--root", str(self.root), "--data-dir", str(self.root / "data"), *args])
            return rc, json.loads(out.getvalue())

        rc, d = call("working-session", "create")
        self.assertEqual(rc, 0)
        task = self.root / "synthetic-task.txt"
        task.write_text("One synthetic ordinary task", encoding="utf-8")
        rc, _ = call(
            "working-session", "add", d["session_id"], "--title", "One", "--file", str(task)
        )
        self.assertEqual(rc, 0)
        rc, d = call("working-session", "prepare", d["session_id"])
        self.assertEqual(rc, 0)
        controller = WorkingSessions(self.root / "data", root=self.root)
        bridge = WorkingSessionBridge(controller)
        scope = bridge.get("/api/working-sessions/" + d["session_id"] + "/scope")
        self.assertEqual(scope["max_sdk_prompts"], 1)
        self.assertFalse(scope["approval_template"]["approved"])
        self.assertFalse(controller._claim(d).exists())

    def test_cancel_sole_task_and_unconfirmed_cleanup_never_false_complete(self):
        for unclean in (False, True):
            d = self.prepared()
            self.backend.mode = "unclean" if unclean else "success"
            peer = WorkingSessions(self.root, backend=self.backend, root=self.root)
            self.backend.callback = lambda b, r, peer=peer: peer.request(
                r["session_id"], r["plan_hash"]
            )
            done = self.execute(d)
            self.assertEqual(done["status"], "INTERRUPTED" if unclean else "CANCELLED")
            self.assertEqual(done["cleanup"], "UNCONFIRMED" if unclean else "CONFIRMED")

    def test_one_result_survives_owner_loss_and_no_replay(self):
        d = self.prepared()
        row = self.store.load(d["session_id"])
        first = report(row, 0)
        row.update(status="RUNNING", cleanup="PENDING", results=[first])
        self.store.save(row)
        self.store._claim(row).write_text("SYNTHETIC_CONSUMED")
        atomic_json(
            self.store.bundle(row) / "progress.json",
            dict(
                session_id=row["session_id"], attempt=row["attempt_id"], status="RUNNING", stages={}
            ),
        )
        done = self.store.get(d["session_id"])
        self.assertEqual((done["status"], done["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(done["results"], [first])
        with self.assertRaises(ValueError):
            self.execute(d)

    def test_existing_two_task_record_and_approval_shape_stays_compatible(self):
        d = self.prepared(2)
        self.backend.verify(self.store.bundle(d), d)
        old = json.loads((self.store.bundle(d) / "approval.template.json").read_text())
        expected = self.backend.approval(d, d["plan_hash"], False)
        self.assertEqual(old, expected)
        # Existing completed two-task records remain readable (no backend invocation).
        row = self.store.load(d["session_id"])
        row.update(
            status="COMPLETED", cleanup="CONFIRMED", results=[report(row, 0), report(row, 1)]
        )
        self.store.save(row)
        self.assertEqual(self.store.get(d["session_id"])["status"], "COMPLETED")
        self.assertEqual(self.backend.calls, 0)

    def test_retained_rc1_two_task_prepared_resources_still_verify_without_execution(self):
        # Historical RC1 source is read-only; no old grant is loaded. Defaults to the bundled
        # copy extracted from the RC1 wheel (see tests/fixtures/rc1-claude-resources/README.md).
        resources = os.environ.get("CAS_HISTORIC_CLAUDE_RESOURCES") or (
            Path(__file__).parent / "fixtures" / "rc1-claude-resources"
        )
        with patch.object(working_backend, "files", return_value=Path(resources)):
            d = self.prepared(2)
        self.backend.verify(self.store.bundle(d), d)
        self.assertTrue((self.store.bundle(d) / "second.json").exists())
        self.assertEqual(self.backend.calls, 0)


class SingleLifecycleTests(LifecycleTests):
    task_count = 1

    def test_one_stage_contract_denies_second_before_any_docker_operation(self):
        self.assertEqual(self.spec.STAGES, {"first": "work_a"})
        self.assertNotIn("work_b", self.spec.CONTAINERS)
        before = self.fake.number
        with self.assertRaisesRegex(ValueError, "UNPLANNED_WORKING_SESSION_ROLE"):
            self.spec.create("work_b", "a" * 64)
        with self.assertRaisesRegex(self.core.Failure, "UNPLANNED_WORKING_SESSION_STAGE"):
            self.runner.stage("second")
        self.assertEqual(self.fake.number, before)
        self.assertFalse((self.bundle / "second.json").exists())

    def test_single_real_controller_never_creates_or_removes_unplanned_b(self):
        # A foreign unused name is neither adopted nor removed by one-task cleanup.
        foreign = self.spec.OWNER + "-work_b"
        self.fake.objects["container"][foreign] = {
            "Id": "f" * 64,
            "Name": "/" + foreign,
            "Mounts": [],
        }
        outcome = self.runner.execute()
        self.runner.cleanup()
        self.assertEqual(outcome["completed_stages"], ["first"])
        self.assertIsNone(outcome["session_ids_distinct"])
        self.assertEqual(self.fake.go_count, 1)
        self.assertEqual(self.fake.private_count, 1)
        self.assertEqual(self.runner.cleanup_errors, [])
        self.assertIn(foreign, self.fake.objects["container"])
        self.assertEqual(self.runner.started_stages, {"first"})


del LifecycleTests  # Do not count the imported two-task base class a second time.


if __name__ == "__main__":
    with (
        patch("subprocess.Popen", side_effect=AssertionError("NO_PROCESS")),
        patch("socket.socket", side_effect=AssertionError("NO_SOCKET")),
    ):
        unittest.main()
