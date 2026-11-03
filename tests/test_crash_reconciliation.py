"""Deterministic storage/owner-loss fixtures; no real process crash or backend execution.

Production WorkingSessions + backend projection + atomic filesystem writes/kernel locks.
The backend is explicitly incompatible with production approval; all tasks are synthetic.
"""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = (
    Path(os.environ["CAS_PROJECT_ROOT"])
    if os.environ.get("CAS_PROJECT_ROOT")
    else next(
        p for p in Path(__file__).resolve().parents if (p / "config/repositories.yaml").is_file()
    )
)
sys.path.insert(0, str(PROJECT / "repositories/agent-runtime/src"))
from agent_runtime.providers.claude.working_backend import DockerWorkingBackend  # noqa: E402
from agent_runtime.telemetry.recorder import RunLock, atomic_json  # noqa: E402

SOURCE = Path(
    os.environ.get(
        "CAS_CRASH_SOURCE",
        str(PROJECT / "repositories/agent-runtime/src/agent_runtime/tasks/working_sessions.py"),
    )
)
definition = importlib.util.spec_from_file_location("crash_candidate", SOURCE)
candidate = importlib.util.module_from_spec(definition)
definition.loader.exec_module(candidate)
WorkingSessions = candidate.WorkingSessions


class FakeBackend(DockerWorkingBackend):
    def __init__(self):
        self.calls = 0
        self.callback = None
        self.clean = True

    def prepare(self, bundle, d):
        bundle.mkdir(exist_ok=False)
        raw = json.dumps(d["tasks"], sort_keys=True).encode()
        (bundle / "synthetic-plan.json").write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def verify(self, bundle, d):
        assert (
            hashlib.sha256((bundle / "synthetic-plan.json").read_bytes()).hexdigest()
            == d["plan_hash"]
        )

    def approval(self, d, digest, approved=False):
        return {"synthetic_only_not_production": True, "approved": approved, "hash": digest}

    def run(self, bundle, d, approval):
        assert approval["synthetic_only_not_production"] is True
        self.calls += 1
        stages = [report(d, 0), report(d, 1)]
        progress(bundle, d, stages)
        if self.callback:
            self.callback(bundle, d)
        return dict(
            completed=True, cleanup_confirmed=self.clean, cancelled=False, stages=stages, code=None
        )


def report(d, i):
    return dict(
        scope="cas-working-task-v1",
        stage=("first", "second")[i],
        run_id=d["tasks"][i]["run_id"],
        result="PASS",
        query_count=1,
        native_success=True,
        text=("First", "Second")[i] + " synthetic result",
        session_hash=hashlib.sha256((d["session_id"] + str(i)).encode()).hexdigest(),
        tree_empty=True,
        auth_profile_shared=True,
        context_isolation="NOT_PROVED",
        failure_code=None,
    )


def progress(bundle, d, stages):
    atomic_json(
        bundle / "progress.json",
        dict(
            session_id=d["session_id"],
            attempt=d["attempt_id"],
            status="RUNNING",
            stages={k: v for k, v in zip(("first", "second"), stages, strict=False)},
        ),
    )


class CrashReconciliation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="cas-crash-synthetic-", dir=os.environ.get("CAS_TEST_TMP")
        )
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = FakeBackend()
        self.owner = WorkingSessions(self.root, backend=self.backend, root=PROJECT)
        self.peer = WorkingSessions(self.root, backend=self.backend, root=PROJECT)
        self.sid = self.owner.create("Synthetic crash assessment")["session_id"]
        for i in (1, 2):
            self.owner.add(self.sid, title=str(i), prompt="Synthetic nonsensitive task")
        self.owner.prepare(self.sid)
        self.d = self.owner.load(self.sid)  # persist schema, not view's local_command
        self.bundle = self.owner.bundle(self.d)
        self.approval = self.root / "synthetic-only-not-owner-grant.json"
        atomic_json(self.approval, self.backend.approval(self.d, self.d["plan_hash"], True))

    def active(self, status="RUNNING", stages=(), stored=()):
        d = self.owner.load(self.sid)
        d.update(status=status, cleanup="PENDING", results=list(stored))
        self.owner.save(d)
        self.owner._claim(d).write_text("SYNTHETIC_CONSUMED_NO_REPLAY", encoding="utf-8")
        progress(self.bundle, d, list(stages))
        return d

    def execute(self):
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
            patch("sys.stderr.isatty", return_value=True),
        ):
            return self.owner.run(self.sid, self.approval, allow_live=True)

    def assert_no_replay(self):
        claim = self.owner._claim(self.d).read_bytes()
        with self.assertRaisesRegex(ValueError, "NO_REPLAY"):
            self.execute()
        self.assertEqual(self.owner._claim(self.d).read_bytes(), claim)

    def test_pending_prepared_reopen_does_not_consume(self):
        self.assertEqual(self.peer.list()[0]["status"], "PREPARED")
        self.peer.close()
        self.assertEqual(self.peer.get(self.sid)["status"], "PREPARED")
        self.assertFalse(self.owner._claim(self.d).exists())
        self.assertEqual(self.backend.calls, 0)

    def test_draft_partial_preparation_never_becomes_execution(self):
        sid = self.owner.create("Synthetic interrupted preparation")["session_id"]
        for i in (1, 2):
            self.owner.add(sid, title=str(i), prompt="Synthetic draft task")
        d = self.owner.load(sid)
        self.owner.bundle(d).mkdir()  # saved filesystem prefix, no prepared/claim commit
        (self.owner.bundle(d) / "synthetic-partial.txt").write_text("nonsensitive")
        self.assertEqual(self.peer.get(sid)["status"], "DRAFT")
        self.assertFalse(self.owner._claim(d).exists())
        with self.assertRaisesRegex(ValueError, "PREPARATION_FAILED"):
            self.owner.prepare(sid)
        self.assertEqual(
            (self.peer.get(sid)["status"], self.peer.get(sid)["cleanup"]), ("FAILED", "NOT_STARTED")
        )
        self.assertEqual(self.backend.calls, 0)

    def test_claim_present_even_empty_or_truncated_blocks_replay(self):
        for body in ("", "{", "SYNTHETIC_CONSUMED"):
            with self.subTest(body_length=len(body)):
                self.owner.save(dict(self.d))
                self.owner._claim(self.d).write_text(body)
                result = self.peer.list()[0]
                self.assertEqual(
                    (result["status"], result["cleanup"]), ("INTERRUPTED", "UNCONFIRMED")
                )
                self.assert_no_replay()
        self.assertEqual(self.backend.calls, 0)

    def test_failure_between_claim_and_starting_save(self):
        original = self.owner.save

        def fault(d):
            if d["status"] == "STARTING":
                raise OSError("SYNTHETIC_WRITE_FAILED")
            return original(d)

        with patch.object(self.owner, "save", side_effect=fault), self.assertRaises(OSError):
            self.execute()
        result = self.peer.get(self.sid)
        self.assertEqual((result["status"], result["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(self.backend.calls, 0)
        self.assert_no_replay()

    def test_direct_detail_reconciles_owner_loss(self):
        self.active(stages=[report(self.d, 0)])
        result = self.peer.get(self.sid)
        self.assertEqual((result["status"], result["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(result["results"]), 1)
        self.assert_no_replay()

    def test_console_reader_close_does_not_terminate_owner(self):
        self.active(stages=[report(self.d, 0)])
        before = (self.bundle / "progress.json").read_bytes()
        with RunLock(self.owner.directory / ".active"):
            self.peer.close()
            self.assertEqual(self.peer.get(self.sid)["status"], "RUNNING")
            self.assertEqual(self.peer.list()[0]["cleanup"], "PENDING")
            self.assertFalse((self.bundle / "cancel.request.json").exists())
        self.assertEqual((self.bundle / "progress.json").read_bytes(), before)
        self.assertEqual(self.peer.get(self.sid)["status"], "INTERRUPTED")
        self.assertEqual(self.backend.calls, 0)

    def test_owner_loss_phase_matrix_never_confirms_cleanup(self):
        for phase in ("STARTING", "LOGIN_REQUIRED", "RUNNING", "CANCEL_REQUESTED", "ENDING"):
            with self.subTest(phase=phase):
                self.owner.save(dict(self.d))
                self.active(phase, stages=[report(self.d, 0)])
                if phase in ("CANCEL_REQUESTED", "ENDING"):
                    self.owner.request(self.sid, self.d["plan_hash"], end=phase == "ENDING")
                    intent = (self.bundle / "cancel.request.json").read_bytes()
                result = self.peer.list()[0]
                self.assertEqual(
                    (result["status"], result["cleanup"]), ("INTERRUPTED", "UNCONFIRMED")
                )
                self.assertEqual(result["results"][0]["text"], "First synthetic result")
                if phase in ("CANCEL_REQUESTED", "ENDING"):
                    self.assertEqual((self.bundle / "cancel.request.json").read_bytes(), intent)
                self.assert_no_replay()

    def test_cancel_marker_survives_failed_status_ack_and_owner_loss(self):
        self.active(stages=[report(self.d, 0)])
        original = self.peer.save

        def fault(d):
            if d["status"] == "CANCEL_REQUESTED":
                raise OSError("SYNTHETIC_INTENT_ACK_FAILED")
            return original(d)

        with (
            RunLock(self.owner.directory / ".active"),
            patch.object(self.peer, "save", side_effect=fault),
            self.assertRaises(OSError),
        ):
            self.peer.request(self.sid, self.d["plan_hash"])
        marker = (self.bundle / "cancel.request.json").read_bytes()
        result = self.peer.get(self.sid)
        self.assertEqual((result["status"], result["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual((self.bundle / "cancel.request.json").read_bytes(), marker)
        self.assertEqual(len(result["results"]), 1)
        self.assert_no_replay()

    def test_short_progress_view_preserves_persisted_first(self):
        self.active(stored=[report(self.d, 0)])
        with RunLock(self.owner.directory / ".active"):
            self.assertEqual(self.peer.get(self.sid)["results"], [report(self.d, 0)])

    def test_short_progress_recovery_preserves_persisted_first(self):
        self.active(stored=[report(self.d, 0)])
        self.assertEqual(self.peer.list()[0]["results"], [report(self.d, 0)])

    def test_conflicting_progress_view_is_safe_unavailable(self):
        changed = report(self.d, 0) | {"text": "Conflicting synthetic result"}
        self.active(stored=[report(self.d, 0)], stages=[changed])
        with RunLock(self.owner.directory / ".active"):
            row = self.peer.get(self.sid)
            self.assertEqual(row["results"], [report(self.d, 0)])
            self.assertEqual(row["code"], "PROGRESS_UNAVAILABLE")

    def test_conflicting_progress_recovery_preserves_first(self):
        self.active(
            stored=[report(self.d, 0)],
            stages=[report(self.d, 0) | {"text": "Conflicting synthetic result"}],
        )
        row = self.peer.list()[0]
        self.assertEqual(row["results"], [report(self.d, 0)])
        self.assertEqual(row["cleanup"], "UNCONFIRMED")

    def test_matching_progress_extends_prefix(self):
        self.active(stored=[report(self.d, 0)], stages=[report(self.d, 0), report(self.d, 1)])
        row = self.peer.list()[0]
        self.assertEqual(len(row["results"]), 2)
        self.assertEqual(row["status"], "INTERRUPTED")
        self.assertEqual(row["cleanup"], "UNCONFIRMED")

    def test_cleanup_without_terminal_commit_is_not_inferred_from_outcome(self):
        self.active(stages=[report(self.d, 0), report(self.d, 1)])
        atomic_json(
            self.bundle / "runtime-evidence/outcome.json",
            {
                "attempt": self.d["attempt_id"],
                "result": "COMPLETED_WORKING_SESSION_ONLY",
                "cleanup_errors": [],
                "evidence_errors": [],
            },
        )
        row = self.peer.list()[0]
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(row["results"]), 2)
        self.assert_no_replay()

    def test_before_atomic_replace_keeps_old_record_then_reconciles(self):
        original = candidate.atomic_json

        def fault(path, d):
            if path.name == "session.json" and d["status"] == "COMPLETED":
                raise OSError("SYNTHETIC_BEFORE_REPLACE")
            return original(path, d)

        with patch.object(candidate, "atomic_json", side_effect=fault), self.assertRaises(OSError):
            self.execute()
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(row["results"]), 2)
        self.assert_no_replay()

    def test_real_atomic_replace_failure_removes_temporary_file(self):
        import agent_runtime.telemetry.recorder as recorder

        original = recorder.os.replace

        def fault(src, dst):
            if (
                Path(dst).name == "session.json"
                and json.loads(Path(src).read_text(encoding="utf-8"))["status"] == "COMPLETED"
            ):
                raise OSError("SYNTHETIC_REPLACE_FAILED")
            return original(src, dst)

        with patch.object(recorder.os, "replace", side_effect=fault), self.assertRaises(OSError):
            self.execute()
        self.assertEqual(list(self.owner.folder(self.sid).glob(".cas-*.tmp")), [])
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(row["results"][0]["text"], "First synthetic result")
        self.assert_no_replay()

    def test_claim_fsync_failure_remains_consumed_before_work(self):
        with (
            patch.object(candidate.os, "fsync", side_effect=OSError("SYNTHETIC_FSYNC_FAILED")),
            self.assertRaises(OSError),
        ):
            self.execute()
        self.assertEqual(self.backend.calls, 0)
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assert_no_replay()

    def test_recovery_write_failure_reports_error_without_fabricated_clean_state(self):
        self.active(stages=[report(self.d, 0)])
        original = candidate.atomic_json

        def fault(path, d):
            if path.name == "session.json":
                raise OSError("SYNTHETIC_RECOVERY_WRITE_FAILED")
            return original(path, d)

        with patch.object(candidate, "atomic_json", side_effect=fault), self.assertRaises(OSError):
            self.peer.get(self.sid)
        self.assertEqual(self.owner.load(self.sid)["cleanup"], "PENDING")
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(row["results"]), 1)
        self.assert_no_replay()

    def test_terminal_prefix_conflict_rejected_without_writing(self):
        d = self.active(stored=[report(self.d, 0)])
        before = (self.owner.folder(self.sid) / "session.json").read_bytes()
        final = dict(
            d,
            status="FAILED",
            cleanup="CONFIRMED",
            results=[report(self.d, 0) | {"text": "Conflicting synthetic result"}],
        )
        with self.assertRaisesRegex(ValueError, "CONFLICTING_WORKING_SESSION_RESULT_PREFIX"):
            self.owner.commit_terminal(self.sid, final)
        self.assertEqual((self.owner.folder(self.sid) / "session.json").read_bytes(), before)

    def test_after_atomic_replace_preserves_terminal_despite_lost_ack(self):
        original = candidate.atomic_json

        def fault(path, d):
            result = original(path, d)
            if path.name == "session.json" and d["status"] == "COMPLETED":
                raise OSError("SYNTHETIC_AFTER_REPLACE")
            return result

        with patch.object(candidate, "atomic_json", side_effect=fault), self.assertRaises(OSError):
            self.execute()
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("COMPLETED", "CONFIRMED"))
        self.assertEqual(len(row["results"]), 2)
        self.assert_no_replay()

    def test_unconfirmed_backend_cleanup_cannot_complete(self):
        self.backend.clean = False
        row = self.execute()
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(row["results"]), 2)
        self.assert_no_replay()

    def test_terminal_commit_lock_failure_requires_reconciliation_no_replay(self):
        with (
            patch.object(
                self.owner,
                "commit_terminal",
                side_effect=RuntimeError("WORKING_SESSION_RECORD_LOCK_TIMEOUT"),
            ),
            self.assertRaisesRegex(RuntimeError, "RECORD_LOCK_TIMEOUT"),
        ):
            self.execute()
        row = self.peer.get(self.sid)
        self.assertEqual((row["status"], row["cleanup"]), ("INTERRUPTED", "UNCONFIRMED"))
        self.assertEqual(len(row["results"]), 2)
        self.assert_no_replay()

    def test_saved_terminal_cannot_regress_or_reexecute_on_reopen(self):
        complete = self.execute()
        stale = dict(
            self.d,
            status="INTERRUPTED",
            cleanup="UNCONFIRMED",
            results=[],
            code="OWNER_LOST_NO_REPLAY",
        )
        self.assertEqual(self.peer.commit_terminal(self.sid, stale)["results"], complete["results"])
        for _ in range(2):
            self.assertEqual(self.peer.list()[0]["status"], "COMPLETED")
            self.peer.request(self.sid, self.d["plan_hash"], end=True)
            self.assert_no_replay()
        self.assertEqual(self.backend.calls, 1)

    def test_invalid_progress_does_not_erase_first_or_echo_private_payload(self):
        self.active(stored=[report(self.d, 0)])
        (self.bundle / "progress.json").write_text("{SYNTHETIC_PRIVATE_PAYLOAD")
        row = self.peer.list()[0]
        self.assertEqual(row["results"], [report(self.d, 0)])
        self.assertNotIn("SYNTHETIC_PRIVATE_PAYLOAD", json.dumps(row))

    def test_corrupt_record_denied_without_replay_or_payload_echo(self):
        self.active(stages=[report(self.d, 0)])
        p = self.owner.folder(self.sid) / "session.json"
        p.write_text("{SYNTHETIC_PRIVATE_PAYLOAD")
        with self.assertRaisesRegex(ValueError, "INVALID_WORKING_SESSION_RECORD") as e:
            self.peer.list()
        self.assertNotIn("SYNTHETIC_PRIVATE_PAYLOAD", str(e.exception))
        self.assertEqual(self.backend.calls, 0)


if __name__ == "__main__":
    with (
        patch("subprocess.Popen", side_effect=AssertionError("NO_CHILD_PROCESS")),
        patch("os.system", side_effect=AssertionError("NO_SHELL")),
        patch("socket.socket", side_effect=AssertionError("NO_SOCKET")),
    ):
        unittest.main(verbosity=2)
