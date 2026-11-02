"""Product tests with synthetic data and a fake backend; no native/API/Docker/socket."""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.working_backend import DockerWorkingBackend, stage_valid
from agent_runtime.tasks.working_sessions import WorkingSessions
from agent_runtime.telemetry.recorder import atomic_json


def report(record, index, text="Ordinary task result"):
    task = record["tasks"][index]
    return dict(
        scope="cas-working-task-v1",
        stage=("first", "second")[index],
        run_id=task["run_id"],
        result="PASS",
        query_count=1,
        native_success=True,
        text=text,
        session_hash=hashlib.sha256(str(index).encode()).hexdigest(),
        tree_empty=True,
        auth_profile_shared=True,
        context_isolation="NOT_PROVED",
        failure_code=None,
    )


class FakeBackend(DockerWorkingBackend):
    def __init__(self):
        self.calls = 0
        self.callback = None
        self.mode = "success"

    def run(self, bundle, record, approval):
        self.calls += 1
        self.verify(bundle, record)
        if self.callback:
            self.callback(bundle, record)
        if self.mode == "lost":
            raise RuntimeError("SYNTHETIC_PRIVATE_EXCEPTION")
        cancel = (Path(bundle) / "cancel.request.json").exists()
        stages = [] if cancel else [report(record, 0), report(record, 1)]
        return dict(
            completed=not cancel,
            cleanup_confirmed=self.mode != "unclean",
            cancelled=cancel,
            stages=stages,
            code=None if not cancel else "WORKING_SESSION_NOT_COMPLETED",
        )


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("CAS_TEST_TMP"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = FakeBackend()
        self.store = WorkingSessions(self.root, backend=self.backend, root=self.root)

    def prepared(self):
        sid = self.store.create("Daily text work")["session_id"]
        self.store.add(sid, title="First", prompt="Summarize a synthetic greeting.")
        self.store.add(sid, title="Second", prompt="Explain simple addition.")
        return self.store.prepare(sid)

    def approval(self, d):
        path = self.root / "synthetic-test-approval.json"
        path.write_text(json.dumps(self.backend.approval(d, d["plan_hash"], True)))
        return path

    def run_fake(self, d):
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
            patch("sys.stderr.isatty", return_value=True),
        ):
            return self.store.run(d["session_id"], self.approval(d), allow_live=True)

    def test_prepare_is_offline_frozen_and_data_not_code(self):
        d = self.prepared()
        self.assertEqual(d["status"], "PREPARED")
        self.assertEqual(self.backend.calls, 0)
        scope = self.store.scope(d["session_id"])
        self.assertEqual(scope["total_docker_operations"], 112)
        self.assertFalse(scope["approval_template"]["approved"])
        bundle = self.store.bundle(d)
        first = json.loads((bundle / "first.json").read_text())
        self.assertEqual(first["prompt"], d["tasks"][0]["prompt"])
        self.assertNotIn(first["prompt"], (bundle / "work_cell.py").read_text())
        with self.assertRaises(ValueError):
            self.store.add(d["session_id"], title="Third", prompt="No")
        with self.assertRaises(ValueError):
            self.store.prepare(d["session_id"])

    def test_happy_path_results_history_cleanup_and_no_replay(self):
        d = self.prepared()
        done = self.run_fake(d)
        self.assertEqual(done["status"], "COMPLETED")
        self.assertEqual(done["cleanup"], "CONFIRMED")
        self.assertEqual(len(done["results"]), 2)
        self.assertEqual(self.store.list()[0]["results"][0]["text"], "Ordinary task result")
        with self.assertRaises(ValueError):
            self.run_fake(d)
        self.assertEqual(self.backend.calls, 1)

    def test_default_closed_bad_approval_and_no_tty_do_not_consume(self):
        d = self.prepared()
        path = self.root / "false.json"
        path.write_text(json.dumps(self.backend.approval(d, d["plan_hash"], False)))
        with self.assertRaises(PermissionError):
            self.store.run(d["session_id"], path)
        with self.assertRaises(PermissionError):
            self.store.run(d["session_id"], path, allow_live=True)
        with (
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stdout.isatty", return_value=True),
            patch("sys.stderr.isatty", return_value=True),
        ):
            with self.assertRaises(PermissionError):
                self.store.run(d["session_id"], path, allow_live=True)
        self.assertFalse(self.store._claim(d).exists())
        self.assertEqual(self.backend.calls, 0)

    def test_prepared_bytes_or_frozen_task_tamper_denies_run(self):
        d = self.prepared()
        (self.store.bundle(d) / "first.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.run_fake(d)
        self.assertEqual(self.backend.calls, 0)
        self.assertFalse(self.store._claim(d).exists())

    def test_cancel_end_are_bound_intents_cleanup_controls_terminal(self):
        for end in [False, True]:
            d = self.prepared()

            def callback(bundle, record, end=end):
                other = WorkingSessions(self.root, backend=self.backend, root=self.root)
                current = other.request(record["session_id"], record["plan_hash"], end=end)
                self.assertIn(current["status"], {"ENDING", "CANCEL_REQUESTED"})
                other.request(record["session_id"], record["plan_hash"], end=end)

            self.backend.callback = callback
            done = self.run_fake(d)
            self.assertEqual(done["status"], "CANCELLED")
            self.assertEqual(done["cleanup"], "CONFIRMED")

    def test_cancel_before_run_closes_without_query_and_stale_hash_rejected(self):
        d = self.prepared()
        with self.assertRaises(ValueError):
            self.store.request(d["session_id"], "wrong")
        ended = self.store.request(d["session_id"], d["plan_hash"], end=True)
        self.assertEqual(ended["status"], "CLOSED")
        with self.assertRaises(ValueError):
            self.run_fake(d)
        self.assertEqual(self.backend.calls, 0)

    def test_restart_and_unknown_cleanup_never_replay_or_erase_claim(self):
        d = self.prepared()
        self.backend.mode = "lost"
        done = self.run_fake(d)
        self.assertEqual(done["status"], "INTERRUPTED")
        self.assertEqual(done["cleanup"], "UNCONFIRMED")
        self.assertNotIn("SYNTHETIC_PRIVATE_EXCEPTION", json.dumps(done))
        claim = self.store._claim(d).read_bytes()
        reopened = WorkingSessions(self.root, backend=self.backend, root=self.root)
        reopened.list()
        self.assertEqual(self.store._claim(d).read_bytes(), claim)
        with self.assertRaises(ValueError):
            self.run_fake(d)

    def test_cold_claim_recovery_marks_interrupted_without_backend(self):
        d = self.prepared()
        self.store._claim(d).write_text("synthetic consumed claim")
        row = self.store.list()[0]
        self.assertEqual(row["status"], "INTERRUPTED")
        self.assertEqual(row["cleanup"], "UNCONFIRMED")
        self.assertEqual(self.backend.calls, 0)

    def test_partial_result_survives_owner_loss_and_backend_exception(self):
        for lose_owner in [True, False]:
            d = self.prepared()

            def progress(bundle, record):
                atomic_json(
                    bundle / "progress.json",
                    dict(
                        session_id=record["session_id"],
                        attempt=record["attempt_id"],
                        status="RUNNING",
                        stages={"first": report(record, 0)},
                    ),
                )

            if lose_owner:
                progress(self.store.bundle(d), d)
                self.store._claim(d).write_text("synthetic consumed")
                done = self.store.list()[-1]
                done = self.store.get(d["session_id"])
            else:
                self.backend.callback = progress
                self.backend.mode = "lost"
                done = self.run_fake(d)
            self.assertEqual(done["status"], "INTERRUPTED")
            self.assertEqual(done["cleanup"], "UNCONFIRMED")
            self.assertEqual(len(done["results"]), 1)
            self.assertEqual(done["results"][0]["text"], "Ordinary task result")

    def test_completed_history_requires_both_distinct_session_hashes(self):
        d = self.prepared()
        done = self.run_fake(d)
        done["results"][1]["session_hash"] = None
        self.store.save(done)
        with self.assertRaisesRegex(ValueError, "INVALID_WORKING_SESSION_RECORD"):
            self.store.get(d["session_id"])

    def test_result_utf8_private_output_and_host_projector(self):
        d = self.prepared()
        good = report(d, 0)
        self.assertTrue(stage_valid(good, d["tasks"][0], "first"))
        for text in [
            "x" * 4097,
            "я" * 2049,
            "https://claude.ai/oauth/authorize?code=SYNTHETIC",
            "sk-ant-abcdefghijklmnop",
            '{"accessToken":"SYNTHETIC_PRIVATE"}',
        ]:
            self.assertFalse(stage_valid(good | {"text": text}, d["tasks"][0], "first"))
        with self.assertRaises(ValueError):
            self.backend.project_stages({"second": report(d, 1)}, d)

    def test_sensitive_prompt_and_corrupt_record_never_echo(self):
        sid = self.store.create()["session_id"]
        with self.assertRaises(ValueError) as caught:
            self.store.add(sid, title="x", prompt="password=SYNTHETIC_PRIVATE")
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))
        with self.assertRaises(ValueError):
            self.store.add(sid, title="x", prompt='{"refreshToken":"SYNTHETIC_PRIVATE"}')
        path = self.store.folder(sid) / "session.json"
        d = json.loads(path.read_text())
        d["status"] = ["SYNTHETIC_PRIVATE"]
        atomic_json(path, d)
        with self.assertRaises(ValueError) as caught:
            self.store.get(sid)
        self.assertNotIn("SYNTHETIC_PRIVATE", str(caught.exception))

    def test_generated_backend_loads_as_isolated_package_without_runtime(self):
        d = self.prepared()
        bundle = self.store.bundle(d)
        name = "offline_working_bundle_test"
        definition = importlib.util.spec_from_file_location(
            name, bundle / "__init__.py", submodule_search_locations=[str(bundle)]
        )
        module = importlib.util.module_from_spec(definition)
        sys.modules[name] = module
        try:
            definition.loader.exec_module(module)
            backend = __import__(name + ".controller", fromlist=["Controller"])
            self.assertEqual(backend.spec.ATTEMPT, d["attempt_id"])
            self.assertEqual(backend.spec.STAGES, {"first": "work_a", "second": "work_b"})
            self.assertNotIn("cas-context-cancel", str(backend.spec.ROOT))
            self.assertEqual(
                backend.spec.approval(d["plan_hash"], False),
                self.backend.approval(d, d["plan_hash"], False),
            )
            fixture = json.loads(
                (Path(__file__).parent / "fixtures/working-preflight-metadata.json").read_text()
            )

            class ReadOnlyFixture:
                def __init__(self):
                    self.index = 0

                def run(self, args):
                    row = fixture["receipts"][self.index]
                    self.index += 1
                    if args != row["args"]:
                        raise AssertionError("actual saved Docker contract mismatch")
                    return dict(rc=row["rc"], out=row["out"].encode(), err=row["err"].encode())

            routes = __import__(name + ".host_routes", fromlist=["read_routes"])
            fake = ReadOnlyFixture()
            with patch.object(routes, "read_routes", return_value=fixture["routes"]):
                backend.preflight(fake)
            self.assertEqual(fake.index, 7)
            self.assertNotIn("host_routes", sys.modules)
            self.assertNotIn("network_contract", sys.modules)
        finally:
            for key in list(sys.modules):
                if key == name or key.startswith(name + "."):
                    sys.modules.pop(key, None)

    def test_packaged_metadata_contract_and_ordinary_text_retention(self):
        import tomllib

        root = Path(__file__).resolve().parents[1]
        config = tomllib.loads((root / "pyproject.toml").read_text())
        self.assertEqual(config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"], ["src/agent_runtime"])
        self.assertNotIn("force-include", config["tool"]["hatch"]["build"]["targets"]["wheel"])
        self.assertTrue(config["tool"]["hatch"]["build"]["targets"]["sdist"]["force-include"])
        d = self.prepared()
        self.backend.mode = "unclean"
        done = self.run_fake(d)
        self.assertEqual(done["status"], "INTERRUPTED")
        self.assertEqual(done["cleanup"], "UNCONFIRMED")
        self.assertEqual(done["results"][0]["text"], "Ordinary task result")

    def test_installed_layout_requires_explicit_root_before_prepare(self):
        d = self.prepared()
        command = self.store.command(d)
        self.assertIn("--root", command)
        self.assertIn(str(self.root).replace("\\", "/"), command)
        with patch.object(WorkingSessions, "_discover_root", return_value=None):
            installed = WorkingSessions(self.root / "installed-data", backend=FakeBackend())
        sid = installed.create()["session_id"]
        for i in range(2):
            installed.add(sid, title=str(i), prompt="Synthetic ordinary text")
        with self.assertRaisesRegex(ValueError, "EXPLICIT_CAS_ROOT"):
            installed.prepare(sid)
        self.assertEqual(installed.get(sid)["status"], "DRAFT")
        self.assertFalse(installed.bundle(installed.load(sid)).exists())


if __name__ == "__main__":
    with (
        patch("subprocess.Popen", side_effect=AssertionError("NO_PROCESS")),
        patch("socket.socket", side_effect=AssertionError("NO_SOCKET")),
    ):
        unittest.main()
