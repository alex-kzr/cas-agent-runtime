"""Execute the product resource controller on asynchronous heap-only Docker objects."""

import ast
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_working_sessions import FakeBackend, WorkingSessions, report


class LifecycleTests(unittest.TestCase):
    task_count = 2
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("CAS_TEST_TMP"))
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        store = WorkingSessions(root, backend=FakeBackend(), root=root)
        sid = store.create("Synthetic offline work")["session_id"]
        for n in range(self.task_count):
            store.add(sid, title=str(n), prompt="Synthetic ordinary text")
        self.record = store.prepare(sid)
        self.bundle = store.bundle(self.record)
        self.name = "agent_runtime.providers.claude._fixture_" + sid.replace("-", "")
        definition = importlib.util.spec_from_file_location(
            self.name, self.bundle / "__init__.py", submodule_search_locations=[str(self.bundle)]
        )
        module = importlib.util.module_from_spec(definition)
        sys.modules[self.name] = module
        definition.loader.exec_module(module)
        self.controller = __import__(self.name + ".controller", fromlist=["Controller"])
        self.core = self.controller.core
        self.spec = self.controller.spec
        source = (Path(__file__).parent / "fixtures/working-lifecycle-source.py").read_text()
        source = (
            source.replace("cas.series1.role", "cas.working1.role")
            .replace("cas-series-1-relay", "cas-working-session-relay")
            .replace(
                "one-approved-personal-subscription-two-stage-series",
                "one-approved-finite-working-session",
            )
        )
        tree = ast.parse(source)
        tree.body = [
            node
            for node in tree.body
            if not isinstance(node, ast.Import)
            or not any(
                x.name
                in {
                    "auth",
                    "controller",
                    "core",
                    "relay",
                    "spec",
                    "validate",
                    "work_a",
                    "ready_channel",
                }
                for x in node.names
            )
        ]
        env = dict(core=self.core, spec=self.spec, ready_channel=self.controller.ready_channel)
        exec(compile(tree, "<historical-heap-fixture>", "exec"), env)
        original = env["container_fixture"]

        def container(role):
            value = original(role)
            if role in {"work_a", "work_b"}:
                stage = "first" if role == "work_a" else "second"
                value["Mounts"].append(
                    dict(
                        Type="bind",
                        Source=str((self.bundle / (stage + ".json")).resolve()),
                        Destination="/cas-task.json",
                        RW=False,
                    )
                )
            return value

        env["container_fixture"] = container
        self.clock = env["Clock"]()
        self.fake = env["FakeDocker"](self.clock)
        self.runner = self.controller.Controller(
            self.fake, self.bundle, clock=self.clock, sleep=self.clock.sleep
        )
        base_finish = self.fake.finish

        def finish(job, seconds, guard=lambda: True):
            value = base_finish(job, seconds, guard)
            if job.role in {"work_a", "work_b"}:
                index = 0 if job.role == "work_a" else 1
                value["out"] = json.dumps(report(self.record, index)).encode()
            return value

        self.fake.finish = finish
        self.addCleanup(self.unload)

    def unload(self):
        for key in list(sys.modules):
            if key == self.name or key.startswith(self.name + "."):
                sys.modules.pop(key, None)

    def test_real_controller_serial_async_start_and_cleanup(self):
        outcome = self.runner.execute()
        self.runner.cleanup()
        self.assertEqual(outcome["result"], "PASS")
        self.assertEqual(self.fake.go_count, self.task_count)
        self.assertEqual(self.fake.private_count, 1)
        self.assertIn("created", self.fake.observed_work_states)
        self.assertIn("running", self.fake.observed_work_states)
        self.assertEqual(self.runner.cleanup_errors, [])
        self.assertTrue(all(not objects for objects in self.fake.objects.values()))
        self.assertLessEqual(self.fake.number, 112)

    def test_early_failure_prevents_second_task_and_still_cleans(self):
        self.fake.bad_work_network = True
        with self.assertRaises(Exception) as failure:
            self.runner.execute()
        self.runner.note_failure(failure.exception)
        self.runner.cleanup()
        self.assertNotIn("second", self.runner.started_stages)
        self.assertEqual(self.fake.go_count, 0)
        self.assertTrue(all(not objects for objects in self.fake.objects.values()))

    def job(self, *, rc=None, cancel=True, overflow=False):
        job = object.__new__(self.core.Job)

        class Process:
            def __init__(self):
                self.rc = rc

            def poll(self):
                return self.rc

            def kill(self):
                self.rc = -9

            def wait(self, timeout):
                return self.rc

        job.process = Process()
        job.start = time.monotonic()
        job.out = bytearray()
        job.err = bytearray()
        job.threads = []
        job.secret = b""
        job.overflow = overflow
        job.capture_lock = threading.Lock()
        job.cancelled = lambda: cancel
        job.authorized_cancel = lambda: cancel
        job.fixed_work = True
        job.expected_stage = "first"
        job.receipt_number = 1
        job.arguments = ["start", "--attach", "--interactive", "e" * 64]
        return job

    def test_cached_real_finish_cancel_preserves_receipt_and_is_not_cleanup_error(self):
        job = self.job()
        docker = object.__new__(self.core.Docker)
        docker.evidence = self.bundle
        docker.number = 1
        docker.bytes = 0
        docker.prefix = ["fixed-docker"]
        docker.ignore_cancel = False
        docker.evidence_errors = []
        with self.assertRaises(self.core.Failure):
            docker.finish(job, 5)
        receipt = json.loads((self.bundle / "01.json").read_text())
        self.assertEqual(receipt["failure"], "WORK_PEER_OR_CANCEL_LOST")
        self.assertTrue(receipt["client_cleanup"]["cancel_terminated_client"])
        self.runner.cancel_cleanup_authorized = True
        self.assertTrue(self.runner.expected_cancel_client(job, True))
        with self.assertRaises(self.core.Failure):
            docker.finish(job, 2)
        self.assertEqual(json.loads((self.bundle / "01.json").read_text()), receipt)
        self.assertFalse(self.runner.expected_cancel_client(job, False))
        job.recorded_result["client_cleanup"]["peer_lost"] = True
        self.assertFalse(self.runner.expected_cancel_client(job, True))

    def test_real_cached_cancel_through_whole_controller_cleanup(self):
        ordinary_finish = self.fake.finish
        self.fake.evidence = self.bundle
        self.fake.bytes = 0
        self.fake.prefix = ["fixed-docker"]
        self.fake.evidence_errors = []

        def finish(job, seconds, guard=lambda: True):
            if job.role in {"work_a", "work_b"}:
                if not getattr(job, "fixed_work", False):
                    direct = self.job()
                    direct.receipt_number = self.fake.number
                    direct.process.stdin = job.process.stdin
                    job.__dict__.update(direct.__dict__)
                    job.poll = types.MethodType(self.core.Job.poll, job)
                    job.output = types.MethodType(self.core.Job.output, job)
                    job.finish = types.MethodType(self.core.Job.finish, job)
                    self.fake.cancelled.set()
                return self.core.Docker.finish(self.fake, job, seconds, guard)
            return ordinary_finish(job, seconds, guard)

        self.fake.finish = finish
        with self.assertRaises(self.core.Failure) as error:
            self.runner.execute()
        self.runner.note_failure(error.exception)
        self.assertTrue(self.runner.cancel_cleanup_authorized)
        self.runner.cleanup()
        self.assertEqual(self.runner.cleanup_errors, [])
        self.assertEqual(self.fake.go_count, 1)
        self.assertTrue(all(not objects for objects in self.fake.objects.values()))
        self.assertNotIn("second", self.runner.started_stages)
        receipts = [json.loads(p.read_text()) for p in self.bundle.glob("[0-9]*.json")]
        self.assertEqual(receipts[0]["failure"], "WORK_PEER_OR_CANCEL_LOST")

    def test_timeout_overflow_natural_exit_late_cancel_never_become_expected_cancel(self):
        self.runner.cancel_cleanup_authorized = True
        cases = [
            (self.job(), 0, "client-timeout"),
            (self.job(overflow=True), 5, "capture-overflow"),
            (self.job(rc=1), 5, None),
        ]
        for job, seconds, expected in cases:
            value = job.finish(seconds)
            self.assertEqual(value["failure"], expected)
            self.assertFalse(value["client_cleanup"]["cancel_terminated_client"])
            job.recorded_result = self.controller.safe_work.sanitize(value, "first")
            self.assertFalse(self.runner.expected_cancel_client(job, True))

    def test_pre_go_cancel_requires_controlled_stop_and_no_prior_terminal(self):
        job = self.job(rc=1)
        job.recorded_result = self.controller.safe_work.sanitize(job.finish(5), "first")
        self.runner.cancel_cleanup_authorized = True
        self.runner.live_before_go_cancel = {"first"}
        self.assertFalse(self.runner.expected_cancel_client(job, True))
        self.runner.controlled_work_stops = {"work_a"}
        self.assertTrue(self.runner.expected_cancel_client(job, True))
        self.runner.live_before_go_cancel = set()
        self.assertFalse(self.runner.expected_cancel_client(job, True))

    def test_cell_selected_result_uses_native_success_and_bounded_safe_text(self):
        cell = __import__(self.name + ".work_cell", fromlist=["execute"])
        task = cell.task_data(self.bundle / "first.json")
        data = self.bundle / "cell-data"
        result = data / "runs" / task["run_id"] / "result.json"
        result.parent.mkdir(parents=True)

        class Executor:
            async def execute(self, request):
                return dict(
                    status="COMPLETED",
                    sdk_outcome=dict(
                        subtype="success", is_error=False, terminal_reason="completed"
                    ),
                    session_id="synthetic-session",
                    usage={
                        "application": {
                            "cleanup": {"tree_empty": True, "mechanism": "linux-pid-namespace"}
                        }
                    },
                )

        for text, expected in [
            ("Ordinary result", "PASS"),
            ("x" * 4097, "PASS"),
            ("x" * 4097 + " password=SYNTHETIC_PRIVATE", "PASS"),
            ("я" * 3000, "PASS"),
            ("password=SYNTHETIC_PRIVATE", "PASS"),
            ('{"password":"SYNTHETIC_PRIVATE"}', "PASS"),
            ('{"claudeAiOauth":{"accessToken":"SYNTHETIC_PRIVATE_ACCESS","refreshToken":"SYNTHETIC_PRIVATE_REFRESH"}}', "PASS"),
        ]:
            result.write_text(json.dumps({"summary": text}))
            coroutine = cell.execute(Executor(), object(), data, task)
            with self.assertRaises(StopIteration) as returned:
                coroutine.send(None)
            value = returned.exception.value
            self.assertEqual(value["result"], expected)
            self.assertNotIn('SYNTHETIC_PRIVATE', value['text'])
            self.assertLessEqual(len(value['text'].encode('utf-8')), 4096)
            if expected == 'PASS' and len(text.encode('utf-8')) > 4096:
                self.assertTrue(value['text'].endswith('[Result truncated]'))
            if expected == "FAIL":
                self.assertEqual(value["text"], "")


if __name__ == "__main__":
    with (
        patch("subprocess.Popen", side_effect=AssertionError("NO_PROCESS")),
        patch("socket.socket", side_effect=AssertionError("NO_SOCKET")),
    ):
        unittest.main()
