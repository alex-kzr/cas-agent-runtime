"""Mock SDK only: no native client, login store, network or model execution."""

import asyncio
import io
import json
import tempfile
import threading
import unittest
import zipfile
from contextlib import ExitStack, aclosing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude import review_transport
from agent_runtime.tasks import repository_analysis_sdk as sdk
from agent_runtime.tasks import review_profile
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import Limits
from agent_runtime.tasks.repository_analysis import SAMPLE, AnalysisControl, expected_fixture_output


def transport(*, text=None, error=False, entered=None, tree_empty=True, outcome=None, queries=1):
    class MockSupervised:
        def __init__(self, environment):
            if environment != {}:
                raise AssertionError("Mocks must not receive ambient credentials")

        async def run(self, request, recorder):
            try:
                if list(request.workspace.iterdir()):
                    raise AssertionError("SDK workspace must be empty")
                for _ in range(queries):
                    recorder.event("sdk.query_started", {"mock_only": True}, "sdk")
                if entered is not None:
                    entered.set()
                    await asyncio.Future()
                if error:
                    raise RuntimeError("RAW_PROVIDER_SECRET_CANARY")
                return NativeResult(
                    text if text is not None else json.dumps(expected_fixture_output()),
                    outcome
                    or {"subtype": "success", "is_error": False, "terminal_reason": "completed"},
                    "synthetic-session",
                    None,
                )
            finally:
                recorder.record["usage"]["application"] = {
                    "cleanup": {
                        "tree_empty": tree_empty,
                        "forced": False,
                        "mechanism": "mock-no-children",
                    }
                }

    return MockSupervised


class PayloadTests(unittest.TestCase):
    def test_closed_by_default_and_only_selected_sources_are_attached(self):
        self.assertIs(sdk.LIVE_ANALYSIS_ENABLED, False)
        payload = sdk.build_payload({"README.md": SAMPLE["README.md"]}, "overview")
        self.assertEqual([item["path"] for item in payload["snapshots"]], ["README.md"])
        self.assertNotIn("def subtotal", str(payload))
        for invalid in (
            {},
            {"../README.md": "x"},
            {"C:/secret": "x"},
            {"README.md": "x" * 8193},
            {"README.md": "changed"},
        ):
            with self.subTest(invalid=list(invalid)), self.assertRaises(ValueError):
                sdk.build_payload(invalid, "overview")


class SDKLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "data"
        self.control = AnalysisControl(self.root, supervised_factory=transport())
        self.addCleanup(lambda: self.control.close())

    def draft(self, files=None):
        return self.control.create("tiny-shop", "overview", files, "sdk")

    def start(self, job):
        return self.control.start(
            job["job_id"],
            allow_live=True,
            allow_existing_login=True,
            snapshot_sha256=job["snapshot_sha256"],
        )

    def finish(self, job):
        self.control.thread.join(5)
        self.assertFalse(self.control.thread.is_alive())
        return self.control.load(job["job_id"])

    def test_closed_gate_cannot_construct_provider_even_with_consents(self):
        job = self.draft()
        with (
            patch("subprocess.Popen", side_effect=AssertionError("No native process")),
            self.assertRaises(PermissionError),
        ):
            self.start(job)
        self.assertFalse((self.root / "runs").exists())
        self.assertFalse((self.control.directory / "sdk-attempt.started").exists())
        self.assertEqual(self.control.load(job["job_id"])["status"], "DRAFT")

    def test_preview_exact_selected_bytes_and_invalid_paths(self):
        for names in (
            [],
            ["../README.md"],
            ["README.md", "README.md"],
            ["C:\\secret"],
            "README.md",
        ):
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.draft(names)
        job = self.draft(["README.md"])
        preview = self.control.preview(job["job_id"])
        self.assertFalse(preview["live_enabled"])
        self.assertEqual(
            preview["query_text"], sdk.query_text({"README.md": SAMPLE["README.md"]}, "overview")
        )
        self.assertEqual(preview["query_sha256"], sdk.sha(preview["query_text"]))
        self.assertEqual(set(self.control.sources(job["job_id"])), {"README.md"})

    def test_fresh_consents_and_exact_digest_required_before_claim(self):
        job = self.draft()
        with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
            for values in (
                {},
                {"allow_live": True},
                {"allow_live": True, "allow_existing_login": True, "snapshot_sha256": "wrong"},
                {
                    "allow_live": 1,
                    "allow_existing_login": True,
                    "snapshot_sha256": job["snapshot_sha256"],
                },
            ):
                with self.subTest(values=values), self.assertRaises(PermissionError):
                    self.control.start(job["job_id"], **values)
        self.assertFalse((self.control.directory / "sdk-attempt.started").exists())

    def test_saved_report_export_restart_and_single_attempt(self):
        job = self.draft()
        with (
            patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
            patch("subprocess.Popen", side_effect=AssertionError("No native")),
        ):
            self.start(job)
            job = self.finish(job)
        self.assertEqual(job["status"], "COMPLETED")
        record = self.control.canonical(job)
        self.assertTrue(record["configuration"]["mock_sdk_test_only"])
        report = self.control.report(job["job_id"])
        self.assertEqual(
            (report["mode"], report["model_requests"], report["real_model_requests"]),
            ("mock-sdk", 1, 0),
        )
        with zipfile.ZipFile(io.BytesIO(self.control.bundle(job["job_id"]))) as archive:
            self.assertIn("files/inventory.py", archive.namelist())
            self.assertIn(b"Mock SDK test only", archive.read("report.md"))
        self.control.close()
        self.control = AnalysisControl(self.root, supervised_factory=transport())
        self.assertEqual(self.control.report(job["job_id"]), report)
        other = self.draft()
        with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True), self.assertRaises(FileExistsError):
            self.start(other)
        self.assertEqual(len(list((self.root / "runs").iterdir())), 1)

    def test_subset_report_acceptance_never_includes_unselected_source(self):
        value = expected_fixture_output()
        value["claims"] = value["claims"][:1]
        self.control.supervised_factory = transport(text=json.dumps(value))
        job = self.draft(["README.md"])
        with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
            self.start(job)
            job = self.finish(job)
        self.assertEqual(job["status"], "COMPLETED")
        with zipfile.ZipFile(io.BytesIO(self.control.bundle(job["job_id"]))) as archive:
            self.assertNotIn("files/inventory.py", archive.namelist())

    def test_invalid_content_duplicate_json_oversize_and_native_error_rejected(self):
        bad = expected_fixture_output()
        bad["claims"][1]["value"] = "price + quantity"
        cases = [
            dict(text=json.dumps(bad)),
            dict(text='{"repository":"tiny-shop","repository":"evil","claims":[]}'),
            dict(text="x" * 16385),
            dict(outcome={"subtype": "success", "is_error": True}),
            dict(error=True),
            dict(queries=0),
            dict(queries=2),
        ]
        for index, case in enumerate(cases):
            with self.subTest(case=index):
                self.control.close()
                self.control = AnalysisControl(
                    Path(self.temp.name) / str(index), supervised_factory=transport(**case)
                )
                job = self.draft()
                with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
                    self.start(job)
                    job = self.finish(job)
                self.assertEqual(job["status"], "FAILED")
                with self.assertRaises(ValueError):
                    self.control.report(job["job_id"])
                record = self.control.canonical(job)
                self.assertNotIn("RAW_PROVIDER_SECRET_CANARY", json.dumps(record))
                self.assertNotIn("price + quantity", json.dumps(record))

    def test_tampered_or_oversized_snapshot_never_starts(self):
        job = self.draft()
        path = self.control.directory / job["job_id"] / "files/README.md"
        for content in ("changed", "x" * 8193):
            path.write_text(content)
            with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True), self.assertRaises(ValueError):
                self.start(job)
        self.assertFalse((self.control.directory / "sdk-attempt.started").exists())

    def test_cancel_requires_confirmed_cleanup(self):
        for tree_empty in (True, False):
            with self.subTest(tree_empty=tree_empty):
                self.control.close()
                entered = threading.Event()
                self.control = AnalysisControl(
                    Path(self.temp.name) / str(tree_empty),
                    supervised_factory=transport(entered=entered, tree_empty=tree_empty),
                )
                job = self.draft()
                with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
                    self.start(job)
                    self.assertTrue(entered.wait(3))
                    self.control.stop(job["job_id"])
                    job = self.finish(job)
                self.assertEqual(job["status"], "CANCELLED" if tree_empty else "INTERRUPTED")
                self.assertIsNone(job["report"])

    def test_cleanup_failure_never_accepts_report(self):
        self.control.supervised_factory = transport(tree_empty=False)
        job = self.draft()
        with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
            self.start(job)
            job = self.finish(job)
        self.assertEqual(job["status"], "INTERRUPTED")

    def test_pinned_sdk_client_contract_with_mock_stream_and_mock_auth_only(self):
        from claude_agent_sdk import ResultMessage

        from agent_runtime.providers.claude.client import ClaudeAdapter

        prompts = []

        class MockClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                prompts.append(prompt)

            async def receive_response(self):
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="synthetic",
                    result=json.dumps(expected_fixture_output()),
                    terminal_reason="completed",
                )

        class MockSupervisor:
            def __init__(self, environment):
                pass

            async def run(self, request, recorder):
                try:
                    return await ClaudeAdapter({}).run(request, recorder)
                finally:
                    recorder.record["usage"]["application"] = {
                        "cleanup": {
                            "tree_empty": True,
                            "mechanism": "mock-no-children",
                            "forced": False,
                        }
                    }

        self.control.supervised_factory = MockSupervisor
        job = self.draft()
        prefix = "agent_runtime.providers.claude.client."
        with (
            patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
            patch.dict("os.environ", {}, clear=True),
            patch(prefix + "require_auth"),
            patch(prefix + "auth_environment", return_value={}),
            patch(prefix + "subscription_status", return_value={"session_status": "mock-only"}),
            patch(prefix + "native_cli", return_value=Path("mock-never-executed")),
            patch(prefix + "ClaudeSDKClient", return_value=MockClient()) as client,
            patch("subprocess.Popen", side_effect=AssertionError("No native SDK process")),
        ):
            self.start(job)
            job = self.finish(job)
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(prompts, [self.control.preview(job["job_id"])["query_text"]])
        options = client.call_args.kwargs["options"]
        self.assertEqual(
            (
                options.tools,
                options.allowed_tools,
                options.setting_sources,
                options.skills,
                options.plugins,
            ),
            ([], [], [], [], []),
        )
        self.assertEqual(options.mcp_servers, {})
        self.assertEqual(
            (options.model, options.max_turns, options.max_budget_usd), (sdk.MODEL, 1, 0.02)
        )

    def test_adapter_refuses_a_recorder_without_the_privacy_policy(self):
        from types import SimpleNamespace

        adapter = sdk.SnapshotSDKAdapter(SAMPLE, "overview", supervised_factory=transport())
        recorder = SimpleNamespace(record={"configuration": {}}, private=False)
        request = SimpleNamespace(
            live_authorized=True,
            allow_existing_login=True,
            auth_mode="subscription",
            model=sdk.MODEL,
            limits=sdk.LIMITS,
            agent_name="text-only-v1",
            resume_session_id=None,
            instructions=sdk.query_text(adapter.sources, "overview"),
            workspace=Path(self.temp.name),
        )
        with (
            patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
            patch.object(sdk, "guarded", return_value=Path(self.temp.name)),
            patch.object(Path, "iterdir", return_value=iter(())),
            self.assertRaises(PermissionError),
        ):
            asyncio.run(adapter.run(request, recorder))

    def test_timeout_keeps_interrupted_without_accepted_report(self):
        self.control.close()
        self.control = AnalysisControl(
            Path(self.temp.name) / "timeout",
            supervised_factory=transport(entered=threading.Event()),
        )
        job = self.draft()
        with (
            patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
            patch.object(sdk, "LIMITS", Limits(1, "0.02", 1)),
        ):
            self.start(job)
            job = self.finish(job)
        self.assertEqual(job["status"], "INTERRUPTED")


# -- mean-review scope, end to end over a REAL ReviewTransport -------------------------------
# The delegate below replaces only the subprocess: raw NDJSON bytes still cross the real
# StreamAccountant/ReviewTransport, the real ClaudeAdapter counters, the real recorder/privacy
# layer and (for the "worker" seam) the real worker + parent import. Counters asserted below are
# therefore measured, not invented by a fake supervised factory. No SDK client, CLI, network or
# auth store is used; the gate is patched only inside the test.

PROFILE = review_profile.canonical()
MODEL_ID = PROFILE.model
CANARY = "CANARY_RAW_PROVIDER_TEXT"
MISSING = object()
GOOD_REPORT = {
    "report_version": 2,
    "repository": "tiny-shop",
    "findings": [
        {
            "id": "F1",
            "problem": "The divisor is one less than the number of values so the result is too large",
            "impact": "Callers receive wrong averages for every input and may decide wrongly",
            "suggested_fix": "Divide the total by the actual count of values instead of subtracting one",
            "file": "mean.py",
            "line": 3,
            "sha256": review_profile.SOURCE_SHA256,
        }
    ],
}
RAW_REPORT = json.dumps(GOOD_REPORT)
EMPTY_REPORT = json.dumps({"report_version": 2, "repository": "tiny-shop", "findings": []})


def line(**body):
    return json.dumps(body) + "\n"


def assistant(model=MODEL_ID, **extra):
    return line(type="assistant", model=model, text=CANARY, **extra)


def terminal(turns=1, text=RAW_REPORT, **extra):
    body = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "session_id": "synthetic",
        "terminal_reason": "completed",
        "result": text,
        **extra,
    }
    if turns is not MISSING:
        body["num_turns"] = turns
    return line(**body)


class RawStream:
    def __init__(self, chunks, hang):
        self.items, self.hang = iter(chunks), hang
        self.release = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.items)
        except StopIteration:
            if self.hang:
                await self.release.wait()
            raise StopAsyncIteration from None


class RawDelegate:
    """Stands in for the subprocess only: it serves raw stdout chunks to the real transport."""

    def __init__(self, chunks, hang=False):
        self._stdout_stream = RawStream(chunks, hang)
        self.written, self.closed, self.ready = [], 0, False

    async def connect(self):
        self.ready = True

    async def write(self, data):
        self.written.append(data)

    async def close(self):
        self.closed += 1
        self._stdout_stream.release.set()

    def is_ready(self):
        return self.ready and not self.closed

    async def end_input(self):
        pass


def to_message(frame):
    from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

    if frame["type"] == "assistant":
        return AssistantMessage(
            content=[TextBlock(text=frame["text"])], model=frame["model"], message_id="msg_1"
        )
    if frame["type"] == "result":
        return ResultMessage(
            subtype=frame["subtype"],
            duration_ms=1,
            duration_api_ms=1,
            is_error=frame["is_error"],
            num_turns=frame.get("num_turns"),
            session_id=frame["session_id"],
            result=frame.get("result"),
            terminal_reason=frame["terminal_reason"],
        )
    return None


class RawClient:
    """Minimal SDK-client stand-in: consumes the real transport's already-bounded frames."""

    def __init__(self, options=None, transport=None):
        self.transport = transport

    async def __aenter__(self):
        await self.transport.connect()
        return self

    async def __aexit__(self, *args):
        await self.transport.close()
        return False

    async def query(self, prompt):
        await self.transport.write(json.dumps({"type": "user", "message": prompt}) + "\n")

    async def receive_response(self):
        async with aclosing(self.transport.read_messages()) as frames:
            async for frame in frames:
                message = to_message(frame)
                if message is not None:
                    yield message


def bypass_client(messages):
    """Mock that skips the raw transport entirely: downstream counters must still hold."""

    class Bypass(RawClient):
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def query(self, prompt):
            pass

        async def receive_response(self):
            for message in messages:
                yield message

    return Bypass


class InProcessOwner:
    """Runs the REAL worker entry point in-process instead of a Job Object child process."""

    def __init__(self, cleanup_seconds=None):
        self.cleanup = {"tree_empty": False, "forced": False, "mechanism": "in-process-test"}

    async def run(self, argv, payload, environment):
        from agent_runtime.providers.claude import worker

        code = await asyncio.to_thread(worker.run_payload, payload)
        self.cleanup["tree_empty"] = True
        return code


class MeanReviewEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.profile = PROFILE.variant()  # identical bounds, test-only: never a real provider
        self.cases = 0
        self.transports = []
        self.factory_calls = []
        self.controls = []

    # -- harness ----------------------------------------------------------------------------
    def factory(self, seam, profile, tree_empty=True):
        calls = self.factory_calls
        if seam == "worker":
            from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter

            def build(environment):
                calls.append(seam)
                return SupervisedClaudeAdapter(environment, profile)

            return build

        from agent_runtime.providers.claude.client import ClaudeAdapter

        class Adapter:
            def __init__(self, environment):
                calls.append(seam)

            async def run(self, request, recorder):
                try:
                    return await ClaudeAdapter({}, profile).run(request, recorder)
                finally:
                    application = recorder.record["usage"].get("application") or {}
                    recorder.record["usage"]["application"] = {
                        **application,
                        "cleanup": {
                            "tree_empty": tree_empty,
                            "forced": False,
                            "mechanism": "mock-no-children",
                        },
                    }

        return Adapter

    def patches(self, chunks=None, *, hang=False, client=RawClient):
        prefix = "agent_runtime.providers.claude.client."
        stack = ExitStack()

        def make(profile, options, accountant):
            delegate = RawDelegate(chunks or [], hang)
            self.transports.append(delegate)
            return review_transport.ReviewTransport(
                profile, options, accountant=accountant, delegate_factory=lambda o: delegate
            )

        stack.enter_context(patch.dict("os.environ", {}, clear=True))
        for name in ("require_auth",):
            stack.enter_context(patch(prefix + name))
        stack.enter_context(patch(prefix + "auth_environment", return_value={}))
        stack.enter_context(
            patch(prefix + "subscription_status", return_value={"session_status": "mock-only"})
        )
        stack.enter_context(patch(prefix + "native_cli", return_value=Path("mock-never-executed")))
        stack.enter_context(patch(prefix + "ClaudeSDKClient", client))
        stack.enter_context(patch(prefix + "make_transport", side_effect=make))
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No native")))
        sup = "agent_runtime.providers.claude.supervised."
        stack.enter_context(patch(sup + "require_auth"))
        stack.enter_context(patch(sup + "auth_environment", return_value={}))
        stack.enter_context(patch(sup + "OwnedProcess", InProcessOwner))
        stack.enter_context(patch("agent_runtime.providers.claude.auth.require_auth"))
        return stack

    def control(self, seam="adapter", profile=None, root=None, **factory):
        profile = profile or self.profile
        self.cases += 1
        control = AnalysisControl(
            root or Path(self.temp.name) / f"case{self.cases}",
            supervised_factory=self.factory(seam, profile, **factory),
            profile=profile,
        )
        self.controls.append(control)
        self.addCleanup(control.close)
        return control

    def draft(self, control):
        return control.create("tiny-shop", "review", ["mean.py"], review_profile.SCOPE_MODE)

    def consents(self, job, **changes):
        return {
            "allow_live": True,
            "allow_existing_login": True,
            "snapshot_sha256": job["snapshot_sha256"],
            "scope_sha256": job["scope_sha256"],
            **changes,
        }

    def run_case(self, chunks, *, seam="adapter", profile=None, **options):
        hang = options.pop("hang", False)
        client = options.pop("client", RawClient)
        control = self.control(seam, profile, **options)
        job = self.draft(control)
        with (
            patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True),
            self.patches(chunks, hang=hang, client=client),
        ):
            control.start(job["job_id"], **self.consents(job))
            control.thread.join(30)
            self.assertFalse(control.thread.is_alive())
        return control, control.load(job["job_id"])

    def events(self, control, job):
        path = control.root / "runs" / job["run_id"] / "events.jsonl"
        return [json.loads(item) for item in path.read_text(encoding="utf-8").splitlines()]

    def scan_tree(self, root, lock):
        """Scan every producer-authored file. Only the exact owned lock marker is skipped."""
        scanned = []
        for path in root.rglob("*"):
            if not path.is_file() or path == lock:
                continue
            data = path.read_bytes()
            self.assertTrue(data, f"empty producer file {path.name}")
            self.assertNotIn(CANARY.encode(), data, str(path.name))
            scanned.append(path.name)
        self.assertIn("run.json", scanned)
        self.assertIn("events.jsonl", scanned)

    def assert_no_canary(self, control):
        # RunLock holds its marker in its own data_dir (root / "analysis"), not in root.
        self.scan_tree(control.root, control.owner.data_dir / ".execution.lock")

    def synthetic_tree(self, name):
        root = Path(self.temp.name) / name
        (root / "analysis").mkdir(parents=True)
        (root / "runs").mkdir()
        (root / "runs" / "run.json").write_text("{}", encoding="utf-8")
        (root / "runs" / "events.jsonl").write_text("{}\n", encoding="utf-8")
        return root, root / "analysis" / ".execution.lock"

    def test_scanner_never_reads_the_exact_owned_marker(self):
        root, lock = self.synthetic_tree("owned")
        lock.write_bytes(CANARY.encode())
        read = []
        original = Path.read_bytes

        def spy(path):
            read.append(path)
            return original(path)

        with patch.object(Path, "read_bytes", spy):
            self.scan_tree(root, lock)
        self.assertTrue(read)
        self.assertNotIn(lock, read)

    def test_scanner_does_not_skip_an_unrelated_nested_lock_named_file(self):
        root, lock = self.synthetic_tree("nested")
        nested = root / "runs" / "sub"
        nested.mkdir()
        (nested / ".execution.lock").write_bytes(CANARY.encode())
        with self.assertRaises(AssertionError):
            self.scan_tree(root, lock)

    def test_scanner_cannot_pass_without_required_producer_files(self):
        root, lock = self.synthetic_tree("missing")
        (root / "runs" / "events.jsonl").unlink()
        with self.assertRaises(AssertionError):
            self.scan_tree(root, lock)
        (root / "runs" / "events.jsonl").write_text("{}\n", encoding="utf-8")
        (root / "runs" / "run.json").unlink()
        with self.assertRaises(AssertionError):
            self.scan_tree(root, lock)

    def assert_no_replay(self, control, job):
        with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
            with self.assertRaises(ValueError):
                control.start(job["job_id"], **self.consents(job))
            other = self.draft(control)
            with self.assertRaises(FileExistsError):
                control.start(other["job_id"], **self.consents(other))
        with self.assertRaises(ValueError):
            control.report(job["job_id"])

    def assert_failed(self, control, job, code, seam):
        self.assertEqual(job["status"], "FAILED", (seam, code))
        self.assertIsNone(job["report"])
        record = control.canonical(job)
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["error"]["message"], review_profile.reason_message(code))
        budget = record["usage"]["application"].get("review_budget") or {}
        self.assertEqual(budget.get("reason_code"), code)
        self.assertIs(budget.get("failed"), True)
        self.assert_no_canary(control)
        self.assert_no_replay(control, job)
        return record

    # -- success, empty report and content proof ----------------------------------------------
    def test_valid_one_turn_stream_completes_with_measured_raw_counters(self):
        for seam in ("adapter", "worker"):
            with self.subTest(seam=seam):
                lines = [assistant(), terminal()]
                control, job = self.run_case(lines, seam=seam)
                self.assertEqual(job["status"], "COMPLETED")
                self.assertEqual(job["report"], GOOD_REPORT)
                record = control.canonical(job)
                budget = record["usage"]["application"]["review_budget"]
                self.assertEqual(
                    budget,
                    {
                        "frames": 2,
                        "blank_frames": 0,
                        "wire_bytes": sum(len(item.encode()) for item in lines),
                        "max_frame_bytes": max(len(item.encode()) - 1 for item in lines),
                        "stderr_bytes": 0,
                        "messages": 2,
                        "results": 1,
                        "observed_turns": 1,
                        "failed": False,
                    },
                )
                audit = record["usage"]["application"]["review_audit"]
                self.assertEqual(audit, {"messages": 2, "results": 1, "observed_turns": 1})
                self.assertEqual(record["usage"]["application"]["model_requests"], 1)
                self.assertEqual(record["provider"]["resolved_model"], MODEL_ID)
                kinds = [event["type"] for event in self.events(control, job)]
                self.assertEqual(kinds.count("sdk.query_started"), 1)
                self.assertEqual(kinds.count("sdk.message"), 2)
                self.assert_no_canary(control)
                self.assertEqual(self.transports[-1].closed, 1)  # closed by the client exit
                self.assertEqual(len(self.transports), self.cases)

    def test_empty_report_completes_but_is_not_content_proof(self):
        control, job = self.run_case([assistant(), terminal(text=EMPTY_REPORT)])
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(job["report"]["findings"], [])
        self.assertEqual(control.report(job["job_id"])["report"]["findings"], [])
        # A COMPLETED run says nothing about the defect: only a grounded finding does.
        proven = self.run_case([assistant(), terminal()])[1]["report"]["findings"]
        self.assertEqual((proven[0]["file"], proven[0]["line"]), ("mean.py", 3))
        self.assertEqual(proven[0]["sha256"], review_profile.SOURCE_SHA256)

    def test_ungrounded_or_malformed_reports_fail_without_persisting_content(self):
        for seam in ("adapter", "worker"):
            for text in (
                json.dumps(
                    {
                        **GOOD_REPORT,
                        "findings": [{**GOOD_REPORT["findings"][0], "sha256": "0" * 64}],
                    }
                ),
                json.dumps(
                    {**GOOD_REPORT, "findings": [{**GOOD_REPORT["findings"][0], "line": 4}]}
                ),
                json.dumps(
                    {**GOOD_REPORT, "findings": [{**GOOD_REPORT["findings"][0], "problem": CANARY}]}
                ),
                CANARY,
                "x" * 16385,
            ):
                with self.subTest(seam=seam, text=text[:20]):
                    control, job = self.run_case([assistant(), terminal(text=text)], seam=seam)
                    self.assertEqual(job["status"], "FAILED")
                    self.assertIsNone(job["report"])
                    self.assert_no_canary(control)
                    self.assert_no_replay(control, job)

    def test_reopen_export_and_second_start_never_replay(self):
        control, job = self.run_case([assistant(), terminal()])
        report = control.report(job["job_id"])
        with zipfile.ZipFile(io.BytesIO(control.bundle(job["job_id"]))) as archive:
            self.assertEqual(archive.read("files/mean.py").decode(), PROFILE.source_content)
        root = control.root
        control.close()
        reopened = self.control(root=root)
        self.assertEqual(reopened.report(job["job_id"]), report)
        self.assertEqual(reopened.load(job["job_id"])["status"], "COMPLETED")
        self.assertEqual(report["scope_sha256"], self.profile.fingerprint)
        self.assert_no_replay_after_success(reopened, job)
        self.assertEqual(len(self.transports), 1)  # exactly one transport, no second query
        self.assertEqual(len(self.factory_calls), 1)

    def assert_no_replay_after_success(self, control, job):
        with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
            with self.assertRaises(ValueError):
                control.start(job["job_id"], **self.consents(job))
            other = self.draft(control)
            with self.assertRaises(FileExistsError):
                control.start(other["job_id"], **self.consents(other))

    # -- turns, model, counters ---------------------------------------------------------------
    def test_missing_bool_negative_zero_two_string_float_turns_fail_numerically(self):
        for seam in ("adapter", "worker"):
            for turns in (MISSING, True, False, -1, 0, 2, "1", 1.0, None):
                with self.subTest(seam=seam, turns=str(turns)):
                    control, job = self.run_case([assistant(), terminal(turns)], seam=seam)
                    self.assert_failed(control, job, review_profile.TURNS, seam)

    def test_conflicting_duplicate_and_non_finite_frames_fail_as_malformed(self):
        text = json.dumps(RAW_REPORT)
        for seam in ("adapter", "worker"):
            for bad in (
                f'{{"type":"result","subtype":"success","num_turns":2,"num_turns":1,"result":{text}}}\n',
                f'{{"type":"assistant","model":"{MODEL_ID}","model":"other","text":"x"}}\n',
                '{"type":"x","nested":{"a":1,"a":1}}\n',
                '{"type":"x","v":NaN}\n',
                '{"type":"x","v":Infinity}\n',
                "[1]\n",
                "not json\n",
            ):
                with self.subTest(seam=seam, bad=bad[:30]):
                    control, job = self.run_case([assistant(), bad, terminal()], seam=seam)
                    self.assert_failed(control, job, review_profile.MALFORMED, seam)

    def test_second_result_unexpected_model_and_missing_result_fail(self):
        cases = (
            ([assistant(), terminal(), terminal()], review_profile.TURNS),
            ([assistant(model="claude-sonnet-5-5"), terminal()], review_profile.MODEL),
            ([assistant(model=CANARY), terminal()], review_profile.MODEL),
            ([assistant()], review_profile.NO_RESULT),
            ([], review_profile.NO_RESULT),
            ([terminal(text=CANARY * 2000)], review_profile.FINAL_BYTES),
        )
        for seam in ("adapter", "worker"):
            for chunks, code in cases:
                with self.subTest(seam=seam, code=code, size=len(chunks)):
                    control, job = self.run_case(chunks, seam=seam)
                    self.assert_failed(control, job, code, seam)

    def test_downstream_counters_hold_when_the_raw_transport_is_bypassed(self):
        from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

        def result(turns):
            return ResultMessage(
                subtype="success",
                duration_ms=1,
                duration_api_ms=1,
                is_error=False,
                num_turns=turns,
                session_id="synthetic",
                result=RAW_REPORT,
                terminal_reason="completed",
            )

        def message(model=MODEL_ID, message_id="m1"):
            return AssistantMessage(
                content=[TextBlock(text=CANARY)], model=model, message_id=message_id
            )

        tight = self.profile.variant(max_messages=2, max_frames=2)
        cases = (
            ([message(), result(2)], None, review_profile.TURNS),
            ([message(), result(True)], None, review_profile.TURNS),
            ([message(model="claude-sonnet-5-5"), result(1)], None, review_profile.MODEL),
            ([message(), message(message_id="m2"), result(1)], None, review_profile.TURNS),
            ([message(), message(), result(1)], tight, review_profile.MESSAGES),
        )
        for messages, profile, code in cases:
            with self.subTest(code=code):
                control, job = self.run_case([], client=bypass_client(messages), profile=profile)
                self.assert_failed(control, job, code, "adapter")

    # -- raw caps before any durable write ----------------------------------------------------
    def test_frame_wire_and_count_caps_fail_before_the_offending_frame_is_written(self):
        big = line(type="assistant", model=MODEL_ID, text=CANARY * 40)  # ~1 KiB frame
        size = len(big.encode())
        cases = (
            (
                self.profile.variant(max_frame_bytes=size - 2),
                [assistant(), big, terminal()],
                review_profile.FRAME_BYTES,
                1,
            ),
            (
                self.profile.variant(max_frame_bytes=size, max_wire_bytes=size * 2),
                [big, big, big, terminal()],
                review_profile.WIRE_BYTES,
                2,
            ),
            (
                self.profile.variant(max_frames=3, max_messages=3),
                [assistant()] * 4 + [terminal()],
                review_profile.FRAMES,
                3,
            ),
        )
        for seam in ("adapter", "worker"):
            for profile, chunks, code, written in cases:
                with self.subTest(seam=seam, code=code):
                    control, job = self.run_case(chunks, seam=seam, profile=profile)
                    self.assert_failed(control, job, code, seam)
                    kinds = [e["type"] for e in self.events(control, job)]
                    self.assertLessEqual(kinds.count("sdk.message"), written)
                    self.assertEqual(kinds.count("sdk.query_started"), 1)

    def test_silent_stream_ends_at_the_idle_bound_without_a_late_success(self):
        profile = self.profile.variant(
            idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3
        )
        for seam in ("adapter", "worker"):
            with self.subTest(seam=seam):
                control, job = self.run_case([assistant()], seam=seam, profile=profile, hang=True)
                self.assert_failed(control, job, review_profile.IDLE, seam)

    # -- journal budgets and canonical truthfulness ---------------------------------------------
    def test_worker_event_and_journal_budgets_fail_truthfully(self):
        cases = (
            (self.profile.variant(worker_events=2, parent_events=34), review_profile.WORKER_EVENTS),
            (self.profile.variant(worker_journal_bytes=1500), review_profile.WORKER_JOURNAL),
        )
        for profile, code in cases:
            with self.subTest(code=code):
                control, job = self.run_case(
                    [assistant(), terminal()], seam="worker", profile=profile
                )
                record = self.assert_failed(control, job, code, "worker")
                # Run, job, events and report all agree: failed, nothing accepted, no message events.
                self.assertEqual(record["evidence_status"], "partial")
                kinds = [event["type"] for event in self.events(control, job)]
                self.assertNotIn("sdk.message", kinds)
                self.assertEqual(kinds[-1] if kinds else None, "run.transition")
                self.assertIsNone(control.load(job["job_id"])["report"])

    # -- consent, gate, cancel and cleanup ---------------------------------------------------------
    def test_closed_gate_and_stale_consent_reject_every_field_before_any_query(self):
        control = self.control()
        job = self.draft(control)
        with patch("subprocess.Popen", side_effect=AssertionError("No native process")):
            with self.assertRaises(PermissionError):
                control.start(
                    job["job_id"], **self.consents(job)
                )  # gate closed, all consents fresh
            with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):  # the legacy gate never opens it
                with self.assertRaises(PermissionError):
                    control.start(job["job_id"], **self.consents(job))
            with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
                for name, value in (
                    ("allow_live", False),
                    ("allow_live", 1),
                    ("allow_live", None),
                    ("allow_existing_login", False),
                    ("allow_existing_login", 1),
                    ("allow_existing_login", None),
                    ("snapshot_sha256", "0" * 64),
                    ("snapshot_sha256", None),
                    ("scope_sha256", "0" * 64),
                    ("scope_sha256", None),
                    (
                        "scope_sha256",
                        PROFILE.fingerprint,
                    ),  # the real profile is not this test-only one
                ):
                    with self.subTest(name=name, value=value), self.assertRaises(PermissionError):
                        control.start(job["job_id"], **self.consents(job, **{name: value}))
                with self.assertRaises(PermissionError):
                    control.start(
                        job["job_id"],
                        allow_live=True,
                        allow_existing_login=True,
                        snapshot_sha256=job["snapshot_sha256"],
                    )
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self.transports, [])
        self.assertEqual(control.load(job["job_id"])["status"], "DRAFT")
        self.assertFalse((control.directory / review_profile.SLOT_FILE).exists())
        self.assertFalse((control.root / "runs").exists())

    def test_any_profile_parameter_change_invalidates_the_draft_consent(self):
        control = self.control()
        job = self.draft(control)
        root = control.root
        control.close()
        changes = [
            {"idle_seconds": 44},
            {"execution_seconds": 89, "stream_deadline_seconds": 80},
            {"watchdog_seconds": 101},
            {"max_messages": 2047},
            {"max_frame_bytes": 1_048_575},
            {"max_wire_bytes": 16_777_215},
            {"worker_events": 8191},
            {"worker_journal_bytes": 2_999_999},
            {"max_raw_final_bytes": 16_383},
            {"max_stderr_bytes": 262_143},
            {"budget_usd": "0.04"},
        ]
        profiles = [self.profile.variant(**change) for change in changes]
        profiles.append(replace(self.profile, model="claude-haiku-5-6"))
        for profile in profiles:
            with self.subTest(fingerprint=profile.fingerprint[:8]):
                changed = self.control(profile=profile, root=root)
                self.assertNotEqual(profile.fingerprint, job["scope_sha256"])
                self.assertFalse(changed.preview(job["job_id"])["scope_current"])
                with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
                    for stored in (job["scope_sha256"], profile.fingerprint):
                        with self.assertRaises(PermissionError):
                            changed.start(job["job_id"], **self.consents(job, scope_sha256=stored))
                self.assertEqual(changed.load(job["job_id"])["status"], "DRAFT")
                changed.close()
        self.assertEqual(self.factory_calls, [])
        self.assertFalse((root / "runs").exists())

    @staticmethod
    def hanging(entered, tree_empty):
        class Hanging:
            def __init__(self, environment):
                pass

            async def run(self, request, recorder):
                try:
                    recorder.event("sdk.query_started", {"mock_only": True}, "sdk")
                    entered.set()
                    await asyncio.Future()
                finally:
                    recorder.record["usage"]["application"] = {
                        "cleanup": {
                            "tree_empty": tree_empty,
                            "forced": False,
                            "mechanism": "mock-no-children",
                        }
                    }

        return Hanging

    def test_cancel_and_unconfirmed_cleanup_report_truthful_states(self):
        for tree_empty in (True, False):
            with self.subTest(tree_empty=tree_empty):
                entered = threading.Event()
                self.cases += 1
                control = AnalysisControl(
                    Path(self.temp.name) / f"cancel{self.cases}",
                    supervised_factory=self.hanging(entered, tree_empty),
                    profile=self.profile,
                )
                self.addCleanup(control.close)
                job = self.draft(control)
                with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
                    control.start(job["job_id"], **self.consents(job))
                    self.assertTrue(entered.wait(5))
                    control.stop(job["job_id"])
                    control.thread.join(10)
                job = control.load(job["job_id"])
                expected = "CANCELLED" if tree_empty else "INTERRUPTED"
                self.assertEqual(job["status"], expected)
                self.assertEqual(control.canonical(job)["status"], expected)
                self.assertIsNone(job["report"])
                self.assert_no_replay(control, job)

    # -- parent success postcondition over the worker's counter map ---------------------------
    VALID_BUDGET = {
        "frames": 2,
        "blank_frames": 0,
        "wire_bytes": 600,
        "max_frame_bytes": 400,
        "stderr_bytes": 0,
        "messages": 2,
        "results": 1,
        "observed_turns": 1,
        "failed": False,
    }

    def require(self, budget):
        review_profile.require_success_budget(self.profile, budget, 2, 1, [1])

    def test_parent_accepts_only_the_full_consistent_measured_success_map(self):
        self.require(dict(self.VALID_BUDGET))
        self.require({**self.VALID_BUDGET, "blank_frames": 1, "frames": 3})
        for name in review_profile.SUCCESS_COUNTERS + ("failed",):
            partial = {k: v for k, v in self.VALID_BUDGET.items() if k != name}
            with self.subTest(missing=name), self.assertRaises(review_profile.BudgetExceeded):
                self.require(partial)

    def test_parent_rejects_inconsistent_bool_failed_and_partial_failure_maps(self):
        cases = (
            {"frames": 0, "blank_frames": 1, "wire_bytes": 0, "max_frame_bytes": 500},
            {"frames": 1},  # fewer non-blank frames than messages
            {"blank_frames": 3},  # more blanks than frames
            {"wire_bytes": 1},  # fewer bytes than non-blank frames
            {"max_frame_bytes": 601},  # a frame larger than the whole wire
            {"max_frame_bytes": 0},
            {"messages": 3},
            {"results": 2},
            {"observed_turns": 2},
            {"observed_turns": True},
            {"results": True},
            {"frames": 2.0},
            {"stderr_bytes": "0"},
            {"failed": True},
            {"failed": 0},
            {"failed": None},
            {"reason_code": review_profile.TURNS},
            {"cleanup_unknown": True},
        )
        for change in cases:
            with self.subTest(change=change), self.assertRaises(review_profile.BudgetExceeded):
                self.require({**self.VALID_BUDGET, **change})
        # A safe partial failure snapshot is valid data but can never promote success.
        failure = {"frames": 1, "failed": True, "reason_code": review_profile.MALFORMED}
        self.assertEqual(review_profile.validate_budget_snapshot(self.profile, failure), failure)
        with self.assertRaises(review_profile.BudgetExceeded):
            self.require(failure)
        for bad in ({"results": True}, {"observed_turns": True}, {"frames": -1}):
            with self.subTest(bad=bad), self.assertRaises(review_profile.BudgetExceeded):
                review_profile.validate_budget_snapshot(self.profile, bad)

    def test_parent_rechecks_imported_message_and_turn_counts_independently(self):
        # The map claims 2 messages / turn 1; the imported journal must agree, not the map.
        for messages, results, turns in ((1, 1, [1]), (2, 2, [1, 1]), (2, 1, [2]), (2, 1, [True])):
            with self.subTest(messages=messages, results=results, turns=turns):
                with self.assertRaises(review_profile.BudgetExceeded):
                    review_profile.require_accepted_counters(self.profile, messages, results, turns)
                    review_profile.require_success_budget(
                        self.profile, dict(self.VALID_BUDGET), messages, results, turns
                    )

    def test_unconfirmed_cleanup_after_a_valid_stream_never_accepts_the_report(self):
        control, job = self.run_case([assistant(), terminal()], tree_empty=False)
        self.assertEqual(job["status"], "INTERRUPTED")
        self.assertIsNone(job["report"])
        self.assertEqual(control.canonical(job)["status"], "INTERRUPTED")
        self.assert_no_replay(control, job)
