"""Mock SDK only: no native client, login store, network or model execution."""

import asyncio
import io
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from agent_runtime.tasks import repository_analysis_sdk as sdk
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
        from agent_runtime.providers.claude.client import ClaudeAdapter
        from claude_agent_sdk import ResultMessage

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
