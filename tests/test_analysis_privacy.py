"""Synthetic canaries only: mock SDK client and auth, no native process, login or network."""

import asyncio
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude import worker
from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter
from agent_runtime.tasks import analysis_privacy as privacy
from agent_runtime.tasks import repository_analysis_sdk as sdk
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.repository_analysis import SAMPLE, AnalysisControl, expected_fixture_output
from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

# Token-shaped on purpose: a shape filter alone must not be what keeps it out.
CANARY = "RAWCANARY-9f2c41"
# Identifier-shaped on purpose and used as a dictionary KEY: keys are data as well.
KEY_CANARY = "REVIEW_SYNTHETIC_RAW_PROVIDER_RESPONSE_001"
CLIENT = "agent_runtime.providers.claude.client."
SUPERVISED = "agent_runtime.providers.claude.supervised."


def result_message(**values):
    base = dict(
        subtype="success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=False,
        num_turns=1,
        session_id="synthetic",
        terminal_reason="completed",
    )
    return ResultMessage(**(base | values))


def stream(final, raises=False):
    messages = [
        SystemMessage(
            subtype="init",
            data={
                "session_id": "synthetic",
                "claude_code_version": "2.1.0",
                "note": CANARY,
                "tools": [CANARY],
            },
        ),
        AssistantMessage(
            content=[ToolUseBlock(id=CANARY, name=CANARY, input={"command": CANARY})],
            model="claude-haiku-5-5",
            message_id="native-1",
            usage={"input_tokens": 3, "output_tokens": 2, "note": CANARY},
        ),
        UserMessage(content=[ToolResultBlock(tool_use_id=CANARY, content=CANARY, is_error=True)]),
    ]

    class MockClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def query(self, prompt):
            pass

        async def receive_response(self):
            for message in messages:
                yield message
            if raises:
                raise RuntimeError(CANARY)
            yield final

    return MockClient()


class DirectRoute:
    """Real ClaudeAdapter observation path, no worker process."""

    def __init__(self, environment):
        pass

    async def run(self, request, recorder):
        try:
            return await ClaudeAdapter({}).run(request, recorder)
        finally:
            recorder.record["usage"]["application"] = {
                **(recorder.record["usage"].get("application") or {}),
                "cleanup": {"tree_empty": True, "forced": False, "mechanism": "mock-no-children"},
            }


class InProcessOwner:
    """Runs the real worker main in this process; no subprocess is ever launched."""

    def __init__(self):
        self.cleanup = {"tree_empty": True, "forced": False, "mechanism": "in-process-mock"}

    async def run(self, argv, payload, environment):
        class Stdin:
            buffer = io.BytesIO(payload)

        with patch("sys.stdin", Stdin()):
            return await asyncio.to_thread(worker.main)


class TamperingOwner(InProcessOwner):
    """Writes a hostile worker response instead of running the worker."""

    async def run(self, argv, payload, environment):
        data = json.loads(payload)
        directory = Path(data["directory"])
        event = {
            "schema_version": 1,
            "run_id": data["record"]["run_id"],
            "seq": data["seq"] + 1,
            "timestamp": "2026-10-21T00:00:00.000Z",
            "source": "sdk",
            "type": "sdk.query_started",
            "session_id": None,
            "parent_event_seq": None,
            "correlation_id": None,
            "payload": {"resume_requested": False, "note": CANARY},
            "redaction": {"applied": True, "fields": []},
        }
        (directory / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
        response = {
            "result": {
                "text": CANARY,
                "outcome": {
                    "subtype": "success",
                    "is_error": False,
                    "terminal_reason": "completed",
                },
                "session_id": CANARY,
                "usage": {"note": CANARY, "total_cost_usd": 0.01},
                "application_usage": {"note": f"{CANARY} with spaces"},
            },
            "error": None,
        }
        (directory / "response.json").write_text(json.dumps(response), encoding="utf-8")
        return 0


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.controls = []
        self.addCleanup(lambda: [control.close() for control in self.controls])

    def run_job(self, route, client, name, owner=InProcessOwner):
        root = self.root / name
        control = AnalysisControl(root, supervised_factory=route)
        self.controls.append(control)
        job = control.create("tiny-shop", "overview", None, "sdk")
        with ExitStack() as stack:
            stack.enter_context(patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True))
            stack.enter_context(patch.dict("os.environ", {}, clear=True))
            # Recorder construction reads platform metadata, which can spawn a child process on
            # some hosts; answer it from mocks so the Popen prohibition below stays absolute.
            stack.enter_context(patch("platform.system", return_value="TestOS"))
            stack.enter_context(patch("platform.python_version", return_value="3.12.0"))
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No native")))
            for prefix in (CLIENT, SUPERVISED):
                stack.enter_context(patch(prefix + "require_auth"))
                stack.enter_context(patch(prefix + "auth_environment", return_value={}))
            stack.enter_context(patch("agent_runtime.providers.claude.auth.require_auth"))
            stack.enter_context(
                patch(CLIENT + "subscription_status", return_value={"session_status": "mock-only"})
            )
            stack.enter_context(patch(CLIENT + "native_cli", return_value=Path("never-executed")))
            stack.enter_context(patch(CLIENT + "ClaudeSDKClient", return_value=client))
            stack.enter_context(patch(SUPERVISED + "OwnedProcess", owner))
            control.start(
                job["job_id"],
                allow_live=True,
                allow_existing_login=True,
                snapshot_sha256=job["snapshot_sha256"],
            )
            control.thread.join(10)
        self.assertFalse(control.thread.is_alive())
        return control, root, control.load(job["job_id"])

    def assert_absent(self, root, *needles, untrusted=()):
        """Scan every producer-authored byte under root.

        Only `.execution.lock` is skipped: the test-owned controller holds it open (an OS lock,
        unreadable on Windows) and it carries no producer data. `untrusted` names directories
        whose files were written by a hostile test double, not by the repaired producer.
        """
        files = [
            path
            for path in root.rglob("*")
            if path.is_file()
            and path.name != ".execution.lock"
            and not set(untrusted) & set(path.relative_to(root).parts)
        ]
        self.assertTrue(list(root.glob("runs/*/events.jsonl")), "scan must not be vacuous")
        self.assertTrue(list(root.glob("runs/*/run.json")), "scan must include the run document")
        for path in files:
            data = path.read_bytes()
            for needle in needles:
                self.assertNotIn(needle.encode(), data, str(path))


ROUTES = {"direct": DirectRoute, "worker": SupervisedClaudeAdapter}


class RawProviderTextTests(Base):
    def cases(self):
        return {
            "native-error": (
                result_message(
                    subtype="error_during_execution",
                    is_error=True,
                    result=CANARY,
                    errors=[CANARY],
                    terminal_reason=CANARY,
                ),
                False,
            ),
            "token-shaped-usage-key": (
                result_message(
                    subtype="error_during_execution",
                    is_error=True,
                    result=None,
                    errors=[KEY_CANARY],
                    usage={KEY_CANARY: 1, "input_tokens": 5},
                ),
                False,
            ),
            "success-invalid-output": (result_message(result=f"{CANARY} is not a report"), False),
            "exception-text": (result_message(result="unused"), True),
        }

    def test_canary_never_reaches_any_generated_file_on_either_route(self):
        for route_name, route in ROUTES.items():
            for case, (final, raises) in self.cases().items():
                with self.subTest(route=route_name, case=case):
                    control, root, job = self.run_job(
                        route, stream(final, raises), f"{route_name}-{case}"
                    )
                    self.assertEqual(job["status"], "FAILED")
                    self.assertIsNone(job["report"])
                    self.assert_absent(root, CANARY, KEY_CANARY)
                    if route_name == "worker":
                        for response in root.glob("runs/*/worker/response.json"):
                            body = json.loads(response.read_text(encoding="utf-8"))
                            self.assertIsNone((body["result"] or {}).get("text"))
                    result = json.loads(next(root.glob("runs/*/result.json")).read_text())
                    self.assertIsNone(result["summary"])

    def test_safe_metadata_is_retained(self):
        final, raises = self.cases()["native-error"]
        control, root, job = self.run_job(DirectRoute, stream(final, raises), "metadata")
        record = control.canonical(job)
        self.assertEqual(
            record["sdk_outcome"],
            {"subtype": "error_during_execution", "is_error": True, "terminal_reason": "other"},
        )
        self.assertEqual(record["provider"]["resolved_model"], "claude-haiku-5-5")
        events = [
            json.loads(line)
            for line in next(root.glob("runs/*/events.jsonl")).read_text().splitlines()
        ]
        messages = [e["payload"] for e in events if e["type"] == "sdk.message"]
        self.assertEqual(
            [m["message_type"] for m in messages],
            ["SystemMessage", "AssistantMessage", "UserMessage", "ResultMessage"],
        )
        self.assertEqual(messages[-1]["message"]["errors_count"], 1)
        self.assertEqual(messages[-1]["message"]["result_bytes"], len(CANARY))
        tool = next(e["payload"] for e in events if e["type"] == "tool.request")
        self.assertEqual(tool["tool_name"], "other")
        self.assertTrue(tool["input_present"])

    def test_task_metadata_withholds_snapshot_text_but_keeps_hash_and_size(self):
        control, root, job = self.run_job(
            DirectRoute,
            stream(result_message(result=json.dumps(expected_fixture_output()))),
            "task",
        )
        source = json.loads(next(root.glob("tasks/*/task.json")).read_text())
        self.assertEqual(source["instructions"], privacy.INSTRUCTIONS_WITHHELD)
        self.assertEqual(
            source["instructions_sha256"], control.preview(job["job_id"])["query_sha256"]
        )
        self.assertGreater(source["instructions_size_bytes"], 0)
        raw = json.dumps(source)
        for content in SAMPLE.values():
            first = next(line for line in content.splitlines() if line.strip())
            self.assertNotIn(first, raw)


class ValidReportTests(Base):
    def test_valid_report_persists_exports_and_reopens_on_both_routes(self):
        for route_name, route in ROUTES.items():
            with self.subTest(route=route_name):
                final = result_message(result=json.dumps(expected_fixture_output()))
                control, root, job = self.run_job(route, stream(final), f"valid-{route_name}")
                self.assertEqual(job["status"], "COMPLETED")
                report = control.report(job["job_id"])
                self.assertEqual(report["model_requests"], 1)
                with zipfile.ZipFile(io.BytesIO(control.bundle(job["job_id"]))) as archive:
                    self.assertIn("report.md", archive.namelist())
                    for name in archive.namelist():
                        self.assertNotIn(CANARY.encode(), archive.read(name))
                self.assert_absent(root, CANARY)
                control.close()
                reopened = AnalysisControl(root, supervised_factory=route)
                self.controls.append(reopened)
                self.assertEqual(reopened.report(job["job_id"]), report)
                if route_name == "worker":
                    body = json.loads(
                        next(root.glob("runs/*/worker/response.json")).read_text(encoding="utf-8")
                    )
                    self.assertEqual(json.loads(body["result"]["text"]), expected_fixture_output())

    def test_parent_reprojects_a_tampered_worker_response(self):
        final = result_message(result=json.dumps(expected_fixture_output()))
        control, root, job = self.run_job(
            SupervisedClaudeAdapter, stream(final), "tamper", owner=TamperingOwner
        )
        self.assertEqual(job["status"], "FAILED")
        # The attacker-written private worker files are untrusted input and may hold the
        # canary; everything the parent itself produced (canonical journal, run, result,
        # history, task) must not.
        self.assert_absent(root, CANARY, untrusted=("worker",))
        result = json.loads(next(root.glob("runs/*/result.json")).read_text())
        self.assertEqual(result["error"]["message"], "analysis_invalid_response")


class PolicyTests(unittest.TestCase):
    def test_events_keep_allowlisted_metadata_only(self):
        self.assertEqual(
            privacy.event(
                "tool.result",
                {"tool_use_id": CANARY, "tool_name": CANARY, "content": CANARY, "error": CANARY},
            )["tool_name"],
            "other",
        )
        again = privacy.event(
            "tool.request",
            privacy.event(
                "tool.request", {"tool_use_id": CANARY, "tool_name": "Read", "input": {}}
            ),
        )
        self.assertEqual(again["tool_name"], "Read")
        self.assertTrue(again["input_present"])
        self.assertNotIn(CANARY, json.dumps(again))
        generic = privacy.event("custom", {"count": 3, "result": CANARY, "text": "two words"})
        self.assertEqual(generic, {"count": 3})

    def test_error_documents_use_fixed_messages_only(self):
        error = privacy.error(
            {"category": "sdk", "code": "RuntimeError", "message": CANARY, "retryable": False}
        )
        self.assertEqual(error["message"], privacy.WITHHELD)
        kept = privacy.error({"category": "sdk", "code": "X", "message": "analysis_sdk_failed"})
        self.assertEqual(kept["message"], "analysis_sdk_failed")

    def test_document_projection_is_idempotent_and_numeric_for_provider_usage(self):
        document = {
            "sdk_outcome": {"subtype": CANARY, "is_error": False, "terminal_reason": "completed"},
            "session_id": "has space",
            "usage": {
                "sdk": {
                    "total_cost_usd": 0.01,
                    "scope": "sdk-call-native",
                    "usage": {"input_tokens": 1, "service_tier": CANARY},
                },
                "application": None,
            },
            "provider": {"resolved_model": CANARY, "cli_version": "2.1.0"},
        }
        once = privacy.document(document)
        self.assertEqual(once["sdk_outcome"]["subtype"], "other")
        self.assertIsNone(once["session_id"])
        self.assertEqual(once["usage"]["sdk"]["usage"], {"input_tokens": 1})
        self.assertEqual(once["usage"]["sdk"]["scope"], "sdk-call-native")
        self.assertIsNone(once["provider"]["resolved_model"])
        self.assertEqual(once["provider"]["cli_version"], "2.1.0")
        self.assertEqual(privacy.document(once), once)

    def test_unknown_keys_are_dropped_even_when_identifier_shaped(self):
        usage = {
            "total_cost_usd": 0.01,
            "scope": "sdk-call-native",
            KEY_CANARY: 1,
            "usage": {"input_tokens": 3, KEY_CANARY: 2, "server_tool_use": {KEY_CANARY: 1}},
            "model_usage": {
                "claude-haiku-5-5": {"inputTokens": 1, KEY_CANARY: 1},
                KEY_CANARY: {"inputTokens": 1},
                CANARY: {"inputTokens": 1},
            },
        }
        kept = privacy.numeric(usage)
        self.assertEqual(
            kept,
            {
                "total_cost_usd": 0.01,
                "scope": "sdk-call-native",
                "usage": {"input_tokens": 3, "server_tool_use": {}},
                "model_usage": {"claude-haiku-5-5": {"inputTokens": 1}},
            },
        )
        self.assertNotIn(KEY_CANARY, json.dumps(kept))
        application = {
            "cleanup": {"tree_empty": True, KEY_CANARY: True},
            "model_requests": 1,
            KEY_CANARY: "value",
            "comparison": {"fields": {KEY_CANARY: {"native": 1}}},
        }
        projected = privacy.structure(application)
        self.assertEqual(projected["cleanup"], {"tree_empty": True})
        self.assertEqual(projected["comparison"], {"fields": {}})
        self.assertNotIn(KEY_CANARY, json.dumps(projected))
        for kind in ("custom", "context.observed", "sdk.query_started"):
            generic = privacy.event(kind, {KEY_CANARY: 1, "resume_requested": False})
            self.assertNotIn(KEY_CANARY, json.dumps(generic))

    def test_accepted_text_requires_a_source_grounded_report(self):
        sources = sdk.checked_sources(SAMPLE)
        instructions = sdk.query_text(sources, "overview")
        good = json.dumps(expected_fixture_output())
        self.assertEqual(
            json.loads(privacy.accepted_text(instructions, good)), expected_fixture_output()
        )
        wrong = expected_fixture_output()
        wrong["claims"][1]["value"] = "price + quantity"
        for raw in (
            json.dumps(wrong),
            f"{CANARY} not json",
            '{"repository":"tiny-shop","repository":"x","claims":[]}',
            "x" * 16385,
            None,
        ):
            self.assertIsNone(privacy.accepted_text(instructions, raw))
        self.assertIsNone(privacy.accepted_text("not json", good))

    def test_worker_result_withholds_text_for_failed_outcome(self):
        instructions = sdk.query_text(sdk.checked_sources(SAMPLE), "overview")
        failed = NativeResult(
            json.dumps(expected_fixture_output()),
            {"subtype": "error_during_execution", "is_error": True, "terminal_reason": "x"},
            "synthetic",
            {"total_cost_usd": 0.0},
        )
        self.assertIsNone(privacy.worker_result(failed, instructions)["text"])


if __name__ == "__main__":
    unittest.main()
