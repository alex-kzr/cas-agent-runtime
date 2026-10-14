"""Native contract mocks only: no connection, native process or session-store lookup."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from claude_agent_sdk import ConversationResetMessage, ResultMessage, StreamEvent, SystemMessage

from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import Recorder


def result(session="expected-session", error=False):
    return ResultMessage(
        subtype="error_during_execution" if error else "success",
        duration_ms=1,
        duration_api_ms=1,
        is_error=error,
        num_turns=1,
        session_id=session,
        result="mock result",
        terminal_reason="completed",
    )


class MockStream:
    def __init__(self, messages):
        self.messages = messages
        self.queries = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def query(self, prompt):
        self.queries += 1

    async def receive_response(self):
        for message in self.messages:
            if isinstance(message, Exception):
                raise message
            yield message


class SessionContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def request(self, resume=True):
        return ExecutionRequest(
            "task",
            "synthetic session contract",
            self.root / "workspaces/one",
            Limits(2, "0.10", 5),
            live_authorized=True,
            auth_mode="api",
            resumes_run_id=str(uuid4()) if resume else None,
            resume_session_id="expected-session" if resume else None,
        )

    async def run_stream(self, messages, *, resume=True):
        request = self.request(resume)
        recorder = Recorder(self.root, request)
        stream = MockStream(messages)
        self.stream = stream
        self.recorder = recorder
        with patch("agent_runtime.providers.claude.client.ClaudeSDKClient", return_value=stream):
            return await ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"}).run(
                request, recorder
            )

    async def test_same_main_identity_and_child_stream(self):
        response = await self.run_stream(
            [
                SystemMessage("init", {"session_id": "expected-session"}),
                StreamEvent("child-event", "child-session", {}, parent_tool_use_id="child-tool"),
                result(),
            ]
        )
        self.assertEqual(response.session_id, "expected-session")
        self.assertEqual(self.recorder.record["session_id"], "expected-session")
        self.assertEqual(self.stream.queries, 1)

    async def test_different_init_or_result_rejects_success(self):
        for messages in (
            [SystemMessage("init", {"session_id": "wrong-session"}), result()],
            [SystemMessage("init", {"session_id": "expected-session"}), result("wrong-session")],
        ):
            with self.subTest(messages=len(messages)), self.assertRaises(ValueError):
                await self.run_stream(messages)
            self.assertEqual(self.stream.queries, 1)

    async def test_reset_does_not_become_successful_continuation(self):
        with self.assertRaises(ValueError):
            await self.run_stream(
                [
                    ConversationResetMessage("new-conversation", "reset-id", "expected-session"),
                    result(),
                ]
            )
        self.assertEqual(self.stream.queries, 1)

    async def test_init_only_interruption_retains_main_session(self):
        with self.assertRaises(RuntimeError):
            await self.run_stream(
                [
                    SystemMessage("init", {"session_id": "expected-session"}),
                    RuntimeError("synthetic stream interruption"),
                ]
            )
        saved = json.loads((self.recorder.directory / "run.json").read_text())
        self.assertEqual(saved["session_id"], "expected-session")

    async def test_missing_session_error_never_retries_or_falls_back(self):
        for messages in ([RuntimeError("synthetic expired session")], []):
            with self.subTest(empty=not messages), self.assertRaises(RuntimeError):
                await self.run_stream(messages)
            self.assertEqual(self.stream.queries, 1)

    async def test_native_error_result_is_retained_without_retry(self):
        response = await self.run_stream([result(error=True)])
        self.assertTrue(response.outcome["is_error"])
        self.assertEqual(self.stream.queries, 1)

    async def test_null_empty_invalid_result_id_fails_and_preserves_cost(self):
        for session_id in (None, "", "invalid id", "x" * 129, "different-session"):
            response = result(session_id)
            response.total_cost_usd = 0.004
            with self.subTest(session_id=session_id), self.assertRaises(ValueError):
                await self.run_stream(
                    [SystemMessage("init", {"session_id": "expected-session"}), response]
                )
            saved = json.loads((self.recorder.directory / "run.json").read_text())
            self.assertEqual(saved["session_id"], "expected-session")
            self.assertEqual(saved["usage"]["sdk"]["total_cost_usd"], 0.004)
            self.assertEqual(saved["sdk_outcome"]["subtype"], "success")
            self.assertEqual(self.stream.queries, 1)

    async def test_supervised_payload_preserves_explicit_identity(self):
        from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter

        captured = []

        class NoProcess:
            cleanup = {"tree_empty": True, "mechanism": "mock-only"}

            async def run(self, command, payload, environment):
                captured.append(json.loads(payload))
                raise RuntimeError("synthetic worker refusal")

        request = self.request()
        recorder = Recorder(self.root, request)
        with patch("agent_runtime.providers.claude.supervised.OwnedProcess", NoProcess):
            with self.assertRaises(RuntimeError):
                await SupervisedClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"}).run(
                    request, recorder
                )
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["request"]["resume_session_id"], "expected-session")
        self.assertEqual(captured[0]["request"]["resumes_run_id"], request.resumes_run_id)

    async def test_explicit_resume_serialization_and_fresh_defaults(self):
        from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

        adapter = ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
        request = self.request()
        recorder = Recorder(self.root, request)
        options = adapter.options(request, recorder)
        self.assertEqual(options.resume, "expected-session")
        self.assertFalse(options.continue_conversation)
        self.assertFalse(options.fork_session)
        self.assertIsNone(options.session_store)
        self.assertEqual(options.permission_mode, "default")
        self.assertTrue(options.strict_mcp_config)
        self.assertIn("PreToolUse", options.hooks)
        command = SubprocessCLITransport(prompt="fixture", options=options)._build_command()
        self.assertEqual(
            [arg for arg in command if arg.startswith("--resume")], ["--resume=expected-session"]
        )
        fresh = self.request(False)
        clean = adapter.options(fresh, Recorder(self.root, fresh))
        self.assertIsNone(clean.resume)
        self.assertFalse(clean.continue_conversation)
        self.assertFalse(clean.fork_session)
