"""Preparation tests only. Never start native CLI, auth, SDK connection or probe."""

import ast
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from claude_agent_sdk._internal.query import Query

from agent_runtime.providers.claude import context_probe as probe


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    def test_module_has_no_query_call(self):
        tree = ast.parse(inspect.getsource(probe))
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "query"
                for node in ast.walk(tree)
            )
        )

    def test_missing_authorization_stops_before_pin_or_supervisor(self):
        with (
            patch.object(probe, "check_pin") as check,
            patch.object(probe, "supervise") as supervisor,
        ):
            for flags in ([], ["--allow-native-startup"], ["--allow-existing-login"]):
                with self.assertRaises(PermissionError):
                    probe.main(flags)
            check.assert_not_called()
            supervisor.assert_not_called()

    def test_scope_pin_checks_source_sdk_and_binary_without_executing_them(self):
        snapshot = {
            "sdk_version": "0.2.165",
            "files": [{"path": "native/claude.exe", "sha256": probe.NATIVE_SHA256}],
        }
        with (
            patch.object(probe, "scope_snapshot", return_value=snapshot),
        ):
            probe.check_pin(probe.scope_hash(snapshot))
            with self.assertRaises(ValueError):
                probe.check_pin("changed-source-hash")
        with patch.object(
            probe, "scope_snapshot", return_value=snapshot | {"sdk_version": "other"}
        ):
            with self.assertRaises(ValueError):
                probe.check_pin("reviewed")
        with (
            patch.object(
                probe,
                "scope_snapshot",
                return_value=snapshot
                | {"files": [{"path": "native/claude.exe", "sha256": "changed"}]},
            ),
        ):
            with self.assertRaises(ValueError):
                probe.check_pin("reviewed")

    def test_summary_drops_all_names_paths_text_and_unknown_fields(self):
        summary = probe.context_summary(
            {
                "totalTokens": 10,
                "maxTokens": 100,
                "rawMaxTokens": 200,
                "model": probe.MODEL,
                "memoryFiles": [
                    {"tokens": 4, "path": "PRIVATE-PATH", "content": "PRIVATE-CONTENT"}
                ],
                "mcpTools": [],
                "agents": [],
                "secret": "PRIVATE-SECRET",
            }
        )
        self.assertEqual(summary["memory_tokens"], 4)
        self.assertEqual(summary["memory_files_count"], 1)
        self.assertNotIn("PRIVATE", json.dumps(summary))
        self.assertFalse(summary["context_isolation_verified"])
        self.assertIsNone(probe.context_summary({"totalTokens": True})["total_tokens"])
        self.assertIsNone(probe.context_summary({})["memory_files_count"])

    def test_parent_whitelist_does_not_trust_worker_fields(self):
        safe = probe.sanitize_worker_report(
            {
                "status": "observed",
                "user_messages_written": 999,
                "secret": "PRIVATE",
                "context": {
                    "memory_tokens": 0,
                    "path": "PRIVATE",
                    "context_isolation_verified": True,
                },
                "auth": {"email": "PRIVATE"},
            }
        )
        self.assertNotIn("PRIVATE", json.dumps(safe))
        self.assertNotIn("user_messages_written", safe)
        self.assertFalse(safe["context"]["context_isolation_verified"])

    async def test_fence_accepts_only_one_of_each_expected_control(self):
        transport = probe.NoQueryTransport(probe.ClaudeAgentOptions(cli_path="synthetic.exe"))
        with patch.object(probe.SubprocessCLITransport, "write", new_callable=AsyncMock) as write:
            for request in (
                {"subtype": "initialize", "hooks": None, "skills": []},
                {"subtype": "get_context_usage"},
            ):
                await transport.write(
                    json.dumps(
                        {"type": "control_request", "request_id": "synthetic", "request": request}
                    )
                )
            self.assertEqual(write.await_count, 2)
            with self.assertRaises(PermissionError):
                await transport.write(
                    json.dumps(
                        {
                            "type": "control_request",
                            "request_id": "again",
                            "request": {"subtype": "get_context_usage"},
                        }
                    )
                )

    async def test_pinned_sdk_builds_the_two_allowed_control_requests_without_processes(self):
        transport = probe.NoQueryTransport(probe.ClaudeAgentOptions(cli_path="synthetic.exe"))
        query = Query(transport=transport, is_streaming_mode=True, skills=[])

        async def send(request, **kwargs):
            await transport.write(
                json.dumps({"type": "control_request", "request_id": "fixture", "request": request})
            )
            return {}

        query._send_control_request = AsyncMock(side_effect=send)
        try:
            with patch.object(
                probe.SubprocessCLITransport, "write", new_callable=AsyncMock
            ) as write:
                await query.initialize()
                await query.get_context_usage()
                self.assertEqual(write.await_count, 2)
        finally:
            await query._message_send.aclose()
            await query._message_receive.aclose()

    async def test_fence_blocks_user_frames_commands_and_content_bearing_controls(self):
        for envelope in (
            {"type": "user", "message": {"role": "user", "content": "PRIVATE"}},
            {
                "type": "control_request",
                "request_id": "x",
                "request": {
                    "subtype": "initialize",
                    "hooks": None,
                    "skills": [],
                    "systemPrompt": "PRIVATE",
                },
            },
            {
                "type": "control_request",
                "request_id": "x",
                "request": {"subtype": "get_context_usage", "prompt": "PRIVATE"},
            },
            {"type": "control_request", "request_id": "x", "request": {"subtype": "set_model"}},
            {"type": "control_response", "response": {}},
        ):
            transport = probe.NoQueryTransport(probe.ClaudeAgentOptions(cli_path="synthetic.exe"))
            with patch.object(
                probe.SubprocessCLITransport, "write", new_callable=AsyncMock
            ) as write:
                with self.assertRaises(PermissionError):
                    await transport.write(json.dumps(envelope))
                write.assert_not_awaited()

    async def test_diagnostic_fixture_never_queries_and_returns_only_safe_metadata(self):
        client = type("FixtureClient", (), {})()
        client.get_context_usage = AsyncMock(
            return_value={"totalTokens": 0, "memoryFiles": [], "content": "PRIVATE"}
        )
        client.query = AsyncMock(side_effect=AssertionError("No query"))
        context = type(
            "FixtureContext",
            (),
            {
                "__aenter__": AsyncMock(return_value=client),
                "__aexit__": AsyncMock(return_value=False),
            },
        )()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = probe.make_request(root / "probe")
            auth = {
                "auth_mode": "subscription",
                "session_status": "verified-native-status",
                "auth_method": "claude.ai",
                "api_fallback": "disabled",
            }
            with (
                patch.dict(
                    "os.environ", {"CLAUDE_CONFIG_DIR": str(root / "synthetic-native")}, clear=True
                ),
                patch.object(probe, "subscription_status", return_value=auth),
                patch.object(probe, "ClaudeSDKClient", return_value=context) as sdk,
            ):
                report = await probe.diagnose(request, root / "probe")
            client.query.assert_not_awaited()
            client.get_context_usage.assert_awaited_once_with()
            self.assertNotIn("PRIVATE", json.dumps(report))
            self.assertEqual(report["status"], "observed")
            self.assertEqual(sdk.call_args.kwargs["options"].tools, [])

    async def test_unknown_cleanup_never_becomes_observed(self):
        class FixtureOwner:
            cleanup = {"tree_empty": False, "forced": True}
            run = AsyncMock(return_value=0)

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(probe, "OwnedProcess", return_value=FixtureOwner()),
            patch.dict(
                "os.environ",
                {"CLAUDE_CONFIG_DIR": str(Path(directory).parent / "synthetic-native")},
                clear=True,
            ),
        ):
            report = await probe.supervise(Path(directory), "synthetic-hash")
            self.assertEqual(report["status"], "inconclusive")
            self.assertFalse(report["context_isolation_verified"])
