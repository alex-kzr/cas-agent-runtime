"""Pinned SDK serialization checks only: no native process, auth or inference."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from claude_agent_sdk import ClaudeSDKClient, SystemMessage
from claude_agent_sdk._internal.query import Query
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

from agent_runtime.providers.claude.auth import auth_environment
from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.providers.claude.context import context_observation
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import Recorder


class ContextIsolationTests(unittest.IsolatedAsyncioTestCase):
    def options(self, root, mode="subscription", agent="text-only-v1"):
        request = ExecutionRequest(
            "task",
            "synthetic",
            root / "workspaces/one",
            Limits(1, "0.10", 60),
            live_authorized=True,
            allow_existing_login=True,
            auth_mode=mode,
            agent_name=agent,
            login_config_dir=str(root.parent / "synthetic-native"),
        )
        environment = {"ANTHROPIC_API_KEY": "synthetic-not-real"}
        return ClaudeAdapter(environment).options(request, Recorder(root, request))

    async def test_real_transport_serializes_guards_for_both_auth_and_tool_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("subscription", "api"):
                for agent in ("text-only-v1", "read-only-v1"):
                    with self.subTest(mode=mode, agent=agent):
                        options = self.options(Path(directory), mode, agent)
                        transport = SubprocessCLITransport("synthetic", options)
                        command = transport._build_command()  # pure argv construction
                        self.assertIn("--disable-slash-commands", command)
                        self.assertIn("--setting-sources=", command)
                        self.assertIn("--strict-mcp-config", command)
                        self.assertNotIn("--plugin-dir", command)
                        self.assertNotIn("--bare", command)
                        self.assertFalse(options.env.get("CLAUDE_CODE_SIMPLE"))
                        settings = json.loads(command[command.index("--settings") + 1])
                        self.assertIs(settings["autoMemoryEnabled"], False)
                        self.assertIs(settings["disableBundledSkills"], True)
                        self.assertEqual(settings["claudeMdExcludes"], ["**"])
                        self.assertEqual(
                            settings["enabledPlugins"],
                            {
                                "cc-plugin-agents-md@builtin": False,
                                "cc-plugin-plugin-authoring@builtin": False,
                            },
                        )
                        for key in (
                            "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
                            "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS",
                        ):
                            self.assertEqual(options.env[key], "1")
                        if mode == "subscription":
                            self.assertEqual(settings["forceLoginMethod"], "claudeai")
                            self.assertEqual(
                                Path(options.env["CLAUDE_CONFIG_DIR"]),
                                Path(directory).parent / "synthetic-native",
                            )
                        self.assertEqual(options.skills, [])
                        self.assertTrue(options.verbatim_prompts)
                        self.assertEqual(
                            command[command.index("--tools") + 1],
                            "Read" if agent == "read-only-v1" else "",
                        )

    async def test_sdk_initialize_transmits_empty_filter_not_omitted(self):
        query = Query(transport=None, is_streaming_mode=True, skills=[])
        query._send_control_request = AsyncMock(return_value={})
        try:
            await query.initialize()
            initialize = query._send_control_request.call_args.args[0]
            self.assertIn("skills", initialize)
            self.assertEqual(initialize["skills"], [])
        finally:
            await query._message_send.aclose()
            await query._message_receive.aclose()

    async def test_real_sdk_prompt_serialization_is_literal_without_native_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            options = self.options(Path(directory))
            # Constructing the SDK object never connects. Replace both connection fields
            # with in-memory sinks and exercise the pinned serializer, not inference.
            client = ClaudeSDKClient(options=options)
            client._verbatim_prompts = options.verbatim_prompts
            client._query = object()
            client._transport = type("Sink", (), {"write": AsyncMock()})()
            text = "/fixture @C:/synthetic/not-to-read.txt @fixture:resource"
            await client.query(text)
            payload = json.loads(client._transport.write.call_args.args[0])
            self.assertIs(payload.get("client_composed"), True)
            self.assertEqual(payload["message"]["content"], text)
            self.assertNotIn("attachments", payload)

    async def test_host_environment_cannot_enable_memory_or_simple_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = self.options(root)
            request = ExecutionRequest(
                "task", "fixture", root, Limits(1, "0.1", 60), auth_mode="api"
            )
            environment = {
                "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "0",
                "CLAUDE_CODE_SIMPLE": "1",
                "CLAUDE_CODE_SAFE_MODE": "1",
            }
            selected = auth_environment(request, environment, root / "state")
            self.assertEqual(selected["CLAUDE_CODE_DISABLE_AUTO_MEMORY"], "1")
            self.assertNotIn("CLAUDE_CODE_SIMPLE", selected)
            with patch.dict("os.environ", environment):
                guarded = self.options(root)
            self.assertEqual(guarded.env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"], "1")
            self.assertEqual(guarded.env["CLAUDE_CODE_SIMPLE"], "")
            self.assertEqual(options.env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"], "1")

    async def test_init_listing_is_counted_without_reading_paths_or_claiming_context(self):
        message = SystemMessage(
            subtype="init",
            data={
                "skills": ["fixture-skill"],
                "plugins": [{"name": "fixture-plugin", "path": "builtin"}],
                "tools": [],
                "mcp_servers": [],
                "memory_paths": {"auto": "C:/synthetic/DO-NOT-READ"},
            },
        )
        with patch.object(Path, "read_text", side_effect=AssertionError("No path reads")):
            observed = context_observation(message)
        self.assertEqual(observed["skills_count"], 1)
        self.assertEqual(observed["plugins_count"], 1)
        self.assertEqual(observed["memory_paths_count"], 1)
        self.assertEqual(observed["provenance"], "sdk-init-advertisement")
        self.assertEqual(observed["context_isolation"], "unverified")
        self.assertNotIn("DO-NOT-READ", json.dumps(observed))

    async def test_empty_or_missing_init_metadata_never_proves_isolation(self):
        for data in (
            {},
            {"skills": [], "plugins": [], "tools": [], "mcp_servers": [], "memory_paths": {}},
            {"skills": "malformed", "memory_paths": []},
        ):
            observed = context_observation(SystemMessage(subtype="init", data=data))
            self.assertEqual(observed["context_isolation"], "unverified")
            self.assertIsNone(observed["content_loaded"])
        self.assertIsNone(context_observation(SystemMessage(subtype="other", data={})))
