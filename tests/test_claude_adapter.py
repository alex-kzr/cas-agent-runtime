import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import Recorder


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    def request(self, root, authorized=False):
        return ExecutionRequest(
            "task", "fixture", root / "workspace", Limits(2, "0.1", 5), live_authorized=authorized
        )

    async def test_no_client_construction_without_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.request(root)
            recorder = Recorder(root, request)
            with patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client:
                with self.assertRaises(PermissionError):
                    await ClaudeAdapter({}).run(request, recorder)
                client.assert_not_called()

    async def test_no_credentials_blocks_before_client(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.request(root, True)
            recorder = Recorder(root, request)
            with patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client:
                with self.assertRaises(ValueError):
                    await ClaudeAdapter({}).run(request, recorder)
                client.assert_not_called()

    async def test_options_are_text_only_and_do_not_leak_ambient_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = ClaudeAdapter(
                {"ANTHROPIC_API_KEY": "synthetic-not-real", "GITHUB_TOKEN": "untrusted"}
            )
            request = self.request(root, True)
            recorder = Recorder(root, request)
            with patch.dict(
                "os.environ",
                {"GITHUB_TOKEN": "untrusted", "ANTHROPIC_BASE_URL": "https://invalid.example"},
            ):
                options = adapter.options(request, recorder)
            self.assertEqual(options.tools, [])
            self.assertEqual(options.setting_sources, [])
            self.assertTrue(options.strict_mcp_config)
            self.assertEqual(options.env["GITHUB_TOKEN"], "")
            self.assertEqual(options.env["ANTHROPIC_BASE_URL"], "")
            decision = await options.can_use_tool("Bash", {"command": "anything"}, None)
            self.assertEqual(decision.behavior, "deny")
