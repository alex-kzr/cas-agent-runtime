import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.providers.claude.permissions import read_allowed
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import Recorder


class ReadPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_filesystem_failure_returns_explicit_deny_from_both_callbacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "task", "fixture", root, Limits(2, "0.1", 5), agent_name="read-only-v1"
            )
            recorder = Recorder(root / "data", request)
            options = ClaudeAdapter({}).options(request, recorder)
            with patch(
                "agent_runtime.providers.claude.permissions.Path.resolve",
                side_effect=OSError("fixture denied"),
            ):
                result = await options.can_use_tool("Read", {"file_path": "source.py"}, None)
                hook = options.hooks["PreToolUse"][0].hooks[0]
                decision = await hook(
                    {"tool_name": "Read", "tool_input": {"file_path": "source.py"}}, None, None
                )
            self.assertEqual(result.behavior, "deny")
            self.assertEqual(decision["hookSpecificOutput"]["permissionDecision"], "deny")

    async def test_policy_accepts_fixture_and_denies_escape_secrets_and_other_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.py").write_text("print('fixture')")
            (root / ".env").write_text("synthetic")
            (root / "secret.pem").write_text("synthetic")
            self.assertTrue(read_allowed(root, "Read", {"file_path": "source.py"}))
            for name, path in (
                ("Read", "../outside"),
                ("Read", ".env"),
                ("Read", "secret.pem"),
                ("Bash", "source.py"),
                ("Write", "source.py"),
            ):
                self.assertFalse(read_allowed(root, name, {"file_path": path}))
            request = ExecutionRequest(
                "task", "fixture", root, Limits(2, "0.1", 5), agent_name="read-only-v1"
            )
            recorder = Recorder(root / "data", request)
            options = ClaudeAdapter({}).options(request, recorder)
            self.assertEqual(options.tools, ["Read"])
            allowed = await options.can_use_tool("Read", {"file_path": "source.py"}, None)
            denied = await options.can_use_tool("Bash", {"command": "anything"}, None)
            self.assertEqual(allowed.behavior, "allow")
            self.assertEqual(denied.behavior, "deny")
            callback = options.hooks["PreToolUse"][0].hooks[0]
            decision = await callback(
                {"tool_name": "Read", "tool_input": {"file_path": "../outside"}}, None, None
            )
            self.assertEqual(decision["hookSpecificOutput"]["permissionDecision"], "deny")
