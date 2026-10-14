"""Offline compatibility checks: no SDK client is started."""
import inspect
import unittest
from dataclasses import fields
from importlib.metadata import version

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, ResultMessage


class BaselineTests(unittest.TestCase):
    def test_exact_distribution_and_required_options(self):
        self.assertEqual(version("claude-agent-sdk"), "0.2.165")
        names = {field.name for field in fields(ClaudeAgentOptions)}
        self.assertLessEqual({"tools", "cwd", "max_turns", "max_budget_usd", "setting_sources",
                              "strict_mcp_config", "can_use_tool", "hooks"}, names)

    def test_client_control_and_result_surface(self):
        for name in ("connect", "query", "receive_response", "interrupt", "disconnect"):
            self.assertTrue(callable(getattr(ClaudeSDKClient, name, None)), name)
        self.assertTrue(inspect.iscoroutinefunction(ClaudeSDKClient.interrupt))
        self.assertLessEqual({"subtype", "is_error", "session_id", "total_cost_usd"},
                             {field.name for field in fields(ResultMessage)})

    def test_unknown_option_rejected_before_client_start(self):
        with self.assertRaises(TypeError):
            ClaudeAgentOptions(cas_unknown_option=True)
