"""Metadata and usage diagnostics are offline observations, never billing verification."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from claude_agent_sdk import SystemMessage

from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.events import observe_message
from agent_runtime.telemetry.metrics import ObservedUsage, compare_usage
from agent_runtime.telemetry.recorder import Recorder


class HookOnlySubagentTests(unittest.IsolatedAsyncioTestCase):
    async def test_hook_only_subagent_withholds_deltas_after_main_snapshots(self):
        from claude_agent_sdk import AssistantMessage, ResultMessage

        from agent_runtime.providers.claude.client import ClaudeAdapter

        class Stream:
            def __init__(self, options):
                self.options = options

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

            async def query(self, prompt):
                pass

            async def receive_response(self):
                yield SystemMessage(
                    "init", {"session_id": "fixture-session", "claude_code_version": "2.1.294"}
                )
                await self.options.hooks["SubagentStart"][0].hooks[0](
                    {"hook_event_name": "SubagentStart"}, None, None
                )
                tokens = {
                    key: 1
                    for key in (
                        "input_tokens",
                        "output_tokens",
                        "cache_creation_input_tokens",
                        "cache_read_input_tokens",
                    )
                }
                yield AssistantMessage(
                    content=[], model="fixture-model", message_id="main-1", usage=tokens
                )
                yield AssistantMessage(
                    content=[], model="fixture-model", message_id="main-2", usage=tokens
                )
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="fixture-session",
                    result="fixture",
                    usage=tokens,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "task",
                "offline hook fixture",
                root / "workspaces/one",
                Limits(1, "0.1", 5),
                live_authorized=True,
                auth_mode="api",
            )
            recorder = Recorder(root, request)
            with patch(
                "agent_runtime.providers.claude.client.ClaudeSDKClient",
                side_effect=lambda options: Stream(options),
            ):
                result = await ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"}).run(
                    request, recorder
                )
            self.assertEqual(recorder.record["provider"]["cli_version"], "2.1.294")
            self.assertTrue(result.application_usage["subagent_activity_observed"])
            comparison = result.application_usage["comparison"]
            self.assertEqual(comparison["status"], "scope-unverified")
            self.assertTrue(
                all(
                    field["native_minus_derived"] is None for field in comparison["fields"].values()
                )
            )


class UsageDiagnosticsTests(unittest.TestCase):
    def test_difference_does_not_reconcile_or_derive_cost(self):
        native = {
            "usage": {
                "input_tokens": 8,
                "output_tokens": 314,
                "cache_creation_input_tokens": 1989,
                "cache_read_input_tokens": 4485,
            }
        }
        app = {
            "observed_main_loop_tokens": {
                "input_tokens": 8,
                "output_tokens": 105,
                "cache_creation_input_tokens": 1989,
                "cache_read_input_tokens": 4485,
            },
            "complete": False,
        }
        result = compare_usage(native, app)
        self.assertEqual(result["status"], "different-observed-values")
        self.assertEqual(result["fields"]["output_tokens"]["native_minus_derived"], 209)
        self.assertFalse(result["scope_verified"])
        self.assertFalse(result["billing_verified"])
        self.assertFalse(result["derived_complete"])

    def test_unknown_invalid_equal_and_resumed_scopes(self):
        result = compare_usage(None, None)
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["fields"]["input_tokens"]["native"])
        for invalid in (True, -1, 1.5, float("nan")):
            result = compare_usage({"usage": {"input_tokens": invalid}}, None)
            self.assertIsNone(result["fields"]["input_tokens"]["native"])
        tokens = {
            key: 0
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            )
        }
        equal = compare_usage({"usage": tokens}, {"observed_main_loop_tokens": tokens})
        self.assertEqual(equal["status"], "equal-observed-values")
        self.assertFalse(equal["derived_complete"])
        resumed = compare_usage(
            {"usage": tokens}, {"observed_main_loop_tokens": tokens}, resumed=True
        )
        self.assertEqual(resumed["status"], "scope-unverified")
        self.assertIsNone(resumed["fields"]["input_tokens"]["native_minus_derived"])

    def test_init_version_has_provenance_and_conflicts_do_not_replace_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = Recorder(
                root,
                ExecutionRequest("task", "fixture", root / "workspaces/one", Limits(1, "0.1", 5)),
            )
            usage = ObservedUsage()
            observe_message(
                SystemMessage("init", {"claude_code_version": "2.1.294"}), recorder, usage
            )
            self.assertEqual(recorder.record["provider"]["cli_version"], "2.1.294")
            self.assertEqual(recorder.record["configuration"]["cli_version_source"], "sdk-init")
            observe_message(
                SystemMessage(
                    "init", {"claude_code_version": "9.0.0", "parent_tool_use_id": "child"}
                ),
                recorder,
                usage,
            )
            self.assertEqual(recorder.record["provider"]["cli_version"], "2.1.294")
            observe_message(
                SystemMessage("init", {"claude_code_version": "2.1.295"}), recorder, usage
            )
            self.assertEqual(recorder.record["provider"]["cli_version"], "2.1.294")
            self.assertTrue(recorder.record["configuration"]["cli_version_conflict"])

    def test_missing_or_malformed_version_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = Recorder(
                root,
                ExecutionRequest("task", "fixture", root / "workspaces/one", Limits(1, "0.1", 5)),
            )
            usage = ObservedUsage()
            for value in (None, 17, "private path/string"):
                observe_message(
                    SystemMessage("init", {"claude_code_version": value}), recorder, usage
                )
            self.assertIsNone(recorder.record["provider"]["cli_version"])
