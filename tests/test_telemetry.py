import tempfile
import unittest
from pathlib import Path

from claude_agent_sdk import AssistantMessage, ToolResultBlock, ToolUseBlock, UserMessage

from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.events import observe_message
from agent_runtime.telemetry.metrics import ObservedUsage
from agent_runtime.telemetry.recorder import Recorder, read_events


class TelemetryTests(unittest.TestCase):
    def test_duplicate_native_ids_do_not_inflate_usage(self):
        observed = ObservedUsage()
        observed.observe("message-1", {"input_tokens": 4, "output_tokens": 2})
        observed.observe("message-1", {"input_tokens": 4, "output_tokens": 2})
        observed.observe("child", {"input_tokens": 100}, subagent=True)
        result = observed.snapshot()
        self.assertEqual(result["observed_main_loop_tokens"]["input_tokens"], 4)
        self.assertEqual(result["observed_message_count"], 1)
        self.assertFalse(result["complete"])
        self.assertFalse(result["cost_derived"])

    def test_unknown_usage_is_not_zero_or_guess(self):
        observed = ObservedUsage()
        observed.observe(None, {"input_tokens": 4})
        self.assertIsNone(observed.snapshot()["observed_main_loop_tokens"])
        observed.observe("invalid", {"input_tokens": True, "output_tokens": -1})
        self.assertIsNone(observed.snapshot()["observed_main_loop_tokens"])
        self.assertTrue(observed.snapshot()["warnings"])

    def test_actual_sdk_block_types_correlate_tools_and_keep_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = Recorder(
                root,
                ExecutionRequest("task", "fixture", root / "workspaces/one", Limits(2, "0.1", 5)),
            )
            observed = ObservedUsage()
            assistant = AssistantMessage(
                content=[ToolUseBlock(id="tool-1", name="Read", input={"file_path": "fixture.py"})],
                model="fixture-model",
                message_id="message-1",
                usage={"input_tokens": 4},
            )
            user = UserMessage(
                content=[ToolResultBlock(tool_use_id="tool-1", content="fixture", is_error=False)]
            )
            observe_message(assistant, recorder, observed)
            observe_message(user, recorder, observed)
            events, _ = read_events(recorder.directory / "events.jsonl")
            tool_events = [event for event in events if event["type"].startswith("tool.")]
            self.assertEqual(
                [event["type"] for event in tool_events], ["tool.request", "tool.result"]
            )
            self.assertEqual(
                [event["payload"]["tool_use_id"] for event in tool_events], ["tool-1", "tool-1"]
            )
            self.assertEqual(recorder.record["provider"]["resolved_model"], "fixture-model")

    def test_subagent_model_does_not_replace_main_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recorder = Recorder(
                root,
                ExecutionRequest("task", "fixture", root / "workspaces/one", Limits(2, "0.1", 5)),
            )
            observed = ObservedUsage()
            observe_message(
                AssistantMessage(
                    content=[], model="main-model", message_id="main", usage={"input_tokens": 4}
                ),
                recorder,
                observed,
            )
            observe_message(
                AssistantMessage(
                    content=[],
                    model="child-model",
                    parent_tool_use_id="parent-1",
                    message_id="child",
                    usage={"input_tokens": 100},
                ),
                recorder,
                observed,
            )
            self.assertEqual(recorder.record["provider"]["resolved_model"], "main-model")
            self.assertEqual(observed.snapshot()["observed_main_loop_tokens"]["input_tokens"], 4)
