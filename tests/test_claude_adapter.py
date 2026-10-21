import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.client import ClaudeAdapter
from agent_runtime.tasks.executor import Executor
from agent_runtime.tasks.models import ExecutionRequest, Limits
from agent_runtime.telemetry.recorder import Recorder
from claude_agent_sdk import AssistantMessage, ResultMessage


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_documented_completed_reason_passes_baseline_and_preserves_native_value(self):
        class CompletedStream:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                pass

            async def receive_response(self):
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="fixture-session",
                    result="CAS_SDK_BASELINE_OK",
                    terminal_reason="completed",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "scenario",
                "fixture",
                root / "workspaces/one",
                Limits(2, "0.1", 5),
                scenario_id="sdk.fundamentals",
                live_authorized=True,
                auth_mode="api",
            )
            with patch(
                "agent_runtime.providers.claude.client.ClaudeSDKClient",
                return_value=CompletedStream(),
            ):
                run = await Executor(
                    root, ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
                ).execute(request)
            self.assertEqual(run["status"], "COMPLETED")
            self.assertEqual(run["sdk_outcome"]["terminal_reason"], "completed")
            import json

            assertions = json.loads((root / "runs" / run["run_id"] / "assertions.json").read_text())
            self.assertEqual(assertions["outcome"], "pass")

    async def test_baseline_marker_alone_cannot_pass_a_native_failure(self):
        class MarkerStream:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                pass

            async def receive_response(self):
                yield ResultMessage(
                    subtype="error_during_execution",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=True,
                    num_turns=1,
                    session_id="fixture-session",
                    result="CAS_SDK_BASELINE_OK",
                    terminal_reason="api_error",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "scenario",
                "fixture",
                root / "workspaces/one",
                Limits(2, "0.1", 5),
                scenario_id="sdk.fundamentals",
                live_authorized=True,
                auth_mode="api",
            )
            with patch(
                "agent_runtime.providers.claude.client.ClaudeSDKClient", return_value=MarkerStream()
            ):
                run = await Executor(
                    root, ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
                ).execute(request)
            self.assertEqual(run["status"], "FAILED")
            import json

            assertions = json.loads((root / "runs" / run["run_id"] / "assertions.json").read_text())
            self.assertEqual(assertions["outcome"], "fail")

    async def test_partial_usage_and_native_error_result_survive_stream_exception(self):
        class FailedStream:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                pass

            async def receive_response(self):
                yield AssistantMessage(
                    content=[],
                    model="fixture",
                    message_id="native-fixture-1",
                    usage={"input_tokens": 4},
                )
                yield ResultMessage(
                    subtype="error_during_execution",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=True,
                    num_turns=1,
                    session_id="fixture-session",
                    total_cost_usd=0.123,
                    terminal_reason="api_error",
                )
                raise RuntimeError("synthetic stream failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "task",
                "fixture",
                root / "workspaces/one",
                Limits(2, "0.1", 5),
                live_authorized=True,
                auth_mode="api",
            )
            with patch(
                "agent_runtime.providers.claude.client.ClaudeSDKClient", return_value=FailedStream()
            ):
                run = await Executor(
                    root, ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
                ).execute(request)
            self.assertEqual(run["status"], "FAILED")
            self.assertEqual(
                run["usage"]["application"]["observed_main_loop_tokens"]["input_tokens"], 4
            )
            self.assertEqual(run["usage"]["sdk"]["total_cost_usd"], 0.123)
            self.assertTrue(run["sdk_outcome"]["is_error"])

    async def test_non_analysis_sdk_messages_keep_the_full_native_payload(self):
        class PlainStream:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                pass

            async def receive_response(self):
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="fixture-session",
                    result="PLAIN-NATIVE-RESULT",
                    terminal_reason="completed",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Executor only permits workspaces below root/workspaces.
            request = ExecutionRequest(
                "task",
                "fixture",
                root / "workspaces/one",
                Limits(2, "0.1", 5),
                live_authorized=True,
                auth_mode="api",
            )
            with patch(
                "agent_runtime.providers.claude.client.ClaudeSDKClient", return_value=PlainStream()
            ):
                run = await Executor(
                    root, ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"})
                ).execute(request)
            events = (root / "runs" / run["run_id"] / "events.jsonl").read_text()
            self.assertIn("PLAIN-NATIVE-RESULT", events)
            self.assertEqual(run["status"], "COMPLETED")

    def request(self, root, authorized=False):
        return ExecutionRequest(
            "task",
            "fixture",
            root / "workspace",
            Limits(2, "0.1", 5),
            live_authorized=authorized,
            auth_mode="api",
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
