import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agent_runtime.cli import main
from agent_runtime.scenarios.registry import SCENARIOS, LocalValidation
from agent_runtime.tasks.executor import Executor
from agent_runtime.tasks.models import ExecutionRequest, Limits


class LocalResearchTests(unittest.IsolatedAsyncioTestCase):
    async def execute_case(self, case):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "scenario",
                SCENARIOS[case]["title"],
                root / "workspaces/fixture",
                Limits(1, "0.01", 10),
                case,
            )
            run = await Executor(root, LocalValidation()).execute(request)
            assertion_path = root / "runs" / run["run_id"] / "assertions.json"
            assertions = json.loads(assertion_path.read_text()) if assertion_path.exists() else None
            return run, assertions

    async def test_structured_output_checks_schema_not_only_json_parse(self):
        run, assertions = await self.execute_case("platform.structured-output")
        self.assertEqual(run["status"], "COMPLETED")
        self.assertIsNone(run["sdk_outcome"])
        self.assertEqual(len(assertions["checks"]), 4)
        self.assertEqual(assertions["outcome"], "pass")

    async def test_usage_case_checks_duplicates_missing_and_child_scope(self):
        run, assertions = await self.execute_case("platform.usage")
        self.assertEqual(run["status"], "COMPLETED")
        self.assertIsNone(run["usage"]["sdk"])
        self.assertEqual(assertions["outcome"], "pass")

    async def test_permission_case_checks_real_files_and_denials(self):
        run, assertions = await self.execute_case("platform.permissions")
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(assertions["outcome"], "pass")
        self.assertEqual(len(assertions["checks"]), 7)

    async def test_permission_regression_is_recorded_as_failure(self):
        with patch("agent_runtime.scenarios.local_research.read_allowed", return_value=True):
            run, assertions = await self.execute_case("platform.permissions")
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(assertions["outcome"], "fail")

    async def test_structured_validator_bypass_cannot_pass_case(self):
        with patch("agent_runtime.scenarios.local_research.Draft202012Validator.validate"):
            run, assertions = await self.execute_case("platform.structured-output")
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(assertions["outcome"], "fail")

    async def test_partial_fixture_creation_failure_is_cleaned(self):
        original = Path.write_text

        def failing_write(path, *args, **kwargs):
            if path.name == ".synthetic-hidden":
                raise OSError("synthetic fixture write failure")
            return original(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = ExecutionRequest(
                "scenario",
                "synthetic fixture cleanup",
                root / "workspaces/one",
                Limits(1, "0.01", 10),
                "platform.permissions",
            )
            with patch.object(Path, "write_text", failing_write):
                run = await Executor(root, LocalValidation()).execute(request)
            self.assertEqual(run["status"], "FAILED")
            self.assertFalse(list(request.workspace.glob("local-policy-fixtures-*")))

    async def test_usage_regression_cannot_pass_case(self):
        from agent_runtime.telemetry.metrics import ObservedUsage

        original = ObservedUsage.snapshot

        def wrong_count(usage):
            return {**original(usage), "observed_message_count": 3}

        with patch.object(ObservedUsage, "snapshot", wrong_count):
            run, assertions = await self.execute_case("platform.usage")
        self.assertEqual(run["status"], "FAILED")
        self.assertEqual(assertions["outcome"], "fail")


class LocalResearchCliTests(unittest.TestCase):
    def test_all_local_cases_never_construct_sdk_and_keep_native_unknown(self):
        import contextlib
        import io

        for case in ("platform.structured-output", "platform.usage", "platform.permissions"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
                patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(main(["--root", directory, "scenarios", "run", case]), 0)
                run = json.loads(output.getvalue())
                self.assertEqual(run["provider"]["name"], "local-validation")
                self.assertIsNone(run["sdk_outcome"])
                client.assert_not_called()
                fixtures = Path(run["workspace"]) / "local-policy-fixtures"
                self.assertFalse(fixtures.exists())
                self.assertFalse(list(Path(run["workspace"]).glob("local-policy-fixtures-*")))

    def test_explicit_live_model_reaches_shared_executor_without_network(self):
        import contextlib
        import io

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": "synthetic-only"}, clear=True),
            patch(
                "agent_runtime.tasks.executor.Executor.execute", new_callable=AsyncMock
            ) as execute,
            patch("agent_runtime.scenarios.registry.write_catalog"),
            patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            execute.return_value = {"status": "COMPLETED"}
            code = main(
                [
                    "--root",
                    directory,
                    "scenarios",
                    "run",
                    "sdk.fundamentals",
                    "--allow-live",
                    "--model",
                    "synthetic-model-id",
                    "--max-turns",
                    "1",
                    "--max-budget-usd",
                    "0.10",
                    "--timeout-seconds",
                    "60",
                ]
            )
            self.assertEqual(code, 0)
            self.assertEqual(execute.call_args.args[0].model, "synthetic-model-id")
            self.assertEqual(execute.call_args.args[0].limits.timeout_seconds, 60)
            client.assert_not_called()

    def test_live_baseline_requires_explicit_model_before_client_construction(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": "synthetic-only"}, clear=True),
            patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client,
        ):
            import contextlib
            import io

            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(
                    [
                        "--root",
                        directory,
                        "scenarios",
                        "run",
                        "sdk.fundamentals",
                        "--allow-live",
                        "--max-turns",
                        "1",
                        "--max-budget-usd",
                        "0.10",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("--model", output.getvalue())
            client.assert_not_called()
            self.assertFalse((Path(directory) / "data").exists())
