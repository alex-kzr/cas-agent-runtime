import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.auth import auth_environment, require_auth, subscription_status
from agent_runtime.tasks.models import ExecutionRequest, Limits


class AuthTests(unittest.TestCase):
    def request(self, **overrides):
        values = dict(
            kind="task",
            instructions="synthetic",
            workspace=Path("synthetic-workspace"),
            limits=Limits(1, "0.10", 60),
            live_authorized=True,
        )
        return ExecutionRequest(**(values | overrides))

    def test_subscription_default_requires_separate_login_reuse_permission(self):
        request = self.request()
        self.assertEqual(request.auth_mode, "subscription")
        with self.assertRaises(PermissionError):
            require_auth(request, {})

    def test_subscription_environment_never_passes_api_or_token_or_cloud_flags(self):
        request = self.request(allow_existing_login=True)
        environment = {
            "USERPROFILE": "C:/synthetic-user",
            "ANTHROPIC_API_KEY": "synthetic-key",
            "ANTHROPIC_AUTH_TOKEN": "synthetic-bearer",
            "CLAUDE_CODE_OAUTH_TOKEN": "synthetic-token",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "ANTHROPIC_BASE_URL": "https://invalid.example",
            "CLAUDE_CONFIG_DIR": "C:/synthetic-existing-native",
        }
        require_auth(request, environment)
        selected = auth_environment(request, environment, Path("synthetic-run/sdk-state"))
        self.assertEqual(
            Path(selected["CLAUDE_CONFIG_DIR"]), Path("C:/synthetic-existing-native").resolve()
        )
        for name in environment.keys() - {"USERPROFILE", "CLAUDE_CONFIG_DIR"}:
            self.assertNotIn(name, selected)
        self.assertEqual(selected["CLAUDE_CODE_MAX_RETRIES"], "0")

    def test_effective_default_and_direct_store_inside_data_are_rejected(self):
        from agent_runtime.config import Configuration

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                Configuration.load(root, {"USERPROFILE": str(root)})
            for request, environment in (
                (self.request(allow_existing_login=True), {"USERPROFILE": str(root / "data")}),
                (
                    self.request(
                        allow_existing_login=True, login_config_dir=str(root / "data/native")
                    ),
                    {},
                ),
            ):
                with self.assertRaises(ValueError):
                    auth_environment(
                        request,
                        environment,
                        root / "data/run/sdk-state",
                        forbidden_roots=(root / "data",),
                    )

    def test_api_mode_explicit_key_and_fresh_state(self):
        request = self.request(auth_mode="api")
        with self.assertRaises(ValueError):
            require_auth(request, {})
        selected = auth_environment(
            request,
            {"ANTHROPIC_API_KEY": "synthetic-key", "CLAUDE_CONFIG_DIR": "external-native"},
            Path("run/sdk-state"),
        )
        self.assertEqual(selected["ANTHROPIC_API_KEY"], "synthetic-key")
        self.assertEqual(selected["CLAUDE_CONFIG_DIR"], str(Path("run/sdk-state")))

    def test_native_status_accepts_only_subscription_and_drops_identity(self):
        from subprocess import CompletedProcess

        request = self.request(allow_existing_login=True)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "agent_runtime.providers.claude.auth.subprocess.run",
                return_value=CompletedProcess(
                    [],
                    0,
                    json.dumps(
                        {
                            "loggedIn": True,
                            "authMethod": "claude.ai",
                            "apiProvider": "firstParty",
                            "subscriptionType": "max",
                            "email": "synthetic-private",
                            "configDirectory": directory,
                        }
                    ),
                ),
            ),
        ):
            result = subscription_status(request, {"CLAUDE_CONFIG_DIR": directory})
            self.assertEqual(result["session_status"], "verified-native-status")
            self.assertNotIn("synthetic-private", str(result))

    def test_missing_api_profile_or_unknown_status_never_falls_back(self):
        from subprocess import CompletedProcess

        request = self.request(allow_existing_login=True)
        values = [
            '{"loggedIn":false,"authMethod":"none"}',
            '{"loggedIn":true,"authMethod":"api_key","subscriptionType":"max"}',
            '{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"unknown","apiProvider":"firstParty"}',
            "invalid-json-synthetic-token",
        ]
        with tempfile.TemporaryDirectory() as directory:
            for value in values:
                with (
                    self.subTest(value=value),
                    patch(
                        "agent_runtime.providers.claude.auth.subprocess.run",
                        return_value=CompletedProcess([], 0, value),
                    ),
                ):
                    with self.assertRaises(ValueError) as error:
                        subscription_status(request, {"CLAUDE_CONFIG_DIR": directory})
                    self.assertNotIn("synthetic-token", str(error.exception))


class SubscriptionAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_session_fails_before_sdk_construction_without_api_fallback(self):
        from subprocess import CompletedProcess

        from agent_runtime.providers.claude.client import ClaudeAdapter
        from agent_runtime.tasks.executor import Executor

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "native"
            native.mkdir()
            environment = {"CLAUDE_CONFIG_DIR": str(native)}
            request = ExecutionRequest(
                "task",
                "synthetic",
                root / "data/workspaces/one",
                Limits(1, "0.10", 5),
                live_authorized=True,
                allow_existing_login=True,
            )
            with (
                patch.dict("os.environ", environment, clear=True),
                patch(
                    "agent_runtime.providers.claude.auth.subprocess.run",
                    return_value=CompletedProcess([], 1, '{"loggedIn":false,"authMethod":"none"}'),
                ),
                patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as sdk,
            ):
                run = await Executor(root / "data", ClaudeAdapter(environment)).execute(request)
            self.assertEqual(run["status"], "FAILED")
            self.assertEqual(run["configuration"]["auth_mode"], "subscription")
            sdk.assert_not_called()

    async def test_valid_personal_session_uses_sdk_without_key_and_records_auth_mode(self):
        from subprocess import CompletedProcess

        from claude_agent_sdk import ResultMessage

        from agent_runtime.providers.claude.client import ClaudeAdapter
        from agent_runtime.tasks.executor import Executor

        class FixtureSdk:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def query(self, prompt):
                self.prompt = prompt

            async def receive_response(self):
                yield ResultMessage(
                    subtype="success",
                    duration_ms=1,
                    duration_api_ms=1,
                    is_error=False,
                    num_turns=1,
                    session_id="synthetic",
                    result="synthetic answer",
                    terminal_reason="completed",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "native"
            native.mkdir()
            environment = {"CLAUDE_CONFIG_DIR": str(native)}
            request = ExecutionRequest(
                "task",
                "synthetic",
                root / "data/workspaces/one",
                Limits(1, "0.10", 5),
                live_authorized=True,
                allow_existing_login=True,
            )
            status = json.dumps(
                {
                    "loggedIn": True,
                    "authMethod": "claude.ai",
                    "subscriptionType": "max",
                    "apiProvider": "firstParty",
                    "configDirectory": str(native),
                }
            )
            with (
                patch.dict("os.environ", environment, clear=True),
                patch(
                    "agent_runtime.providers.claude.auth.subprocess.run",
                    return_value=CompletedProcess([], 0, status),
                ),
                patch(
                    "agent_runtime.providers.claude.client.ClaudeSDKClient",
                    return_value=FixtureSdk(),
                ) as sdk,
            ):
                run = await Executor(root / "data", ClaudeAdapter(environment)).execute(request)
            self.assertEqual(run["status"], "COMPLETED")
            self.assertEqual(run["configuration"]["session_status"], "verified-native-status")
            options = sdk.call_args.kwargs["options"]
            self.assertNotIn("ANTHROPIC_API_KEY", options.env)
            self.assertEqual(options.env["CLAUDE_CONFIG_DIR"], str(native))
            self.assertEqual(json.loads(options.settings)["forceLoginMethod"], "claudeai")

    async def test_subscription_cli_requires_reuse_consent_even_with_ambient_api_key(self):
        import io
        from contextlib import redirect_stdout

        from agent_runtime.cli import main

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": "synthetic"}, clear=True),
            patch("agent_runtime.providers.claude.supervised.OwnedProcess") as process,
            redirect_stdout(io.StringIO()) as output,
        ):
            result = main(
                [
                    "--root",
                    directory,
                    "scenarios",
                    "run",
                    "sdk.fundamentals",
                    "--allow-live",
                    "--model",
                    "synthetic",
                ]
            )
            self.assertEqual(result, 2)
            self.assertIn("allow-existing-login", output.getvalue())
            process.assert_not_called()

    async def test_offline_doctor_reports_subscription_and_never_checks_native_status(self):
        import io
        from contextlib import redirect_stdout

        from agent_runtime.cli import main

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict("os.environ", {}, clear=True),
            patch("agent_runtime.providers.claude.auth.subprocess.run") as status,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(["--root", directory, "doctor"]), 0)
            self.assertEqual(
                json.loads(output.getvalue())["authentication"]["selected"], "subscription"
            )
            status.assert_not_called()
