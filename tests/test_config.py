import tempfile
import unittest
from pathlib import Path

from agent_runtime.config import Configuration


class ConfigurationTests(unittest.TestCase):
    def test_arbitrary_root_and_no_implicit_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = Configuration.load(
                root, {"CAS_RUNTIME_MAX_TURNS": "3", "CAS_RUNTIME_MAX_BUDGET_USD": "0.25"}
            )
            self.assertEqual(cfg.data_dir, root / "data")
            self.assertEqual(cfg.workspace_root, root / "data/workspaces")
            self.assertNotIn("ANTHROPIC_API_KEY", str(cfg.public()))

    def test_invalid_live_configuration(self):
        for env in (
            {},
            {"CAS_RUNTIME_MAX_TURNS": "x"},
            {"CAS_RUNTIME_PROVIDER": "unknown"},
            {"CAS_CONSOLE_HOST": "0.0.0.0"},
            {"CAS_CONSOLE_PORT": "0"},
        ):
            with self.subTest(env=env), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    Configuration.load(Path(directory), env).live_limits()

    def test_cli_precedence_and_policy_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Configuration.load(
                Path(directory),
                {"CAS_RUNTIME_MAX_TURNS": "4", "CAS_RUNTIME_MAX_BUDGET_USD": "0.50"},
                {"max_turns": 3},
            )
            self.assertEqual(cfg.live_limits().max_turns, 3)
            with self.assertRaises(ValueError):
                cfg.live_limits(requested_turns=5)
