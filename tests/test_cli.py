import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def call(self, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--root", str(self.root), *args])
        return code, json.loads(stdout.getvalue())

    def test_doctor_is_offline_and_does_not_create_data(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "synthetic-private-key"}, clear=True):
            code, output = self.call("doctor")
        self.assertEqual(code, 0)
        self.assertNotIn("synthetic-private-key", str(output))
        self.assertFalse((self.root / "data").exists())

    def test_live_is_never_implicit(self):
        code, output = self.call("task", "run", "--file", "nonexistent.md")
        self.assertEqual(code, 2)
        self.assertIn("allow-live", output["message"])
        self.assertFalse((self.root / "data").exists())

    def test_actual_offline_scenario_and_inspection(self):
        code, run = self.call("scenarios", "run", "platform.contracts")
        self.assertEqual(code, 0)
        self.assertEqual(run["provider"]["name"], "local-validation")
        self.assertIsNone(run["sdk_outcome"])
        self.assertIsNone(run["usage"]["sdk"])
        code, detail = self.call("runs", "inspect", run["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(detail["run"]["status"], "COMPLETED")
        code, report = self.call("report", run["run_id"])
        self.assertTrue(Path(report["report"]).is_file())

    def test_unknown_scenario_and_bad_run_id_reject(self):
        for args in (("scenarios", "run", "unimplemented"), ("runs", "inspect", "../secret")):
            code, _ = self.call(*args)
            self.assertEqual(code, 2)

    def test_bad_configuration_never_echoes_raw_value(self):
        with patch.dict("os.environ", {"CAS_CONSOLE_PORT": "synthetic-private-marker"}, clear=True):
            code, result = self.call("doctor")
        self.assertEqual(code, 2)
        self.assertNotIn("synthetic-private-marker", json.dumps(result))

    def test_external_data_dir_resolves_default_workspace(self):
        with tempfile.TemporaryDirectory() as external:
            code, run = self.call("--data-dir", external, "scenarios", "run", "platform.redaction")
            self.assertEqual(code, 0)
            self.assertTrue(Path(run["workspace"]).is_relative_to(Path(external)))
