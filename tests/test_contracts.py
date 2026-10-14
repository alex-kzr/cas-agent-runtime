import copy
import json
import unittest
from pathlib import Path

from agent_runtime.tasks.models import Limits, State, transition, validate_document

FIXTURES = Path(__file__).parent / "fixtures"


class ContractTests(unittest.TestCase):
    def test_run_fixtures(self):
        for file in FIXTURES.glob("run-*.json"):
            with self.subTest(file=file.name):
                validate_document("run", json.loads(file.read_text(encoding="utf-8")))

    def test_unknown_major_and_missing_fields(self):
        run = json.loads((FIXTURES / "run-task.json").read_text())
        for change in ({"schema_version": 2}, {"run_id": "../../secret"}, {"task_id": None}):
            bad = copy.deepcopy(run)
            bad.update(change)
            with self.assertRaises(ValueError):
                validate_document("run", bad)
        del run["limits"]
        with self.assertRaises(ValueError):
            validate_document("run", run)

    def test_unknown_additive_field_allowed(self):
        run = json.loads((FIXTURES / "run-task.json").read_text())
        run["future_v1_field"] = "safe"
        validate_document("run", run)

    def test_unknown_additive_limit_field_allowed(self):
        run = json.loads((FIXTURES / "run-task.json").read_text())
        run["limits"]["future_v1_field"] = "safe"
        validate_document("run", run)

    def test_completed_contradictory_native_result_rejected(self):
        run = json.loads((FIXTURES / "run-task.json").read_text())
        run.update(
            status="COMPLETED",
            sdk_outcome={"subtype": "error_max_turns", "is_error": False, "terminal_reason": None},
        )
        run["validation"]["status"] = "passed"
        with self.assertRaises(ValueError):
            validate_document("run", run)

    def test_self_resume_rejected(self):
        run = json.loads((FIXTURES / "run-task.json").read_text())
        run["resumes_run_id"] = run["run_id"]
        with self.assertRaises(ValueError):
            validate_document("run", run)

    def test_invalid_limits(self):
        for value in ("NaN", "Infinity", "0", "-1", "100.01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Limits(2, value, 10)
        for value in (True, 0, 1001):
            with self.assertRaises(ValueError):
                Limits(value, "0.10", 10)

    def test_lifecycle_terminal_states_cannot_resume(self):
        transition(State.CREATED, State.VALIDATING)
        transition(State.VALIDATING, State.INTERRUPTED)
        for state in (State.COMPLETED, State.FAILED, State.CANCELLED, State.INTERRUPTED):
            with self.assertRaises(ValueError):
                transition(state, State.RUNNING)

    def test_expected_negative_keeps_operational_failure(self):
        run = json.loads((FIXTURES / "run-negative-scenario.json").read_text())
        self.assertEqual(run["status"], "FAILED")
        self.assertTrue(run["sdk_outcome"]["is_error"])
        validate_document("run", run)

    def test_safe_paths_in_manifests(self):
        for value in ("../secret", "C:/secret", "/secret", "a\\secret", "a/../secret"):
            manifest = {
                "schema_version": 1,
                "run_id": "00000000-0000-4000-8000-000000000001",
                "artifacts": [
                    {
                        "artifact_id": "00000000-0000-4000-8000-000000000002",
                        "path": value,
                        "media_type": "text/plain",
                        "size_bytes": 1,
                        "sha256": "a" * 64,
                        "producer": "test",
                        "sensitivity": "normal",
                    }
                ],
            }
            with self.subTest(path=value), self.assertRaises(ValueError):
                validate_document("artifacts", manifest)
