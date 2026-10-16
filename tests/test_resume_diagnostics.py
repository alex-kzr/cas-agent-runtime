"""Exact synthetic diagnostic literals only; no SDK/native invocation."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agent_runtime.providers.claude.resume_diagnostics import PREFIX, SCENARIO, observe_rejection


class RecorderFixture:
    def __init__(self):
        self.record = {"configuration": {}}
        self.events = []

    def event(self, kind, payload, source):
        self.events.append((kind, payload, source))

    def save(self):
        pass


class ResumeDiagnosticTests(unittest.TestCase):
    def test_reserved_options_callback_uses_real_recorder_without_client(self):
        from unittest.mock import patch
        from uuid import uuid4

        from agent_runtime.providers.claude.client import ClaudeAdapter
        from agent_runtime.tasks.models import ExecutionRequest, Limits
        from agent_runtime.telemetry.recorder import Recorder, read_events

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = ExecutionRequest(
                "scenario",
                "synthetic",
                root / "workspaces/one",
                Limits(1, "0.02", 30),
                SCENARIO,
                auth_mode="api",
                live_authorized=True,
                resumes_run_id=str(uuid4()),
                resume_session_id=str(uuid4()),
            )
            recorder = Recorder(root, request)
            with patch("agent_runtime.providers.claude.client.ClaudeSDKClient") as client:
                options = ClaudeAdapter({"ANTHROPIC_API_KEY": "synthetic-not-real"}).options(
                    request, recorder
                )
                options.stderr(PREFIX + request.resume_session_id)
                client.assert_not_called()
            events, warnings = read_events(recorder.directory / "events.jsonl")
            self.assertEqual(warnings, [])
            tags = [e for e in events if e["type"] == "session.resume_rejected"]
            self.assertEqual(len(tags), 1)
            self.assertNotIn(request.resume_session_id, str(tags))

    def test_exact_sid_bound_tag_once_without_raw_line(self):
        request = SimpleNamespace(scenario_id=SCENARIO, resume_session_id="synthetic-id")
        recorder = RecorderFixture()
        for source in ("stderr", "result-errors"):
            observe_rejection(request, recorder, [PREFIX + request.resume_session_id], source)
        self.assertEqual(len(recorder.events), 1)
        self.assertEqual(recorder.events[0][1]["reason"], "unknown-sid")
        self.assertNotIn("synthetic-id", str(recorder.events))
        self.assertNotIn(PREFIX, str(recorder.events))

    def test_other_sid_generic_error_or_unbounded_input_never_matches(self):
        request = SimpleNamespace(scenario_id=SCENARIO, resume_session_id="synthetic-id")
        for values in (
            [PREFIX + "another-id"],
            ["Session not found"],
            ["ProcessError"],
            ["private " + PREFIX + "synthetic-id"],
            ["x" * 5000],
            None,
            PREFIX,
        ):
            with self.subTest(values=values):
                recorder = RecorderFixture()
                observe_rejection(request, recorder, values, "stderr")
                self.assertEqual(recorder.events, [])

    def test_other_scenarios_keep_diagnostic_disabled(self):
        recorder = RecorderFixture()
        request = SimpleNamespace(scenario_id="sdk.fundamentals", resume_session_id="synthetic-id")
        observe_rejection(request, recorder, [PREFIX + "synthetic-id"], "stderr")
        self.assertEqual(recorder.events, [])
