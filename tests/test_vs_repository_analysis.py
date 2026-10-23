"""Fixed two-file VS scope through AnalysisControl, mock worker/parent and a raw transport.

Only invented text for the two approved PATHS is used (never VS content), no real root is read,
no SDK client, CLI, network or auth store exists, and the gate is patched only inside a test. The
raw-stream harness is the one already used by the mean-review tests; it replaces the subprocess
only, so frames still cross the real StreamAccountant/ReviewTransport, ClaudeAdapter counters,
recorder and privacy layers.
"""

import asyncio
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime.providers.claude import review_transport
from agent_runtime.tasks import analysis_privacy as privacy
from agent_runtime.tasks import repository_analysis_sdk as sdk
from agent_runtime.tasks import review_findings as findings
from agent_runtime.tasks import review_profile
from agent_runtime.tasks import vs_review_profile as vs
from agent_runtime.tasks.repository_analysis import (
    PROFILE,
    SAMPLE,
    AnalysisControl,
    validate_for,
)

try:
    from tests import test_repository_analysis_sdk as base
except ImportError:  # the suite may run with tests/ itself as the top-level directory
    import test_repository_analysis_sdk as base

API, SPEC = vs.NAMES
API_TEXT = "export const fixture = 1;\r\nexport const other = 2;\n"
SPEC_TEXT = "// unrelated synthetic test text\r\nconst value = 1;\nconst second = 2;\n"
SYNTHETIC = {API: API_TEXT, SPEC: SPEC_TEXT}
CANARY = base.CANARY
FINDING = {
    "id": "F1",
    "problem": "The first constant is never validated so later checks may read an unexpected value",
    "impact": "Callers could trust an unchecked value and make wrong decisions downstream",
    "suggested_fix": "Validate the constant before use and add a focused regression check",
    "file": API,
    "line": 1,
    "sha256": hashlib.sha256(API_TEXT.encode()).hexdigest(),
}
GOOD = {"report_version": 2, "repository": vs.REPOSITORY, "findings": [FINDING]}
RAW = json.dumps(GOOD)
EMPTY = json.dumps({"report_version": 2, "repository": vs.REPOSITORY, "findings": []})


def synthetic(**bounds):
    return vs.canonical().test_variant(SYNTHETIC, **bounds)


def with_finding(**changes):
    return json.dumps({**GOOD, "findings": [{**FINDING, **changes}]})


class VsHarness(unittest.TestCase):
    # The raw-transport harness is borrowed method-for-method from the mean-review tests.
    factory = base.MeanReviewEndToEndTests.factory
    patches = base.MeanReviewEndToEndTests.patches
    scan_tree = base.MeanReviewEndToEndTests.scan_tree
    assert_no_canary = base.MeanReviewEndToEndTests.assert_no_canary
    events = base.MeanReviewEndToEndTests.events

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.profile = synthetic()
        self.cases = 0
        self.transports = []
        self.factory_calls = []

    def gate(self):
        return patch.object(vs, "VS_API_REVIEW_LIVE_ENABLED", True)

    def control(self, seam="adapter", profile=None, root=None, **factory):
        profile = profile or self.profile
        self.cases += 1
        control = AnalysisControl(
            root or Path(self.temp.name) / f"case{self.cases}",
            supervised_factory=self.factory(seam, profile, **factory),
            vs_profile=profile,
        )
        self.addCleanup(control.close)
        return control

    def draft(self, control):
        return control.create(vs.REPOSITORY, "review", list(vs.NAMES), vs.SCOPE_MODE)

    def consents(self, job, **changes):
        return {
            "allow_live": True,
            "allow_existing_login": True,
            "snapshot_sha256": job["snapshot_sha256"],
            "scope_sha256": job["scope_sha256"],
            **changes,
        }

    def run_case(self, chunks, *, seam="adapter", profile=None, **options):
        hang = options.pop("hang", False)
        control = self.control(seam, profile, **options)
        job = self.draft(control)
        with self.gate(), self.patches(chunks, hang=hang):
            control.start(job["job_id"], **self.consents(job))
            control.thread.join(30)
            self.assertFalse(control.thread.is_alive())
        return control, control.load(job["job_id"])

    def assert_no_replay(self, control, job):
        with self.gate():
            with self.assertRaises(ValueError):
                control.start(job["job_id"], **self.consents(job))
            other = self.draft(control)
            with self.assertRaises(FileExistsError):
                control.start(other["job_id"], **self.consents(other))
        with self.assertRaises(ValueError):
            control.report(job["job_id"])


class ClosedGateTests(VsHarness):
    def test_canonical_scope_reads_and_stages_nothing_while_the_gate_is_closed(self):
        control = AnalysisControl(Path(self.temp.name) / "canonical")
        self.addCleanup(control.close)
        boom = AssertionError("a closed gate must not read or stage any source")
        with (
            patch.object(vs, "read_manifest_files", side_effect=boom) as reader,
            patch.object(vs, "stage", side_effect=boom) as stage,
            patch.object(Path, "open", side_effect=boom),
        ):
            metadata = control.vs_scope()
            self.assertEqual(control.list(), [])
            with self.assertRaises(PermissionError):
                self.draft(control)
            # Neither of the other scopes' gates opens it.
            with (
                patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True),
                patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
                self.assertRaises(PermissionError),
            ):
                self.draft(control)
        reader.assert_not_called()
        stage.assert_not_called()
        self.assertEqual(control.list(), [])
        self.assertFalse(any(p.is_dir() for p in control.directory.iterdir()))
        self.assertEqual(metadata["source_staging"], "closed")
        self.assertEqual(metadata["scope_sha256"], vs.canonical().fingerprint)
        self.assertIs(metadata["live_enabled"], False)

    def test_canonical_scope_names_exact_files_only(self):
        control = AnalysisControl(Path(self.temp.name) / "canonical")
        self.addCleanup(control.close)
        for args in (
            ("tiny-shop", "review", list(vs.NAMES)),
            (vs.REPOSITORY, "overview", list(vs.NAMES)),
            (vs.REPOSITORY, "review", [SPEC, API]),
            (vs.REPOSITORY, "review", [API]),
            (vs.REPOSITORY, "review", [*vs.NAMES, "src/third.ts"]),
            (vs.REPOSITORY, "review", "src/api.ts"),
            ("other-repository", "review", list(vs.NAMES)),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                control.create(*args, vs.SCOPE_MODE)

    def test_untrusted_callers_cannot_select_test_only_content_or_root(self):
        control = self.control()
        for extra in ({"test_only": True}, {"contents": SYNTHETIC}, {"root": "C:\\other"}):
            with self.subTest(extra=list(extra)), self.assertRaises(TypeError):
                control.create(vs.REPOSITORY, "review", list(vs.NAMES), vs.SCOPE_MODE, **extra)

    def test_old_routes_reject_the_vs_repository_and_names(self):
        control = self.control()
        for args in (
            (vs.REPOSITORY, "review", list(vs.NAMES), "sdk"),
            ("tiny-shop", "review", list(vs.NAMES), "sdk"),
            (vs.REPOSITORY, "overview", None, "offline"),
            (vs.REPOSITORY, "review", ["README.md"], "sdk"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                control.create(*args)
        legacy = control.create("tiny-shop", "overview", None, "offline")
        self.assertEqual((legacy["profile"], legacy["repository"]), (PROFILE, "tiny-shop"))

    def test_mean_and_vs_drafts_coexist_with_separate_identity_and_slots(self):
        control = self.control()
        mean = control.create("tiny-shop", "review", ["mean.py"], review_profile.SCOPE_MODE)
        job = self.draft(control)
        self.assertNotEqual(mean["scope_sha256"], job["scope_sha256"])
        self.assertEqual(job["profile"], vs.PROFILE_ID)
        self.assertEqual(job["repository"], vs.REPOSITORY)
        self.assertEqual(mean["repository"], "tiny-shop")
        self.assertEqual(control.load(mean["job_id"])["profile"], review_profile.PROFILE_ID)
        self.assertEqual({j["job_id"] for j in control.list()}, {mean["job_id"], job["job_id"]})

    def test_closed_gate_and_stale_consent_reject_every_field_before_any_query(self):
        control = self.control()
        job = self.draft(control)
        with patch("subprocess.Popen", side_effect=AssertionError("No native process")):
            with self.assertRaises(PermissionError):
                control.start(job["job_id"], **self.consents(job))
            with (
                patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True),
                patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True),
                self.assertRaises(PermissionError),
            ):
                control.start(job["job_id"], **self.consents(job))
            with self.gate():
                for name, value in (
                    ("allow_live", False),
                    ("allow_live", 1),
                    ("allow_existing_login", None),
                    ("allow_existing_login", 1),
                    ("snapshot_sha256", "0" * 64),
                    ("snapshot_sha256", None),
                    ("scope_sha256", "0" * 64),
                    ("scope_sha256", None),
                    ("scope_sha256", review_profile.canonical().fingerprint),
                    ("scope_sha256", vs.canonical().fingerprint),  # the real scope, not this one
                ):
                    with self.subTest(name=name, value=value), self.assertRaises(PermissionError):
                        control.start(job["job_id"], **self.consents(job, **{name: value}))
                with self.assertRaises(PermissionError):
                    control.start(
                        job["job_id"],
                        allow_live=True,
                        allow_existing_login=True,
                        snapshot_sha256=job["snapshot_sha256"],
                    )
        self.assertEqual((self.factory_calls, self.transports), ([], []))
        self.assertEqual(control.load(job["job_id"])["status"], "DRAFT")
        self.assertFalse((control.directory / vs.SLOT_FILE).exists())
        self.assertFalse((control.root / "runs").exists())

    def test_any_profile_change_invalidates_the_draft_consent(self):
        control = self.control()
        job = self.draft(control)
        root = control.root
        control.close()
        for change in ({"idle_seconds": 44}, {"max_messages": 2047}, {"budget_usd": "0.04"}):
            with self.subTest(change=change):
                changed = self.control(profile=self.profile.variant(**change), root=root)
                self.assertNotEqual(changed.vs_profile.fingerprint, job["scope_sha256"])
                self.assertFalse(changed.preview(job["job_id"])["scope_current"])
                with self.gate():
                    for stored in (job["scope_sha256"], changed.vs_profile.fingerprint):
                        with self.assertRaises(PermissionError):
                            changed.start(job["job_id"], **self.consents(job, scope_sha256=stored))
                self.assertEqual(changed.load(job["job_id"])["status"], "DRAFT")
                changed.close()
        self.assertEqual(self.factory_calls, [])

    def test_test_only_scope_never_reaches_a_real_provider_or_transport(self):
        adapter = sdk.SnapshotSDKAdapter(SYNTHETIC, "review", profile=self.profile)
        recorder = SimpleNamespace(record={"configuration": {}}, private=True)
        request = SimpleNamespace(
            live_authorized=True,
            allow_existing_login=True,
            auth_mode="subscription",
            model=self.profile.model,
            limits=self.profile.limits(),
            agent_name="text-only-v1",
            resume_session_id=None,
            instructions=self.profile.query_text,
            workspace=Path(self.temp.name),
        )
        with (
            self.gate(),
            patch("subprocess.Popen", side_effect=AssertionError("No native process")),
            patch(
                "agent_runtime.providers.claude.supervised.SupervisedClaudeAdapter",
                side_effect=AssertionError("No real provider"),
            ),
            self.assertRaises(PermissionError),
        ):
            asyncio.run(adapter.run(request, recorder))
        with self.assertRaises(PermissionError):
            review_transport.ReviewTransport(self.profile, None)

    def test_tampered_staged_snapshots_never_start_or_preview(self):
        control = self.control()
        job = self.draft(control)
        staged = control.directory / job["job_id"] / "files"
        original = (staged / API).read_bytes()
        extra = staged / "src" / "extra.ts"
        mutations = {
            "changed": lambda: (staged / API).write_bytes(original.replace(b"1", b"7")),
            "newline drift": lambda: (staged / API).write_bytes(original.replace(b"\r\n", b"\n")),
            "appended": lambda: (staged / API).write_bytes(original + b" "),
            "extra file": lambda: extra.write_bytes(b"x"),
            "missing file": lambda: (staged / SPEC).unlink(),
        }
        for name, mutate in mutations.items():
            # Restore the staged snapshot, then damage it in exactly one way.
            (staged / API).write_bytes(original)
            (staged / SPEC).write_bytes(SPEC_TEXT.encode())
            extra.unlink(missing_ok=True)
            mutate()
            with self.subTest(name=name):
                with self.gate(), self.assertRaises(ValueError):
                    control.start(job["job_id"], **self.consents(job))
                with self.assertRaises(ValueError):
                    control.preview(job["job_id"])
        self.assertFalse((control.directory / vs.SLOT_FILE).exists())


class PreviewTests(VsHarness):
    def test_preview_binds_exact_ordered_bytes_query_and_fingerprint(self):
        control = self.control()
        job = self.draft(control)
        staged = control.directory / job["job_id"] / "files"
        self.assertEqual((staged / API).read_bytes(), API_TEXT.encode())  # CRLF/LF preserved
        self.assertEqual((staged / SPEC).read_bytes(), SPEC_TEXT.encode())
        self.assertEqual(job["files"], list(vs.NAMES))
        preview = control.preview(job["job_id"])
        self.assertEqual(preview["query_text"], self.profile.query_text)
        self.assertEqual(preview["query_sha256"], sdk.sha(self.profile.query_text))
        self.assertEqual(preview["scope_sha256"], self.profile.fingerprint)
        self.assertEqual(preview["scope"], self.profile.identity())
        self.assertIs(preview["scope_current"], True)
        self.assertIs(preview["live_enabled"], False)
        self.assertEqual(preview["tools"], [])
        self.assertEqual([s["path"] for s in preview["payload"]["snapshots"]], [API, SPEC])
        self.assertEqual(list(control.sources(job["job_id"])), [API, SPEC])
        with self.gate():
            self.assertIs(control.preview(job["job_id"])["live_enabled"], True)

    def test_scope_metadata_lists_exact_names_bytes_hashes_without_content(self):
        metadata = AnalysisControl.vs_scope(self.control())
        self.assertTrue(metadata["test_only"])
        manifest = metadata["manifest"]
        self.assertEqual([m["path"] for m in manifest], [API, SPEC])
        self.assertEqual(
            [m["bytes"] for m in manifest], [len(API_TEXT.encode()), len(SPEC_TEXT.encode())]
        )
        self.assertNotIn("fixture", json.dumps(metadata))


class VsRunTests(VsHarness):
    def test_valid_one_turn_stream_completes_for_worker_and_parent_seams(self):
        for seam in ("adapter", "worker"):
            with self.subTest(seam=seam):
                lines = [base.assistant(), base.terminal(text=RAW)]
                control, job = self.run_case(lines, seam=seam)
                self.assertEqual(job["status"], "COMPLETED")
                self.assertEqual(job["report"], GOOD)
                record = control.canonical(job)
                self.assertEqual(
                    record["usage"]["application"]["review_budget"],
                    {
                        "frames": 2,
                        "blank_frames": 0,
                        "wire_bytes": sum(len(item.encode()) for item in lines),
                        "max_frame_bytes": max(len(item.encode()) - 1 for item in lines),
                        "stderr_bytes": 0,
                        "messages": 2,
                        "results": 1,
                        "observed_turns": 1,
                        "failed": False,
                    },
                )
                self.assertEqual(
                    record["usage"]["application"]["review_audit"],
                    {"messages": 2, "results": 1, "observed_turns": 1},
                )
                self.assertEqual(record["usage"]["application"]["model_requests"], 1)
                self.assertEqual(record["configuration"]["scope_sha256"], self.profile.fingerprint)
                self.assertEqual(record["configuration"]["analysis_profile"], vs.PROFILE_ID)
                kinds = [event["type"] for event in self.events(control, job)]
                self.assertEqual(kinds.count("sdk.query_started"), 1)
                self.assertEqual(kinds.count("sdk.message"), 2)
                self.assertTrue((control.directory / vs.SLOT_FILE).exists())
                self.assertFalse((control.directory / review_profile.SLOT_FILE).exists())
                self.assert_no_canary(control)
                self.assertEqual(self.transports[-1].closed, 1)

    def test_empty_report_completes_but_is_not_content_proof(self):
        control, job = self.run_case([base.assistant(), base.terminal(text=EMPTY)])
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(job["report"]["findings"], [])
        text = control.report(job["job_id"])["markdown"]
        self.assertIn("No findings reported. This is not proof", text)

    def test_ungrounded_or_cross_injected_reports_fail_without_persisting_content(self):
        bad_reports = (
            json.dumps({**GOOD, "repository": "tiny-shop"}),
            json.dumps({**GOOD, "repository": "other-repository"}),
            with_finding(sha256="0" * 64),
            with_finding(file="src/other.ts"),
            with_finding(file="README.md"),
            with_finding(line=99),
            with_finding(line=0),
            with_finding(problem=CANARY),
            with_finding(unknown_field=1),
            json.dumps({**GOOD, "extra": 1}),
            CANARY,
            "x" * 16385,
        )
        for seam in ("adapter", "worker"):
            for text in bad_reports:
                with self.subTest(seam=seam, text=text[:30]):
                    control, job = self.run_case(
                        [base.assistant(), base.terminal(text=text)], seam=seam
                    )
                    self.assertEqual(job["status"], "FAILED")
                    self.assertIsNone(job["report"])
                    self.assert_no_canary(control)
                    self.assert_no_replay(control, job)

    def test_turn_model_and_stream_counters_fail_with_numeric_reasons(self):
        cases = (
            ([base.assistant(), base.terminal(2, text=RAW)], review_profile.TURNS),
            ([base.assistant(), base.terminal(base.MISSING, text=RAW)], review_profile.TURNS),
            (
                [base.assistant(model="claude-sonnet-5-5"), base.terminal(text=RAW)],
                review_profile.MODEL,
            ),
            ([base.assistant()], review_profile.NO_RESULT),
            ([base.assistant(), "not json\n", base.terminal(text=RAW)], review_profile.MALFORMED),
        )
        for seam in ("adapter", "worker"):
            for chunks, code in cases:
                with self.subTest(seam=seam, code=code):
                    control, job = self.run_case(chunks, seam=seam)
                    self.assertEqual(job["status"], "FAILED")
                    record = control.canonical(job)
                    self.assertEqual(
                        record["error"]["message"], review_profile.reason_message(code)
                    )
                    self.assert_no_canary(control)
                    self.assert_no_replay(control, job)

    def test_wire_and_frame_caps_fail_before_the_offending_frame_is_written(self):
        big = base.line(type="assistant", model=base.MODEL_ID, text=CANARY * 40)
        size = len(big.encode())
        cases = (
            (
                synthetic(max_frame_bytes=size - 2),
                [base.assistant(), big],
                review_profile.FRAME_BYTES,
            ),
            (
                synthetic(max_frame_bytes=size, max_wire_bytes=size * 2),
                [big, big, big],
                review_profile.WIRE_BYTES,
            ),
        )
        for profile, chunks, code in cases:
            with self.subTest(code=code):
                control, job = self.run_case(chunks, profile=profile)
                self.assertEqual(job["status"], "FAILED")
                self.assertEqual(
                    control.canonical(job)["error"]["message"], review_profile.reason_message(code)
                )
                self.assert_no_canary(control)

    def test_silent_stream_ends_at_the_idle_bound(self):
        profile = synthetic(idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3)
        control, job = self.run_case([base.assistant()], profile=profile, hang=True)
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(
            control.canonical(job)["error"]["message"],
            review_profile.reason_message(review_profile.IDLE),
        )

    def test_cancel_and_unconfirmed_cleanup_report_truthful_states_without_replay(self):
        import threading

        for tree_empty in (True, False):
            with self.subTest(tree_empty=tree_empty):
                entered = threading.Event()
                self.cases += 1
                control = AnalysisControl(
                    Path(self.temp.name) / f"cancel{self.cases}",
                    supervised_factory=base.MeanReviewEndToEndTests.hanging(entered, tree_empty),
                    vs_profile=self.profile,
                )
                self.addCleanup(control.close)
                job = self.draft(control)
                with self.gate():
                    control.start(job["job_id"], **self.consents(job))
                    self.assertTrue(entered.wait(5))
                    control.stop(job["job_id"])
                    control.thread.join(10)
                job = control.load(job["job_id"])
                expected = "CANCELLED" if tree_empty else "INTERRUPTED"
                self.assertEqual((job["status"], control.canonical(job)["status"]), (expected,) * 2)
                self.assertIsNone(job["report"])
                self.assert_no_replay(control, job)

    def test_provider_error_unknown_outcome_and_extra_queries_fail_without_content(self):
        for options in ({"error": True}, {"queries": 2}, {"queries": 0}):
            with self.subTest(options=options):
                self.cases += 1
                control = AnalysisControl(
                    Path(self.temp.name) / f"mock{self.cases}",
                    supervised_factory=base.transport(**options),
                    vs_profile=self.profile,
                )
                self.addCleanup(control.close)
                job = self.draft(control)
                with self.gate():
                    control.start(job["job_id"], **self.consents(job))
                    control.thread.join(10)
                job = control.load(job["job_id"])
                self.assertEqual(job["status"], "FAILED")
                self.assertNotIn("RAW_PROVIDER_SECRET_CANARY", json.dumps(control.canonical(job)))
                self.assert_no_replay(control, job)

    def test_unconfirmed_cleanup_after_a_valid_stream_never_accepts_the_report(self):
        control, job = self.run_case([base.assistant(), base.terminal(text=RAW)], tree_empty=False)
        self.assertEqual(job["status"], "INTERRUPTED")
        self.assertIsNone(job["report"])
        self.assert_no_replay(control, job)

    def test_reopen_and_export_preserve_provenance_without_reading_or_querying_again(self):
        control, job = self.run_case([base.assistant(), base.terminal(text=RAW)])
        report = control.report(job["job_id"])
        self.assertEqual(report["scope_sha256"], self.profile.fingerprint)
        self.assertEqual(report["profile"], vs.PROFILE_ID)
        self.assertEqual((report["mode"], report["model_requests"]), ("mock-sdk", 1))
        self.assertIn("# Vacancy Search frontend API review", report["markdown"])
        self.assertIn("(files/src/api.ts#L1)", report["markdown"])
        with zipfile.ZipFile(io.BytesIO(control.bundle(job["job_id"]))) as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["files/src/api.test.ts", "files/src/api.ts", "report.json", "report.md"],
            )
            self.assertEqual(archive.read("files/src/api.ts"), API_TEXT.encode())
            self.assertEqual(archive.read("files/src/api.test.ts"), SPEC_TEXT.encode())
            self.assertEqual(
                json.loads(archive.read("report.json"))["scope_sha256"], report["scope_sha256"]
            )
        root = control.root
        control.close()
        boom = AssertionError("reopen must not read the source root or start a query")
        with (
            patch.object(vs, "read_manifest_files", side_effect=boom),
            patch.object(vs, "materialize", side_effect=boom),
            patch("subprocess.Popen", side_effect=boom),
        ):
            reopened = self.control(root=root)
            self.assertEqual(reopened.report(job["job_id"]), report)
            self.assertEqual(reopened.load(job["job_id"])["status"], "COMPLETED")
        self.assertEqual(len(self.transports), 1)
        self.assertEqual(len(self.factory_calls), 1)
        self.assert_no_replay_after_success(reopened, job)

    def assert_no_replay_after_success(self, control, job):
        with self.gate():
            with self.assertRaises(ValueError):
                control.start(job["job_id"], **self.consents(job))
            other = self.draft(control)
            with self.assertRaises(FileExistsError):
                control.start(other["job_id"], **self.consents(other))


class RepositoryBindingTests(unittest.TestCase):
    """Strict repository cross-injection for the report v2 validator and the worker boundary."""

    def test_the_vs_token_validates_only_with_exactly_the_two_vs_files(self):
        self.assertEqual(len(findings.validate_findings(GOOD, SYNTHETIC, vs.REPOSITORY)), 1)
        for value, sources, repository in (
            (GOOD, SYNTHETIC, None),  # old route: tiny-shop contract
            (GOOD, SYNTHETIC, "tiny-shop"),
            (GOOD, SYNTHETIC, "other-repository"),
            (GOOD, {API: API_TEXT}, vs.REPOSITORY),
            (GOOD, {**SYNTHETIC, "mean.py": "x = 1\n"}, vs.REPOSITORY),
            (GOOD, SAMPLE, vs.REPOSITORY),
            ({**GOOD, "repository": "tiny-shop"}, SYNTHETIC, vs.REPOSITORY),
            ({**GOOD, "repository": "tiny-shop"}, SYNTHETIC, None),
        ):
            with self.subTest(repository=repository, files=list(sources)):
                with self.assertRaises(ValueError):
                    findings.validate_findings(value, sources, repository)

    def test_legacy_tiny_shop_contract_is_unchanged(self):
        clean = {"report_version": 2, "repository": "tiny-shop", "findings": []}
        for repository in (None, "tiny-shop"):
            self.assertEqual(findings.validate_findings(clean, SAMPLE, repository), [])
        with self.assertRaises(ValueError):
            findings.validate_findings({**clean, "repository": vs.REPOSITORY}, SAMPLE)
        with self.assertRaises(ValueError):
            validate_for("review", {**clean, "repository": "other"}, SAMPLE)
        # Version 1 questions never take a VS repository.
        with self.assertRaises(ValueError):
            validate_for(
                "overview", {"repository": "tiny-shop", "claims": []}, SAMPLE, vs.REPOSITORY
            )

    def test_worker_boundary_accepts_only_the_profile_bound_repository(self):
        profile = synthetic()
        accepted = privacy.accepted_text(profile.query_text, RAW, profile)
        self.assertEqual(json.loads(accepted), GOOD)
        self.assertLessEqual(len(accepted.encode()), profile.max_canonical_bytes)
        for raw in (
            json.dumps({**GOOD, "repository": "tiny-shop"}),
            with_finding(sha256="0" * 64),
            RAW.replace('"F1"', '"F1", "id": "F2"', 1),  # duplicate key
            "x" * (profile.max_raw_final_bytes + 1),
            CANARY,
        ):
            with self.subTest(raw=raw[:30]):
                self.assertIsNone(privacy.accepted_text(profile.query_text, raw, profile))
        # A different request than the profile's, or no profile at all, never validates.
        other = vs.canonical().test_variant({API: "export const a = 1;\n", SPEC: "// t\n"})
        self.assertIsNone(privacy.accepted_text(other.query_text, RAW, profile))
        self.assertIsNone(privacy.accepted_text(profile.query_text, RAW))
        self.assertIsNone(
            privacy.accepted_text(profile.query_text, RAW, review_profile.canonical())
        )

    def test_worker_result_withholds_unaccepted_text(self):
        profile = synthetic()
        from agent_runtime.tasks.executor import NativeResult

        outcome = {"subtype": "success", "is_error": False, "terminal_reason": "completed"}
        for text, expected in ((RAW, True), (CANARY, False)):
            result = privacy.worker_result(
                NativeResult(text, outcome, "synthetic", None), profile.query_text, profile
            )
            self.assertEqual(result["text"] is not None, expected)
            self.assertNotIn(CANARY, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
