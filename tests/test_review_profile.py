"""Synthetic only: the typed mean-review profile, its gate, fingerprint and cross-profile limits."""

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from agent_runtime.tasks import analysis_privacy, review_profile
from agent_runtime.tasks import repository_analysis_sdk as sdk
from agent_runtime.tasks.repository_analysis import SAMPLE

PROFILE = review_profile.canonical()
INT_BOUNDS = [name for name in review_profile.BOUND_FIELDS if name != "budget_usd"]


def good_report():
    return {
        "report_version": 2,
        "repository": "tiny-shop",
        "findings": [
            {
                "id": "F1",
                "problem": "The divisor is one less than the number of values so the result is too large",
                "impact": "Callers receive wrong averages for every input and may decide wrongly",
                "suggested_fix": "Divide the total by the actual count of values instead of subtracting one",
                "file": "mean.py",
                "line": 3,
                "sha256": review_profile.SOURCE_SHA256,
            }
        ],
    }


class FixtureTests(unittest.TestCase):
    def test_exact_frozen_bytes_and_hashes(self):
        content = PROFILE.source_content.encode("utf-8")
        self.assertEqual(len(content), 122)
        self.assertEqual(hashlib.sha256(content).hexdigest(), review_profile.SOURCE_SHA256)
        self.assertNotIn(b"\r", content)
        self.assertTrue(content.endswith(b"\n"))
        query = PROFILE.query_text.encode("utf-8")
        self.assertEqual(len(query), 1272)
        self.assertEqual(hashlib.sha256(query).hexdigest(), review_profile.QUERY_SHA256)
        self.assertFalse(query.endswith(b"\n"))
        self.assertTrue(review_profile.is_scope_query(PROFILE.query_text))
        self.assertFalse(review_profile.is_scope_query(PROFILE.query_text + "\n"))

    def test_instruction_matches_the_legacy_review_instruction_today(self):
        # The frozen copy must not drift silently from what the proposal documented.
        self.assertEqual(review_profile.INSTRUCTION, sdk.FINDINGS_INSTRUCTION)
        self.assertEqual(json.loads(PROFILE.query_text), PROFILE.payload())

    def test_the_fixture_defect_is_independently_observable(self):
        namespace = {}
        exec(  # noqa: S102 - fixed synthetic fixture with only sum/len available
            PROFILE.source_content, {"__builtins__": {"sum": sum, "len": len}}, namespace
        )
        self.assertEqual(namespace["mean"]([2, 4]), 6)  # correct mean is 3
        self.assertEqual(namespace["mean"]([1, 3, 5]), 4.5)  # correct mean is 3

    def test_fixture_or_prompt_changes_cannot_build_a_profile(self):
        for change in (
            {"source_content": PROFILE.source_content.replace("- 1", "- 0")},
            {"source_content": PROFILE.source_content + "\n"},
            {"source_name": "other.py"},
            {"instruction": PROFILE.instruction + " "},
            {"question_key": "overview"},
            {"profile_id": "repository-analysis-review-other"},
            {"repository": "other"},
        ):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                replace(PROFILE, **change)


class GateTests(unittest.TestCase):
    def test_both_gates_are_closed_and_independent(self):
        self.assertIs(review_profile.MEAN_REVIEW_LIVE_ENABLED, False)
        self.assertIs(sdk.LIVE_ANALYSIS_ENABLED, False)
        with self.assertRaises(PermissionError):
            review_profile.require_scope_release()
        with patch.object(sdk, "LIVE_ANALYSIS_ENABLED", True):
            with self.assertRaises(PermissionError):
                review_profile.require_scope_release()
            sdk.require_release()  # the legacy gate opens only the legacy scope
        with patch.object(review_profile, "MEAN_REVIEW_LIVE_ENABLED", True):
            review_profile.require_scope_release()
            with self.assertRaises(PermissionError):
                sdk.require_release()


class BoundTests(unittest.TestCase):
    def test_proposal_bounds_are_the_profile_defaults(self):
        self.assertEqual(
            PROFILE.bounds(),
            {
                "logical_queries": 1,
                "max_turns": 1,
                "observed_turns": 1,
                "budget_usd": "0.05",
                "execution_seconds": 90,
                "idle_seconds": 45,
                "stream_deadline_seconds": 85,
                "cleanup_seconds": 3,
                "finalize_seconds": 5,
                "watchdog_seconds": 100,
                "max_messages": 2048,
                "max_frames": 2048,
                "worker_events": 8192,
                "parent_events": 8224,
                "max_frame_bytes": 1048576,
                "max_wire_bytes": 16777216,
                "worker_journal_bytes": 3000000,
                "parent_import_bytes": 4000000,
                "max_raw_final_bytes": 16384,
                "max_canonical_bytes": 5120,
                "max_input_bytes": 1000000,
                "max_response_bytes": 1000000,
                "max_stderr_bytes": 262144,
            },
        )
        self.assertEqual(PROFILE.model, "claude-haiku-5-5")
        self.assertFalse(PROFILE.test_only)
        limits = PROFILE.limits()
        self.assertEqual(
            (limits.max_turns, limits.max_budget_usd, limits.timeout_seconds), (1, "0.05", 90)
        )

    def test_boolean_string_negative_zero_and_float_limits_reject(self):
        for name in INT_BOUNDS:
            for bad in (True, False, "5", -1, 0, 1.5, None):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    replace(PROFILE, test_only=True, **{name: bad})
        for bad in (0.05, 5, True, "0", "-1", "nan", "inf", "abc", "101"):
            with self.subTest(budget=bad), self.assertRaises(ValueError):
                replace(PROFILE, test_only=True, budget_usd=bad)
        with self.assertRaises(ValueError):
            replace(PROFILE, test_only="yes")

    def test_one_query_and_one_turn_cannot_be_varied(self):
        for name in ("logical_queries", "max_turns", "observed_turns"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                PROFILE.variant(**{name: 2})

    def test_inner_and_outer_bounds_must_be_coherent(self):
        for change in (
            {"idle_seconds": 85},  # idle not below the stream deadline
            {"stream_deadline_seconds": 90},  # stream deadline not below execution
            {"watchdog_seconds": 97},  # execution + cleanup + finalize exceeds the watchdog
            {"parent_events": 8223},  # no explicit envelope/control/cleanup overhead
            {"parent_import_bytes": 2_999_999},
            {"max_frames": 2047},
            {"max_wire_bytes": 1000},
            {"max_raw_final_bytes": 5119},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                PROFILE.variant(**change)

    def test_event_budget_covers_the_message_budget_with_explicit_overhead(self):
        self.assertGreaterEqual(PROFILE.worker_events, 2 * PROFILE.max_messages + 64)
        self.assertGreaterEqual(
            PROFILE.parent_events - PROFILE.worker_events, review_profile.MIN_PARENT_OVERHEAD_EVENTS
        )
        self.assertLess(PROFILE.idle_seconds, PROFILE.stream_deadline_seconds)
        self.assertLess(PROFILE.stream_deadline_seconds, PROFILE.execution_seconds)
        self.assertLessEqual(
            PROFILE.execution_seconds + PROFILE.cleanup_seconds + PROFILE.finalize_seconds,
            PROFILE.watchdog_seconds,
        )

    def test_only_listed_bounds_can_be_varied_and_variants_are_test_only(self):
        variant = PROFILE.variant(max_frame_bytes=64)
        self.assertTrue(variant.test_only)
        self.assertEqual(variant.max_frame_bytes, 64)
        for bad in ({"model": "claude-other"}, {"source_content": "x"}, {"unknown": 1}):
            with self.subTest(bad=list(bad)), self.assertRaises(ValueError):
                PROFILE.variant(**bad)

    def test_identical_bounds_variant_is_test_only_with_its_own_fingerprint(self):
        same = PROFILE.variant()
        self.assertTrue(same.test_only)
        self.assertEqual(same.bounds(), PROFILE.bounds())
        self.assertNotEqual(same.fingerprint, PROFILE.fingerprint)
        self.assertEqual(review_profile.from_payload(same.to_payload()), same)
        self.assertEqual(review_profile.from_payload(PROFILE.to_payload()), PROFILE)
        self.assertFalse(PROFILE.test_only)


class FingerprintTests(unittest.TestCase):
    def test_every_bound_the_model_and_the_test_flag_change_the_fingerprint(self):
        seen = {PROFILE.fingerprint}
        changes = {
            "idle_seconds": 44,
            "execution_seconds": 91,
            "watchdog_seconds": 101,
            "max_messages": 2047,
            "max_frame_bytes": 1048575,
            "max_wire_bytes": 16777215,
            "worker_events": 8191,
            "parent_events": 8225,
            "worker_journal_bytes": 2999999,
            "max_raw_final_bytes": 16383,
            "max_stderr_bytes": 262143,
            "budget_usd": "0.04",
        }
        for name, value in changes.items():
            other = replace(PROFILE, test_only=True, **{name: value})
            seen.add(other.fingerprint)
        self.assertEqual(len(seen), len(changes) + 1)
        self.assertNotIn(replace(PROFILE, model="claude-haiku-5-6").fingerprint, seen)
        self.assertNotEqual(PROFILE.fingerprint, replace(PROFILE, test_only=True).fingerprint)
        self.assertEqual(PROFILE.fingerprint, review_profile.ReviewProfile().fingerprint)

    def test_identity_binds_prompt_source_model_and_gate_name(self):
        identity = PROFILE.identity()
        self.assertEqual(identity["query_sha256"], review_profile.QUERY_SHA256)
        self.assertEqual(identity["source"]["sha256"], review_profile.SOURCE_SHA256)
        self.assertEqual(identity["model"], "claude-haiku-5-5")
        self.assertEqual(identity["gate"], "MEAN_REVIEW_LIVE_ENABLED")
        self.assertEqual(identity["tools"], [])
        self.assertEqual(identity["retries"], 0)


class PayloadTests(unittest.TestCase):
    def test_roundtrip_and_tamper_rejection(self):
        self.assertEqual(review_profile.from_payload(PROFILE.to_payload()), PROFILE)
        variant = PROFILE.variant(max_messages=8, max_frames=8)
        self.assertEqual(review_profile.from_payload(variant.to_payload()), variant)
        payload = PROFILE.to_payload()
        for bad in (
            {**payload, "extra": 1},
            {k: v for k, v in payload.items() if k != "model"},
            {**payload, "max_messages": 8},  # a changed bound without the test-only flag
            {**payload, "model": "claude-sonnet-5-5", "test_only": True},
            {**payload, "instruction": "changed"},
            {**payload, "max_frame_bytes": True, "test_only": True},
            [],
            None,
        ):
            with self.subTest(bad=str(bad)[:40]), self.assertRaises(ValueError):
                review_profile.from_payload(bad)

    def test_model_matches_exact_or_dated_snapshot_only(self):
        for good in ("claude-haiku-5-5", "claude-haiku-5-5-20260101"):
            self.assertTrue(review_profile.model_matches(PROFILE, good))
        for bad in (
            None,
            5,
            "claude-haiku-5-5-x",
            "claude-haiku-5",
            "claude-sonnet-5-5",
            "claude-haiku-5-5-2026",
        ):
            self.assertFalse(review_profile.model_matches(PROFILE, bad))


class FixtureBindingTests(unittest.TestCase):
    def test_mean_is_accepted_only_through_its_own_profile(self):
        sources = dict(PROFILE.sources)
        self.assertEqual(sdk.checked_sources(sources, PROFILE), sources)
        with self.assertRaises(ValueError):
            sdk.checked_sources(sources)  # legacy SAMPLE allowlist is unchanged
        for bad in (
            {"mean.py": PROFILE.source_content + "# x\n"},
            {"mean.py": PROFILE.source_content.replace("mean", "avg")},
            {"mean.py": PROFILE.source_content, "README.md": SAMPLE["README.md"]},
            dict(SAMPLE),
            {"README.md": SAMPLE["README.md"]},
            {},
            {"../mean.py": PROFILE.source_content},
        ):
            with self.subTest(bad=list(bad)), self.assertRaises(ValueError):
                sdk.checked_sources(bad, PROFILE)

    def test_matching_question_text_does_not_unlock_other_content(self):
        with self.assertRaises(ValueError):
            sdk.build_payload({"mean.py": "def mean(v):\n    return 0\n"}, "review", PROFILE)
        with self.assertRaises(ValueError):
            sdk.build_payload(dict(PROFILE.sources), "overview", PROFILE)
        # Legacy query text keeps its legacy selection; mean.py never joins it.
        with self.assertRaises(ValueError):
            sdk.build_payload(dict(PROFILE.sources), "review")
        legacy = sdk.build_payload(dict(SAMPLE), "review")
        self.assertEqual(legacy["instruction"], sdk.FINDINGS_INSTRUCTION)
        self.assertEqual([item["path"] for item in legacy["snapshots"]], sorted(SAMPLE))

    def test_scope_query_is_text_identical_to_the_proposal_build(self):
        self.assertEqual(
            sdk.query_text(dict(PROFILE.sources), "review", PROFILE), PROFILE.query_text
        )


class AcceptedTextTests(unittest.TestCase):
    def test_scoped_report_is_accepted_only_with_the_scoped_profile(self):
        raw = json.dumps(good_report())
        canonical = analysis_privacy.accepted_text(PROFILE.query_text, raw, PROFILE)
        self.assertEqual(json.loads(canonical), good_report())
        # No profile: a scoped query never falls back to the legacy SAMPLE selection.
        self.assertIsNone(analysis_privacy.accepted_text(PROFILE.query_text, raw))
        # A profile never validates a legacy payload.
        legacy = sdk.query_text(dict(SAMPLE), "review")
        self.assertIsNone(analysis_privacy.accepted_text(legacy, raw, PROFILE))

    def test_output_limits_apply_to_raw_and_canonical_forms(self):
        raw = json.dumps(good_report())
        tight = PROFILE.variant(
            max_raw_final_bytes=len(raw.encode("utf-8")) - 1, max_canonical_bytes=100
        )
        self.assertIsNone(analysis_privacy.accepted_text(PROFILE.query_text, raw, tight))
        canonical = json.dumps(good_report(), sort_keys=True, separators=(",", ":"))
        small = PROFILE.variant(max_canonical_bytes=len(canonical.encode("utf-8")) - 1)
        self.assertIsNone(analysis_privacy.accepted_text(PROFILE.query_text, raw, small))
        exact = PROFILE.variant(max_canonical_bytes=len(canonical.encode("utf-8")))
        self.assertEqual(analysis_privacy.accepted_text(PROFILE.query_text, raw, exact), canonical)

    def test_wrong_hash_line_file_and_extra_fields_are_rejected(self):
        # Line 2 is a real non-blank line: the shared validator checks grounding, not semantics.
        for mutate in (
            lambda r: r["findings"][0].update(sha256="0" * 64),
            lambda r: r["findings"][0].update(line=0),
            lambda r: r["findings"][0].update(line=4),
            lambda r: r["findings"][0].update(file="README.md"),
            lambda r: r["findings"][0].update(extra="x"),
            lambda r: r.update(report_version=True),
        ):
            report = good_report()
            mutate(report)
            with self.subTest(report=str(report)[:60]):
                self.assertIsNone(
                    analysis_privacy.accepted_text(PROFILE.query_text, json.dumps(report), PROFILE)
                )


class CounterTests(unittest.TestCase):
    def test_worker_counters_are_revalidated_not_trusted(self):
        good = {
            "frames": 3,
            "blank_frames": 0,
            "wire_bytes": 900,
            "max_frame_bytes": 500,
            "stderr_bytes": 0,
            "messages": 2,
            "results": 1,
            "observed_turns": 1,
            "failed": False,
        }
        self.assertEqual(review_profile.validate_budget_snapshot(PROFILE, good), good)
        for bad in (
            {**good, "frames": True},
            {**good, "frames": -1},
            {**good, "frames": PROFILE.max_frames + 1},
            {**good, "wire_bytes": PROFILE.max_wire_bytes + 1},
            {**good, "messages": "2"},
            {**good, "results": 2},
            {**good, "observed_turns": 2},
            {**good, "failed": 0},
            {**good, "unknown": 1},
            {**good, "raw": "payload"},
            [],
            None,
        ):
            with self.subTest(bad=str(bad)[:50]), self.assertRaises(review_profile.BudgetExceeded):
                review_profile.validate_budget_snapshot(PROFILE, bad)

    def test_turns_must_be_exactly_one_integer(self):
        review_profile.require_accepted_counters(PROFILE, 2, 1, [1])
        for messages, results, turns in (
            (2, 1, [True]),
            (2, 1, [2]),
            (2, 1, [0]),
            (2, 1, [-1]),
            (2, 1, [None]),
            (2, 1, []),
            (2, 1, [1, 1]),
            (2, 0, []),
            (2, 2, [1, 1]),
            (0, 1, [1]),
            (PROFILE.max_messages + 1, 1, [1]),
            (True, 1, [1]),
        ):
            with (
                self.subTest(messages=messages, results=results, turns=turns),
                self.assertRaises(review_profile.BudgetExceeded),
            ):
                review_profile.require_accepted_counters(PROFILE, messages, results, turns)

    def test_budget_reason_is_numeric_only(self):
        self.assertEqual(str(review_profile.BudgetExceeded(3)), "analysis_budget_3")
        self.assertEqual(str(review_profile.BudgetExceeded(99)), "analysis_budget_0")
        self.assertEqual(str(review_profile.BudgetExceeded("secret")), "analysis_budget_0")
        self.assertIsNone(review_profile.reason_message("x"))
        for code in review_profile.REASONS:
            self.assertIn(review_profile.reason_message(code), analysis_privacy.ANALYSIS_CODES)

    def test_audit_counts_journal_messages_and_turns(self):
        def event(kind, payload):
            return {"type": kind, "payload": payload}

        events = [
            event("run.created", {}),
            event("sdk.message", {"message_type": "AssistantMessage", "message": {}}),
            event("sdk.message", {"message_type": "ResultMessage", "message": {"num_turns": 1}}),
        ]
        self.assertEqual(
            review_profile.audit_events(PROFILE, events),
            {"messages": 2, "results": 1, "turns": [1]},
        )
        flagged = events[:2] + [
            event("sdk.message", {"message_type": "ResultMessage", "message": {"num_turns": True}})
        ]
        self.assertEqual(review_profile.audit_events(PROFILE, flagged)["turns"], [None])
        with self.assertRaises(review_profile.BudgetExceeded):
            review_profile.audit_events(
                PROFILE.variant(worker_events=9000, parent_events=9100, max_messages=1), events
            )
        with self.assertRaises(review_profile.BudgetExceeded):
            review_profile.audit_events(PROFILE.variant(worker_events=1, parent_events=40), events)


if __name__ == "__main__":
    unittest.main()
