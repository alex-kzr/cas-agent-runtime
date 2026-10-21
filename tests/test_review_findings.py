"""Report version 2 contract: synthetic Tiny Shop findings only, no model, no process."""

import copy
import hashlib
import json
import unittest

from agent_runtime.tasks import repository_analysis_sdk as sdk
from agent_runtime.tasks import review_findings as findings
from agent_runtime.tasks.repository_analysis import (
    SAMPLE,
    expected_fixture_output,
    markdown,
    validate_for,
)


def sha(name):
    return hashlib.sha256(SAMPLE[name].encode("utf-8")).hexdigest()


def report():
    return {
        "report_version": 2,
        "repository": "tiny-shop",
        "findings": [
            {
                "id": "F1",
                "problem": "The subtotal helper never checks for negative quantities.",
                "impact": "A negative quantity silently produces a negative line total.",
                "suggested_fix": "Reject quantities below zero before multiplying.",
                "file": "inventory.py",
                "line": 1,
                "sha256": sha("inventory.py"),
            },
            {
                "id": "F2",
                "problem": "The README does not say which currency or rounding rules apply.",
                "impact": "Readers cannot tell whether results are cents or whole units.",
                "suggested_fix": "Document the currency and rounding behavior in the README.",
                "file": "README.md",
                "line": 3,
                "sha256": sha("README.md"),
            },
        ],
    }


def mutated(**changes):
    value = report()
    value["findings"][0].update(changes)
    return value


class FindingsContractTests(unittest.TestCase):
    def test_useful_prose_findings_validate_and_render_safe_markdown(self):
        value = report()
        self.assertEqual(len(findings.validate_findings(value, SAMPLE)), 2)
        text = markdown(value, SAMPLE, "00000000-0000-4000-8000-000000000000", mode="mock-sdk")
        self.assertIn("(files/inventory.py#L1)", text)
        self.assertIn("- Problem: The subtotal helper never checks", text)
        self.assertNotIn("<", text)

    def test_markdown_escapes_emphasis_characters(self):
        value = mutated(problem="The with_tax helper uses a bare *rate* argument for tax.")
        text = markdown(value, SAMPLE, "00000000-0000-4000-8000-000000000000")
        self.assertIn("with\\_tax", text)
        self.assertIn("\\*rate\\*", text)

    def test_mentioning_a_selected_file_name_is_allowed(self):
        value = mutated(problem="The inventory.py helper never checks negative quantities.")
        self.assertEqual(len(findings.validate_findings(value, SAMPLE)), 2)

    def test_subset_selection_requires_selected_files_only(self):
        only_readme = {"README.md": SAMPLE["README.md"]}
        value = report()
        value["findings"] = [value["findings"][1]]
        findings.validate_findings(value, only_readme)
        with self.assertRaises(ValueError):
            findings.validate_findings(report(), only_readme)

    def test_clean_review_with_no_findings_is_valid_and_not_a_proof(self):
        clean = {"report_version": 2, "repository": "tiny-shop", "findings": []}
        for sources in (SAMPLE, {"README.md": SAMPLE["README.md"]}):
            self.assertEqual(findings.validate_findings(clean, sources), [])
        self.assertEqual(validate_for("review", clean, SAMPLE), [])
        text = markdown(clean, SAMPLE, "00000000-0000-4000-8000-000000000000", mode="mock-sdk")
        self.assertIn("No findings reported.", text)
        self.assertIn("not proof", text)
        self.assertIn("## Approved source hashes", text)
        # Still a version 2 document: it needs the version, the identity and the exact shape.
        for broken in (
            {"repository": "tiny-shop", "findings": []},
            {"report_version": 2, "repository": "other", "findings": []},
            {"report_version": 2, "repository": "tiny-shop", "findings": [], "extra": 1},
            {"report_version": 1, "repository": "tiny-shop", "findings": []},
        ):
            with self.subTest(value=broken), self.assertRaises(ValueError):
                findings.validate_findings(broken, SAMPLE)
        with self.assertRaises(ValueError):
            validate_for("overview", clean, SAMPLE)
        with self.assertRaises(ValueError):
            findings.validate_findings(clean, {})

    def test_review_instruction_allows_an_empty_list_and_v1_instruction_is_unchanged(self):
        self.assertIn("empty findings list", sdk.FINDINGS_INSTRUCTION)
        self.assertNotIn("one to five", sdk.FINDINGS_INSTRUCTION)
        self.assertNotIn("findings", sdk.INSTRUCTION)
        self.assertNotIn("empty", sdk.INSTRUCTION)

    def test_wrong_grounding_is_rejected(self):
        for change in (
            {"file": "secrets.env"},
            {"file": "../inventory.py"},
            {"line": 0},
            {"line": 99},
            {"line": 3},  # blank line in inventory.py
            {"line": True},
            {"line": "1"},
            {"sha256": sha("README.md")},
            {"sha256": "0" * 64},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                findings.validate_findings(mutated(**change), SAMPLE)

    def test_malformed_shape_and_versions_are_rejected(self):
        broken = []
        for version in (1, 3, 2.0, True, "2", None):
            value = report()
            value["report_version"] = version
            broken.append(value)
        value = report()
        del value["report_version"]
        broken.append(value)
        value = report()
        value["extra"] = 1
        broken.append(value)
        value = report()
        value["findings"] = {}
        broken.append(value)
        value = report()
        value["findings"] = None
        broken.append(value)
        value = report()
        value["findings"] = [copy.deepcopy(value["findings"][0]) for _ in range(6)]
        broken.append(value)
        value = report()
        value["findings"][0]["id"] = "F2"  # duplicate identity
        broken.append(value)
        value = report()
        value["findings"][0]["id"] = "finding-1"
        broken.append(value)
        value = report()
        value["findings"][1]["problem"] = value["findings"][0]["problem"]
        broken.append(value)
        value = report()
        value["findings"][0]["extra"] = "x"
        broken.append(value)
        value = report()
        value["repository"] = "other"
        broken.append(value)
        broken += [None, [], "text", {}]
        for value in broken:
            with self.subTest(value=repr(value)[:80]), self.assertRaises(ValueError):
                findings.validate_findings(value, SAMPLE)

    def test_unsafe_or_unscreened_text_is_rejected(self):
        unsafe = {
            "control": "The subtotal helper\nnever checks negative quantities.",
            "tab": "The subtotal helper\tnever checks negative quantities.",
            "bidi": "The subtotal helper ‮never checks negative values.",
            "null": "The subtotal helper never\x00 checks negative values.",
            "markup": "The subtotal helper <b>never</b> checks negative values.",
            "backtick": "The subtotal helper `never` checks negative values.",
            "link": "The subtotal helper [never](http://example.com) checks values.",
            "url": "See http://example.com for the subtotal helper details.",
            "path": "The helper in config/settings.py never checks negative values.",
            "unapproved-file": "The helper in secrets.env never checks negative values.",
            "secret-word": "The password for the subtotal helper is stored somewhere.",
            "secret-shape": "The subtotal helper uses sk-abcdefghijklmnop1234 for access.",
            "long-token": "The subtotal helper uses " + "a" * 30 + " to compute values.",
            "pii-number": "Call 555 123 4567 about the subtotal helper negative values.",
            "error": "Traceback shows the subtotal helper fails on negative values.",
            "exception": "The subtotal helper raised an exception on negative values.",
            "source-line": "The code def subtotal(price, quantity): never checks values.",
            "copied-line": "Note that return price * quantity never validates the inputs.",
            "readme-copy": "A small price and tax calculation library is described only briefly.",
            "short": "Too short.",
            "few-words": "Averyveryverylongsinglewordwithoutanyspaces",
            "empty": "",
            "oversized": "The helper never checks values. " * 12,
            "non-ascii": "The subtotal helper never checks negative значения.",
            "leading-space": " The subtotal helper never checks negative values.",
            "double-space": "The subtotal helper  never checks negative values.",
            "not-text": 12345,
        }
        for name, text in unsafe.items():
            for field in ("problem", "impact", "suggested_fix"):
                with self.subTest(case=name, field=field), self.assertRaises(ValueError):
                    findings.validate_findings(mutated(**{field: text}), SAMPLE)

    def test_overall_report_size_is_bounded(self):
        value = report()
        template = value["findings"][0]
        value["findings"] = []
        for number in range(1, 6):
            item = dict(template, id=f"F{number}")
            for name in ("problem", "impact", "suggested_fix"):
                item[name] = f"Finding {number} {name} " + "word " * 40
                item[name] = item[name].strip()[:240]
            value["findings"].append(item)
        original = findings.MAX_REPORT_BYTES
        findings.MAX_REPORT_BYTES = 600
        try:
            with self.assertRaises(ValueError):
                findings.validate_findings(value, SAMPLE)
        finally:
            findings.MAX_REPORT_BYTES = original

    def test_question_binding_keeps_version_1_unchanged(self):
        facts = expected_fixture_output()
        self.assertEqual(len(validate_for("overview", facts, SAMPLE)), 3)
        self.assertEqual(len(validate_for("functions", facts, SAMPLE)), 3)
        with self.assertRaises(ValueError):
            validate_for("overview", report(), SAMPLE)
        with self.assertRaises(ValueError):
            validate_for("review", facts, SAMPLE)
        self.assertEqual(len(validate_for("review", report(), SAMPLE)), 2)
        self.assertNotIn("report_version", json.dumps(facts))


if __name__ == "__main__":
    unittest.main()
