"""Real offline application checks; these never claim native SDK enforcement."""

import json
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from agent_runtime.providers.claude.permissions import read_allowed
from agent_runtime.telemetry.metrics import ObservedUsage


def check(identifier, expected, observed):
    return {
        "id": identifier,
        "expected": expected,
        "observed": observed,
        "outcome": "pass" if observed == expected else "fail",
        "evidence_refs": [],
    }


def structured_checks():
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "integer"}},
        "required": ["answer"],
        "additionalProperties": False,
    }
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    checks = []
    for identifier, text, accepted in (
        ("valid-object", '{"answer": 42}', True),
        ("parseable-wrong-type", '{"answer": "42"}', False),
        ("extra-field", '{"answer": 42, "unapproved": true}', False),
    ):
        try:
            validator.validate(json.loads(text))
            observed = True
        except ValidationError:
            observed = False
        checks.append(check(identifier, accepted, observed))
    try:
        Draft202012Validator.check_schema({"type": "synthetic-invalid-type"})
        rejected = False
    except SchemaError:
        rejected = True
    checks.append(check("invalid-schema-rejected", True, rejected))
    return checks


def usage_checks():
    usage = ObservedUsage()
    first = {
        "input_tokens": 7,
        "output_tokens": 3,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    usage.observe("synthetic-main-1", first)
    usage.observe("synthetic-main-1", first)
    usage.observe("synthetic-child-1", {**first, "input_tokens": 900}, subagent=True)
    usage.observe(None, first)
    snapshot = usage.snapshot()
    return [
        check("deduplicate-main-usage", first, snapshot["observed_main_loop_tokens"]),
        check("exclude-child-and-unstable-ids", 1, snapshot["observed_message_count"]),
        check("never-claim-completeness", False, snapshot["complete"]),
        check("never-derive-cost", False, snapshot["cost_derived"]),
        check("unknown-id-warning", True, bool(snapshot["warnings"])),
        check("unknown-not-zero", None, ObservedUsage().snapshot()["observed_main_loop_tokens"]),
    ]


def permission_checks(workspace):
    # Fixtures are synthetic, below the caller-approved disposable workspace. No actual
    # secret, credential file, sibling project or user document is opened by this check.
    with tempfile.TemporaryDirectory(prefix="local-policy-fixtures-", dir=workspace) as directory:
        fixture = Path(directory)
        for name in ("allowed.txt", ".synthetic-hidden", "synthetic.key"):
            (fixture / name).write_text("CAS synthetic policy fixture", encoding="utf-8")
        cases = [
            ("allow-bounded-file", "Read", {"file_path": str(fixture / "allowed.txt")}, True),
            ("deny-write-tool", "Write", {"file_path": str(fixture / "allowed.txt")}, False),
            ("deny-shell", "Bash", {"command": "synthetic-not-executed"}, False),
            ("deny-hidden", "Read", {"file_path": str(fixture / ".synthetic-hidden")}, False),
            ("deny-key-suffix", "Read", {"file_path": str(fixture / "synthetic.key")}, False),
            ("deny-traversal", "Read", {"file_path": "../outside-synthetic.txt"}, False),
            ("deny-missing", "Read", {"file_path": str(fixture / "missing.txt")}, False),
        ]
        return [
            check(name, expected, read_allowed(workspace, tool, arguments))
            for name, tool, arguments, expected in cases
        ]
