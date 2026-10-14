"""Small real local checks, not simulated SDK/model responses."""

from __future__ import annotations

import json

from agent_runtime import __version__
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import validate_document
from agent_runtime.telemetry.recorder import RunLock, atomic_json, now, redact

SCENARIOS = {
    "sdk.fundamentals": {
        "title": "Reply with the exact text CAS_SDK_BASELINE_OK and nothing else.",
        "group": "fundamentals",
        "family_id": "FND-01",
        "execution_mode": "live",
    },
    "platform.contracts": {
        "title": "Validate run contract and reject unknown major",
        "group": "platform",
        "family_id": "LOCAL-CONTRACT",
    },
    "platform.redaction": {
        "title": "Verify synthetic secret redaction",
        "group": "platform",
        "family_id": "LOCAL-REDACTION",
    },
    "platform.structured-output": {
        "title": "Validate synthetic JSON output independently against JSON Schema",
        "group": "platform",
        "family_id": "OUT-01-local",
    },
    "platform.usage": {
        "title": "Verify observed usage deduplication and explicit unknown scope",
        "group": "platform",
        "family_id": "USE-01-local",
    },
    "platform.permissions": {
        "title": "Verify local Read policy with disposable synthetic files",
        "group": "platform",
        "family_id": "SEC-01-local",
    },
}


class LocalValidation:
    local_validation = True

    async def run(self, request, recorder) -> NativeResult:
        checks = []
        if request.scenario_id == "platform.contracts":
            validate_document("run", recorder.record)
            bad = dict(recorder.record, schema_version=2)
            try:
                validate_document("run", bad)
            except ValueError:
                rejected = True
            else:
                rejected = False
            checks.append(
                {
                    "id": "unknown-major-rejected",
                    "expected": True,
                    "observed": rejected,
                    "outcome": "pass" if rejected else "fail",
                    "evidence_refs": [],
                }
            )
        elif request.scenario_id == "platform.redaction":
            marker = "synthetic-private-marker"
            observed = marker not in json.dumps(
                redact({marker: marker, "api_key": marker}, [marker])
            )
            checks.append(
                {
                    "id": "marker-redacted",
                    "expected": True,
                    "observed": observed,
                    "outcome": "pass" if observed else "fail",
                    "evidence_refs": [],
                }
            )
        elif request.scenario_id.startswith("platform."):
            from agent_runtime.scenarios.local_research import (
                permission_checks,
                structured_checks,
                usage_checks,
            )

            cases = {
                "platform.structured-output": structured_checks,
                "platform.usage": usage_checks,
                "platform.permissions": lambda: permission_checks(request.workspace),
            }
            if request.scenario_id not in cases:
                raise ValueError("Unknown local scenario")
            checks = cases[request.scenario_id]()
        else:
            raise ValueError("Unknown local scenario")
        recorder.event("validation.result", {"mode": "offline", "checks": checks}, "validator")
        return NativeResult(
            json.dumps({"mode": "offline", "checks": checks}),
            None,
            None,
            None,
            source="application",
            checks=checks,
        )


def write_catalog(data_dir, run=None, *, locked=False) -> None:
    if not locked:
        with RunLock(data_dir):
            return write_catalog(data_dir, run, locked=True)
    entries = []
    previous = {}
    path = data_dir / "capabilities/catalog.json"
    if path.is_file():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            validate_document("catalog", document)
            previous = {entry["scenario_id"]: entry for entry in document["scenarios"]}
        except (ValueError, OSError):
            pass
    for scenario_id, metadata in SCENARIOS.items():
        mode = metadata.get("execution_mode", "local")
        entry = {
            "scenario_id": scenario_id,
            "scenario_version": "1",
            **metadata,
            "prerequisites": ["offline Python environment"]
            if mode == "local"
            else ["explicit live consent", "native API key", "bounded turn/budget/wall limits"],
            "execution_mode": mode,
            "evidence_status": "pending",
            "latest_run_id": None,
            "evidence_refs": [],
            "tested_context": None,
            "blocked_reason": None,
        }
        if scenario_id in previous:
            entry = previous[scenario_id]
        if run and run["scenario_id"] == scenario_id:
            evidence_ref = f"runs/{run['run_id']}/run.json"
            status = "error"
            try:
                assertions_path = data_dir / "runs" / run["run_id"] / "assertions.json"
                assertions = json.loads(assertions_path.read_text(encoding="utf-8"))
                validate_document("assertions", assertions)
                if assertions["run_id"] != run["run_id"]:
                    raise ValueError("Assertion identity mismatch")
                status = assertions["outcome"]
                evidence_ref = f"runs/{run['run_id']}/assertions.json"
            except (ValueError, OSError):
                pass
            entry = dict(
                entry,
                evidence_status=status,
                latest_run_id=run["run_id"],
                tested_context={
                    "mode": "offline" if mode == "local" else "live",
                    "os": run["provider"]["os"],
                    "sdk_version": run["provider"]["sdk_version"],
                },
                evidence_refs=[evidence_ref],
            )
        entries.append(entry)
    catalog = {
        "schema_version": 1,
        "generated_at": now(),
        "catalog_version": "platform-v1",
        "producer": {"runtime_version": __version__, "contract_version": "1"},
        "scenarios": entries,
    }
    validate_document("catalog", catalog)
    atomic_json(path, catalog)
