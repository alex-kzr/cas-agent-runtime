# Analysis findings (report version 2) in the runtime

Contract: [`docs/contracts/ANALYSIS_FINDINGS.md`](../../../docs/contracts/ANALYSIS_FINDINGS.md).

- `tasks/review_findings.py` is a stdlib-only leaf module: `validate_findings`,
  `screen_text`, `markdown_lines`. It imports nothing from the task layer, so the worker
  boundary and the parent adapter share it without import cycles.
- An empty `findings` list is a valid clean review (0 to 5 findings). `FINDINGS_INSTRUCTION`
  tells the model not to invent a defect; Markdown says "No findings reported" and that this
  is not proof of correctness. All outcome/query-count/cleanup/validation checks still apply.
- `repository_analysis.QUESTIONS` gains `review`; `FINDINGS_QUESTIONS` marks the questions
  answered with version 2. `validate_for(question, value, sources)` is the single entry
  used by `accepted_text`, `SnapshotSDKAdapter`, recovery, `report()` and export.
- `build_payload` emits `schema_version` 2 and `FINDINGS_INSTRUCTION` only for `review`;
  `overview`/`functions` payload bytes and snapshot hashes are unchanged.
- `review` requires `mode="sdk"` at create time and when a record is loaded. The offline
  `SampleAdapter` refuses it, so no scripted output can pass as a review.
- `analysis_privacy.context_observed` projects advertised registration counts (typed,
  bounded, idempotent) and nothing else.

Tests (offline, mock SDK, synthetic canaries): `tests/test_review_findings.py`
(contract, screening, grounding, version binding), `tests/test_analysis_privacy.py`
(`FindingsFlowTests`, `ContextCountTests`: producer -> recorder -> worker import ->
reopen/export on both routes). Do not run these against a live model.

Remaining limits: prose is screened, not verified; the model's claims about the code can
be wrong; only the two Tiny Shop sample files can be input; the live gate stays false.
