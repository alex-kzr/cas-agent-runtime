# VS frontend API review scope: readiness (VS-01, 2026-10-22)

Historical verification clarification (prepared 2026-10-23; no new test run): the authorized correction recorded on 2026-10-22 reports 367 runtime tests: **365 PASS + 2 native SKIP**, zero failures/errors and strict exit 1; HTTP **21/21 PASS**, Ruff lint/format PASS. Earlier NOT_RUN/unverified and lint-failure statements below are preserved historical checkpoints, not the current verification status. Source: umbrella `docs/review/VS01_OFFLINE_IMPLEMENTATION_2026-10-22.md` and `docs/review/evidence/vs01-offline-2026-10-22/authorized-correction.json`. The 2026-10-23 read-only component review matched all 14 source/test hashes to that receipt; this does not rerun the tests or establish native path safety. Source staging and live gates remain closed; **NOT_READY_FOR_LIVE**.

Current authorized-correction checkpoint: **lint/format PASS; runtime 365 PASS plus two retained native symlink skips (367 total), HTTP21 PASS**. Synthetic symlink/junction observations passed and do not replace native filesystem coverage. All gates remain closed; NOT_READY_FOR_LIVE. See umbrella docs/review/VS01_OFFLINE_IMPLEMENTATION_2026-10-22.md. Older blocker/checkpoint statements below are historical.

Coordinator update: **PARTIAL_OFFLINE_ACCEPTANCE / NOT_READY_FOR_LIVE**. Runtime 365 discovered, 363 passed, two symlink skips; HTTP21 and tools169 PASS. Four lint findings and three unformatted files remain. See umbrella docs/review/VS01_OFFLINE_IMPLEMENTATION_2026-10-22.md for exact evidence and the developer correction blocker. Older unverified statements below are historical checkpoints.

Status: **NOT_READY_FOR_LIVE**. Offline code and tests were written without running any
command; nothing is verified until the coordinator records evidence. No VS file content was
read, sent or stored by this work, and no model, auth or native process was used.

## What exists

- `agent_runtime.tasks.vs_review_profile`: a separate immutable, **manifest-only** profile
  (`repository-analysis-vs-api-v1`, mode `sdk-vs-api-review`, slot `review-vs-api-attempt.started`,
  gate `VS_API_REVIEW_LIVE_ENABLED = False`). It binds both exact names/bytes/hashes in the fixed
  order (`src/api.ts` 3550, `src/api.test.ts` 6932), the root identity, repository token
  `vacancy-search-frontend`, the frozen instruction, question and the prepared query identity
  (12496 bytes, `b642ac77…8a`), plus the same model, SDK pin, transport and all mean-review bounds
  (a test asserts the bounds are identical). It stores no source text.
- Fingerprint: computed at runtime by `vs_review_profile.canonical().fingerprint` from the
  canonical identity. **The value is not recorded here because no command was run**; the
  coordinator must record it from an offline run and treat it as the consent identity.
- `review_profile.validate_bounds` is the shared bound validation (mean behavior unchanged);
  `review_profile.from_payload` dispatches the VS profile id to its own validator.
- Report v2 repository: `review_findings.validate_findings(value, sources, repository=None)`.
  `None` keeps tiny-shop. The VS token is accepted only from a trusted profile together with
  exactly the two VS names; neither token validates the other's sources, and old routes accept no
  other string. `validate_for`/`markdown` forward the token; v1 questions reject it.
- `AnalysisControl(vs_profile=…)` (trusted constructor argument): `create(..., mode="sdk-vs-api-review")`,
  `vs_scope()` (metadata), preview, start (own gate, own slot, fingerprint-bound consent), canonical
  record checks, report and ZIP export through the profile-bound repository.

## Source boundary

- Closed gate: constructors, `list`, `vs_scope()` and the API metadata never read VS contents or
  create a snapshot. `materialize()` checks the gate **before any filesystem access**.
- Open gate (future, after source-owner approval only): `read_manifest_files` checks the fixed
  root and relative paths, no symlink/junction/hardlink, regular files, exact size and SHA-256,
  strict UTF-8 without BOM or replacement characters, all **before** decoding is returned,
  staging or payload use. Bytes are read as `rb` and staged as exact bytes, so CRLF/LF survive.
  Staged snapshots are read back the same way and refused if extra, missing, renamed or changed.
- Worker and parent each rebuild the profile from the request: `bind_query` parses the query,
  requires the exact snapshot names/order/bytes/hashes, repository, instruction and question, and
  for the canonical profile also the prepared query size and digest. The worker payload carries
  the manifest only.
- Test-only variants (`test_variant`) bind the same two paths to invented text with a different
  fingerprint. They are refused by the adapter without a mock factory and by the pinned
  transport, and `create` has no parameter that selects them.

## Not changed

`client.py`, `supervised.py` and `review_transport.py` needed no change: they use the profile
interface (bounds, query, model, `test_only`) that the VS profile implements. Mean-review
behavior, legacy Tiny Shop records, hashes and the consumed synthetic claim are untouched.

## Tests (written, NOT_RUN)

`tests/test_vs_review_profile.py` (manifest, identity, zero reads, tamper, verified reads in a
temporary directory with invented bytes) and `tests/test_vs_repository_analysis.py` (closed gate,
consent, mock worker/parent over the raw transport, counters, reports, cancel/unknown cleanup,
no replay, reopen/export, repository cross-injection). They use the mean harness; no real root is
opened, and no real hash is forged.

## Before any live use (all still open)

1. Coordinator runs the offline checks and records the fingerprint and results.
2. The source owner approves sending the two exact files; metadata is re-hashed locally. If it
   differs from the approved values, record **stale** and do not update them automatically.
3. After approval, an actual post-development preview is checked against the 12496-byte
   candidate identity (the constants have not been compared with real bytes by this work).
4. A separate explicit live approval opens the scope's own gate. Native hidden requests stay
   unobservable, the USD value is an SDK threshold and no remote deletion is promised.
