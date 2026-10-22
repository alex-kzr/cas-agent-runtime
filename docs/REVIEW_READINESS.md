# Mean-review scope: runtime readiness (CURRENT, 2026-10-22)

Status: **NOT_READY. No live consent requested or consumed. Both gates are False:**
`review_profile.MEAN_REVIEW_LIVE_ENABLED` and `repository_analysis_sdk.LIVE_ANALYSIS_ENABLED`.
This continuation made source and test edits only. **No test, lint, build, browser or model
command was run by the developer (file tools only).** Every check below is `NOT_RUN` until the
coordinator records evidence. Earlier independent results (2026-10-21 checkpoint, in the
umbrella `docs/review/RV01_READINESS_2026-10-21.md`) are history, not proof of this diff.

## Frozen scope (what a consent would bind)

| Item | Value |
| --- | --- |
| Selected file | `mean.py`, 122 UTF-8 bytes, LF, SHA-256 `9d5b6624b93480039a6c1003b8e8fc2411f10989fb9233bcebd19ec1a4975206` |
| Application prompt | 1272 UTF-8 bytes, SHA-256 `5ca9260b44df34d044f03c8aab2b0f094e57991e6481b7b91ed8a83f8b069e59` |
| Model | `claude-haiku-5-5` (exact, or the same id with a `-YYYYMMDD` suffix) |
| Profile fingerprint | `3ca3ade227a8a677a78121141681e6e0330f235d2abc8630d23c42163b8ece13` as of the 2026-10-21 checkpoint. This continuation did not edit the profile identity or any bound, so it should be unchanged; recomputation is `NOT_RUN`. |
| Queries / turns | 1 logical query, 1 observed turn, 0 automatic retries |
| Time (s) | idle 45, stream deadline 85, execution 90, owned cleanup 3, finalize 5, cooperative watchdog 100 |
| Counts | messages 2048, frames 2048, worker events 8192, parent events 8224 |
| Bytes | frame 1048576, wire 16777216, stderr 262144 (own cap), worker journal 3000000, parent import 4000000, raw final 16384, canonical 5120, input 1000000, response 1000000 |
| SDK threshold | USD 0.05 (`budget_usd`) |

## Caveats that must stay in every consent

- **One logical query is not one provider request.** CAS counts one `client.query` and one
  reported turn. Provider or CLI-internal retries and hidden calls are not observable.
- **No hard billing cap.** The USD 0.05 value is an SDK threshold, not an invoice, credit or
  subscription-quota ceiling. Actual usage is unknown.
- **No promised provider deletion or cancellation.** Local owned-process cleanup says nothing
  about provider-side cancellation, retention or deletion.
- **`finalize_seconds` (5) is an accounting allowance**, not an independently enforced timer.
- **Timing is cooperative.** The 100 s watchdog and the 85 s / 45 s stream bounds cannot
  preempt a blocked native call or an OS-level stall; unknown cleanup stays `INTERRUPTED`.
- Model/account eligibility, login validity and native context isolation are unverified.
- An empty findings list is valid v2 data and proves nothing about the file.

## Parent success postcondition (this continuation)

A COMPLETED scoped run is promoted only when all of the following hold
(`review_profile.require_accepted_counters`, `require_success_budget`; called from
`SnapshotSDKAdapter._require_counters`):

1. The worker's `review_budget` map exists (only the in-process mock seam, which has no raw
   transport, may lack it) and passes `validate_budget_snapshot`: strict `int` values within
   the profile bounds, never `bool`; `failed` and `cleanup_unknown` are `bool`.
2. **Every** measured field is present as a strict int: `frames`, `blank_frames`,
   `wire_bytes`, `max_frame_bytes`, `stderr_bytes`, `messages`, `results`, `observed_turns`.
3. `failed is False`; no `reason_code`; no `cleanup_unknown`.
4. Consistency: `blank_frames <= frames`; non-blank frames `>= messages`; `wire_bytes >=`
   non-blank frames; `1 <= max_frame_bytes <= wire_bytes`.
5. The parent independently re-derives `messages`, `results` and turns from the imported
   journal (`audit_events`) and they must equal the map (`results == 1`, turns `== [1]`,
   each turn a real int); requested and resolved model are checked against the profile.

A partial failure snapshot (for example only `frames` and a `reason_code`) is still accepted
as safe failure data, but can never promote success.

**Trust boundary:** frame, blank-frame, wire, max-frame and stderr byte counts are measured by
the worker's raw transport. The parent sees only the projected, redacted journal and cannot
rebuild those counts from it. They are checked for presence, type, bounds and mutual
consistency, not independently verified. Message and turn counts are independently checked.

## Other changes in this continuation

- The mock SDK stream generator is now closed explicitly (`AsyncExitStack` in
  `providers/claude/client.py`) so an early failure does not leave a pending
  `async_generator_athrow`. No behavior of the stream limits changed; no replay is added.
- E2E canary scanner (`tests/test_repository_analysis_sdk.py`): skips only the
  controller-owned `control.root / ".execution.lock"`, requires every other producer file to
  be non-empty and `run.json` and `events.jsonl` to exist, and scans all of them. No
  exception suppression. The 71 earlier errors were this fixture reading its own lock, not
  71 application defects.
- Ruff fixes: UP031 (two f-strings), B023 (`hanging(entered, tree_empty)` helper), I001
  (console HTTP test imports). Formatting of the affected files is left to the coordinator.

## Source-review verification (reading only, nothing executed)

Present in source: duplicate-key, NaN/Infinity and overflowing-float rejection
(`review_transport.strict_loads`); raw stderr counted against its own cap; late frames refused
and never reset idle (`check_time` before the idle reset); idle and stream deadline; frame,
wire and frame-count caps applied before parse; message cap before expansion
(`client.ReviewCounters.message`); worker event cap (`audit_events`) and journal writer budget
(`recorder.journal_limit`), parent size check before import; raw final cap; typed turn
(`type is int`, `== 1`, one result) and model checks. This is a reading, not a test result.

## Check status

| Check | Status |
| --- | --- |
| Runtime unit and E2E suites, lint, format | NOT_RUN |
| Console HTTP, Node DOM and race suites | NOT_RUN |
| Fresh builds and fresh browser acceptance | NOT_RUN |
| Live CAS, native model, discovery, auth | NOT_RUN, not authorized |

Old FFEE failure cause remains unknown. Do not label this scope READY until the coordinator
evidence is recorded and every item above is confirmed.
