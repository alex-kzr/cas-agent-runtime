# Analysis privacy policy (CH-01)

Scope: the `sdk.repository-analysis` scenario only. Non-analysis tasks and scenarios keep their
existing full-payload evidence. The live gate (`LIVE_ANALYSIS_ENABLED`) stays `False`.

## Problem

A synthetic provider canary in `ResultMessage.errors` was rejected at the final analysis error
but still persisted in `sdk.message` events, the private worker journal, `response.json` and
history. Sanitizing only the final error cannot close that channel; the policy must act before
every write.

## Policy

`tasks/analysis_privacy.py` is an allowlist, not a scrubber. It is applied at the choke points
that write durable state:

| Channel | Where applied | What survives |
| --- | --- | --- |
| Events (canonical and worker journals) | `Recorder.event` when `recorder.private` | Per-type allowlisted fields: message type, enumerated subtype/outcome/reason, counts, byte sizes, tool name from a closed set, 16-hex digests of provider ids, fixed CAS messages |
| `sdk.message` | `client.py` builds `message_summary()` before serializing; recorder re-projects | `message_type`, `content_blocks`, `num_turns`, `result_bytes`, `errors_count`, enumerated `subtype`/`terminal_reason`, `is_error` |
| Run/result documents | `Recorder.clean_document` | `sdk_outcome` enumerated; `session_id` shape-checked; `usage.sdk` numbers/bools only (plus the CAS-set `scope`); `usage.application` tokens and fixed text; model/CLI version shape-checked; `error.message` only a fixed CAS message or analysis code |
| `task.json` | `Recorder.__init__` | Instructions replaced by a placeholder; SHA-256 and size retained. Exact approved snapshots stay only in the existing snapshot storage/export |
| Worker `response.json` | `worker.bounded_result` -> `worker_result` | Safe metadata plus text only if it is a source-grounded valid report (re-serialized canonical JSON); otherwise `text: null` |
| Worker exception | `worker.main` | Exception type name; message withheld |
| Parent import | `SupervisedClaudeAdapter.run` | The parent re-projects the worker response independently and re-imports events through the same recorder policy |

Provider strings are never hashed as a substitute for policy. Unknown enum values collapse to
`"other"`. A token-shaped canary is still excluded because provider-controlled fields use
closed sets or numeric-only projection, not a character-shape filter alone.

### Finite key policy

Dictionary keys are data too, so a shape check (identifier/token regex) is never what keeps a
key. Unknown keys are omitted, whatever they look like:

- **Provider usage** (`usage.sdk`, worker `usage`, `numeric()`): only names in `USAGE_KEYS`
  survive (`total_cost_usd`, `usage`, `model_usage`, `scope`, `estimate`, the four token
  counters, `server_tool_use`/`cache_creation` counters and the camelCase per-model counters).
  Values are numbers/bools, plus the exact CAS-set pair `scope: sdk-call-native`. Keys of
  `model_usage` are kept only if they match the model-label shape
  `claude-<haiku|sonnet|opus|fable>-<version>[-date]`; any other model key, with its value, is
  dropped. Unknown nested metadata is omitted.
- **CAS application usage and generic/fallback events** (`structure()`): only names in
  `STRUCTURE_KEYS` (observed token counters, comparison, cleanup, query counts, fixed event
  fields). The one exception is the `sha256` map of `analysis.sources`, keyed by CAS snapshot
  file paths, whose keys must still be path-shaped tokens. Raw-content names (`result`,
  `errors`, `input`, ...) are always dropped. Unknown keys, including token-shaped ones, are
  omitted.
- Kept by design: query counts, cleanup evidence, fixed CAS values, known usage provenance and
  normal source-grounded success. Dropped diagnostic precision is the accepted trade-off; new
  CAS fields must be added to the lists deliberately.

The worker validates provider text against the sources embedded in the request instructions
before writing `response.json`. This is transient and does not replace the parent: the adapter
still validates source/AST/line/hash coverage itself. No report is ever fabricated from
untrusted output; rejected output yields `analysis_invalid_response` / `analysis_invalid_report`.

`SnapshotSDKAdapter` refuses to run if the recorder has no active privacy policy.

## Unchanged

Gate closed before provider/auth construction, one-shot consumption, query-count and cleanup
evidence, cancelled vs. interrupted semantics, the existing non-analysis behaviour. Old approval
fingerprints are not refreshed by this change and grant no permission.

## Changed files

`providers/claude/{client,worker,supervised}.py`, `telemetry/{recorder,events}.py`,
`tasks/repository_analysis_sdk.py`, new `tasks/analysis_privacy.py`, tests
`test_analysis_privacy.py`, `test_repository_analysis_sdk.py`, `test_claude_adapter.py`,
`test_recorder.py`, and this document.

## Test plan (offline, not run by the implementing session)

Guarded Python 3.12.9 `-B -I -S` with `tools/sdk_bootstrap.py`: `test_analysis_privacy`,
`test_repository_analysis_sdk`, `test_claude_adapter`, `test_recorder`, `test_supervision`, then
the full runtime and console suites, Node analysis/usage DOM, Ruff/format/security checks, and
`python tools/check_docs.py` in the umbrella. `test_analysis_privacy` uses a mocked SDK client
and auth, runs the real worker `main` in-process (no subprocess), and scans only generated
synthetic roots for token-shaped canaries in `errors`, `result` (native error and invalid
success), exception text, tool input/output and nested init data, plus a token-shaped canary used
as a `usage` dictionary key, on both the direct-client and worker routes.

Fixture notes: `subprocess.Popen` stays patched to raise; `platform.system` and
`platform.python_version` are mocked so Recorder construction does not trip that guard. The scan
skips only `.execution.lock` (held open by the test-owned controller, no producer data). The
tampering test treats the attacker-written private `worker/` files as untrusted input and scans
only parent-produced files. The non-analysis regression in `test_claude_adapter` uses a
`root/workspaces/one` request; production workspace policy is unchanged.

Status of this repair: edited without a shell. None of the above has been run by the repairing
session; the coordinator runs it offline.

## Limitations

- Not executed here: this session had no shell, so no test, Ruff or docs check was run.
  Constructor fields assumed from the pinned SDK (`ResultMessage.errors`, `UserMessage(content=...)`)
  need confirmation by the first test run.
- Store/HTTP history/export live in other repositories and were not edited; they read only the
  files above, which are now projected. The tests scan generated files and the bundle export.
- Dropped provider detail (e.g. unknown `terminal_reason` values) is reduced to `"other"`, so
  some diagnostic precision is lost by design.
- `configuration` is CAS-authored and not projected; it is not a provider-text channel today.
- Historical consumed evidence is untouched. Source fingerprints change; old approvals must not
  be reused.
