# Offline repository analysis profile

`agent_runtime.tasks.repository_analysis` adds an owned two-file sample workflow
through the existing Executor. It is an application/offline scenario, not an SDK
provider, native model response or general repository scanner.

The only repository is Tiny Shop: `README.md` and `inventory.py`, created once inside
the dedicated data directory. No source editing, shell, recursive discovery, network
tool, auth store or arbitrary workspace path is exposed. Reads reject symlinks,
junctions, hardlinks, extra files, oversized files and changed source bytes. Each
started run stores an exact source snapshot; report/source download revalidates it.

`expected_fixture_output()` supplies explicit scripted observations. A separate
validator parses Python AST and the README title, requiring complete/unique known
claims, exact return expressions, approved filenames, integer definition lines and
matching source hashes. Missing, duplicate, invented, altered-expression, path-escape
or hash-mismatched claims fail before acceptance. This is source-fact validation for
the small supported grammar, not a general proof of arbitrary prose correctness.

Canonical execution uses kind=scenario, provider=local-validation, application source,
sdk_outcome=null and model_requests=0. Scenario assertions record source-grounded
acceptance. The existing wrapper's text-nonempty validator is not the substantive
validator; malformed reports raise before producing an accepted result. Native usage
and cost remain unavailable, not fabricated zero SDK token/cost measurements.

Control records and a validated report checkpoint are persisted atomically. A started
claim cannot replay. Reload leaves DRAFT untouched; restart restores a matching
terminal canonical state/report checkpoint or marks a lost writer INTERRUPTED without
running it again. Report access rechecks canonical identity, local provenance and
source facts. Reports retain run ID, file references and source hashes. ZIP includes
`report.md`, `report.json`, `files/README.md` and `files/inventory.py`.

Stop cancels the local asyncio execution. This profile never starts children, so its
finally block records in-process/no-children cleanup; Executor requires cleanup before
CANCELLED. There is no native cancellation flag or provider interruption claim. The
consumed real-stream -04 experiment and its semantics remain unchanged.

Only a fresh dedicated data directory (or a previously initialized analysis-profile
directory) is accepted. Do not point this profile at historical CAS/native stores.
The controls are application checks for trusted local use, not an OS sandbox.

Tests: `tests/test_repository_analysis.py`; use the installed runtime environment or
the umbrella fixed-import bootstrap. Existing component unittest discovery includes
the new tests. No native model/auth call is a test prerequisite. No dependencies,
schemas, existing Executor code or runtime CLI defaults changed.

Future live analysis requires a separately approved input allowlist/workspace snapshot,
new model/prompt/limit/auth/transport scope and independent live result validation.
There is no live switch in this profile; earlier consumed approvals cannot enable it.


## Default-closed SDK path (mock verified)

The same analysis page now accepts explicit nonempty checkbox selection of the two
allowlisted Tiny Shop files. Preparation captures only selected synthetic bytes with
per-file and combined SHA-256. Paths, links, duplicates, changed content and files over
8 KiB are rejected; aggregate source limit is 16 KiB. No arbitrary repository path or
upload is accepted. Legacy offline create/start requests remain supported.

Choose SDK payload preview, prepare a draft, then Review SDK payload. The literal
query, fixed model, recipient and limits are displayed with two fresh unchecked
consents. SDK Start remains disabled while the source gate is false; the backend
rejects even crafted consent requests before run claims or provider construction.
There is no CLI/environment/API switch that activates it.

SnapshotSDKAdapter delegates to the existing SupervisedClaudeAdapter and Executor.
One query/turn, USD 0.02 SDK threshold, 30-second executor timeout, text-only tools
and empty SDK workspace are enforced. One SDK attempt is consumed per dedicated
analysis directory. Strict bounded JSON parsing and independent heading/AST, path,
line/hash/coverage checks decide report acceptance. Native success alone is insufficient.
Accepted reports/checkpoints and selected sources survive restart and export as ZIP.
Mock reports explicitly identify mock provenance and zero real model requests.

Stop uses actual local task cancellation and existing owned-process cleanup. CANCELLED
requires confirmed empty cleanup; unknown cleanup/timeout is INTERRUPTED. Neither
status proves provider cancellation or stopped billing. Invalid reports and raw SDK
errors are not published as accepted reports; public errors use safe codes. Source
snapshots are revalidated before checkpoint/export. No replay or retry is automatic.

Live/native/auth behavior has not been exercised for this path. The single future
scope and fresh-session review handoff live in the umbrella
`docs/review/REPOSITORY_ANALYSIS_SDK_2026-10-17.md`. Keep the gate closed pending that
review and separate explicit approval. No new framework/dependency is introduced.
