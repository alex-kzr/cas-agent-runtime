# Bounded coding fixture and task control

Runtime owns `tasks/coding.py`, fixed `tasks/testing_worker.py` and opt-in `tasks/control.py`.
Only calc.py with one pure arithmetic `def add(a, b)` is editable. The profile exposes
three SDK MCP tools, no native builtins/shell. AST, size/path/link checks and fixed commands
are application controls, not an OS sandbox. Test source is executed from the exact
validated snapshot with empty builtins. At most three tests run for five seconds each,
using existing Windows Job ownership and three-second cleanup observation.

Coding acceptance requires validated test results for the exact final hash plus a diff;
explicit continuation may verify a no-op. Before/after, diff, coding/test results use the
existing artifact manifest and download integrity checks. Missing/corrupt/rejected output
never passes. Partial snapshots are retained after interruption only when safe cleanup
is confirmed. Existing SDK task/scenario execution remains the sole execution engine.

TaskControl persists single-use drafts, excludes duplicate starts and concurrent console
owners, requires two fresh per-run consents, and reconciles a lost writer without replay.
Continuation rechecks terminal run/session, subscription profile, cleanup and workspace hash
before preparing and starting a distinct run. The SDK resume option is passed explicitly;
missing session failure never becomes an automatic new query. Native resume is unverified.

Install console into this runtime environment to use `cas-cli console --enable-tasks`.
The umbrella guide docs/guides/CODING_CONSOLE.md has exact local install/start instructions.
No production flag selects a fake provider. `tools/coding_browser_server.py` in umbrella
is an explicitly test-only harness with injected scripted adapter and synthetic data.

Offline commands from this component:

```powershell
uv run --locked --offline python -m unittest discover -s tests -v
uv run --locked --offline ruff check src tests
uv run --locked --offline ruff check src --select S
uv build --offline
```

These verify application behavior only. No Claude/auth/model call is needed for tests.
Context isolation stays unverified; future native coding E2E requires separate approval.

## Subsequent one-shot native positive

CAS-CODING-LIVE-001 subsequently verified the fixed coding path through production UI once, using unchanged source `133bfbf`. Read/write/tests ran once each, three exact-source checks passed, native outcome succeeded and forced cleanup observed an empty tree. SDK estimate is not billing evidence. Native resume, denied paths and broad context isolation remain pending. Snapshot export uses CRLF while tested source uses LF; raw-byte equality is not claimed. See umbrella docs/research/CODING_E2E_RESULT_2026-10-14.md; approval is consumed.

## Offline session/restart hardening

Current snapshots preserve exact LF/CRLF source bytes. Main init/session identity is persisted immediately; child streams cannot replace it. Explicit resume with missing/mismatched Result identity or reset fails acceptance while native outcome/cost remain recorded. Restart reconciles canonical terminal status and consumes old claims without replay. Continuation eligibility is read-only local evidence, not native history validation. Tests use mocked SDK replies; real native resume remains pending. See umbrella docs/review/SESSION_RECOVERY_2026-10-14.md. Historical live data and approval manifests are unchanged; their old scope cannot authorize current source.
