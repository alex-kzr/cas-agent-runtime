# agent-runtime

CAS manual task/scenario CLI using Claude Agent SDK directly. Python 3.12+, independent
`uv.lock`, Hatchling package. SDK is pinned at 0.2.165; no orchestration framework.

```powershell
uv sync --locked
uv run --locked --offline cas-cli doctor
uv run --locked --offline cas-cli scenarios list
uv run --locked --offline cas-cli scenarios run platform.contracts
uv run --locked --offline cas-cli scenarios run platform.redaction
uv run --locked --offline cas-cli runs list
uv run --locked --offline python -m unittest discover -s tests -v
uv run --locked --offline ruff check src tests
uv run --locked --offline ruff check src --select S
uv build --offline
```

Root is discovered from this checkout's ancestors; installed wheels need `--root <umbrella>`.
Global `--root`/`--data-dir` precede commands. CAS data is ignored outside source and
components keep independent histories. No remote is configured or published yet.

The same executor handles manual tasks and real local validation scenarios. Local runs
have provider `local-validation`, null SDK outcome/usage and real assertion evidence.
There is no selectable fake task provider. Unit tests explicitly inject test doubles.

Live tasks require `task run --file task.md --allow-live --max-turns N --max-budget-usd B`,
positive wall timeout and explicit auth-profile prerequisites. Do not run this as a setup check.
No live model has been called. Default `text-only-v1` disables every tool. Optional `--agent read-only-v1 --workspace
<directory-under-CAS-workspace-root>` permits only bounded Read, with path/secret-file
policy and explicit deny on filesystem errors. Both profiles disable MCP/skills/plugins
and accept nonempty text only; native tool enforcement remains unverified.
Timeouts/interrupts are INTERRUPTED; `runs recover` marks abandoned records without retry.
Resume, automatic retries, scheduler and production isolation are not implemented.

Console launch requires the independent agent-console environment. Canonical contracts,
security requirements and research scope live in umbrella docs, with byte-identical
schema snapshots packaged here. See [baseline evidence](docs/BASELINE.md).

## Prepared native baseline (requires separate authorization)

After explicit spend approval and an externally supplied native key, the prepared
command is `cas-cli --auth-mode api scenarios run sdk.fundamentals --model claude-haiku-5-5 --allow-live --max-turns 1
--max-budget-usd 0.10 --timeout-seconds 60` (one shell line). These are example
limits for operator review, not authorization to run. Both the exact baseline marker
and successful native result must pass; missing native fields remain unknown.

Offline research preparation adds `platform.structured-output`, `platform.usage` and
`platform.permissions`. They validate CAS policy/accounting/validation with synthetic
fixtures, never native model behavior. Failed checks persist failed assertions.

## Bounded worker cleanup (Windows)

CLI live execution now supervises the direct SDK adapter in a private worker. It starts
suspended, receives its Windows Job Object, resumes, then reads bounded private stdin.
At deadline, cancellation or worker exit, remaining owned descendants are terminated;
exit observation has a separate 3-second deadline. Cleanup status/duration are persisted.
Unknown cleanup is INTERRUPTED; timeout stays INTERRUPTED even if the tree was reaped.
This does not guarantee provider-side cancellation, a hard invoice ceiling, or total
CLI completion within the worker deadline plus cleanup grace. Supervised live execution
fails closed outside Windows. Offline commands and the single executor remain available.

Current auth policy: **subscription by default**, with separate per-invocation
`--allow-existing-login` and `--allow-live` consent. Explicit `--auth-mode api` retains
external-key execution with isolated state. No fallback between profiles, login, token
copy or persistent reuse grant is automatic. Doctor reports selected mode without
opening the native store. Native status/model behavior remains live-unverified.
