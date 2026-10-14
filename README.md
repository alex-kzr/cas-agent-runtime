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
positive wall timeout and external `ANTHROPIC_API_KEY`. Do not run this as a setup check.
No live model has been called. Default `text-only-v1` disables every tool. Optional `--agent read-only-v1 --workspace
<directory-under-CAS-workspace-root>` permits only bounded Read, with path/secret-file
policy and explicit deny on filesystem errors. Both profiles disable MCP/skills/plugins
and accept nonempty text only; native tool enforcement remains unverified.
Timeouts/interrupts are INTERRUPTED; `runs recover` marks abandoned records without retry.
Resume, automatic retries, scheduler and production isolation are not implemented.

Console launch requires the independent agent-console environment. Canonical contracts,
security requirements and research scope live in umbrella docs, with byte-identical
schema snapshots packaged here. See [baseline evidence](docs/BASELINE.md).
