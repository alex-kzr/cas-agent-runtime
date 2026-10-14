# Verified offline SDK baseline

2026-10-14, Windows, Python 3.12.9, uv 0.12.17. Direct dependency
`claude-agent-sdk==0.2.165` is resolved from the official PyPI index in `uv.lock`.
SDK requirements and tagged API were checked against the official
[tagged source](https://github.com/anthropics/claude-agent-sdk-python/tree/v0.2.165).
The installed bundled executable reports `2.1.294 (Claude Code)` through `--version`.
No SDK client, credentials or model session was started for baseline verification.

`uv run --locked --offline python -m unittest discover -s tests -p test_baseline.py -v`
passes three checks: installed exact SDK version and required option fields, async
client control/result surface, and rejection of unknown constructor options. These are
offline API-surface checks, not evidence for live permissions, cancellation or sessions.

The application uses Hatchling with `src/agent_runtime`; `jsonschema` is explicitly
declared because CAS directly validates its own persisted contracts. Ruff is a dev-only
dependency. Transitive MCP and HTTP/server dependencies come from SDK metadata, not
from adding an orchestration framework. Each component retains its own dependency graph.
Never launch the SDK CLI as a diagnostic except its side-effect-free `--version` check.
