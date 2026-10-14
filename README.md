# agent-runtime

The core execution application: cas-cli, one task/scenario executor, direct Claude SDK integration, lifecycle, native-session association, permissions/hooks, telemetry, task validation and reports.

**Status: local repository scaffold only.** No executable application, CLI, SDK/MCP
integration or service has been implemented. The suggested remote name `cas-agent-runtime`
is not a confirmed repository URL. No remote is configured or published.

This repository owns its application source, dependencies, tests, lockfile and local
documentation. Cross-project requirements and proposed v1 contracts live in the CAS
umbrella repository supplied by the owner: <https://github.com/alex-kzr/claude-agent-sdk>.
Use its `docs/contracts/DATA_CONTRACT.md` and `docs/plans/2026-10-14-cas-foundation.md`
from a known umbrella commit; remote file availability has not been verified.

## Development direction

Use Python 3.12+, a future `src/agent_runtime/` package and `tests/` directory as real code
is added. No empty module tree or placeholder executable is supplied. `pyproject.toml`
is metadata, with no build backend, entry point or runtime dependency yet. Add only
the dependencies the first implementation needs, generate/review `uv.lock`, and then
document `uv sync --locked`. Do not claim installability before packaging is tested.

Do not run models, activate credentials, start Docker, expose diagnostics or publish
this repository during scaffolding. Review [component acceptance](docs/IMPLEMENTATION.md).
