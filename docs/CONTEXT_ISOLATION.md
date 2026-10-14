# Requested context policy

`literal-input-no-discovery-v1` is a versioned CAS request policy, not a native isolation
guarantee. See [implementation](../src/agent_runtime/providers/claude/context.py) and
[offline serializer regressions](../tests/test_context_isolation.py).

Both auth profiles retain explicit empty settings sources/skills/plugins, strict empty
MCP configuration and their existing tool permissions. They now request:

- `--disable-slash-commands` and literal `verbatim_prompts=True`;
- `autoMemoryEnabled:false` and fixed `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`;
- `disableBundledSkills:true` and fixed `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS=1`;
- `claudeMdExcludes:["**"]` for nonmanaged instructions;
- exact `enabledPlugins:false` entries for `cc-plugin-agents-md@builtin` and
  `cc-plugin-plugin-authoring@builtin`, observed in pinned native 2.1.294.

These are session/child-process controls. The existing subscription directory and
`forceLoginMethod=claudeai` remain selected; CAS does not edit native settings or copy
credentials. No `--bare`/`CLAUDE_CODE_SIMPLE` is selected because it disables subscription
login. No `CLAUDE_CODE_DISABLE_CLAUDE_MDS` is selected because its native loader also
suppresses managed instructions. Managed policy still applies and can affect behavior.

The SDK `plugins=[]` means no extra plugin directories, not all builtins off. The empty
skills filter is actually sent in initialize, while native init may still advertise
entries. The exact two overrides do not cover all future/current builtins. `verbatim_prompts`
skips the entire turn-start attachment pass; attachment handling between tool calls
remains, particularly relevant to the opt-in Read profile. Task text is now literal;
`@path` and `/command` are not native expansion instructions.

`configuration.context_policy` and `context.configured` describe requests, never proof.
`context.observed` has count-only native init advertisements with unknown content and
`context_isolation=unverified`. Missing fields stay null; empty lists never prove zero
loaded or transmitted content. This helper opens no metadata paths. Existing bounded
native events still require reviewed redaction before sharing raw runs.

Offline checks from the component root:

```powershell
uv run --locked --offline python tools/inspect_context_source.py
uv run --locked --offline python -m unittest discover -s tests -p test_context_isolation.py -v
```

The inspector maps the binary as data; it never executes CLI/auth. Its hashes/markers
support pinned source review, not runtime guarantees. The umbrella research report is
`docs/research/CONTEXT_ISOLATION_2026-10-14.md`, with source references, offsets and a
separately gated next-probe proposal. New controls have no live evidence yet. Existing
query consent is spent. Native initialization/diagnostics and inference require new
bounded approval; no automatic repeat or fallback is implied.

The separate `agent_runtime.providers.claude.context_probe` module is now prepared,
with no query call, a two-control outgoing protocol fence, count-only output and the
existing Windows supervisor. Both native-startup and existing-login flags plus a
reviewed composite source/executable hash are mandatory. No setup/default command
runs it. Consult umbrella `docs/research/CONTEXT_PROBE_APPROVAL_SCOPE.md` before any
new consent; it explains native profile/network risks beyond the CAS protocol boundary.

## Subsequently authorized diagnostic result

The separately approved probe was subsequently executed exactly once on 2026-10-14
against source `6e18318`, with all 59 manifest entries verified. It returned observed:
one initialize/one context request, zero user frames; pre-query accounting reported
10 total tokens, zero memory files/tokens, MCP tools and agents. Forced Windows Job
cleanup observed the owned tree empty. The umbrella report is
`docs/research/CONTEXT_PROBE_RESULT_2026-10-14.md` (CAS-CTX-PROBE-001).
This does not prove builtin unload, native file/wire isolation, causal control effects
or zero billing. The one-shot approval is consumed; do not rerun on this authority.
