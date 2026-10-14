# Implementation status

The first local agent-runtime implementation is available. Its README defines exact install,
test and build commands; package dependencies are independently locked. No remote has
been configured. The initial offline implementation stage made no model call or external publication. A subsequent explicitly authorized subscription baseline is recorded in umbrella docs/research/SUBSCRIPTION_BASELINE_2026-10-14.md: exact marker, two assertions pass, zero tools, forced owned-tree cleanup. Native builtin context metadata, derived usage and CLI-version propagation gaps remain open. No further live call or publication is authorized by that evidence.

See umbrella docs/review/IMPLEMENTATION.md for cross-component evidence and remaining
limitations. Application changes belong in this repository, shared contracts and research
conclusions in umbrella. Offline test results never establish native SDK/model behavior.

The subsequent [context policy](CONTEXT_ISOLATION.md) investigation uses installed
SDK/native static source and saved safe metadata only. Six regression cases verify
real SDK serialization, environment controls and metadata semantics. The full suite
passed 96 tests; Ruff including security selection and wheel/sdist build passed. No
native CLI/auth/model was started for this follow-up. No live capability is promoted.

## Prepared native probe, never executed

A separately gated diagnostic module now uses the existing supervisor and direct SDK
connect/context control only. It has no query call; the outgoing transport rejects user
frames and all but one initialize/one context request. The parent and worker verify a
composite manifest of reviewed source/SDK/lock/executable files. Counts/tokens are
whitelisted twice and unknown cleanup stays inconclusive. Native profile/content/network
behavior is not proved by the fence; see the separate umbrella approval scope. Full
offline suite: 106 tests in 12.579 seconds, lint/security/build pass. No probe/native
auth/model was used for verification.
