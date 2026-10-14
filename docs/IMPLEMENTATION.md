# Implementation handoff

Start with contract/config fixtures and an offline doctor, then one bounded SDK adapter spike. Implement one executor before task/scenario adapters; cancellation/resume need explicit evidence. Only expose cas-cli commands after real behavior exists. The SDK candidate is 0.2.165, uninstalled/unverified; inspect tagged API before pinning.

This repository has no tests or runtime code yet. Add meaningful deterministic tests
before integration behavior; live SDK tests are a separate opt-in tier. Record exact
commands and prerequisites here when they exist. Read the umbrella requirements,
contract v1 proposal, security guide and scenario catalog before implementation.
Preserve the repository boundary and independent dependency history. No orchestration
framework or speculative provider abstraction is permitted by SPEC.
