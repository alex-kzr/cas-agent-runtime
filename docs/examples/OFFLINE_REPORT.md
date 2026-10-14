# Recorded offline report-export example

Date: 2026-10-14. This is a real application contract scenario and report export, not
a model response or a practical repository-analysis task. No SDK/native client,
authentication command, native session store, model, installation or synchronization
was used. Follow the umbrella `docs/guides/OFFLINE_OPERATIONS.md` runbook for a new run.

The existing runtime Python 3.12.9 interpreter executed the current source through
`-B -m agent_runtime --root <umbrella> --data-dir <new-temporary-data>`.
The new data directory was outside the source checkout, below the delegated task root.
The verification subprocess received a small system environment plus the selected source
path; no provider/auth variables were forwarded. Global settings were not changed.

| Command suffix | Observed exit code |
| --- | --- |
| `scenarios run platform.contracts` | 0 |
| `runs inspect 5def4645-3e70-4d70-a1c9-84d2532d2e65` | 0 |
| `runs list` | 0 |
| `report 5def4645-3e70-4d70-a1c9-84d2532d2e65` | 0 |
| `report 00000000-0000-4000-8000-000000000099` | 2; JSON FileNotFoundError; no report directory created |

Exported report envelope: `schema_version: 1`, `run`, `warning`. Selected actual run
fields are shown below; omitted fields and machine-specific paths are not reproduced.
The excerpt is not a complete machine-valid run fixture.

```json
{
  "run_id": "5def4645-3e70-4d70-a1c9-84d2532d2e65",
  "kind": "scenario",
  "scenario_id": "platform.contracts",
  "status": "COMPLETED",
  "provider": {"name": "local-validation"},
  "session_id": null,
  "sdk_outcome": null,
  "usage": {"sdk": null},
  "validation": {
    "status": "passed",
    "validator_version": "text-nonempty-v1",
    "checks": [{"id": "nonempty-result", "passed": true}]
  }
}
```

The scenario validates the current v1 run and records the separate
`unknown-major-rejected` assertion with outcome `pass`. The text validator above is not
itself proof of that assertion. Inspect both the run and its `assertions.json` when
reviewing scenario acceptance.

SHA-256 of the original local export:
`634d99b88f5de4c9bbb4f753b815750be207ce7474f0b5fb24a71fe21454db06`.
Different runs contain new UUIDs, timestamps and local paths, so they will have different
digests. Raw records and their verification summary remain in the temporary data directory
and are not committed. The digest identifies that local export; it does not independently
certify its contents or establish native SDK support.

An initial sandboxed interpreter attempt timed out before evidence was produced; the
authorized existing-interpreter execution completed. That environment restriction is not
recorded as application failure. The missing-record check's observed exit code is 2.

No task model call follows from this document. S-02's live practical-task and remote
clone/install acceptance remain open. Native usage/session/cost remain unavailable here;
application elapsed time is not provider billing.
