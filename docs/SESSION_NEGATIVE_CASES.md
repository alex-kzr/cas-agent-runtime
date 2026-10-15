# Synthetic SES-01 negatives

These are selectable Python test scenarios, not CLI-selectable fake providers or
evidence of native missing-session behavior. They reuse MockStream/result from
tests/test_session_contract.py, the production ClaudeAdapter/Executor and existing
TaskControl interrupted-start fixture. The SDK client factory returns a test double;
the API string is synthetic and subprocess/status boundaries reject accidental escape.
No real SDK connection, auth/status, model, native history or credential lookup occurs.

| Stable case ID | Fixture variants | Required observations |
|---|---|---|
| SES-01-missing-session-local | Mock stream raises missing-session RuntimeError; empty stream | Resumed scenario FAILED/partial, one mock query, retryable=false, old run byte-identical, explicit resume remains set with no continue/fork fallback |
| SES-01-sid-mismatch-local | Wrong init SID; wrong terminal SID after correct init | FAILED/partial despite native-shaped success; expected SID retained, old run unchanged, one mock query; observed cost/outcome retained on terminal mismatch |
| SES-01-no-replay-local | Reconcile/reopen after failed run; controller restart with own temporary consumed claim | No new query/client/adapter, failed snapshot/old run preserved, interrupted draft cannot start and fixture claim unchanged |

Run from the runtime checkout with its existing environment:

```powershell
python -m unittest discover -s tests -p test_scenario_sessions.py -v
python -m unittest discover -s tests -p test_scenario_sessions.py -k missing_session -v
python -m unittest discover -s tests -p test_scenario_sessions.py -k sid_mismatch -v
python -m unittest discover -s tests -p test_scenario_sessions.py -k replay -v
```

Each expected negative runtime execution remains FAILED. A passing unittest means
the failure policy held, not that the native model/session succeeded. Scenario records
use scenario_id and have null task_id; distinct run IDs preserve explicit previous-run
links. Mock-shaped SDK outcomes are confined to disposable test directories and must
not be promoted to live capability evidence. These tests are not added to the normal
CAS scenario catalog because its model-facing path must not select a simulated provider.

The separate real -02 positive remains valid only for its recorded versions/configuration.
Native missing/deleted-store, wrong/reset SID, fork, moved workspace, longer-term
durability and retry/side-effect behavior require separately authorized live evidence.

## Cleanup policy fixture

The existing test_normal_worker_exit_still_cleans_leftover_descendant now uses base
Python -B -I -S and an owned harmless sleeping Python child, retaining its PID in a
temporary fixture file. It proves parent exit 0 can coexist with forced=true and
tree_empty=true, and checks that exact owned child exited. No native process is used.

OwnedProcess immediately terminates remaining Job members after the direct child
finishes; its 3s limit bounds cleanup/emptiness observation, not a preliminary graceful
wait. Saved -02 receipts contain no descendant PID/name or disconnect timing, so they
cannot identify which process remained or prove an SDK graceful-shutdown defect.
