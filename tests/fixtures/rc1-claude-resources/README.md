# RC1 working_cells compatibility fixture

Read-only copy of `agent_runtime/providers/claude/working_cells/` extracted unchanged from the
RC1 release-candidate wheel `cas_agent_runtime-0.1.0-py3-none-any.whl`
(SHA-256 `bdf5d8a4928929d292902aac0aa337c2e52558f3e585f71e6ddd130e620034ee`). Used by
`test_single_task_working_session.CardinalityTests.test_retained_rc1_two_task_prepared_resources_still_verify_without_execution`
to prove current code still verifies resources prepared by RC1. Nothing here is executed.
Override with `CAS_HISTORIC_CLAUDE_RESOURCES=<.../agent_runtime/providers/claude>`.
