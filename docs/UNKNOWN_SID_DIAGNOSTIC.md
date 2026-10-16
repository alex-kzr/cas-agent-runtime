# Opt-in unknown-SID diagnostic

Only scenario sdk.sessions.unknown-sid-negative observes a bounded exact pinned CLI
rejection literal. stderr and native is_error ResultMessage.errors may supply it;
success text never does. The prefix must match the requested resume SID exactly, so
generic ProcessError, MCP's Session not found, another SID or prefixed prose do not
qualify. One fixed reason/source/contract tag is stored, with no raw stderr or SID.

This is diagnostic instrumentation on the production adapter, not a new provider or
SDK engine. Ordinary scenarios retain their existing discarded-stderr behavior. CLI
delivery is not guaranteed: missing/ambiguous reason must remain inconclusive. A tag
observes the pinned CLI's reported rejection, not independent native-store absence.

The separate umbrella harness is closed pending specific live/existing-login consent;
no unknown-SID native test has been executed. Test fixtures mock SDK streams or use
ordinary owned Python only. No existing consumed scope/marker is reset. A future
activation must bind changed source with a new fingerprint; old activation bytes no
longer describe this instrumented client.
