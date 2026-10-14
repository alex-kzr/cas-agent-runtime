"""Bounded direct SDK client with explicit text-only or single-file read profile."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
)

from agent_runtime.providers.claude.auth import (
    SUBSCRIPTION_SETTINGS,
    SYSTEM_ENV,
    auth_environment,
    native_cli,
    require_auth,
    subscription_status,
)
from agent_runtime.providers.claude.permissions import read_allowed
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import ExecutionRequest, sdk_succeeded
from agent_runtime.telemetry.events import observe_message
from agent_runtime.telemetry.metrics import ObservedUsage
from agent_runtime.telemetry.recorder import Recorder


class ClaudeAdapter:
    def __init__(self, environment: Mapping[str, str]):
        self.environment = dict(environment)

    def options(self, request: ExecutionRequest, recorder: Recorder) -> ClaudeAgentOptions:
        def permitted(name, arguments):
            return request.agent_name == "read-only-v1" and read_allowed(
                request.workspace, name, arguments
            )

        async def decide(name, arguments, context):
            allow = permitted(name, arguments)
            recorder.event(
                "permission.decision",
                {
                    "tool": name,
                    "decision": "allow" if allow else "deny",
                    "reason": request.agent_name,
                },
                "permission",
            )
            return (
                PermissionResultAllow(updated_input=arguments)
                if allow
                else PermissionResultDeny(message="CAS profile denies this tool request")
            )

        async def before_tool(input_data, tool_use_id, context):
            recorder.event("hook.callback", {"hook": "PreToolUse", "input": input_data}, "hook")
            allow = permitted(input_data.get("tool_name"), input_data.get("tool_input", {}))
            recorder.event(
                "tool.request",
                {
                    "tool_name": input_data.get("tool_name"),
                    "tool_use_id": tool_use_id,
                    "allowed": allow,
                },
                "hook",
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow" if allow else "deny",
                    "permissionDecisionReason": request.agent_name,
                }
            }

        async def after_tool(input_data, tool_use_id, context):
            recorder.event(
                "hook.callback",
                {"hook": input_data.get("hook_event_name"), "input": input_data},
                "hook",
            )
            recorder.event(
                "tool.result",
                {
                    "tool_use_id": tool_use_id,
                    "tool_name": input_data.get("tool_name"),
                    "result": input_data.get("tool_response"),
                    "error": input_data.get("error"),
                    "provenance": "sdk-hook",
                },
                "hook",
            )
            return {}

        async def subagent(input_data, tool_use_id, context):
            started = input_data.get("hook_event_name") == "SubagentStart"
            recorder.event(
                "subagent.started" if started else "subagent.stopped",
                {
                    "agent_id": input_data.get("agent_id"),
                    "agent_type": input_data.get("agent_type"),
                    "session_id": input_data.get("session_id"),
                    "provenance": "sdk-hook",
                },
                "hook",
            )
            return {}

        # SDK merges os.environ before options.env. Explicitly blank unapproved inherited
        # variables so external credentials/endpoints/settings do not leak to the child.
        environment = {key: "" for key in os.environ if key.upper() not in SYSTEM_ENV}
        environment.update(
            auth_environment(
                request,
                self.environment,
                recorder.directory / "sdk-state",
                forbidden_roots=(recorder.data_dir,),
            )
        )
        return ClaudeAgentOptions(
            cli_path=str(native_cli()),
            settings=json.dumps(SUBSCRIPTION_SETTINGS)
            if request.auth_mode == "subscription"
            else None,
            tools=["Read"] if request.agent_name == "read-only-v1" else [],
            allowed_tools=[],
            setting_sources=[],
            skills=[],
            plugins=[],
            mcp_servers={},
            strict_mcp_config=True,
            permission_mode="default",
            can_use_tool=decide,
            hooks={
                "PreToolUse": [HookMatcher(hooks=[before_tool])],
                "PostToolUse": [HookMatcher(hooks=[after_tool])],
                "PostToolUseFailure": [HookMatcher(hooks=[after_tool])],
                "SubagentStart": [HookMatcher(hooks=[subagent])],
                "SubagentStop": [HookMatcher(hooks=[subagent])],
            },
            cwd=str(request.workspace),
            model=request.model,
            max_turns=request.limits.max_turns,
            max_budget_usd=float(request.limits.max_budget_usd),
            env=environment,
            include_partial_messages=True,
            stderr=lambda _: None,
        )

    async def run(self, request: ExecutionRequest, recorder: Recorder) -> NativeResult:
        require_auth(request, self.environment)
        if request.auth_mode == "subscription":
            selected = auth_environment(
                request,
                self.environment,
                recorder.directory / "sdk-state",
                forbidden_roots=(recorder.data_dir,),
            )
            blocked = [
                name
                for name in os.environ
                if name.upper().startswith(("ANTHROPIC_", "CLAUDE_CODE_USE_"))
                and name.upper() != "ANTHROPIC_CONFIG_DIR"
            ]
            if blocked or "CLAUDE_CODE_OAUTH_TOKEN" in os.environ:
                raise ValueError(
                    "Subscription SDK requires sanitized worker environment; no fallback"
                )
            info = subscription_status(request, selected)
            recorder.record["configuration"].update(info)
            recorder.event("auth.selected", info)
        result = None
        observed_usage = ObservedUsage()
        async with ClaudeSDKClient(options=self.options(request, recorder)) as client:
            await client.query(request.instructions)
            async for message in client.receive_response():
                observe_message(message, recorder, observed_usage)
                payload = (
                    asdict(message) if is_dataclass(message) else {"type": type(message).__name__}
                )
                recorder.event(
                    "sdk.message",
                    {"message_type": type(message).__name__, "message": payload},
                    "sdk",
                )
                session_id = getattr(message, "session_id", None)
                if session_id:
                    recorder.record["session_id"] = session_id
                if isinstance(message, ResultMessage):
                    result = NativeResult(
                        message.result,
                        {
                            "subtype": message.subtype,
                            "is_error": message.is_error,
                            "terminal_reason": message.terminal_reason,
                        },
                        message.session_id,
                        {
                            "total_cost_usd": message.total_cost_usd,
                            "usage": message.usage,
                            "model_usage": asdict(message).get("model_usage"),
                            "scope": "sdk-call-native",
                            "estimate": True,
                        },
                        application_usage=observed_usage.snapshot(),
                    )
                    if request.scenario_id == "sdk.fundamentals":
                        observed = (message.result or "").strip()
                        check = {
                            "id": "exact-baseline-marker",
                            "expected": "CAS_SDK_BASELINE_OK",
                            "observed": observed,
                            "outcome": "pass" if observed == "CAS_SDK_BASELINE_OK" else "fail",
                            "evidence_refs": [f"runs/{recorder.run_id}/events.jsonl"],
                        }
                        from dataclasses import replace

                        native_ok = sdk_succeeded(result.outcome)
                        native_check = {
                            "id": "native-success",
                            "expected": True,
                            "observed": native_ok,
                            "outcome": "pass" if native_ok else "fail",
                            "evidence_refs": [f"runs/{recorder.run_id}/events.jsonl"],
                        }
                        result = replace(result, checks=[check, native_check])
                    # A subsequent native stream/context error must not erase already
                    # observed outcome/cost evidence from a failed run summary.
                    recorder.record["sdk_outcome"] = result.outcome
                    recorder.record["usage"]["sdk"] = result.usage
                # Worker-private snapshot retains observations even if native context
                # shutdown later stalls and the parent must terminate the process tree.
                recorder.save()
        if result is None:
            raise RuntimeError("SDK stream ended without a terminal ResultMessage")
        return result
