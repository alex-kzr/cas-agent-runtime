"""Bounded direct SDK client with explicit text-only or single-file read profile."""

from __future__ import annotations

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

from agent_runtime.providers.claude.permissions import read_allowed
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import ExecutionRequest
from agent_runtime.telemetry.recorder import Recorder

SYSTEM_ENV = {
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "APPDATA",
    "LANG",
}


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

        # SDK merges os.environ before options.env. Explicitly blank unapproved inherited
        # variables so external credentials/endpoints/settings do not leak to the child.
        environment = {key: "" for key in os.environ if key.upper() not in SYSTEM_ENV}
        environment.update(
            {key: value for key, value in self.environment.items() if key.upper() in SYSTEM_ENV}
        )
        environment["ANTHROPIC_API_KEY"] = self.environment.get("ANTHROPIC_API_KEY", "")
        environment["CLAUDE_CONFIG_DIR"] = str(recorder.directory / "sdk-state")
        return ClaudeAgentOptions(
            tools=["Read"] if request.agent_name == "read-only-v1" else [],
            allowed_tools=[],
            setting_sources=[],
            skills=[],
            plugins=[],
            mcp_servers={},
            strict_mcp_config=True,
            permission_mode="default",
            can_use_tool=decide,
            hooks={"PreToolUse": [HookMatcher(hooks=[before_tool])]},
            cwd=str(request.workspace),
            model=request.model,
            max_turns=request.limits.max_turns,
            max_budget_usd=float(request.limits.max_budget_usd),
            env=environment,
            include_partial_messages=True,
            stderr=lambda _: None,
        )

    async def run(self, request: ExecutionRequest, recorder: Recorder) -> NativeResult:
        if not request.live_authorized:
            raise PermissionError("Live model execution requires explicit --allow-live")
        if not self.environment.get("ANTHROPIC_API_KEY"):
            raise ValueError("ANTHROPIC_API_KEY must be supplied externally for a live run")
        result = None
        async with ClaudeSDKClient(options=self.options(request, recorder)) as client:
            await client.query(request.instructions)
            async for message in client.receive_response():
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
                    )
        if result is None:
            raise RuntimeError("SDK stream ended without a terminal ResultMessage")
        return result
