"""Normalize known pinned SDK message blocks while preserving native evidence separately."""

import re

from claude_agent_sdk import (
    AssistantMessage,
    SystemMessage,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from agent_runtime.telemetry.metrics import ObservedUsage


def observe_message(message, recorder, usage: ObservedUsage) -> None:
    child = bool(getattr(message, "parent_tool_use_id", None))
    if isinstance(message, SystemMessage):
        child = child or bool(message.data.get("parent_tool_use_id"))
    if child:
        recorder.record["configuration"]["subagent_activity_observed"] = True
    if recorder.record["configuration"].get("subagent_activity_observed") is True:
        usage.subagents_observed = True
    if isinstance(message, SystemMessage) and message.subtype == "init":
        if message.data.get("parent_tool_use_id"):
            return
        version = message.data.get("claude_code_version")
        if (
            isinstance(version, str)
            and len(version) <= 64
            and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?", version)
        ):
            previous = recorder.record["provider"]["cli_version"]
            if previous is None:
                recorder.record["provider"]["cli_version"] = version
                recorder.record["configuration"]["cli_version_source"] = "sdk-init"
                recorder.event(
                    "provider.metadata",
                    {"field": "cli_version", "value": version, "provenance": "sdk-init"},
                    "sdk",
                )
            elif previous != version:
                recorder.record["configuration"]["cli_version_conflict"] = True
                recorder.event(
                    "provider.metadata_conflict",
                    {
                        "field": "cli_version",
                        "retained": previous,
                        "observed": version,
                        "provenance": "sdk-init",
                    },
                    "sdk",
                )
    elif isinstance(message, AssistantMessage):
        if message.parent_tool_use_id:
            recorder.event(
                "subagent.model",
                {
                    "model": message.model,
                    "parent_tool_use_id": message.parent_tool_use_id,
                    "agent_id": None,
                    "provenance": "sdk-assistant-block",
                },
                "sdk",
            )
        else:
            recorder.record["provider"]["resolved_model"] = message.model
        usage.observe(message.message_id, message.usage, subagent=bool(message.parent_tool_use_id))
        recorder.record["usage"]["application"] = usage.snapshot()
        for block in message.content:
            if isinstance(block, ToolUseBlock):
                recorder.event(
                    "tool.request",
                    {
                        "tool_use_id": block.id,
                        "tool_name": block.name,
                        "input": block.input,
                        "parent_tool_use_id": message.parent_tool_use_id,
                        "provenance": "sdk-assistant-block",
                    },
                    "sdk",
                )
    elif isinstance(message, UserMessage) and isinstance(message.content, list):
        for block in message.content:
            if isinstance(block, ToolResultBlock):
                recorder.event(
                    "tool.result",
                    {
                        "tool_use_id": block.tool_use_id,
                        "content": block.content,
                        "is_error": block.is_error,
                        "parent_tool_use_id": message.parent_tool_use_id,
                        "provenance": "sdk-user-block",
                    },
                    "sdk",
                )
