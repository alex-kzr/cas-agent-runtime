"""Normalize known pinned SDK message blocks while preserving native evidence separately."""

from claude_agent_sdk import AssistantMessage, ToolResultBlock, ToolUseBlock, UserMessage

from agent_runtime.telemetry.metrics import ObservedUsage


def observe_message(message, recorder, usage: ObservedUsage) -> None:
    if isinstance(message, AssistantMessage):
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
