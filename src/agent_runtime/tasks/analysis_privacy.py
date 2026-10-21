"""Analysis-only disclosure policy applied before any durable write.

Allowlist, not scrubbing: provider text (result, errors, exceptions, tool payloads, nested SDK
fields) never becomes log/history content. Only bounded metadata survives: enumerated
outcomes, counts, sizes, numbers, validated identifiers and our own fixed messages.
"""

from __future__ import annotations

import hashlib
import json
import math
import re

from agent_runtime.tasks.models import sdk_succeeded

SCENARIO = "sdk.repository-analysis"
TOKEN = re.compile(r"[A-Za-z0-9_.:/+-]{1,96}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
MODEL = re.compile(r"claude-[a-z0-9][a-z0-9.-]{0,56}")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]{1,32})?")
SESSION = re.compile(r"[A-Za-z0-9_-]{1,128}")
WITHHELD = "Details withheld by analysis privacy policy"
INSTRUCTIONS_WITHHELD = "[withheld: analysis snapshot payload; see sha256 and size]"

MESSAGE_TYPES = frozenset(
    {
        "AssistantMessage",
        "UserMessage",
        "SystemMessage",
        "ResultMessage",
        "StreamEvent",
        "ConversationResetMessage",
    }
)
SUBTYPES = frozenset(
    {
        "success",
        "init",
        "error_max_turns",
        "error_during_execution",
        "error_max_budget_usd",
        "error_max_structured_output_retries",
    }
)
REASONS = frozenset(
    {
        "completed",
        "max_turns",
        "max_budget",
        "aborted_streaming",
        "aborted_tools",
        "blocking_limit",
        "model_error",
        "api_error",
        "prompt_too_long",
        "hook_stopped",
    }
)
TOOLS = frozenset(
    {
        "Read",
        "Write",
        "Edit",
        "Bash",
        "Glob",
        "Grep",
        "WebFetch",
        "WebSearch",
        "Task",
        "NotebookEdit",
    }
)
HOOKS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "SubagentStart",
        "SubagentStop",
    }
)
ANALYSIS_CODES = frozenset(
    {
        "analysis_query_count_exceeded",
        "analysis_sdk_unsuccessful",
        "analysis_invalid_response",
        "analysis_invalid_report",
        "analysis_sdk_failed",
        "analysis_response_withheld",
    }
)
# Messages produced by CAS code itself; provider text can never equal an entry by accident.
FIXED_TEXT = frozenset(
    {
        "Execution did not meet acceptance",
        "Wall timeout; external cleanup unverified",
        "Operator cancelled; owned tree empty",
        "Interrupted; external cleanup unverified",
        "Owned SDK worker cleanup was not confirmed",
        "Previous CAS writer is no longer active; effects may remain",
        "Resumed or subagent totals may have different scopes; deltas withheld.",
        "Observed equality/difference does not establish complete usage or billing.",
        "Usage without a stable native message ID was not summed",
        "Conflicting usage for a duplicate message ID; first observation retained",
        "Observed usage identity limit reached; further usage not summed",
        "Missing or invalid token fields; observed accounting is partial",
        "Worker evidence import failed",
        WITHHELD,
    }
)
# Provider-controlled usage maps may hold strings only for these exact CAS-set pairs.
KNOWN_PAIRS = frozenset({("scope", "sdk-call-native")})
RAW_KEYS = frozenset(
    {
        "input",
        "content",
        "result",
        "error",
        "errors",
        "text",
        "tool_response",
        "tool_input",
        "data",
        "output",
        "prompt",
        "stderr",
        "exception",
        "message",
    }
)
# Finite key policy. A key is data too: provider-controlled maps may only keep names listed here
# (or a model label of the exact claude-<family>-<version> shape); a shape check alone is never
# a reason to keep a key.
USAGE_KEYS = frozenset(
    {
        "total_cost_usd",
        "usage",
        "model_usage",
        "scope",
        "estimate",
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "server_tool_use",
        "web_search_requests",
        "web_fetch_requests",
        "cache_creation",
        "ephemeral_5m_input_tokens",
        "ephemeral_1h_input_tokens",
        "inputTokens",
        "outputTokens",
        "cacheReadInputTokens",
        "cacheCreationInputTokens",
        "webSearchRequests",
        "costUSD",
        "contextWindow",
        "maxOutputTokens",
    }
)
MODEL_LABEL = re.compile(r"claude-(?:haiku|sonnet|opus|fable)-\d+(?:[.-]\d+){0,2}(?:-\d{8})?")
# CAS-authored application/event fields (usage.application, comparison, cleanup, fixed events).
STRUCTURE_KEYS = frozenset(
    {
        "observed_main_loop_tokens",
        "observed_message_count",
        "scope",
        "complete",
        "warnings",
        "warning",
        "cost_derived",
        "subagent_tokens_included",
        "subagent_activity_observed",
        "comparison",
        "version",
        "status",
        "fields",
        "native",
        "derived",
        "native_minus_derived",
        "scope_verified",
        "derived_complete",
        "billing_verified",
        "reason",
        "cleanup",
        "mechanism",
        "tree_empty",
        "forced",
        "deadline_seconds",
        "duration_ms",
        "failure_type",
        "model_requests",
        "analysis_validator",
        "mock_sdk_test_only",
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "kind",
        "from",
        "to",
        "field",
        "value",
        "provenance",
        "retained",
        "observed",
        "worker_timestamp",
        "resume_requested",
        "policy",
        "verbatim_prompts",
        "disable_slash_commands",
        "auto_memory",
        "nonmanaged_instructions",
        "bundled_skills",
        "observed_builtin_plugins",
        "native_effect",
        "auth_mode",
        "session_status",
        "auth_method",
        "api_fallback",
        "total_tokens",
        "max_tokens",
        "raw_max_tokens",
        "memory_files_count",
        "memory_tokens",
        "mcp_tools_count",
        "agents_count",
        "requested_model_matches",
        "context_isolation_verified",
        "validator",
        "passed",
        "claims",
        "files",
        "sha256",
        "artifact_id",
        "count",
        "mode",
        "tag",
    }
)
# Maps keyed by CAS-snapshot file paths (analysis.sources); keys must still be path-shaped.
PATH_MAPS = frozenset({"sha256"})
_DROP = object()


def enabled(scenario_id) -> bool:
    return scenario_id == SCENARIO


def digest(value) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:16]


def token(value):
    return value if isinstance(value, str) and TOKEN.fullmatch(value) else None


def model_id(value):
    """Native model identifier shape only (claude-...), else None."""
    return value if isinstance(value, str) and MODEL.fullmatch(value) else None


def version(value):
    return value if isinstance(value, str) and VERSION.fullmatch(value) else None


def session(value):
    return value if isinstance(value, str) and SESSION.fullmatch(value) else None


def number(value):
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    return _DROP


def text(value):
    if isinstance(value, str) and (value in FIXED_TEXT or TOKEN.fullmatch(value)):
        return value
    return _DROP


def structure(value, depth=0, key=""):
    """CAS-authored structures: known keys, scalars, tokens and fixed text; the rest is dropped."""
    if depth > 6:
        return _DROP
    if value is None:
        return None
    if isinstance(value, dict):
        result = {}
        for name, item in list(value.items())[:64]:
            if not isinstance(name, str) or name in RAW_KEYS:
                continue
            if key in PATH_MAPS:
                if not TOKEN.fullmatch(name):
                    continue
            elif name not in STRUCTURE_KEYS:
                continue
            kept = structure(item, depth + 1, name)
            if kept is not _DROP:
                result[name] = kept
        return result
    if isinstance(value, (list, tuple)):
        kept = [structure(item, depth + 1, key) for item in list(value)[:32]]
        return [item for item in kept if item is not _DROP]
    if isinstance(value, str):
        return text(value)
    return number(value)


def numeric(value, key="", depth=0):
    """Provider-controlled maps (usage): known keys, numbers/bools and exact CAS-set pairs."""
    if depth > 5:
        return _DROP
    if value is None:
        return None
    if isinstance(value, dict):
        result = {}
        for name, item in list(value.items())[:64]:
            if not isinstance(name, str):
                continue
            if key == "model_usage":
                if not MODEL_LABEL.fullmatch(name):
                    continue
            elif name not in USAGE_KEYS:
                continue
            kept = numeric(item, name, depth + 1)
            if kept is not _DROP:
                result[name] = kept
        return result
    if isinstance(value, (list, tuple)):
        kept = [numeric(item, key, depth + 1) for item in list(value)[:32]]
        return [item for item in kept if item is not _DROP]
    if isinstance(value, str):
        return value if (key, value) in KNOWN_PAIRS else _DROP
    return number(value)


def outcome(value):
    """Enumerated SDK outcome; unknown provider strings collapse to 'other'."""
    if not isinstance(value, dict):
        return None
    return {
        "subtype": enum(value.get("subtype"), SUBTYPES),
        "is_error": value.get("is_error") if type(value.get("is_error")) is bool else True,
        "terminal_reason": enum(value.get("terminal_reason"), REASONS),
    }


def enum(value, allowed):
    """Member of the closed set, None when absent, else 'other' (never provider text)."""
    if value is None:
        return None
    return value if isinstance(value, str) and value in allowed else "other"


def count(value):
    return min(len(value), 1_000_000) if isinstance(value, (list, tuple, dict, str)) else None


def message_summary(message) -> dict:
    """Bounded metadata for one SDK message; never any field content."""
    kind = type(message).__name__
    summary = {"message_type": kind if kind in MESSAGE_TYPES else "Other"}
    content = getattr(message, "content", None)
    if isinstance(content, list):
        summary["content_blocks"] = len(content)
    if kind == "ResultMessage":
        summary.update(
            outcome(
                {
                    "subtype": getattr(message, "subtype", None),
                    "is_error": getattr(message, "is_error", None),
                    "terminal_reason": getattr(message, "terminal_reason", None),
                }
            )
        )
        turns = getattr(message, "num_turns", None)
        if type(turns) is int:
            summary["num_turns"] = turns
        result = getattr(message, "result", None)
        summary["result_bytes"] = (
            len(result.encode("utf-8", errors="replace")) if isinstance(result, str) else None
        )
        summary["errors_count"] = count(getattr(message, "errors", None))
    elif kind == "SystemMessage":
        summary["subtype"] = enum(getattr(message, "subtype", None), SUBTYPES)
    return summary


def _message(payload):
    kind = payload.get("message_type")
    result = {"message_type": kind if isinstance(kind, str) and kind in MESSAGE_TYPES else "Other"}
    raw = payload.get("message")
    if isinstance(raw, dict):
        for name in ("content_blocks", "num_turns", "result_bytes", "errors_count"):
            if type(raw.get(name)) is int:
                result[name] = raw[name]
        if "subtype" in raw:
            result["subtype"] = enum(raw["subtype"], SUBTYPES)
        if "is_error" in raw:
            result["is_error"] = raw["is_error"] if type(raw["is_error"]) is bool else True
        if "terminal_reason" in raw:
            result["terminal_reason"] = enum(raw["terminal_reason"], REASONS)
    return {"message_type": result.pop("message_type"), "message": result}


def _tool(value):
    return value if isinstance(value, str) and value in TOOLS else "other"


def _flag(value):
    return value if type(value) is bool else None


def _hashed(payload, name):
    """Hash of a provider id; an already-projected digest passes through (idempotent)."""
    existing = payload.get(name + "_sha256")
    if isinstance(existing, str) and re.fullmatch(r"[0-9a-f]{16}", existing):
        return existing
    return digest(payload.get(name))


def _present(payload, flag, raw_keys, truthy=False):
    if type(payload.get(flag)) is bool:
        return payload[flag]
    return any(bool(payload.get(key)) if truthy else key in payload for key in raw_keys)


def _fixed(value):
    kept = token(value)
    return kept if kept is not None else "other"


def event(kind, payload):
    """Project one event payload to its allowlisted metadata before it is written."""
    if not isinstance(payload, dict):
        return {}
    if kind == "sdk.message":
        return _message(payload)
    if kind == "tool.request":
        return {
            "tool_name": _tool(payload.get("tool_name")),
            "tool_use_id_sha256": _hashed(payload, "tool_use_id"),
            "allowed": _flag(payload.get("allowed")),
            "input_present": _present(payload, "input_present", ("input",)),
            "provenance": _fixed(payload.get("provenance")),
        }
    if kind == "tool.result":
        return {
            "tool_name": _tool(payload.get("tool_name")),
            "tool_use_id_sha256": _hashed(payload, "tool_use_id"),
            "is_error": _flag(payload.get("is_error")),
            "content_present": _present(payload, "content_present", ("content", "result")),
            "error_present": _present(payload, "error_present", ("error",), truthy=True),
            "provenance": _fixed(payload.get("provenance")),
        }
    if kind == "hook.callback":
        return {"hook": enum(payload.get("hook"), HOOKS)}
    if kind == "permission.decision":
        return {
            "tool": _tool(payload.get("tool")),
            "decision": enum(payload.get("decision"), {"allow", "deny"}),
            "reason": _fixed(payload.get("reason")),
        }
    if kind in {"subagent.started", "subagent.stopped"}:
        return {"provenance": _fixed(payload.get("provenance"))}
    if kind == "subagent.model":
        return {
            "model": model_id(payload.get("model")),
            "parent_tool_use_id_sha256": _hashed(payload, "parent_tool_use_id"),
            "provenance": _fixed(payload.get("provenance")),
        }
    if kind in {"session.identity_mismatch", "session.identity_rejected"}:
        return {
            "expected_session_id": session(payload.get("expected_session_id")),
            "observed_session_id": session(payload.get("observed_session_id")),
            "resume_requested": _flag(payload.get("resume_requested")),
            "reason": _fixed(payload.get("reason")),
        }
    if kind == "error":
        return error(payload)
    return structure(payload)


def error(value):
    if not isinstance(value, dict):
        return None
    message = value.get("message")
    return {
        "category": _fixed(value.get("category")),
        "code": _fixed(value.get("code")),
        "message": message
        if isinstance(message, str) and (message in FIXED_TEXT or message in ANALYSIS_CODES)
        else WITHHELD,
        "retryable": value.get("retryable") is True,
        "evidence_refs": [
            item for item in (value.get("evidence_refs") or [])[:16] if token(item) is not None
        ]
        if isinstance(value.get("evidence_refs"), list)
        else [],
        **({"last_status": _fixed(value["last_status"])} if "last_status" in value else {}),
    }


def document(value):
    """Apply the policy to the provider-reachable fields of a run/result document."""
    if not isinstance(value, dict):
        return value
    result = dict(value)
    if "sdk_outcome" in result:
        result["sdk_outcome"] = outcome(result["sdk_outcome"])
    if "session_id" in result:
        result["session_id"] = session(result["session_id"])
    if "error" in result and result["error"] is not None:
        result["error"] = error(result["error"])
    if isinstance(result.get("usage"), dict):
        usage = dict(result["usage"])
        if "sdk" in usage:
            usage["sdk"] = None if usage["sdk"] is None else numeric(usage["sdk"])
        if "application" in usage:
            usage["application"] = (
                None if usage["application"] is None else structure(usage["application"])
            )
        result["usage"] = usage
    if isinstance(result.get("provider"), dict):
        provider = dict(result["provider"])
        for name, check in (("resolved_model", model_id), ("cli_version", version)):
            if provider.get(name) is not None:
                provider[name] = check(provider[name])
        result["provider"] = provider
    return result


def task_source(source):
    """Task metadata keeps hash/size of the instructions, never the snapshot text."""
    return {**source, "instructions": INSTRUCTIONS_WITHHELD, "instructions_truncated": False}


def worker_result(result, instructions):
    """Worker response body: validated report text or no text, plus safe metadata only."""
    if result is None:
        return None
    report = accepted_text(instructions, result.text) if sdk_succeeded(result.outcome) else None
    return {
        "text": report,
        "outcome": outcome(result.outcome),
        "session_id": session(result.session_id),
        "usage": None if result.usage is None else numeric(result.usage),
        "source": "sdk",
        "checks": None,
        "application_usage": (
            None if result.application_usage is None else structure(result.application_usage)
        ),
    }


def accepted_text(instructions, raw):
    """Canonical JSON of a source-grounded valid report, else None; the parent re-validates."""
    # Lazy imports: recorder -> this module must not import the task layer at load time.
    from agent_runtime.tasks.repository_analysis import validate_report
    from agent_runtime.tasks.repository_analysis_sdk import (
        MAX_RESPONSE_BYTES,
        checked_sources,
        unique,
    )

    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
            return None
        snapshots = json.loads(instructions)["snapshots"]
        sources = checked_sources({item["path"]: item["content"] for item in snapshots})
        value = json.loads(raw, object_pairs_hook=unique)
        validate_report(value, sources)
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError):
        return None
