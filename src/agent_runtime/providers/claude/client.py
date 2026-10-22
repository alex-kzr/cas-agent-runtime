"""Bounded direct SDK client with explicit text-only or single-file read profile."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import asdict, is_dataclass

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ConversationResetMessage,
    HookMatcher,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    SystemMessage,
)

from agent_runtime.providers.claude.auth import (
    SUBSCRIPTION_SETTINGS,
    SYSTEM_ENV,
    auth_environment,
    native_cli,
    require_auth,
    subscription_status,
)
from agent_runtime.providers.claude.context import (
    CONTEXT_POLICY,
    CONTEXT_SETTINGS,
    context_observation,
)
from agent_runtime.providers.claude.permissions import read_allowed
from agent_runtime.providers.claude.resume_diagnostics import SCENARIO, observe_rejection
from agent_runtime.tasks import analysis_privacy, review_profile
from agent_runtime.tasks.executor import NativeResult
from agent_runtime.tasks.models import ExecutionRequest, sdk_succeeded
from agent_runtime.telemetry.events import observe_message
from agent_runtime.telemetry.metrics import ObservedUsage, compare_usage
from agent_runtime.telemetry.recorder import Recorder


def observe_session_identity(message, request, recorder):
    """Main-session identity only; this does not verify native history durability."""
    if getattr(message, "parent_tool_use_id", None):
        return
    if isinstance(message, ConversationResetMessage):
        recorder.record["configuration"]["session_identity"] = "reset-observed"
        recorder.event(
            "session.reset", {"resume_requested": bool(request.resume_session_id)}, "sdk"
        )
        recorder.save()
        raise ValueError("Native conversation reset during a single CAS task; no replay")
    if isinstance(message, SystemMessage):
        if message.subtype != "init" or message.data.get("parent_tool_use_id"):
            return
        session_id = message.data.get("session_id")
    else:
        session_id = getattr(message, "session_id", None)
    if session_id is None and not isinstance(message, ResultMessage):
        return
    if not isinstance(session_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id) is None:
        recorder.record["configuration"]["session_identity"] = "invalid-main-id"
        recorder.event("session.identity_rejected", {"reason": "invalid-main-id"}, "sdk")
        recorder.save()
        raise ValueError("Invalid main native session identity")
    expected = request.resume_session_id or recorder.record["session_id"]
    if expected is not None and expected != session_id:
        recorder.record["configuration"]["session_identity"] = "mismatch"
        recorder.event(
            "session.identity_mismatch",
            {
                "expected_session_id": expected,
                "observed_session_id": session_id,
                "resume_requested": bool(request.resume_session_id),
            },
            "sdk",
        )
        recorder.save()
        raise ValueError("Main native session identity changed; no fallback or replay")
    recorder.record["session_id"] = session_id
    recorder.record["configuration"]["session_identity"] = (
        "matched-resume" if request.resume_session_id else "observed-main"
    )
    recorder.save()


def make_transport(profile, options, accountant):
    """The only constructor of the bounded transport; tests substitute a mock delegate here."""
    from agent_runtime.providers.claude.review_transport import ReviewTransport

    return ReviewTransport(profile, options, accountant=accountant)


class ReviewCounters:
    """Downstream per-message counters of the mean-review scope (independent of the transport)."""

    def __init__(self, profile):
        self.profile = profile
        self.messages = self.results = 0
        self.turns = None
        self.message_ids = set()
        self.code = None

    def message(self, message):
        profile = self.profile
        self.messages += 1
        if self.messages > profile.max_messages:
            raise review_profile.BudgetExceeded(review_profile.MESSAGES)

    def checked(self, message):
        """Post-event consistency checks on one message."""
        profile = self.profile
        if isinstance(message, AssistantMessage):
            if message.parent_tool_use_id:
                raise review_profile.BudgetExceeded(review_profile.COUNTERS)
            if not review_profile.model_matches(profile, message.model):
                raise review_profile.BudgetExceeded(review_profile.MODEL)
            if message.message_id is not None:
                self.message_ids.add(message.message_id)
                if len(self.message_ids) > profile.observed_turns:
                    raise review_profile.BudgetExceeded(review_profile.TURNS)
        elif isinstance(message, ResultMessage):
            self.results += 1
            turns = message.num_turns
            if self.results > 1 or type(turns) is not int or turns != profile.observed_turns:
                raise review_profile.BudgetExceeded(review_profile.TURNS)
            self.turns = turns

    def snapshot(self, accountant, code, failed):
        snapshot = {
            **accountant.snapshot(),
            "messages": self.messages,
            "results": self.results,
            "failed": failed,
        }
        if self.turns is not None:
            snapshot["observed_turns"] = self.turns
        if code is not None:
            snapshot["reason_code"] = code
        return snapshot


class ClaudeAdapter:
    def __init__(self, environment: Mapping[str, str], profile=None):
        self.environment = dict(environment)
        self.profile = profile

    def options(
        self, request: ExecutionRequest, recorder: Recorder, accountant=None
    ) -> ClaudeAgentOptions:
        from agent_runtime.tasks.coding import PROFILE, TOOLS, CodingWorkspace, sdk_server

        coding = (
            CodingWorkspace(
                request.workspace, recorder.data_dir / "runs" / recorder.run_id / "coding"
            )
            if request.agent_name == PROFILE
            else None
        )

        def permitted(name, arguments):
            if coding is not None:
                return name in TOOLS and isinstance(arguments, dict)
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
            recorder.record["configuration"]["subagent_activity_observed"] = True
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
            settings=json.dumps(
                CONTEXT_SETTINGS
                | (SUBSCRIPTION_SETTINGS if request.auth_mode == "subscription" else {})
            ),
            tools=["Read"] if request.agent_name == "read-only-v1" else [],
            allowed_tools=[],
            setting_sources=[],
            skills=[],
            plugins=[],
            extra_args={"disable-slash-commands": None},
            verbatim_prompts=True,
            mcp_servers=({"cas_workspace": sdk_server(coding, recorder)} if coding else {}),
            resume=request.resume_session_id,
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
            # The bounded scope reads whole messages only: partial-message streaming would spend
            # the message/frame budget on token deltas.
            include_partial_messages=self.profile is None,
            stderr=accountant.stderr_line
            if accountant is not None
            else (lambda line: observe_rejection(request, recorder, [line], "stderr"))
            if request.scenario_id == SCENARIO
            else (lambda _: None),
            **({"max_buffer_size": self.profile.max_frame_bytes} if self.profile else {}),
        )

    async def run(self, request: ExecutionRequest, recorder: Recorder) -> NativeResult:
        profile = self.profile
        if profile is None:
            return await self._run(request, recorder, None, None)
        # Mean-review scope: the request must be exactly the profile before any auth/provider path.
        if (
            request.model != profile.model
            or request.limits != profile.limits()
            or request.instructions != profile.query_text
            or request.agent_name != "text-only-v1"
            or request.resume_session_id is not None
        ):
            raise PermissionError("Request differs from the bounded review profile")
        from agent_runtime.providers.claude.review_transport import StreamAccountant

        accountant, counters = StreamAccountant(profile), ReviewCounters(profile)
        code, failed = None, True
        try:
            result = await self._run(request, recorder, accountant, counters)
            accountant.raise_if_failed()  # a budget breach after the result still fails the run
            failed = False
        except review_profile.BudgetExceeded as error:
            code = error.code
            raise
        except Exception:
            if accountant.failure is not None:
                code = accountant.failure
                raise review_profile.BudgetExceeded(code) from None
            raise
        finally:
            snapshot = counters.snapshot(accountant, code, failed)
            application = dict(recorder.record["usage"].get("application") or {})
            application["review_budget"] = snapshot
            recorder.record["usage"]["application"] = application
        result.application_usage["review_budget"] = snapshot
        return result

    async def _run(self, request, recorder, accountant, counters) -> NativeResult:
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
        recorder.record["configuration"]["context_policy"] = CONTEXT_POLICY
        recorder.record["configuration"]["context_isolation"] = "unverified"
        recorder.event(
            "context.configured",
            {
                "policy": CONTEXT_POLICY,
                "verbatim_prompts": True,
                "disable_slash_commands": True,
                "auto_memory": "requested-disabled",
                "nonmanaged_instructions": "requested-excluded",
                "bundled_skills": "requested-disabled",
                "observed_builtin_plugins": "requested-disabled-by-exact-id",
                "native_effect": "not-live-verified",
            },
        )
        result = None
        observed_usage = ObservedUsage()
        options = self.options(request, recorder, accountant)
        if self.profile is None:
            sdk_client = ClaudeSDKClient(options=options)
        else:
            # Never the default transport: oversize/silence must not fall through to CLI defaults.
            sdk_client = ClaudeSDKClient(
                options=options, transport=make_transport(self.profile, options, accountant)
            )
        async with sdk_client as client, AsyncExitStack() as streams:
            recorder.event(
                "sdk.query_started", {"resume_requested": bool(request.resume_session_id)}, "sdk"
            )
            await client.query(request.instructions)
            stream = client.receive_response()
            if callable(getattr(stream, "aclose", None)):
                # An early failure must close the generator before the client/loop shut down.
                streams.push_async_callback(stream.aclose)
            async for message in stream:
                if counters is not None:
                    counters.message(message)  # before context/summary/event expansion
                context = context_observation(message)
                if context is not None:
                    recorder.event("context.observed", context, "sdk")
                observe_message(message, recorder, observed_usage)
                # Analysis: bounded metadata is built here, before anything is serialized.
                payload = (
                    analysis_privacy.message_summary(message)
                    if getattr(recorder, "private", False) is True
                    else asdict(message)
                    if is_dataclass(message)
                    else {"type": type(message).__name__}
                )
                recorder.event(
                    "sdk.message",
                    {"message_type": type(message).__name__, "message": payload},
                    "sdk",
                )
                if counters is not None:
                    counters.checked(message)
                if not isinstance(message, ResultMessage):
                    observe_session_identity(message, request, recorder)
                if isinstance(message, ResultMessage):
                    if message.is_error:
                        observe_rejection(
                            request, recorder, getattr(message, "errors", None), "result-errors"
                        )
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
                    result.application_usage["comparison"] = compare_usage(
                        result.usage, result.application_usage, resumed=bool(request.resumes_run_id)
                    )
                    recorder.record["usage"]["application"] = result.application_usage
                    recorder.event(
                        "usage.comparison", result.application_usage["comparison"], "application"
                    )
                    observe_session_identity(message, request, recorder)
                # Worker-private snapshot retains observations even if native context
                # shutdown later stalls and the parent must terminate the process tree.
                recorder.save()
        if result is None:
            raise RuntimeError("SDK stream ended without a terminal ResultMessage")
        return result
