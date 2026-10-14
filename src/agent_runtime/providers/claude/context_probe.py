"""Explicitly gated, supervised native diagnostics. Never sends a user/model query."""

import argparse
import asyncio
import hashlib
import json
import os
import sys
from dataclasses import dataclass, replace
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, PermissionResultDeny
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

from agent_runtime.providers.claude.auth import (
    SUBSCRIPTION_SETTINGS,
    auth_environment,
    native_cli,
    subscription_status,
)
from agent_runtime.providers.claude.context import CONTEXT_POLICY, CONTEXT_SETTINGS
from agent_runtime.providers.claude.supervision import OwnedProcess
from agent_runtime.tasks.models import Limits
from agent_runtime.telemetry.recorder import atomic_json

NATIVE_SHA256 = "1f6471eb5a1c21a1f8b54a7827329d64433424dcce51717a54e837adb542163a"
WORKER_SECONDS = 30
MODEL = "claude-haiku-5-5"  # Context accounting target only; never an inference query.


@dataclass(frozen=True)
class ProbeSettings:
    """Auth/limits only; diagnostics are not a task and carry no user instructions."""

    workspace: Path
    limits: Limits
    auth_mode: str = "subscription"
    login_config_dir: None = None
    live_authorized: bool = True  # Native startup grant only, never model consent.
    allow_existing_login: bool = True


def file_hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def scope_snapshot():
    """Fingerprint reviewed runtime/SDK source, lock and executable files, without running them."""
    runtime = Path(__file__).resolve().parents[4]
    package = runtime / "src/agent_runtime"
    sdk = Path(str(files("claude_agent_sdk")))
    targets = [
        (f"runtime/src/agent_runtime/{path.relative_to(package).as_posix()}", path)
        for path in package.rglob("*.py")
    ]
    targets += [(f"sdk/{path.relative_to(sdk).as_posix()}", path) for path in sdk.rglob("*.py")]
    targets += [(f"runtime/{name}", runtime / name) for name in ("uv.lock", "pyproject.toml")]
    targets += [
        ("native/claude.exe", native_cli()),
        ("python/launcher.exe", Path(sys.executable)),
        ("python/base.exe", Path(sys._base_executable)),
    ]
    targets += [
        (f"python/{path.name}", path)
        for path in Path(sys._base_executable).parent.glob("python3*.dll")
    ]
    return {
        "schema_version": 1,
        "sdk_version": version("claude-agent-sdk"),
        "files": [
            {"path": label, "sha256": file_hash(path), "size_bytes": path.stat().st_size}
            for label, path in sorted(targets)
        ],
    }


def scope_hash(snapshot):
    return hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def check_pin(expected_scope_sha256):
    snapshot = scope_snapshot()
    if snapshot["sdk_version"] != "0.2.165":
        raise ValueError("SDK pin mismatch")
    native = next(item for item in snapshot["files"] if item["path"] == "native/claude.exe")
    if native["sha256"] != NATIVE_SHA256:
        raise ValueError("Native executable hash mismatch")
    if scope_hash(snapshot) != expected_scope_sha256:
        raise ValueError("Reviewed scope manifest mismatch")


def context_summary(response):
    """Whitelist numbers/counts only, never copy names, paths, text or arbitrary keys."""
    response = response if isinstance(response, dict) else {}

    def number(value):
        return value if type(value) is int and 0 <= value <= 2**53 else None

    memory = response.get("memoryFiles")
    tokens = (
        [number(item.get("tokens")) if isinstance(item, dict) else None for item in memory]
        if isinstance(memory, list)
        else None
    )
    return {
        "total_tokens": number(response.get("totalTokens")),
        "max_tokens": number(response.get("maxTokens")),
        "raw_max_tokens": number(response.get("rawMaxTokens")),
        "memory_files_count": len(memory) if isinstance(memory, list) else None,
        "memory_tokens": sum(tokens)
        if tokens is not None and all(value is not None for value in tokens)
        else None,
        "mcp_tools_count": len(response["mcpTools"])
        if isinstance(response.get("mcpTools"), list)
        else None,
        "agents_count": len(response["agents"])
        if isinstance(response.get("agents"), list)
        else None,
        "requested_model_matches": response.get("model") == MODEL,
        "context_isolation_verified": False,
    }


def sanitize_worker_report(child):
    """Re-apply an explicit parent-side whitelist; never merge an arbitrary worker map."""
    child = child if isinstance(child, dict) else {}
    status = child.get("status")
    result = {"status": status if status in {"observed", "failed", "inconclusive"} else "failed"}
    context = child.get("context")
    if isinstance(context, dict):
        result["context"] = {
            key: value if type(value) is int and 0 <= value <= 2**53 else None
            for key in (
                "total_tokens",
                "max_tokens",
                "raw_max_tokens",
                "memory_files_count",
                "memory_tokens",
                "mcp_tools_count",
                "agents_count",
            )
            for value in (context.get(key),)
        }
        result["context"]["requested_model_matches"] = (
            context.get("requested_model_matches") is True
        )
        result["context"]["context_isolation_verified"] = False
    if child.get("auth") == {
        "auth_mode": "subscription",
        "session_status": "verified-native-status",
        "auth_method": "claude.ai",
        "api_fallback": "disabled",
    }:
        result["auth"] = dict(child["auth"])
    controls = child.get("outbound_control_requests_attempted")
    if isinstance(controls, dict):
        result["outbound_control_requests_attempted"] = {
            key: controls.get(key)
            if type(controls.get(key)) is int and controls[key] in (0, 1)
            else None
            for key in ("initialize", "get_context_usage")
        }
    if result["status"] == "observed" and (
        "auth" not in result
        or result.get("outbound_control_requests_attempted")
        != {"initialize": 1, "get_context_usage": 1}
        or result.get("context", {}).get("total_tokens") is None
        or result.get("context", {}).get("memory_files_count") is None
    ):
        result["status"] = "inconclusive"
    return result


class NoQueryTransport(SubprocessCLITransport):
    """Pinned SDK transport with a fail-closed outgoing protocol fence."""

    def __init__(self, options):
        super().__init__(prompt="", options=options)
        self.sent = {"initialize": 0, "get_context_usage": 0}

    async def write(self, data):
        if len(data.encode("utf-8")) > 8192:
            raise PermissionError("Probe control input exceeds fixed bound")
        envelope = json.loads(data)
        if (
            not isinstance(envelope, dict)
            or set(envelope) != {"type", "request_id", "request"}
            or envelope["type"] != "control_request"
        ):
            raise PermissionError("Probe blocks non-control input, including user queries")
        request = envelope["request"]
        if not isinstance(request, dict):
            raise PermissionError("Malformed probe control request")
        subtype = request.get("subtype")
        if subtype not in self.sent or self.sent[subtype] != 0:
            raise PermissionError("Probe blocks unexpected or repeated control requests")
        if subtype == "initialize":
            if (
                set(request) != {"subtype", "hooks", "skills"}
                or request["hooks"] not in (None, {})
                or request["skills"] != []
            ):
                raise PermissionError("Probe blocks context-bearing initialize options")
        elif set(request) != {"subtype"}:
            raise PermissionError("Probe blocks unexpected diagnostic fields")
        self.sent[subtype] += 1
        await super().write(data)


async def diagnose(request, directory):
    """Worker-only diagnostics; tests replace all native interactions with fixtures."""
    environment = auth_environment(
        request, os.environ, directory / "sdk-state", forbidden_roots=(directory,)
    )
    auth = subscription_status(request, environment)  # One bounded native auth-status call.

    async def deny(*args):
        return PermissionResultDeny(message="CAS probe denies all tools")

    options = ClaudeAgentOptions(
        cli_path=str(native_cli()),
        settings=json.dumps(CONTEXT_SETTINGS | SUBSCRIPTION_SETTINGS),
        tools=[],
        allowed_tools=[],
        disallowed_tools=["*"],
        skills=[],
        plugins=[],
        setting_sources=[],
        mcp_servers={},
        strict_mcp_config=True,
        extra_args={"disable-slash-commands": None, "no-session-persistence": None},
        verbatim_prompts=True,
        permission_mode="default",
        can_use_tool=deny,
        hooks={},
        cwd=str(request.workspace),
        model=MODEL,
        max_turns=1,
        max_budget_usd=0.10,
        env=environment,
        stderr=lambda _: None,
        max_buffer_size=65_536,
    )
    # A custom transport must receive the same stdio permission routing the pinned
    # SDK configures on its own options copy; no provider/default transport is used.
    transport = NoQueryTransport(replace(options, permission_prompt_tool_name="stdio"))
    async with ClaudeSDKClient(options=options, transport=transport) as client:
        response = await client.get_context_usage()  # Exactly one diagnostic, no query().
        summary = context_summary(response)
    return {
        "status": "observed"
        if summary["total_tokens"] is not None and summary["memory_files_count"] is not None
        else "inconclusive",
        "auth": auth,
        "context": summary,
        "outbound_control_requests_attempted": transport.sent,
    }


def make_request(directory):
    return ProbeSettings(directory / "workspace", Limits(1, "0.10", WORKER_SECONDS))


async def supervise(directory, expected_scope_sha256):
    owner = OwnedProcess()
    request = make_request(directory)
    environment = auth_environment(
        request, os.environ, directory / "sdk-state", forbidden_roots=(directory,)
    )
    payload = json.dumps(
        {
            "directory": str(directory),
            "expected_scope_sha256": expected_scope_sha256,
            "allow_native_startup": True,
            "allow_existing_login": True,
        }
    ).encode()
    report = {
        "mode": "context-probe-no-query",
        "status": "failed",
        "context_policy": CONTEXT_POLICY,
        "user_messages_written": 0,
        "context_isolation_verified": False,
        "native_sha256": NATIVE_SHA256,
        "scope_sha256": expected_scope_sha256,
        "probe_sha256": file_hash(__file__),
    }
    try:
        async with asyncio.timeout(WORKER_SECONDS):
            code = await owner.run(
                [sys.executable, "-m", __spec__.name, "--worker"], payload, environment
            )
        response = directory / "worker-response.json"
        if (
            not owner.cleanup["tree_empty"]
            or code != 0
            or not response.is_file()
            or response.stat().st_size > 16_384
        ):
            raise ValueError("Probe response/cleanup unavailable")
        # Only our whitelisted worker report is stored; never raw native control replies.
        child = json.loads(response.read_text(encoding="utf-8"))
        report.update(sanitize_worker_report(child))
    except TimeoutError:
        report["status"] = "timeout"
    except asyncio.CancelledError:
        report["status"] = "interrupted"
    except Exception:
        report["status"] = "failed"
    finally:
        report["cleanup"] = owner.cleanup
        if not owner.cleanup["tree_empty"]:
            report["status"] = "inconclusive"
        atomic_json(directory / "probe.json", report)
    return report


def worker():
    raw = sys.stdin.buffer.read(16_385)
    if not raw or len(raw) > 16_384:
        return 2
    payload = json.loads(raw)
    if (
        payload.get("allow_native_startup") is not True
        or payload.get("allow_existing_login") is not True
    ):
        return 2
    directory = Path(payload["directory"])
    check_pin(payload["expected_scope_sha256"])
    request = make_request(directory)
    request.workspace.mkdir(exist_ok=False)
    os.chdir(request.workspace)
    try:
        response = asyncio.run(diagnose(request, directory))
    except Exception:
        response = {"status": "failed"}  # No exception text, paths, native output or secrets.
    atomic_json(directory / "worker-response.json", response)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Supervised native context diagnostics; no user query"
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--expected-scope-sha256")
    parser.add_argument("--allow-native-startup", action="store_true")
    parser.add_argument("--allow-existing-login", action="store_true")
    args = parser.parse_args(argv)
    if args.worker:
        return worker()
    if not args.allow_native_startup or not args.allow_existing_login:
        raise PermissionError("Separate native-startup and existing-login authorization required")
    if args.output_dir is None or args.expected_scope_sha256 is None:
        raise ValueError("Explicit output directory and reviewed source hash required")
    check_pin(args.expected_scope_sha256)
    directory = args.output_dir.resolve()
    if any((parent / ".git").exists() for parent in (directory, *directory.parents)):
        raise ValueError("Probe output/workspace must be outside every Git root")
    directory.mkdir(parents=True, exist_ok=False)  # Prevent reuse/overwrite or automatic rerun.
    report = asyncio.run(supervise(directory, args.expected_scope_sha256))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
