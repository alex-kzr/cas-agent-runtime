"""Explicit personal subscription vs API selection; never copies native credentials."""

import json
import subprocess
from importlib.resources import files
from pathlib import Path

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
    "HOME",
}
SUBSCRIPTION_SETTINGS = {"forceLoginMethod": "claudeai"}


def native_cli():
    path = Path(str(files("claude_agent_sdk").joinpath("_bundled", "claude.exe")))
    if not path.is_file():
        raise ValueError("Pinned bundled Claude CLI is required; no PATH fallback")
    return path


def require_auth(request, environment):
    if not request.live_authorized:
        raise PermissionError("Live model execution requires explicit --allow-live")
    if request.auth_mode == "subscription":
        if not request.allow_existing_login:
            raise PermissionError(
                "Subscription mode requires separate --allow-existing-login consent to native session reuse"
            )
    elif not environment.get("ANTHROPIC_API_KEY"):
        raise ValueError("ANTHROPIC_API_KEY must be supplied externally for explicit api mode")


def auth_environment(request, environment, state_directory, *, forbidden_roots=()):
    selected = {key: value for key, value in environment.items() if key.upper() in SYSTEM_ENV}
    selected.update(
        CLAUDE_CODE_MAX_RETRIES="0",
        CLAUDE_CODE_RETRY_WATCHDOG="0",
        API_TIMEOUT_MS=str(request.limits.timeout_seconds * 1000),
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
    )
    selected["ANTHROPIC_CONFIG_DIR"] = str(state_directory / "unused-anthropic-profiles")
    if request.auth_mode == "api":
        selected["ANTHROPIC_API_KEY"] = environment.get("ANTHROPIC_API_KEY", "")
        selected["CLAUDE_CONFIG_DIR"] = str(state_directory)
    else:
        # Auth stays in the existing native store, never sdk-state or CAS config.
        configured = request.login_config_dir or environment.get("CLAUDE_CONFIG_DIR")
        selected["CLAUDE_CONFIG_DIR"] = str(
            configured
            or (
                Path(environment.get("USERPROFILE") or environment.get("HOME") or Path.home())
                / ".claude"
            )
        )
    if request.auth_mode == "subscription":
        effective = Path(selected["CLAUDE_CONFIG_DIR"]).expanduser().resolve()
        roots = list(forbidden_roots)
        for parent in Path(__file__).resolve().parents:
            if (parent / "config/repositories.yaml").is_file():
                roots.append(parent)
                break
        if any(effective.is_relative_to(Path(root).resolve()) for root in roots):
            raise ValueError("Native subscription store must remain outside CAS and data")
        selected["CLAUDE_CONFIG_DIR"] = str(effective)
    return selected


def subscription_status(request, environment):
    require_auth(request, environment)
    if request.auth_mode != "subscription":
        raise ValueError("Native subscription status is only used in subscription mode")
    directory = Path(environment["CLAUDE_CONFIG_DIR"])
    if not directory.is_dir():
        raise ValueError(
            "No existing native login directory; sign in yourself only after separate approval"
        )
    try:
        result = subprocess.run(  # noqa: S603 - pinned bundled executable and fixed auth-status argv
            [
                str(native_cli()),
                "--setting-sources",
                "",
                "--settings",
                json.dumps(SUBSCRIPTION_SETTINGS),
                "auth",
                "status",
                "--json",
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if len(result.stdout.encode("utf-8")) > 65_536:
            raise ValueError("Oversized native status")
        status = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise ValueError("Native subscription status unavailable; no API fallback") from error
    if (
        not isinstance(status, dict)
        or result.returncode != 0
        or status.get("loggedIn") is not True
        or status.get("authMethod") != "claude.ai"
        or status.get("apiProvider") != "firstParty"
        or status.get("subscriptionType") not in {"pro", "max", "team", "enterprise"}
    ):
        raise ValueError(
            "No verified native subscription session; no API fallback; use your own native login after approval"
        )
    config = status.get("configDirectory")
    if not isinstance(config, str) or Path(config).resolve() != directory.resolve():
        raise ValueError("Native subscription config directory mismatch; no fallback")
    return {
        "auth_mode": "subscription",
        "session_status": "verified-native-status",
        "auth_method": "claude.ai",
        "api_fallback": "disabled",
    }
