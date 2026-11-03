"""Small concrete tool policy. Native enforcement remains a live research question."""

from pathlib import Path, PureWindowsPath


def read_allowed(workspace: Path, name: str, arguments: dict) -> bool:
    try:
        return _read_allowed(workspace, name, arguments)
    except (OSError, RuntimeError, ValueError):
        return False


def _read_allowed(workspace: Path, name: str, arguments: dict) -> bool:
    if name != "Read" or not isinstance(arguments, dict):
        return False
    value = arguments.get("file_path")
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        return False
    root = workspace.resolve()
    if value.startswith(("//", "\\\\")):
        return False
    if PureWindowsPath(value).drive and PureWindowsPath(value).drive.lower() != root.drive.lower():
        return False
    raw = Path(value)
    target = (raw if raw.is_absolute() else root / raw).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return False
    relative = target.relative_to(root)
    if any(part.startswith(".") for part in relative.parts):
        return False
    if target.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
        return False
    # This profile is intentionally a bounded single-file reader, with no shell,
    # recursive search, skill or external service capability.
    return target.stat().st_size <= 1_000_000


READ_ONLY_DENIAL = (
    "Denied by CAS read-only-v1 policy: Read accepts only an existing regular file inside "
    "the task workspace, at most 1 MB, with no hidden (dot) path segment and no key/certificate "
    "extension (.pem, .key, .p12, .pfx). Other tools and directory listing are unavailable."
)


def decision_reason(agent_name: str, allowed: bool) -> str:
    """Fixed text shown to the model; never echoes the requested path or file content."""
    if allowed:
        return agent_name
    if agent_name == "read-only-v1":
        return READ_ONLY_DENIAL
    return f"Denied by CAS {agent_name} policy: this tool request is outside the profile."
