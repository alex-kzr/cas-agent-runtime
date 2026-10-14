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
