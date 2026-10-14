"""Read installed package code/binary only; never execute CLI or open native stores.

Marker presence supports a static investigation, not runtime behavior verification.
Prints hashes/offsets, no source text, user paths, environment values or credentials.
"""

import hashlib
import json
import mmap
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path


def inspect():
    sdk_version = version("claude-agent-sdk")
    if sdk_version != "0.2.165":
        raise ValueError("Re-review context controls before changing the SDK pin")
    root = Path(str(files("claude_agent_sdk")))
    sources = (
        "types.py",
        "client.py",
        "_internal/query.py",
        "_internal/transport/subprocess_cli.py",
    )
    fingerprints = []
    for name in sources:
        content = (root / name).read_bytes()
        fingerprints.append(
            {
                "path": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    markers = (
        "--disable-slash-commands",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS",
        "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS",
        "autoMemoryEnabled",
        "claudeMdExcludes",
        "disableBundledSkills",
        "cc-plugin-agents-md",
        "cc-plugin-plugin-authoring",
        "enabledPlugins",
        "client_composed",
        "memory_paths",
        "builtinPluginsInitialized",
    )
    binary = root / "_bundled/claude.exe"
    with (
        binary.open("rb") as stream,
        mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as image,
    ):
        offsets = {marker: image.find(marker.encode()) for marker in markers}
        native = {
            "path": "_bundled/claude.exe",
            "sha256": hashlib.sha256(image).hexdigest(),
            "size_bytes": len(image),
            "marker_offsets": offsets,
        }
    if any(offset < 0 for offset in offsets.values()):
        raise ValueError("Pinned native marker missing; review before adopting controls")
    return {
        "sdk_version": sdk_version,
        "method": "static-package-read-only",
        "native_execution": False,
        "native_store_read": False,
        "behavior_verified": False,
        "sdk_sources": fingerprints,
        "native_binary": native,
    }


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2))
