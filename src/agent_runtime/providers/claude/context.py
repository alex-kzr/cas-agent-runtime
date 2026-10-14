"""Requested input controls and metadata-only observations, never an isolation proof."""

from claude_agent_sdk import SystemMessage

CONTEXT_POLICY = "literal-input-no-discovery-v1"
CONTEXT_ENV = {
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
}
CONTEXT_SETTINGS = {
    "autoMemoryEnabled": False,
    "disableBundledSkills": True,
    "claudeMdExcludes": ["**"],
    # Exact builtins advertised by pinned 2.1.294, not a universal plugin disable.
    "enabledPlugins": {
        "cc-plugin-agents-md@builtin": False,
        "cc-plugin-plugin-authoring@builtin": False,
    },
}


def context_observation(message: object) -> dict[str, object] | None:
    """Count advertised registrations without opening paths or inferring loaded content."""
    if not isinstance(message, SystemMessage) or message.subtype != "init":
        return None
    data = message.data
    return {
        "provenance": "sdk-init-advertisement",
        "tools_count": len(data["tools"]) if isinstance(data.get("tools"), list) else None,
        "mcp_servers_count": len(data["mcp_servers"])
        if isinstance(data.get("mcp_servers"), list)
        else None,
        "skills_count": len(data["skills"]) if isinstance(data.get("skills"), list) else None,
        "plugins_count": len(data["plugins"]) if isinstance(data.get("plugins"), list) else None,
        "memory_paths_count": len(data["memory_paths"])
        if isinstance(data.get("memory_paths"), dict)
        else None,
        "content_loaded": None,
        "context_isolation": "unverified",
    }
