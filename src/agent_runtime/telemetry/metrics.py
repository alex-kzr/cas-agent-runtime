"""Conservative observed-step accounting, distinct from SDK cumulative cost totals."""

from typing import Any

TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


class ObservedUsage:
    def __init__(self) -> None:
        self.seen: dict[str, dict] = {}
        self.tokens: dict[str, int] = {}
        self.warnings: set[str] = set()

    def observe(self, message_id: str | None, usage: dict | None, *, subagent=False) -> None:
        if usage is None or subagent:
            return
        if not isinstance(usage, dict) or not isinstance(message_id, str) or not message_id:
            self.warnings.add("Usage without a stable native message ID was not summed")
            return
        if message_id in self.seen:
            if self.seen[message_id] != usage:
                self.warnings.add(
                    "Conflicting usage for a duplicate message ID; first observation retained"
                )
            return
        if len(self.seen) >= 10_000 or len(message_id) > 1024:
            self.warnings.add("Observed usage identity limit reached; further usage not summed")
            return
        self.seen[message_id] = dict(usage)
        for name in TOKEN_FIELDS:
            value = usage.get(name)
            if type(value) is int and value >= 0:
                self.tokens[name] = self.tokens.get(name, 0) + value
            else:
                self.warnings.add("Missing or invalid token fields; observed accounting is partial")

    def snapshot(self) -> dict[str, Any]:
        return {
            "observed_main_loop_tokens": self.tokens or None,
            "observed_message_count": len(self.seen),
            "scope": "observed-unique-main-loop-message-ids",
            "complete": False,
            "warnings": sorted(self.warnings),
            "cost_derived": False,
            "subagent_tokens_included": False,
        }
