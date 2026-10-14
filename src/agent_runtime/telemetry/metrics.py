"""Conservative observed-step accounting, distinct from SDK cumulative cost totals."""

from typing import Any

TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def compare_usage(native, application, *, resumed=False):
    """Compare recorded values only; neither scope equality nor billing is verified."""
    native_tokens = native.get("usage") if isinstance(native, dict) else None
    observed = (
        application.get("observed_main_loop_tokens") if isinstance(application, dict) else None
    )
    uncertain_scope = resumed or (
        isinstance(application, dict) and application.get("subagent_activity_observed") is True
    )
    fields = {}
    comparable = 0
    differences = False

    def token(mapping, name):
        value = mapping.get(name) if isinstance(mapping, dict) else None
        return value if type(value) is int and 0 <= value <= 2**53 - 1 else None

    for name in TOKEN_FIELDS:
        left, right = token(native_tokens, name), token(observed, name)
        delta = None
        if left is not None and right is not None and not uncertain_scope:
            delta = left - right
            comparable += 1
            differences = differences or delta != 0
        fields[name] = {"native": left, "derived": right, "native_minus_derived": delta}
    status = (
        "scope-unverified"
        if uncertain_scope
        else "unavailable"
        if not comparable
        else "partial-observed-values"
        if comparable != len(TOKEN_FIELDS)
        else "different-observed-values"
        if differences
        else "equal-observed-values"
    )
    return {
        "version": 1,
        "status": status,
        "fields": fields,
        "comparison": "raw-recorded-values-only",
        "scope_verified": False,
        "derived_complete": False,
        "billing_verified": False,
        "reason": (
            "Resumed or subagent totals may have different scopes; deltas withheld."
            if uncertain_scope
            else "Observed equality/difference does not establish complete usage or billing."
        ),
    }


class ObservedUsage:
    def __init__(self) -> None:
        self.seen: dict[str, dict] = {}
        self.tokens: dict[str, int] = {}
        self.warnings: set[str] = set()
        self.subagents_observed = False

    def observe(self, message_id: str | None, usage: dict | None, *, subagent=False) -> None:
        if subagent:
            self.subagents_observed = True
            return
        if usage is None:
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
            "subagent_activity_observed": self.subagents_observed,
        }
