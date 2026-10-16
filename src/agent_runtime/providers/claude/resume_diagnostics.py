"""Opt-in pinned unknown-SID literal: no raw stderr, response text or SID export."""

SCENARIO = "sdk.sessions.unknown-sid-negative"
PREFIX = "No conversation found with session ID: "


def observe_rejection(request, recorder, values, source):
    if request.scenario_id != SCENARIO or not request.resume_session_id:
        return
    if recorder.record["configuration"].get("resume_rejection") is not None:
        return
    if not isinstance(values, list):
        return
    expected = PREFIX + request.resume_session_id
    if not any(
        isinstance(value, str) and len(value) <= 4096 and value.strip() == expected
        for value in values[:16]
    ):
        return
    tag = {"reason": "unknown-sid", "source": source, "contract": "pinned-cli-literal-v1"}
    recorder.record["configuration"]["resume_rejection"] = tag
    recorder.event("session.resume_rejected", tag, "sdk")
    recorder.save()
