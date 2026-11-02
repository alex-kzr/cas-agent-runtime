"""Bounded selected ordinary text, never raw SDK/login/stderr evidence."""

import json
import re

from . import spec

PRIVATE = re.compile(
    r'''(?i)(sk-ant-[\w-]{12,}|\bbearer\s+\S{12,}|-----BEGIN [\w ]*PRIVATE KEY|(?:access_?token|refresh_?token|client_?secret|password)["']?\s*[:=]|https?://\S*(?:oauth|[?&]code=|[?&]token=|/auth/))'''
)
KEYS = {
    "scope",
    "stage",
    "run_id",
    "result",
    "query_count",
    "native_success",
    "text",
    "session_hash",
    "tree_empty",
    "auth_profile_shared",
    "context_isolation",
    "failure_code",
}


def valid(d, stage=None):
    try:
        return (
            isinstance(d, dict)
            and set(d) == KEYS
            and d["scope"] == "cas-working-task-v1"
            and d["stage"] in spec.STAGES
            and (stage is None or d["stage"] == stage)
            and d["run_id"] == spec.RUNS[d["stage"]]
            and d["result"] in {"PASS", "FAIL"}
            and type(d["query_count"]) is int
            and d["query_count"] == 1
            and all(
                type(d[k]) is bool for k in ["native_success", "tree_empty", "auth_profile_shared"]
            )
            and d["auth_profile_shared"] is True
            and isinstance(d["text"], str)
            and len(d["text"].encode("utf-8")) <= 4096
            and not PRIVATE.search(d["text"])
            and (
                d["session_hash"] is None
                or isinstance(d["session_hash"], str)
                and re.fullmatch("[0-9a-f]{64}", d["session_hash"])
            )
            and d["context_isolation"] == "NOT_PROVED"
            and d["failure_code"] in {None, "EXECUTION_NOT_ACCEPTED", "WORK_EXCEPTION"}
        )
    except (TypeError, KeyError, ValueError, RecursionError):
        return False


def accepted(d, stage):
    return (
        valid(d, stage)
        and d["result"] == "PASS"
        and d["failure_code"] is None
        and d["native_success"] is True
        and d["tree_empty"] is True
        and bool(d["text"].strip())
        and d["session_hash"] is not None
    )



def checked_task_metadata(value):
    """Finite diagnostics only. Never admit child text, IDs, errors or extra keys."""
    if not isinstance(value, dict) or set(value) != {
        "reported_result", "native_success", "tree_empty", "declared_query_count",
        "failure_code", "selected_text_state",
    }:
        return None
    if (
        type(value["reported_result"]) is not str
        or value["reported_result"] not in {"PASS", "FAIL"}
        or type(value["native_success"]) is not bool
        or type(value["tree_empty"]) is not bool
        or type(value["declared_query_count"]) is not int
        or value["declared_query_count"] != 1
        or not (value["failure_code"] is None or type(value["failure_code"]) is str
                and value["failure_code"] in {"EXECUTION_NOT_ACCEPTED", "WORK_EXCEPTION"})
        or type(value["selected_text_state"]) is not str
        or value["selected_text_state"] not in {"EMPTY", "PRESENT_BOUNDED"}
    ):
        return None
    return dict(value)


def task_metadata(doc, stage):
    if not valid(doc, stage):
        return None
    return checked_task_metadata(dict(
        reported_result=doc["result"], native_success=doc["native_success"],
        tree_empty=doc["tree_empty"], declared_query_count=doc["query_count"],
        failure_code=doc["failure_code"],
        selected_text_state="PRESENT_BOUNDED" if doc["text"] else "EMPTY",
    ))


def completed_client(value):
    """Client/capture fact only; no task success or provider cancellation inference."""
    if not isinstance(value, dict) or value.get("evidence_write_failed"):
        return False
    projection = value.get("work_projection")
    info = value.get("client_cleanup")
    return (
        isinstance(projection, dict)
        and type(projection.get("transport")) is str
        and projection.get("transport") in {"OK", "TIMEOUT", "PEER_OR_CANCEL_LOST"}
        and type(projection.get("client_rc")) is str
        and projection.get("client_rc") in {"ZERO", "NONZERO"}
        and isinstance(info, dict)
        and set(info) == {"client_stopped", "capture_complete", "capture_overflow",
                         "explicit_cancel", "peer_lost", "cancel_terminated_client"}
        and all(type(v) is bool for v in info.values())
        and info["client_stopped"] and info["capture_complete"]
        and not info["capture_overflow"]
    )


def sanitize(value, stage):
    def unique(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError("duplicate")
            d[k] = v
        return d

    doc = None
    try:
        doc = json.loads(value["out"], object_pairs_hook=unique)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        pass
    state = {
        None: "OK",
        "cancelled-or-peer-failed": "PEER_OR_CANCEL_LOST",
        "client-timeout": "TIMEOUT",
        "client-termination-unconfirmed": "TERMINATION_UNCONFIRMED",
        "capture-overflow": "CAPTURE_OVERFLOW",
        "capture-incomplete": "CAPTURE_INCOMPLETE",
    }.get(value.get("failure"), "UNKNOWN_FAILURE")
    projection = dict(
        transport=state,
        client_rc="ZERO"
        if value.get("rc") == 0
        else "NONZERO"
        if type(value.get("rc")) is int
        else "UNKNOWN",
        output="VALID_SUMMARY"
        if valid(doc, stage)
        else "EMPTY"
        if value.get("out") == b""
        else "INVALID_SUMMARY",
        stderr_present=value.get("err") != b"",
        task=task_metadata(doc, stage),
    )
    ok = state == "OK" and value.get("rc") == 0 and value.get("err") == b"" and valid(doc, stage)
    code = (
        None
        if ok
        else "WORK_" + state
        if state != "OK"
        else "WORK_CLIENT_NONZERO"
        if value.get("rc") != 0
        else "WORK_STDERR_PRESENT"
        if value.get("err") != b""
        else "WORK_SUMMARY_INVALID"
    )
    evidence = value.get("client_cleanup")
    if (
        not isinstance(evidence, dict)
        or set(evidence)
        != {
            "client_stopped",
            "capture_complete",
            "capture_overflow",
            "explicit_cancel",
            "peer_lost",
            "cancel_terminated_client",
        }
        or any(type(v) is not bool for v in evidence.values())
    ):
        evidence = None
    return dict(
        rc=0 if ok else 1,
        out=(json.dumps(doc, sort_keys=True) + "\n").encode() if ok else b"",
        err=b"",
        failure=code,
        elapsed=value.get("elapsed", 0),
        work_projection=projection,
        client_cleanup=evidence,
    )
