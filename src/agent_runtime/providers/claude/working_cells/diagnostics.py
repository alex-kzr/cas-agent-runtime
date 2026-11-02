"""Safe structured failures: no raw stderr, argv, profile/account or login stream."""

import hashlib
import json
from pathlib import Path

from .inventory_gate import CODES
from .network_contract import POLICY_CODES

SERIES_CODES = {
    "lifecycle-deadline",
    "inspection-uncertain",
    "relay-terminal-failure",
    "docker-nonzero",
    "private-login-attach-failed",
    "SERIES_FOREIGN_WORK_NAME",
    "SERIES_REMAINING_LIFE",
    "private-foreground-required",
    "name-already-exists",
    "WORK_START_STATE_INVALID",
    "SERIES_FIRST_NOT_QUIESCENT",
    "SERIES_WORK_STOP_UNCONFIRMED",
    "fresh-specific-owner-grant-required",
    "profile-remains",
    "SERIES_SESSION_REUSED",
    "WORK_START_CLIENT_OR_HOLDER_LOST",
    "READY_EXEC_AUTHORITY_DENIED",
    "post-rm-network-present",
    "relay-start-failed",
    "private-login-cancel-or-budget",
    "profile-consumers-unknown",
    "WORK_RESTART_FORBIDDEN",
    "cleanup-identity",
    "SERIES_FOREIGN_NAME",
    "holder-terminal-state",
    "CAPTURE_START_AUTHORITY_DENIED",
    "evidence-write-failed",
    "cleanup-still-running",
    "SERIES_SHARED_ABSENCE_UNCONFIRMED",
    "WORK_START_TIMEOUT",
    "fixed-evidence-must-be-new",
    "SERIES_NETWORK_ID_CHANGED",
    "profile-name-already-exists",
    "operation-budget",
    "PRIVATE_LOGIN_ONLY",
    "cancelled",
    "SERIES_PEER_LOST",
    "cleanup-network-consumers-or-id",
    "client-changed",
    "relay-upstream",
    "actual-running-state-required",
    "SERIES_SHARED_STOP_UNCONFIRMED",
    "post-rm-container-present",
    "fixed-sealed-location-required",
    "SERIES_WORK_ABSENCE_UNCONFIRMED",
    "network-remains",
    "SERIES_WORK_EXIT",
    "SERIES_ENDPOINT_NOT_RELEASED",
    "relay-ready-timeout",
    "image-backend-change-no-repin",
    "CREATED_NETWORK_ID_MISMATCH",
    "network-consumers",
    "sealed-file-changed",
    "CLEANUP_OPERATION_RESERVE",
    "relay-ready-targets",
    "SERIES_STAGE_NOT_ACCEPTED",
}


def safe_failure(error, phase, receipt_number=None, receipt=None, setup_stderr=b""):
    phases = {
        "preflight",
        "freshness",
        "resource_setup",
        "private_login",
        "ready_transport",
        "work_start_barrier",
        "sdk",
        "cleanup",
        "unknown",
    }
    phase = phase if isinstance(phase, str) and phase in phases else "unknown"
    diagnostic = {
        "phase": phase,
        "exception_class": type(error).__name__,
        "code": "UNCLASSIFIED_FAILURE",
    }
    # Only fixed codes; never stringify arbitrary exceptions or provider/native output.
    message = (
        str(error)
        if type(error).__name__ in {"Failure", "ReadinessError", "NetworkPolicyError"}
        else ""
    )
    if message in SERIES_CODES | CODES | POLICY_CODES | {
        "READY_CHANNEL_REJECTED",
        "READY_CHANNEL_ALREADY_ATTEMPTED",
        "READY_EXEC_AUTHORITY_DENIED",
        "WORK_OUTPUT_REJECTED",
        "WORK_PEER_OR_CANCEL_LOST",
        "WORK_TIMEOUT",
        "WORK_TERMINATION_UNCONFIRMED",
        "WORK_CAPTURE_OVERFLOW",
        "WORK_CAPTURE_INCOMPLETE",
        "WORK_UNKNOWN_FAILURE",
        "WORK_CLIENT_NONZERO",
        "WORK_STDERR_PRESENT",
        "WORK_SUMMARY_INVALID",
        "CREATED_NETWORK_ID_MISMATCH",
        "PRIVATE_LOGIN_ONLY",
        "WORK_START_CLIENT_OR_HOLDER_LOST",
        "WORK_START_TIMEOUT",
        "WORK_START_STATE_INVALID",
        "docker-nonzero",
        "inspection-uncertain",
        "image-backend-change-no-repin",
        "lifecycle-deadline",
        "operation-budget",
        "cancelled",
        "NETWORK_POOL_OR_ROUTE_OVERLAP",
        "NETWORK_INVENTORY_CHANGED",
        "NETWORK_INVENTORY_INCOMPLETE",
        "NETWORK_IPAM_UNAVAILABLE",
    }:
        diagnostic["code"] = message
    if type(receipt_number) is int and 1 <= receipt_number <= 112:
        diagnostic["receipt"] = f"{receipt_number:02}.json"
    if isinstance(receipt, dict):
        args = receipt.get("argv", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            args = []
        operations = [
            args[i : i + 2]
            for i in range(len(args) - 1)
            if args[i : i + 2]
            in [
                ["start", "--attach"],
                ["exec", "--user"],
                ["network", "create"],
                ["volume", "create"],
                ["container", "inspect"],
                ["network", "inspect"],
                ["volume", "inspect"],
                ["volume", "rm"],
            ]
        ]
        if operations:
            diagnostic["operation"] = " ".join(operations[-1])
        if isinstance(receipt.get("rc"), int):
            diagnostic["docker_rc"] = receipt["rc"]
        if receipt.get("capture") == "FIXED_WORK_SUMMARY":
            from .safe_work import checked_task_metadata

            projection = receipt.get("work_projection")
            task = checked_task_metadata(projection.get("task")) if isinstance(projection, dict) else None
            if task is not None:
                diagnostic["work_task"] = task
        # Classify only the exact setup operation's observed failure, discard raw bytes.
        if (
            diagnostic.get("operation") == "network create"
            and receipt.get("rc") == 1
            and receipt.get("failure") is None
        ):
            diagnostic["hint"] = "CHECK_SAVED_STDERR_AND_DOCKER_IPAM"
            if (
                setup_stderr.strip()
                == b"Error response from daemon: invalid pool request: Pool overlaps with other one on this address space"
            ):
                diagnostic["code"] = "DOCKER_IPAM_OVERLAP"
    return diagnostic


def from_evidence(error, phase, evidence, number):
    """Read only fixed local receipt metadata; raw setup error never enters result."""
    linked = getattr(error, "receipt_number", None)
    if type(linked) is int and 1 <= linked <= 112:
        number = linked
    value = safe_failure(error, phase, number)
    if type(number) is not int or not 1 <= number <= 112:
        return value
    try:
        root = Path(evidence)
        raw = (root / f"{number:02}.json").read_bytes()
        if len(raw) > 16384:
            raise ValueError("receipt-size")
        receipt = json.loads(raw)
        value = safe_failure(error, phase, number, receipt)
        if value.get("operation") == "network create":
            stderr = (root / f"{number:02}.err.bin").read_bytes()
            if len(stderr) > 65536 or hashlib.sha256(stderr).hexdigest() != receipt.get(
                "err_sha256"
            ):
                raise ValueError("receipt-integrity")
            value = safe_failure(error, phase, number, receipt, stderr)
    except (OSError, ValueError, TypeError, KeyError):
        value["diagnostic_evidence"] = "UNAVAILABLE_OR_INVALID"
    return value
