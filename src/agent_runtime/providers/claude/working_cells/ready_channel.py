"""One exact noninteractive exec; fixed token or fixed failure, never raw output evidence."""

from . import core as transport
from . import spec

TOKEN = b"CAS_READY_V1_OK\n"


def sanitize(result):
    accepted = (
        result.get("rc") == 0
        and result.get("failure") is None
        and result.get("out") == TOKEN
        and result.get("err") == b""
    )
    return dict(
        rc=0 if accepted else 1,
        out=TOKEN if accepted else b"",
        err=b"",
        failure=None if accepted else "READY_CHANNEL_REJECTED",
        elapsed=result.get("elapsed", 0),
        capture="FIXED_READY_ONLY",
        raw_output_discarded=True,
    )


def once(docker, identifier, seconds, guard=lambda: True):
    if getattr(docker, "ready_channel_attempted", False):
        raise transport.Failure("READY_CHANNEL_ALREADY_ATTEMPTED")
    docker.ready_channel_attempted = True
    if seconds <= 0 or docker.cancelled.is_set() or not guard():
        raise transport.Failure("READY_CHANNEL_REJECTED")
    args = spec.ready_exec(identifier)
    spec.authorize(args)
    job = docker.launch(args)
    job.fixed_ready = True
    job.process.stdin.close()
    # Killing the CLI does not prove termination of daemon-side exec. Caller must
    # stop/remove the exact owned container on ANY failure, before any SDK GO.
    value = docker.finish(job, min(5, seconds), guard)
    if value["out"] != TOKEN or value["err"] or value["rc"] != 0:
        raise transport.Failure("READY_CHANNEL_REJECTED")
    return True
