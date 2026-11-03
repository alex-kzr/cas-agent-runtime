"""One-shot host lifecycle controller. Import/tests are offline; execute requires a fresh grant."""

import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

from . import spec, validate


class Failure(RuntimeError):
    def __init__(self, code, receipt_number=None):
        super().__init__(code)
        self.receipt_number = receipt_number


def latch_cancel(docker, cancellations, number):
    cancellations.append(number)
    docker.cancelled.set()


def absent(returncode, stderr, kind, target):
    message = stderr.decode("utf-8", errors="strict").strip()
    expected = {"Error: No such object: " + target}
    if kind == "container":
        expected.add("Error: No such container: " + target)
        expected.add("Error response from daemon: No such container: " + target)
    elif kind == "network":
        expected.add("Error response from daemon: network " + target + " not found")
        expected.add("Error: No such network: " + target)
    elif kind == "volume":
        expected.update(
            {
                "Error response from daemon: get " + target + ": no such volume",
                "Error: No such volume: " + target,
            }
        )
    return returncode == 1 and message in expected


class Job:
    """Bounded capture of the direct Docker client, not a claim about its process tree."""

    def __init__(self, prefix, arguments, environment, secret=b"", cancelled=lambda: False):
        self.start = time.monotonic()
        self.process = subprocess.Popen(
            prefix + arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            bufsize=0,
        )
        self.out, self.err = bytearray(), bytearray()
        self.overflow = False
        self.secret = secret
        self.cancelled = cancelled
        self.capture_lock = threading.Lock()
        self.threads = []
        for stream, target in ((self.process.stdout, self.out), (self.process.stderr, self.err)):

            def drain(stream=stream, target=target):
                try:
                    while chunk := stream.read(4096):
                        with self.capture_lock:
                            if len(self.out) + len(self.err) + len(chunk) > (
                                32768 if arguments[:1] == ["exec"] else 65536
                            ):
                                self.overflow = True
                                return
                            target.extend(chunk)
                except OSError:
                    self.overflow = True

            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            self.threads.append(thread)

    def poll(self):
        return self.process.poll()

    def output(self):
        return bytes(self.out), bytes(self.err)

    def finish(self, seconds, guard=lambda: True):
        deadline = time.monotonic() + max(0, seconds)
        failure = None
        explicit_cancel = False
        peer_lost = False
        cancel_terminated_client = False
        while self.poll() is None:
            cancelled = getattr(self, "cancelled", lambda: False)
            requested = cancelled()
            peer_ok = guard()
            explicit_cancel = explicit_cancel or bool(
                getattr(self, "authorized_cancel", cancelled)()
            )
            peer_lost = peer_lost or not peer_ok
            expired = time.monotonic() >= deadline
            if self.overflow or requested or not peer_ok or expired:
                failure = (
                    "capture-overflow"
                    if self.overflow
                    else "client-timeout"
                    if expired
                    else "cancelled-or-peer-failed"
                )
                cancel_terminated_client = bool(
                    requested and explicit_cancel and peer_ok and not self.overflow and not expired
                )
                self.process.kill()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    failure = "client-termination-unconfirmed"
                break
            time.sleep(0.02)
        for thread in self.threads:
            thread.join(timeout=0.5)
        if any(thread.is_alive() for thread in self.threads) and failure in {
            None,
            "cancelled-or-peer-failed",
        }:
            failure = "capture-incomplete"
        if self.overflow and failure in {None, "cancelled-or-peer-failed"}:
            failure = "capture-overflow"
        requested = getattr(self, "cancelled", lambda: False)()
        peer_ok = guard()
        explicit_cancel = explicit_cancel or bool(
            getattr(self, "authorized_cancel", getattr(self, "cancelled", lambda: False))()
        )
        peer_lost = peer_lost or not peer_ok
        if not peer_ok and failure is None:
            failure = "cancelled-or-peer-failed"
        out, err = self.output()
        if self.secret:
            out, err = (
                out.replace(self.secret, b"[REDACTED]"),
                err.replace(self.secret, b"[REDACTED]"),
            )
        return {
            "rc": self.poll(),
            "out": out,
            "err": err,
            "failure": failure,
            "elapsed": time.monotonic() - self.start,
            "client_cleanup": dict(
                client_stopped=self.poll() is not None,
                capture_complete=not any(t.is_alive() for t in self.threads),
                capture_overflow=self.overflow,
                explicit_cancel=explicit_cancel,
                peer_lost=peer_lost,
                cancel_terminated_client=cancel_terminated_client,
            ),
        }


class Docker:
    def __init__(self, evidence, secret=b""):
        self.evidence = evidence
        self.secret = secret
        self.number = 0
        self.bytes = 0
        self.jobs = []
        self.evidence_errors = []
        self.cancelled = threading.Event()
        self.ignore_cancel = False
        config = evidence / "empty-docker-config"
        config.mkdir()
        client = spec.load("client.json")
        self.prefix = [client["Path"], "--config", str(config), "--host", spec.ENDPOINT]
        self.env = {
            name: os.environ[name] for name in ("SYSTEMROOT", "WINDIR") if name in os.environ
        }
        self.env["PATH"] = str(Path(client["Path"]).parent)

    def launch(self, args):
        spec.authorize(args)
        self.last_args = list(args)
        self.last_rc = None
        if args[:1] == ["exec"]:
            if args[5] != getattr(self, "ready_owner_id", None) or getattr(
                self, "exec_used", False
            ):
                raise Failure("READY_EXEC_AUTHORITY_DENIED")
            self.exec_used = True
        if self.cancelled.is_set() and not self.ignore_cancel:
            raise Failure("cancelled")
        if self.number >= (112 if self.ignore_cancel else 72):
            raise Failure("operation-budget")
        if (
            not self.ignore_cancel
            and self.number + 1 + getattr(self, "cleanup_reserve", lambda: 0)() > 112
        ):
            raise Failure("CLEANUP_OPERATION_RESERVE")
        is_work = args == [
            "start",
            "--attach",
            "--interactive",
            getattr(self, "work_owner_id", None),
        ]
        if args[:1] == ["start"]:
            is_relay = args == ["start", "--attach", getattr(self, "relay_owner_id", None)]
            if not is_work and not is_relay:
                raise Failure("CAPTURE_START_AUTHORITY_DENIED")
            if is_relay:
                if getattr(self, "relay_start_used", False):
                    raise Failure("CAPTURE_START_AUTHORITY_DENIED")
                self.relay_start_used = True
        if is_work:
            stage = getattr(self, "work_owner_stage", None)
            if stage not in {"first", "second"} or args[-1] in getattr(
                self, "started_work_ids", set()
            ):
                raise Failure("WORK_RESTART_FORBIDDEN")
            self.started_work_ids = getattr(self, "started_work_ids", set()) | {args[-1]}
        self.number += 1
        job = Job(
            self.prefix,
            args,
            self.env,
            self.secret,
            cancelled=lambda: self.cancelled.is_set() and not self.ignore_cancel,
        )
        job.fixed_work = args == [
            "start",
            "--attach",
            "--interactive",
            getattr(self, "work_owner_id", None),
        ]
        job.authorized_cancel = lambda: (
            getattr(self.cancelled, "authorized", self.cancelled.is_set)()
            and not self.ignore_cancel
        )
        job.expected_stage = getattr(self, "work_owner_stage", None) if job.fixed_work else None
        job.fixed_ready = args[:1] == ["exec"]
        job.receipt_number = self.number
        job.arguments = args
        self.jobs.append(job)
        return job

    def private(self, args):
        spec.authorize(args)
        if (
            args[:-1] != ["start", "--attach", "--interactive", "--detach-keys=ctrl-p,ctrl-q"]
            or args[-1] != getattr(self, "auth_owner_id", None)
            or getattr(self, "private_used", False)
        ):
            raise Failure("PRIVATE_LOGIN_ONLY")
        self.private_used = True
        self.last_args = list(args)
        self.last_rc = None
        if self.cancelled.is_set() or self.number >= 72:
            raise Failure("private-login-cancel-or-budget")
        self.number += 1
        job = Job.__new__(Job)
        job.start = time.monotonic()
        # Inherit the user's unrecorded console. Never pipe/record URL, account, auth code or tokens.
        job.process = subprocess.Popen(
            self.prefix + args, stdin=None, stdout=None, stderr=None, env=self.env, shell=False
        )
        job.out, job.err, job.threads, job.secret, job.overflow = (
            bytearray(),
            bytearray(),
            [],
            b"",
            False,
        )
        job.cancelled = lambda: self.cancelled.is_set() and not self.ignore_cancel
        job.receipt_number, job.arguments, job.private = self.number, args, True
        self.jobs.append(job)
        return job

    def finish(self, job, seconds, guard=lambda: True):
        if hasattr(job, "recorded_result"):
            if job.recorded_result["failure"]:
                raise Failure(job.recorded_result["failure"], job.receipt_number)
            if job.recorded_result.get("evidence_write_failed") and not self.ignore_cancel:
                raise Failure("evidence-write-failed")
            return job.recorded_result
        result = job.finish(seconds, guard)
        captured = len(result["out"]) + len(result["err"])
        if getattr(job, "fixed_ready", False):
            from .ready_channel import sanitize

            result = sanitize(result)
            with job.capture_lock:
                job.out.clear()
                job.err.clear()
        if getattr(job, "fixed_work", False):
            from .safe_work import sanitize

            result = sanitize(result, job.expected_stage)
            with job.capture_lock:
                job.out.clear()
                job.err.clear()
        if job.receipt_number == self.number:
            self.last_rc = result["rc"]
        self.bytes += captured
        if self.bytes > (3145728 if self.ignore_cancel else 2097152):
            result["failure"] = "total-output-budget"
        base = f"{job.receipt_number:02d}"
        receipt = {
            "argv": self.prefix + job.arguments,
            "rc": result["rc"],
            "failure": result["failure"],
            "elapsed_monotonic_seconds": result["elapsed"],
            "ended_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "out_bytes": len(result["out"]),
            "err_bytes": len(result["err"]),
            "out_sha256": hashlib.sha256(result["out"]).hexdigest(),
            "err_sha256": hashlib.sha256(result["err"]).hexdigest(),
        }
        if getattr(job, "fixed_work", False):
            receipt["work_projection"] = result["work_projection"]
            receipt["stage"] = job.expected_stage
            receipt["client_cleanup"] = result.get("client_cleanup")
        receipt["capture"] = (
            "FIXED_READY_ONLY"
            if getattr(job, "fixed_ready", False)
            else "FIXED_WORK_SUMMARY"
            if getattr(job, "fixed_work", False)
            else "PRIVATE_LOGIN_NOT_CAPTURED"
            if getattr(job, "private", False)
            else "BOUNDED"
        )
        if getattr(job, "fixed_ready", False) or getattr(job, "fixed_work", False):
            receipt["raw_output_discarded"] = True
        job.recorded_result = result
        try:
            for label in ("out", "err"):
                (self.evidence / (base + "." + label + ".bin")).write_bytes(result[label])
            (self.evidence / (base + ".json")).write_text(json.dumps(receipt, indent=2))
        except OSError:
            result["evidence_write_failed"] = True
            self.evidence_errors.append({"receipt": base, "reason": "evidence-write-failed"})
            if not self.ignore_cancel:
                raise Failure("evidence-write-failed") from None
        if result["failure"]:
            raise Failure(result["failure"], job.receipt_number)
        return result

    def sweep(self, seconds=3):
        deadline = time.monotonic() + seconds
        errors = []
        for job in self.jobs:
            if job.poll() is None:
                job.process.kill()
                try:
                    job.process.wait(timeout=max(0.01, min(1, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    errors.append("direct-client-termination-unconfirmed")
            for thread in job.threads:
                thread.join(timeout=max(0, min(0.1, deadline - time.monotonic())))
            if any(thread.is_alive() for thread in job.threads):
                errors.append("client-capture-incomplete")
        try:
            (self.evidence / "direct-client-sweep.json").write_text(
                json.dumps({"errors": errors, "jobs": len(self.jobs)})
            )
        except OSError:
            errors.append("sweep-evidence-write-failed")
        return errors

    def run(self, args, seconds=5):
        job = self.launch(args)
        job.process.stdin.close()
        return self.finish(job, seconds)


class ControllerBase:
    def __init__(self, docker, evidence, *, clock=time.monotonic, sleep=time.sleep):
        self.docker, self.evidence, self.clock, self.sleep = docker, evidence, clock, sleep
        self.ids, self.networks = {}, {}
        self.created_roles, self.created_networks = [], []
        self.jobs = []
        self.cleanup_errors = []
        self.deadline = clock() + 420
        self.cleaning = False

    def call(self, args, seconds=5, allow_nonzero=False):
        if (
            getattr(self.docker, "cancelled", None)
            and self.docker.cancelled.is_set()
            and not self.cleaning
        ):
            raise Failure("cancelled")
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise Failure("lifecycle-deadline")
        result = self.docker.run(args, min(seconds, remaining))
        if result["rc"] != 0 and not allow_nonzero:
            raise Failure("docker-nonzero")
        return result

    def inspect(self, kind, target):
        result = self.call(
            spec.inspect_container(target) if kind == "container" else [kind, "inspect", target],
            allow_nonzero=True,
        )
        if absent(result["rc"], result["err"], kind, target) and result["out"].strip() in {
            b"",
            b"[]",
        }:
            return None
        if result["rc"] != 0:
            raise Failure("inspection-uncertain")
        return validate.one(json.loads(result["out"]))

    def fresh(self):
        for kind, names in (("container", spec.CONTAINERS), ("network", spec.NETWORKS)):
            for name in names.values():
                if self.inspect(kind, name) is not None:
                    raise Failure("name-already-exists")

    def relay_alive(self):
        job = self.relay_job
        out, err = job.output()
        return job.poll() is None and not job.overflow and not err and b'"FAIL"' not in out

    def cleanup(self):
        self.cleaning = True
        self.docker.ignore_cancel = True
        self.deadline = self.clock() + 45
        if "work" not in self.created_roles:
            try:
                self.work_stopped_observed = (
                    self.inspect("container", spec.CONTAINERS["work"]) is None
                )
            except Exception:
                self.work_stopped_observed = False
        for role in reversed(self.created_roles):
            try:
                target = self.ids.get(role, spec.CONTAINERS[role])
                doc = self.inspect("container", target)
                if doc is None:
                    if role == "work":
                        self.work_stopped_observed = True
                    continue
                identifier = validate.container_owner(doc, role, self.ids.get(role))
                if (
                    self.ids.get(role)
                    and identifier != self.ids[role]
                    or doc.get("Image") != spec.IMAGE
                ):
                    raise Failure("cleanup-identity")
                if (
                    role in {"relay", "auth"}
                    and getattr(self, "work_accepted", False)
                    and validate.stopped(doc)
                ):
                    self.cleanup_errors.append(
                        {
                            "kind": role,
                            "target": identifier,
                            "reason": role + "-exited-before-controller-stop",
                        }
                    )
                if not validate.stopped(doc):
                    if role == "auth" and getattr(self, "work_stopped_observed", False):
                        try:
                            # Nonfatal SIGUSR1 only acknowledges that no work writer remains.
                            self.call(["kill", "--signal", "USR1", identifier], 3)
                        except Exception:
                            self.cleanup_errors.append(
                                {"kind": "auth", "reason": "logout-ack-unconfirmed"}
                            )
                    # stop may time out; reread exact-ID state before choosing kill.
                    try:
                        self.call(["stop", "--timeout", "5", identifier], 7)
                    except Exception:
                        pass
                    doc = self.inspect("container", identifier)
                    validate.container_owner(doc, role, identifier)
                    if not validate.stopped(doc):
                        self.call(["kill", identifier], 3)
                        doc = self.inspect("container", identifier)
                        validate.container_owner(doc, role, identifier)
                        if not validate.stopped(doc):
                            raise Failure("cleanup-still-running")
                if role == "work":
                    self.work_stopped_observed = True
                if role in {"relay", "auth"} and not validate.success_exit(doc):
                    self.cleanup_errors.append(
                        {
                            "kind": role,
                            "target": identifier,
                            "reason": role + "-nonzero-or-unclean-exit",
                        }
                    )
                self.call(["rm", identifier], 3)
                if self.inspect("container", identifier) is not None:
                    raise Failure("post-rm-container-present")
            except Exception as error:
                self.cleanup_errors.append(
                    {
                        "kind": "container",
                        "target": self.ids.get(role, spec.CONTAINERS[role]),
                        "reason": type(error).__name__,
                    }
                )
        for job in self.jobs:
            try:
                result = self.docker.finish(job, 2)
                if job is getattr(self, "relay_job", None) and (
                    result["rc"] != 0 or result["err"] or b'"FAIL"' in result["out"]
                ):
                    raise Failure("relay-terminal-failure")
            except Exception:
                self.cleanup_errors.append(
                    {"kind": "client", "reason": "capture-or-termination-unconfirmed"}
                )
        for role in reversed(self.created_networks):
            try:
                doc = self.inspect("network", self.networks.get(role, spec.NETWORKS[role]))
                if doc is None:
                    continue
                identifier = validate.cleanup_network(doc, role, self.networks.get(role))
                if (
                    self.networks.get(role)
                    and identifier != self.networks[role]
                    or doc.get("Containers")
                ):
                    raise Failure("cleanup-network-consumers-or-id")
                self.call(["network", "rm", identifier], 3)
                if self.inspect("network", identifier) is not None:
                    raise Failure("post-rm-network-present")
            except Exception as error:
                self.cleanup_errors.append(
                    {
                        "kind": "network",
                        "target": self.networks.get(role, spec.NETWORKS[role]),
                        "reason": type(error).__name__,
                    }
                )
