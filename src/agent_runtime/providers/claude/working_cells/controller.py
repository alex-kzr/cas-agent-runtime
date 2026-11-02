"""Offline by default; one private login and one or two planned fresh cells."""

import argparse
import ipaddress
import json
import os
import signal
import sys
from pathlib import Path

from . import (
    core,
    diagnostics,
    inventory_gate,
    network_contract,
    ready_channel,
    safe_work,
    spec,
    validate,
)

Failure = core.Failure


def running(doc):
    s = doc.get("State", {})
    if (
        s.get("Status") != "running"
        or s.get("Running") is not True
        or s.get("Pid", 0) <= 0
        or s.get("Paused")
        or s.get("Restarting")
    ):
        raise Failure("actual-running-state-required")


class Controller(core.ControllerBase):
    def __init__(self, *a, projection_callback=None, **kw):
        if projection_callback is not None:
            from agent_runtime.tasks import finite_projection
            if not finite_projection.enabled():
                raise Failure('FINITE_PROJECTION_GATE_CLOSED')
        super().__init__(*a, **kw)
        self.projection_callback = projection_callback
        self.volume_created = False
        self.removed = set()
        self.stopped = set()
        self.reports = {}
        self.started_stages = set()
        self.go_stages = set()
        self.docker.cleanup_reserve = self.cleanup_reserve

    def ready(self, job):
        deadline = min(self.deadline, self.clock() + 10)
        while self.clock() < deadline:
            out, err = job.output()
            if job.overflow or err or job.poll() is not None:
                raise Failure("relay-start-failed")
            if b"\n" in out:
                doc = json.loads(out.split(b"\n", 1)[0])
                addresses = doc.get("addresses", {})
                if (
                    doc.get("scope") != "cas-working-session-relay"
                    or doc.get("status") != "READY"
                    or doc.get("port") != 443
                    or (set(addresses) != set(spec.HOSTS))
                ):
                    raise Failure("relay-ready-targets")
                for address in addresses.values():
                    ip = ipaddress.ip_address(address)
                    if (
                        not isinstance(ip, ipaddress.IPv4Address)
                        or not ip.is_global
                        or ip.is_multicast
                        or ip.is_reserved
                    ):
                        raise Failure("relay-upstream")
                return
            self.sleep(0.02)
        raise Failure("relay-ready-timeout")

    def alive(self):
        return (
            self.relay_alive()
            and getattr(self, "auth_wait", None) is not None
            and (self.auth_wait.poll() is None)
        )

    def checked_running(self, role):
        doc = self.inspect("container", self.ids[role])
        validate.container_owner(doc, role, self.ids[role])
        validate.container(doc, role, self.networks)
        running(doc)
        return doc

    def wait_work_started(self, job, role):
        self.phase = "work_start_barrier"
        until = min(self.deadline, self.clock() + 5)
        for index in range(20):
            if (
                self.docker.cancelled.is_set()
                or not self.alive()
                or job.overflow
                or (job.poll() is not None)
            ):
                raise Failure("WORK_START_CLIENT_OR_HOLDER_LOST")
            remaining = until - self.clock()
            if remaining <= 0:
                raise Failure("WORK_START_TIMEOUT")
            doc = validate.one(
                json.loads(
                    self.call(spec.inspect_container(self.ids[role]), min(5, remaining))["out"]
                )
            )
            validate.container_owner(doc, role, self.ids[role])
            state = doc.get("State", {})
            if state.get("Status") == "running":
                validate.container(doc, role, self.networks)
                running(doc)
                if (
                    self.docker.cancelled.is_set()
                    or not self.alive()
                    or job.overflow
                    or (job.poll() is not None)
                ):
                    raise Failure("WORK_START_CLIENT_OR_HOLDER_LOST")
                self.phase = "sdk"
                return doc
            if state.get("Status") != "created":
                raise Failure("WORK_START_STATE_INVALID")
            validate.container(doc, role, self.networks, created=True)
            self.sleep(max(0, until - self.clock()) / (20 - index))
        raise Failure("WORK_START_TIMEOUT")

    def progress(self, status):
        from agent_runtime.telemetry.recorder import atomic_json

        atomic_json(
            spec.ROOT / "progress.json",
            dict(
                session_id=spec.POLICY["session_id"],
                attempt=spec.ATTEMPT,
                status=status,
                stages=self.reports,
            ),
        )

    def completed_failed_work_client(self, job, error, writers_absent):
        """A task/protocol failure is separate from proven client/resource cleanup."""
        value = getattr(job, "recorded_result", None)
        if (
            writers_absent is not True or getattr(job, "fixed_work", False) is not True
            or not isinstance(error, core.Failure) or not isinstance(value, dict)
            or type(value.get("failure")) is not str
            or value.get("failure") not in {
                "WORK_CLIENT_NONZERO", "WORK_STDERR_PRESENT", "WORK_SUMMARY_INVALID",
                "WORK_TIMEOUT", "WORK_PEER_OR_CANCEL_LOST",
            }
            or str(error) != value["failure"]
            or type(error.receipt_number) is not int or not 1 <= error.receipt_number <= 112
            or error.receipt_number != getattr(job, "receipt_number", None)
            or not safe_work.completed_client(value)
        ):
            return False
        try:
            rc = job.poll()
            threads = getattr(job, "threads", None)
            return (
                type(rc) is int and getattr(job, "overflow", None) is False
                and isinstance(threads, list) and not any(t.is_alive() for t in threads)
                and value["work_projection"]["client_rc"] == ("ZERO" if rc == 0 else "NONZERO")
            )
        except Exception:
            return False

    def cleanup_reserve(self):
        # Upper bound for remaining exact-owned cleanup calls under the serial invariant.
        count = 0
        for role in spec.CONTAINERS:
            count += (
                1
                if role not in self.created_roles or role in self.removed
                else 3
                if role in self.stopped
                else 7
            )
        return count + 2 + 1 + 3 * len(self.created_networks) + (6 if self.volume_created else 0)

    def note_failure(self, error):
        codes = {
            "cancelled",
            "WORK_PEER_OR_CANCEL_LOST",
            "WORK_START_CLIENT_OR_HOLDER_LOST",
            "SERIES_PEER_LOST",
        }
        code = str(error) if isinstance(error, core.Failure) else None
        requested = getattr(self.docker.cancelled, "authorized", self.docker.cancelled.is_set)()
        peers = (
            hasattr(self, "relay_job")
            and getattr(self, "auth_wait", None) is not None
            and self.alive()
        )
        self.cancel_cleanup_authorized = bool(requested and peers and code in codes)
        self.live_before_go_cancel = {
            getattr(j, "expected_stage", None)
            for j in self.jobs
            if getattr(j, "fixed_work", False)
            and getattr(j, "expected_stage", None) not in self.go_stages
            and j.poll() is None
            and not hasattr(j, "recorded_result")
        }

    def expected_cancel_client(self, job, writers_absent):
        value = getattr(job, "recorded_result", {})
        info = value.get("client_cleanup")
        if (
            not getattr(self, "cancel_cleanup_authorized", False)
            or not writers_absent
            or not getattr(job, "fixed_work", False)
            or not isinstance(info, dict)
        ):
            return False
        clean = (
            info.get("client_stopped") is True
            and info.get("capture_complete") is True
            and info.get("capture_overflow") is False
            and info.get("peer_lost") is False
        )
        requested = (
            value.get("failure") == "WORK_PEER_OR_CANCEL_LOST"
            and info.get("explicit_cancel") is True
            and info.get("cancel_terminated_client") is True
        )
        stage = getattr(job, "expected_stage", None)
        before_go = (
            stage in getattr(self, "live_before_go_cancel", set())
            and spec.STAGES.get(stage) in getattr(self, "controlled_work_stops", set())
            and value.get("failure") == "WORK_CLIENT_NONZERO"
        )
        return clean and (requested or before_go)

    def fresh(self):
        super().fresh()
        if self.inspect("volume", spec.VOLUME) is not None:
            raise Failure("profile-name-already-exists")

    def create_role(self, role):
        if role in self.created_roles:
            raise Failure("WORK_RESTART_FORBIDDEN")
        self.created_roles.append(role)  # Before uncertain create, recover only exact owned name.
        value = self.call(spec.create(role, self.networks["internal"]))
        self.ids[role] = network_contract.create_id(value["out"])
        validate.container_owner(self.inspect("container", self.ids[role]), role, self.ids[role])
        if role == "relay":
            self.call(
                [
                    "network",
                    "connect",
                    "--ip",
                    "10.253.251.2",
                    self.networks["external"],
                    self.ids[role],
                ]
            )
        doc = self.inspect("container", self.ids[role])
        validate.container_owner(doc, role, self.ids[role])
        validate.container(doc, role, self.networks, created=True)

    def create_shared(self):
        self.volume_created = True
        self.call(spec.volume_create())
        validate.volume(self.inspect("volume", spec.VOLUME))
        for role in ("internal", "external"):
            self.created_networks.append(role)
            value = self.call(spec.network_create(role))
            self.networks[role] = network_contract.create_id(value["out"])
            if (
                validate.network(self.inspect("network", self.networks[role]), role)
                != self.networks[role]
            ):
                raise Failure("CREATED_NETWORK_ID_MISMATCH")
        for role in ("relay", "auth"):
            self.create_role(role)

    def endpoint_gate(self):
        doc = self.inspect("network", self.networks["internal"])
        if validate.network(doc, "internal") != self.networks["internal"]:
            raise Failure("SERIES_NETWORK_ID_CHANGED")
        if not set(doc.get("Containers") or {}).issubset({self.ids["relay"], self.ids["auth"]}):
            raise Failure("SERIES_ENDPOINT_NOT_RELEASED")

    def remaining_gate(self):
        if self.docker.cancelled.is_set() or not self.alive():
            raise Failure("SERIES_PEER_LOST")
        if (
            min(
                self.deadline - self.clock(),
                self.relay_started + 400 - self.clock(),
                self.auth_started + 380 - self.clock(),
            )
            < 60
        ):
            raise Failure("SERIES_REMAINING_LIFE")

    def absent_work(self, role):
        # Both immutable ID (if known) and fixed name; never accept a foreign-name collision.
        targets = list(
            dict.fromkeys(
                [self.ids[role], spec.CONTAINERS[role]]
                if role in self.ids
                else [spec.CONTAINERS[role]]
            )
        )
        return all(self.inspect("container", target) is None for target in targets)

    def remove_work(self, role):
        target = self.ids.get(role, spec.CONTAINERS[role])
        doc = self.inspect("container", target)
        if doc is not None:
            if role not in self.created_roles:
                raise Failure("SERIES_FOREIGN_WORK_NAME")
            identifier = validate.container_owner(doc, role, self.ids.get(role))
            self.ids.setdefault(role, identifier)
            if not validate.stopped(doc):
                stop_ok = False
                try:
                    self.call(["stop", "--timeout", "5", identifier], 7)
                    stop_ok = True
                except Exception:
                    pass
                doc = self.inspect("container", identifier)
                validate.container_owner(doc, role, identifier)
                if not validate.stopped(doc):
                    self.call(["kill", identifier], 3)
                    stop_ok = True
                    doc = self.inspect("container", identifier)
                    validate.container_owner(doc, role, identifier)
                    if not validate.stopped(doc):
                        raise Failure("SERIES_WORK_STOP_UNCONFIRMED")
                if stop_ok:
                    self.controlled_work_stops = getattr(self, "controlled_work_stops", set()) | {
                        role
                    }
            self.stopped.add(role)
            self.call(["rm", identifier], 3)
        if doc is None:
            if (
                target != spec.CONTAINERS[role]
                and self.inspect("container", spec.CONTAINERS[role]) is not None
            ):
                raise Failure("SERIES_WORK_ABSENCE_UNCONFIRMED")
        elif not self.absent_work(role):
            raise Failure("SERIES_WORK_ABSENCE_UNCONFIRMED")
        self.removed.add(role)

    def stage(self, stage):
        if stage not in spec.STAGES:
            raise Failure("UNPLANNED_WORKING_SESSION_STAGE")
        role = spec.STAGES[stage]
        if stage in self.started_stages:
            raise Failure("WORK_RESTART_FORBIDDEN")
        if stage == "second" and ("first" not in self.reports or not self.absent_work("work_a")):
            raise Failure("SERIES_FIRST_NOT_QUIESCENT")
        self.remaining_gate()
        self.endpoint_gate()
        self.remaining_gate()
        self.phase = "resource_setup"
        self.create_role(role)
        self.docker.work_owner_id = self.ids[role]
        self.docker.work_owner_stage = stage
        self.started_stages.add(stage)
        job = self.docker.launch(["start", "--attach", "--interactive", self.ids[role]])
        self.jobs.append(job)
        self.wait_work_started(job, role)
        self.checked_running("auth")
        validate.volume(self.inspect("volume", spec.VOLUME))
        self.remaining_gate()
        if (
            self.docker.cancelled.is_set()
            or not self.alive()
            or job.overflow
            or job.poll() is not None
        ):
            raise Failure("WORK_START_CLIENT_OR_HOLDER_LOST")
        if stage in self.go_stages:
            raise Failure("WORK_RESTART_FORBIDDEN")
        self.go_stages.add(stage)
        job.process.stdin.write(b"GO\n")
        job.process.stdin.close()
        value = self.docker.finish(job, min(60, self.deadline - self.clock()), guard=self.alive)
        self.jobs.remove(job)
        report = json.loads(value["out"])
        if value["rc"] != 0 or not safe_work.accepted(report, stage):
            raise Failure("SERIES_STAGE_NOT_ACCEPTED")
        doc = self.inspect("container", self.ids[role])
        validate.container_owner(doc, role, self.ids[role])
        validate.container(doc, role, self.networks, exited=True)
        if not validate.success_exit(doc):
            raise Failure("SERIES_WORK_EXIT")
        self.stopped.add(role)
        self.checked_running("auth")
        self.remaining_gate()
        if stage == "second" and report["session_hash"] == self.reports["first"]["session_hash"]:
            raise Failure("SERIES_SESSION_REUSED")
        self.remove_work(role)
        if self.projection_callback is not None:
            from agent_runtime.tasks import finite_projection
            if not finite_projection.enabled():
                raise Failure('FINITE_PROJECTION_GATE_CLOSED')
            self.projection_callback(stage, spec.RUNS[stage])
        self.reports[stage] = report
        self.progress("RUNNING")

    def execute(self):
        self.phase = "freshness"
        self.fresh()
        self.phase = "resource_setup"
        self.create_shared()
        self.relay_started = self.clock()
        self.docker.relay_owner_id = self.ids["relay"]
        self.relay_job = self.docker.launch(["start", "--attach", self.ids["relay"]])
        self.relay_job.process.stdin.close()
        self.jobs.append(self.relay_job)
        self.ready(self.relay_job)
        self.checked_running("relay")
        if not spec.LOCAL_AUTH:
            print(
                "One official login in this PRIVATE terminal. After CAS_LOGIN_READY detach Ctrl-P then Ctrl-Q. Never paste login details into chat.",
                flush=True,
            )
        self.progress("LOGIN_REQUIRED")
        self.phase = "private_login"
        self.auth_started = self.clock()
        self.docker.auth_owner_id = self.ids["auth"]
        if spec.LOCAL_AUTH:
            attach = self.docker.launch(['start', self.ids['auth']])
            attach.process.stdin.close()
        else:
            attach = self.docker.private(
                ["start", "--attach", "--interactive", "--detach-keys=ctrl-p,ctrl-q", self.ids["auth"]]
            )
        if (
            self.docker.finish(
                attach, min(300, self.deadline - self.clock()), guard=self.relay_alive
            )["rc"]
            != 0
        ):
            raise Failure("private-login-attach-failed")
        self.checked_running("auth")
        self.phase = "ready_transport"
        self.docker.ready_owner_id = self.ids["auth"]
        ready_channel.once(
            self.docker,
            self.ids["auth"],
            min(5, self.deadline - self.clock()),
            guard=self.relay_alive,
        )
        self.checked_running("auth")
        self.auth_wait = self.docker.launch(["wait", self.ids["auth"]])
        self.auth_wait.process.stdin.close()
        self.jobs.append(self.auth_wait)
        self.progress("RUNNING")
        for stage in spec.STAGES:
            self.stage(stage)
        return dict(
            scope="cas-product-working-session-v1",
            result="PASS",
            completed_stages=list(spec.STAGES),
            session_ids_distinct=True if len(spec.STAGES) == 2 else None,
            auth_profile_shared=True,
            context_isolation="NOT_PROVED",
            provider_cancellation="NOT_PROVED",
        )

    def cleanup(self):
        self.cleaning = True
        self.docker.ignore_cancel = True
        self.deadline = self.clock() + 45
        quiet = []
        for role in reversed(tuple(spec.STAGES.values())):
            try:
                self.remove_work(role)
                quiet.append(True)
            except Exception:
                self.cleanup_errors.append(
                    dict(
                        kind="container",
                        target=self.ids.get(role, spec.CONTAINERS[role]),
                        reason="WORK_CLEANUP_UNCONFIRMED",
                    )
                )
                quiet.append(False)
        writers_absent = all(quiet)
        for role in ("auth", "relay"):
            try:
                target = self.ids.get(role, spec.CONTAINERS[role])
                doc = self.inspect("container", target)
                if doc is None:
                    continue
                if role not in self.created_roles:
                    raise Failure("SERIES_FOREIGN_NAME")
                identifier = validate.container_owner(doc, role, self.ids.get(role))
                self.ids.setdefault(role, identifier)
                if not validate.stopped(doc):
                    if role == "auth" and writers_absent:
                        self.call(["kill", "--signal", "USR1", identifier], 3)
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
                            raise Failure("SERIES_SHARED_STOP_UNCONFIRMED")
                if not validate.success_exit(doc):
                    self.cleanup_errors.append(dict(kind=role, reason="NONZERO_OR_UNCLEAN_EXIT"))
                self.call(["rm", identifier], 3)
                if self.inspect("container", identifier) is not None:
                    raise Failure("SERIES_SHARED_ABSENCE_UNCONFIRMED")
                self.removed.add(role)
            except Exception:
                self.cleanup_errors.append(
                    dict(
                        kind="container",
                        target=self.ids.get(role, spec.CONTAINERS[role]),
                        reason="SHARED_CLEANUP_UNCONFIRMED",
                    )
                )
        for job in self.jobs:
            try:
                value = self.docker.finish(job, 2)
                if job is getattr(self, "relay_job", None) and (
                    value["rc"] != 0 or value["err"] or b'"FAIL"' in value["out"]
                ):
                    raise Failure("relay-terminal-failure")
            except Exception as error:
                if not (
                    self.completed_failed_work_client(job, error, writers_absent)
                    or self.expected_cancel_client(job, writers_absent)
                ):
                    self.cleanup_errors.append(
                        dict(kind="client", reason="CAPTURE_OR_TERMINATION_UNCONFIRMED")
                    )
        if getattr(self, "auth_wait", None) is not None:
            try:
                value = self.docker.finish(self.auth_wait, 1)
                if value["rc"] != 0 or value["out"].strip() != b"0" or value["err"]:
                    raise Failure("holder-terminal-state")
            except Exception:
                self.cleanup_errors.append(dict(kind="holder", reason="HOLDER_EXIT_UNCONFIRMED"))
        for role in reversed(self.created_networks):
            try:
                doc = self.inspect("network", self.networks.get(role, spec.NETWORKS[role]))
                if doc is None:
                    continue
                identifier = validate.cleanup_network(doc, role, self.networks.get(role))
                if doc.get("Containers"):
                    raise Failure("network-consumers")
                self.call(["network", "rm", identifier], 3)
                if self.inspect("network", identifier) is not None:
                    raise Failure("network-remains")
            except Exception:
                self.cleanup_errors.append(
                    dict(
                        kind="network",
                        target=self.networks.get(role, spec.NETWORKS[role]),
                        reason="NETWORK_CLEANUP_UNCONFIRMED",
                    )
                )
        if self.volume_created:
            try:
                doc = self.inspect("volume", spec.VOLUME)
                if doc is not None:
                    validate.volume_owner(doc)
                    if not writers_absent or any(
                        self.inspect("container", spec.CONTAINERS[r]) is not None
                        for r in ("auth", *spec.STAGES.values())
                    ):
                        raise Failure("profile-consumers-unknown")
                    self.call(["volume", "rm", spec.VOLUME], 3)
                    if self.inspect("volume", spec.VOLUME) is not None:
                        raise Failure("profile-remains")
            except Exception:
                self.cleanup_errors.append(
                    dict(kind="volume", target=spec.VOLUME, reason="PROFILE_CLEANUP_UNCONFIRMED")
                )
        try:
            for reason in self.docker.sweep(3):
                self.cleanup_errors.append(dict(kind="client", reason=reason))
        except Exception:
            self.cleanup_errors.append(dict(kind="client", reason="SWEEP_FAILED"))


def gates(approval):
    if spec.ROOT.resolve() != spec.EXPECTED_ROOT.resolve():
        raise Failure("fixed-sealed-location-required")
    manifest = json.loads((spec.ROOT / "manifest.json").read_text())
    digest = spec.hashfile(spec.ROOT / "manifest.json")
    expected = spec.approval(digest, True)
    if approval != expected:
        raise Failure("fresh-specific-owner-grant-required")
    for row in manifest["files"]:
        p = (spec.ROOT / row["path"]).resolve()
        if not p.is_relative_to(spec.ROOT.resolve()) or spec.hashfile(p) != row["sha256"]:
            raise Failure("sealed-file-changed")
    if spec.hashfile(spec.load("client.json")["Path"]) != spec.load("client.json")["SHA256"]:
        raise Failure("client-changed")
    return digest


def preflight(docker):
    from .host_routes import assert_no_overlap, read_routes

    routes = read_routes()
    assert_no_overlap(routes, [spec.INTERNAL, spec.EXTERNAL])
    inventory_gate.check_live(docker, routes, [spec.INTERNAL, spec.EXTERNAL])
    requests = [
        (
            [
                "image",
                "inspect",
                "--format",
                '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}}}',
                spec.IMAGE,
            ],
            "image.json",
        ),
        (
            [
                "info",
                "--format",
                '{"ServerVersion":{{json .ServerVersion}},"OSType":{{json .OSType}},"Architecture":{{json .Architecture}},"KernelVersion":{{json .KernelVersion}},"CgroupVersion":{{json .CgroupVersion}},"SecurityOptions":{{json .SecurityOptions}},"DefaultRuntime":{{json .DefaultRuntime}}}',
            ],
            "backend.json",
        ),
        (["version", "--format", "{{json .Server}}"], "server-version.json"),
        (spec.image_defaults(), "image-defaults.json"),
    ]
    for args, name in requests:
        value = docker.run(args)
        if value["rc"] != 0 or json.loads(value["out"]) != spec.load(name):
            raise Failure("image-backend-change-no-repin")


def claim_once(digest):
    if spec.EVIDENCE.exists():
        raise Failure("fixed-evidence-must-be-new")
    with spec.CLAIM.open("x") as f:
        json.dump(dict(state="CONSUMED_NO_RETRY", attempt=spec.ATTEMPT, manifest_sha256=digest), f)
        f.flush()
        os.fsync(f.fileno())
    spec.EVIDENCE.mkdir()


class CancelRequest:
    def __init__(self, event):
        self.event = event
        self.invalid = False

    def set(self):
        self.event.set()

    def authorized(self):
        path = spec.ROOT / "cancel.request.json"
        try:
            if path.is_symlink() or path.is_junction():
                self.invalid = True
                return False
            if path.exists():
                if path.stat().st_size > 1024:
                    self.invalid = True
                    return False
                value = json.loads(path.read_text())
                if value != dict(
                    session_id=spec.POLICY["session_id"],
                    attempt=spec.ATTEMPT,
                    manifest_sha256=spec.hashfile(spec.ROOT / "manifest.json"),
                ):
                    self.invalid = True
                    return False
                return True
        except (OSError, ValueError):
            self.invalid = True
            return False
        return self.event.is_set()

    def is_set(self):
        return self.authorized() or self.invalid


def main(argv=None, emit_result=True, projection_callback=None):
    if projection_callback is not None:
        from agent_runtime.tasks import finite_projection
        if not finite_projection.enabled():
            raise Failure('FINITE_PROJECTION_GATE_CLOSED')
    p = argparse.ArgumentParser()
    p.add_argument("--execute", action="store_true")
    p.add_argument("--approval", type=Path)
    args = p.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(dict(status="OFFLINE_ONLY", runtime="NOT_RUN", logins=1, max_sdk_prompts=len(spec.STAGES)))
        )
        return 0
    if args.approval is None or (not spec.LOCAL_AUTH and not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr))):
        raise Failure("private-foreground-required")
    digest = gates(json.loads(args.approval.read_text()))
    claim_once(digest)
    docker = core.Docker(spec.EVIDENCE)
    runner = (Controller(docker, spec.EVIDENCE) if projection_callback is None else
              Controller(docker, spec.EVIDENCE, projection_callback=projection_callback))
    docker.cancelled = CancelRequest(docker.cancelled)
    cancellations = []
    previous = {
        n: signal.signal(n, lambda n, frame: core.latch_cancel(docker, cancellations, n))
        for n in (signal.SIGINT, signal.SIGTERM)
    }
    result = reason = diagnostic = None
    try:
        preflight(docker)
        result = runner.execute()
    except BaseException as error:
        reason = type(error).__name__
        runner.note_failure(error)
        diagnostic = diagnostics.from_evidence(
            error, getattr(runner, "phase", "preflight"), spec.EVIDENCE, docker.number
        )
    finally:
        runner.cleanup()
    if cancellations and reason is None:
        reason = "CANCELLED"
    if docker.evidence_errors and reason is None:
        reason = "EVIDENCE_WRITE_FAILED"
    outcome = dict(
        attempt=spec.ATTEMPT,
        result="COMPLETED_WORKING_SESSION_ONLY"
        if result and reason is None and not runner.cleanup_errors
        else "FAIL_OR_INCONCLUSIVE",
        summary=result,
        stages=runner.reports,
        reason=reason,
        cleanup_errors=runner.cleanup_errors,
        evidence_errors=docker.evidence_errors,
        containers=runner.ids,
        networks=runner.networks,
        profile_volume=spec.VOLUME,
        latched_cancellations=len(cancellations),
        no_retry=True,
        diagnostic=diagnostic,
        context_isolation="NOT_PROVED",
        provider_cancellation="NOT_PROVED",
        cancellation_local_expected=bool(getattr(runner, "cancel_cleanup_authorized", False)),
    )
    try:
        (spec.EVIDENCE / "outcome.json").write_text(json.dumps(outcome, indent=2))
    except OSError:
        outcome.update(result="FAIL_OR_INCONCLUSIVE", reason="FINAL_EVIDENCE_WRITE_FAILED")
    if emit_result:
        print(json.dumps(outcome, indent=2))
    for n, handler in previous.items():
        signal.signal(n, handler)
    return 0 if outcome["result"] == "COMPLETED_WORKING_SESSION_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
