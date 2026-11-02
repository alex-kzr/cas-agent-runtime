"""Finite product working sessions. No queue, automatic login, retry or persistent auth."""

import copy
import errno
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from agent_runtime.providers.claude.working_backend import (
    MODEL,
    complete_results,
    PRIVATE,
    DockerWorkingBackend,
    LEGACY_PRIVATE,
    read_json,
)
from agent_runtime.telemetry.recorder import RunLock, atomic_json
from agent_runtime.tasks import finite_projection

ACTIVE = {"STARTING", "LOGIN_REQUIRED", "RUNNING", "CANCEL_REQUESTED", "ENDING"}
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED", "CLOSED"}


def identity(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("INVALID_WORKING_SESSION_ID")
    return value


def stamp():
    return datetime.now(UTC).isoformat()


def safe_path(path):
    path = Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in [path, *path.parents]):
        raise ValueError("LINKED_WORKING_SESSION_PATH")
    return path


def text(value, maximum, empty=False, *, legacy=False):
    if (
        not isinstance(value, str)
        or (not empty and not value.strip())
        or len(value.encode("utf-8")) > maximum
        or (LEGACY_PRIVATE if legacy else PRIVATE).search(value)
    ):
        raise ValueError("BOUNDED_NONSENSITIVE_TEXT_REQUIRED")
    return value


class WorkingSessions:
    def __init__(self, data_dir, *, backend=None, root=None):
        self.data_dir = safe_path(data_dir)
        self.directory = safe_path(self.data_dir / "working-sessions")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.backend = backend or DockerWorkingBackend()
        self.root = Path(root).resolve() if root else self._discover_root()
        self.mutex = threading.RLock()

    def _discover_root(self):
        for p in Path(__file__).resolve().parents:
            if (p / "config/repositories.yaml").is_file():
                return p
        return None

    def folder(self, sid):
        return safe_path(self.directory / identity(sid))

    @contextmanager
    def guard(self):
        # Short record transactions may overlap across independent controllers.
        # Wait only for the kernel lock's explicit contention error; never retry work.
        deadline = time.monotonic() + 5
        lock = RunLock(safe_path(self.directory / ".records"))
        while True:
            try:
                lock.__enter__()
                break
            except RuntimeError as error:
                if (
                    str(error) != "Another CAS execution owns this data directory"
                    or not isinstance(error.__cause__, OSError)
                    or error.__cause__.errno not in {errno.EACCES, errno.EAGAIN}
                ):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("WORKING_SESSION_RECORD_LOCK_TIMEOUT") from error
                time.sleep(min(0.01, remaining))
        try:
            yield lock
        finally:
            lock.__exit__()

    def commit_terminal(self, sid, final):
        with self.mutex, self.guard():
            current = self.load(sid)
            if (current["attempt_id"], current["plan_hash"]) != (
                final["attempt_id"], final["plan_hash"]
            ):
                raise ValueError("STALE_WORKING_SESSION_TERMINAL")
            if current["status"] in TERMINAL:
                return current
            if current['schema_version'] == 2 and not finite_projection.enabled():
                raise PermissionError('FINITE_PROJECTION_GATE_CLOSED')
            # Keep the latest immutable plan; accepted intent remains in its durable
            # marker. Outcome retains completion/error precedence over late intent.
            current["results"] = self.merge_results(current, final["results"])
            for key in ("status", "cleanup", "code"):
                current[key] = final[key]
            if current['schema_version'] == 2:
                current['projection'] = finite_projection.append(current['projection'], 'terminal', current['status'])
            self.save(current)
            return current

    def load(self, sid):
        try:
            return self._load(sid)
        except (ValueError, OSError, TypeError, KeyError, IndexError, RecursionError):
            raise ValueError("INVALID_WORKING_SESSION_RECORD") from None

    def _load(self, sid):
        d = read_json(self.folder(sid) / "session.json")
        keys = {
            "schema_version",
            "session_id",
            "attempt_id",
            "title",
            "status",
            "created_at",
            "updated_at",
            "tasks",
            "plan_hash",
            "backend_version",
            "results",
            "cleanup",
            "code",
            "context_isolation",
            "provider_cancellation",
        }
        version = d.get('schema_version') if isinstance(d, dict) else None
        if type(version) is int and version == 2:
            keys.add('projection')
        if (
            not isinstance(d, dict)
            or set(d) != keys
            or type(version) is not int or version not in (1, 2)
            or d["session_id"] != sid
            or d["backend_version"] != self.backend.version
            or d["status"] not in ACTIVE | TERMINAL | {"DRAFT", "PREPARED"}
            or d["context_isolation"] != "NOT_PROVED"
            or d["provider_cancellation"] != "NOT_PROVED"
        ):
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        identity(d["attempt_id"])
        text(d["title"], 80, legacy=version == 1)
        for key in ["created_at", "updated_at"]:
            if (
                not isinstance(d[key], str)
                or len(d[key]) > 64
                or datetime.fromisoformat(d[key]).tzinfo is None
            ):
                raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if d["code"] not in {
            None,
            "PROGRESS_UNAVAILABLE",
            "PREPARATION_FAILED",
            "OWNER_LOST_NO_REPLAY",
            "EXECUTION_UNCONFIRMED_NO_REPLAY",
            "WORKING_SESSION_NOT_COMPLETED",
            "WORKING_SESSION_RESULT_UNAVAILABLE",
        }:
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if (
            not isinstance(d["tasks"], list)
            or len(d["tasks"]) > 2
            or not isinstance(d["results"], list)
            or len(d["results"]) > len(d["tasks"])
        ):
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        for task in d["tasks"]:
            if set(task) != {"task_id", "run_id", "title", "prompt"}:
                raise ValueError("INVALID_WORKING_SESSION_RECORD")
            identity(task["task_id"])
            identity(task["run_id"])
            text(task["title"], 80, legacy=version == 1)
            text(task["prompt"], 2048, legacy=version == 1)
        if any(len({t[k] for t in d["tasks"]}) != len(d["tasks"]) for k in ["task_id", "run_id"]):
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if d["plan_hash"] is not None and (
            not isinstance(d["plan_hash"], str)
            or len(d["plan_hash"]) != 64
            or any(c not in "0123456789abcdef" for c in d["plan_hash"])
        ):
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if d["cleanup"] not in {"NOT_STARTED", "PENDING", "CONFIRMED", "UNCONFIRMED"}:
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if d["results"]:
            stages = {s: r for s, r in zip(("first", "second"), d["results"], strict=False)}
            self.backend.project_stages(stages, d, legacy=version == 1)
        if d["status"] == "COMPLETED" and (
            d["cleanup"] != "CONFIRMED"
            or not complete_results(d, d["results"])
        ):
            raise ValueError("INVALID_WORKING_SESSION_RECORD")
        if version == 2:
            if d['status'] not in ACTIVE | TERMINAL or d['plan_hash'] is None or not d['tasks']:
                raise ValueError('INVALID_WORKING_SESSION_RECORD')
            projection = finite_projection.validate(d['projection'])
            terminal_events = [event for event in projection['events'] if event['kind'] == 'terminal']
            if projection['state']['terminal'] != (d['status'] if d['status'] in TERMINAL else None):
                raise ValueError('INVALID_WORKING_SESSION_RECORD')
            if 'second' in projection['state']['stages'] and len(d['tasks']) != 2:
                raise ValueError('INVALID_WORKING_SESSION_RECORD')
            for event in projection['events']:
                if event['kind'] == 'stage_completed' and (event['value'] == 'second' and len(d['tasks']) != 2 or not d['tasks']):
                    raise ValueError('INVALID_WORKING_SESSION_RECORD')
                if event['kind'] == 'terminal' and event['value'] != d['status']:
                    raise ValueError('INVALID_WORKING_SESSION_RECORD')
        return d

    def save(self, d):
        d["updated_at"] = stamp()
        if d.get('schema_version') == 2:
            if not finite_projection.enabled(): raise PermissionError('FINITE_PROJECTION_GATE_CLOSED')
            finite_projection.validate(d['projection'])
            encoded = json.dumps(d, ensure_ascii=False, allow_nan=False, indent=2) + '\n'
            if len(encoded.encode('utf-8')) > 65536:
                raise ValueError('FINITE_PROJECTION_RECORD_TOO_LARGE')
        atomic_json(self.folder(d["session_id"]) / "session.json", d)

    def _issue_finite_callback(self, d):
        """Private per-run sink; no callback can be issued with the release gate closed."""
        if not finite_projection.enabled():
            raise PermissionError('FINITE_PROJECTION_GATE_CLOSED')
        sid, attempt, plan = d['session_id'], d['attempt_id'], d['plan_hash']
        claim = {'attempt':attempt, 'manifest_sha256':plan, 'state':'CONSUMED_NO_REPLAY'}
        if d['schema_version'] != 2 or d['status'] != 'STARTING' or read_json(self._claim(d),4096) != claim:
            raise ValueError('FINITE_PROJECTION_ISSUER_UNAVAILABLE')
        runs = {s:t['run_id'] for s,t in zip(('first','second'),d['tasks'],strict=False)}
        fault = {'uncertain': False}
        def emit(stage, run_id):
            if fault['uncertain'] or not finite_projection.enabled():
                raise ValueError('FINITE_PROJECTION_UNAVAILABLE')
            try:
                if stage not in runs or runs[stage] != run_id:
                    raise ValueError('FINITE_PROJECTION_BINDING_MISMATCH')
                with self.mutex, self.guard():
                    current = self.load(sid)
                    if ((current['attempt_id'],current['plan_hash']) != (attempt,plan)
                            or current['schema_version'] != 2 or current['status'] not in ACTIVE
                            or read_json(self._claim(current),4096) != claim
                            or {s:t['run_id'] for s,t in zip(('first','second'),current['tasks'],strict=False)} != runs):
                        raise ValueError('FINITE_PROJECTION_STALE')
                    if stage == 'second' and 'first' not in current['projection']['state']['stages']:
                        raise ValueError('FINITE_PROJECTION_STAGE_ORDER')
                    current['projection'] = finite_projection.append(current['projection'],'stage_completed',stage)
                    self.save(current)
            except Exception:
                fault['uncertain'] = True
                raise ValueError('FINITE_PROJECTION_UNCONFIRMED') from None
            except BaseException:
                fault['uncertain'] = True
                raise
        return emit, fault

    def _claim(self, d):
        return self.folder(d["session_id"]) / "attempt.claim.json"

    def bundle(self, d):
        return safe_path(self.folder(d["session_id"]) / "bundle")

    def create(self, title="Working session"):
        text(title, 80)
        with self.mutex, self.guard():
            sid = str(uuid4())
            folder = self.folder(sid)
            folder.mkdir(exist_ok=False)
            d = dict(
                schema_version=1,
                session_id=sid,
                attempt_id=str(uuid4()),
                title=title,
                status="DRAFT",
                created_at=stamp(),
                updated_at=stamp(),
                tasks=[],
                plan_hash=None,
                backend_version=self.backend.version,
                results=[],
                cleanup="NOT_STARTED",
                code=None,
                context_isolation="NOT_PROVED",
                provider_cancellation="NOT_PROVED",
            )
            self.save(d)
            return self.view(d)

    def add(self, sid, *, title, prompt):
        text(title, 80)
        text(prompt, 2048)
        with self.mutex, self.guard():
            d = self.load(sid)
            if d["status"] != "DRAFT" or self._claim(d).exists() or len(d["tasks"]) >= 2:
                raise ValueError("WORKING_SESSION_PLAN_FROZEN_OR_FULL")
            d["tasks"].append(
                dict(task_id=str(uuid4()), run_id=str(uuid4()), title=title, prompt=prompt)
            )
            self.save(d)
            return self.view(d)

    def prepare(self, sid):
        if self.root is None:
            raise ValueError("EXPLICIT_CAS_ROOT_REQUIRED_FOR_LOCAL_COMMAND")
        with self.mutex, self.guard():
            d = self.load(sid)
            if d["status"] != "DRAFT" or not 1 <= len(d["tasks"]) <= 2 or self._claim(d).exists():
                raise ValueError("ONE_OR_TWO_DRAFT_TASKS_REQUIRED")
            self.validate_new_input(d)
            try:
                d["plan_hash"] = self.backend.prepare(self.bundle(d), d)
                d["status"] = "PREPARED"
                self.save(d)
            except Exception:
                d["status"] = "FAILED"
                d["code"] = "PREPARATION_FAILED"
                self.save(d)
                raise ValueError("WORKING_SESSION_PREPARATION_FAILED") from None
            return self.view(d)

    def merge_results(self, d, incoming):
        # A validated published prefix is immutable even if progress is stale.
        self.backend.project_stages(
            {s: r for s, r in zip(("first", "second"), incoming, strict=False)}, d
        )
        if len(incoming) > len(d["tasks"]):
            raise ValueError("INVALID_WORKING_SESSION_RESULT_PREFIX")
        if any(old != new for old, new in zip(d["results"], incoming, strict=False)):
            raise ValueError("CONFLICTING_WORKING_SESSION_RESULT_PREFIX")
        return copy.deepcopy(d["results"] if len(d["results"]) > len(incoming) else incoming)

    def read_progress(self, d):
        progress = self.backend.progress(self.bundle(d), d)
        if progress:
            return self.merge_results(d, progress[0]), progress[1]
        return None

    def view(self, d):
        result = copy.deepcopy(d)
        # No finite projection is exposed through existing API/UI while unqualified.
        result.pop('projection', None)
        if d["status"] in ACTIVE:
            try:
                progress = self.read_progress(d)
                if progress:
                    result["results"], status = progress
                    if d["status"] not in {"CANCEL_REQUESTED", "ENDING"}:
                        result["status"] = status
            except (ValueError, OSError, KeyError, TypeError):
                result["code"] = "PROGRESS_UNAVAILABLE"
        result['title'] = self.visible_text(result['title'])
        for task in result['tasks']:
            task['title'] = self.visible_text(task['title'])
            task['prompt'] = self.visible_text(task['prompt'])
        for item in result['results']:
            item['text'] = self.visible_text(item['text'])
        if d["status"] == "PREPARED":
            result["local_command"] = self.command(d)
            result['local_auth_mode'] = self.local_auth_mode(d)
        return result

    @staticmethod
    def visible_text(value):
        return '[REDACTED]' if PRIVATE.search(value) else value

    @staticmethod
    def validate_new_input(d):
        text(d['title'], 80)
        for task in d['tasks']:
            text(task['title'], 80)
            text(task['prompt'], 2048)

    def local_auth_mode(self, d):
        policy = self.bundle(d) / 'policy.json'
        return bool(read_json(policy).get('local_auth_file')) if policy.exists() else False

    def get(self, sid):
        sid = identity(sid)
        self.recover(sid)
        return self.view(self.load(sid))

    def list(self):
        self.recover()
        paths = list(self.directory.glob("*/session.json"))
        records = [self.load(p.parent.name) for p in paths]
        records.sort(key=lambda d: (datetime.fromisoformat(d['created_at']), d['session_id']),
                     reverse=True)
        return [self.view(d) for d in records]

    def scope(self, sid):
        d = self.load(sid)
        if d["status"] != "PREPARED":
            raise ValueError("PREPARED_WORKING_SESSION_REQUIRED")
        self.backend.verify(self.bundle(d), d)
        return dict(
            session_id=sid,
            attempt_id=d["attempt_id"],
            manifest_sha256=d["plan_hash"],
            tasks=[dict(task, title=self.visible_text(task['title']),
                        prompt=self.visible_text(task['prompt'])) for task in d['tasks']],
            model=MODEL,
            max_turns_each=1,
            sdk_seconds_each=30,
            sdk_estimate_usd_each="0.05",
            aggregate_estimate_usd="0.05" if len(d["tasks"]) == 1 else "0.10",
            max_sdk_prompts=len(d["tasks"]),
            billing_cap=False,
            subscription_only=True,
            persistent_auth=False,
            shared_auth_and_native_history=True,
            local_prompt_result_retention=True,
            max_result_utf8_each=4096,
            max_results_utf8_total=4096 * len(d["tasks"]),
            profile_tmpfs_mib=64,
            containers_total=2 + len(d["tasks"]),
            containers_concurrent=3,
            cpu_each=1,
            ram_mib_each=1024,
            pids_each=64,
            main_seconds=420,
            cleanup_seconds=45,
            total_docker_operations=112,
            main_docker_operations=72,
            networks=["10.253.250.0/29", "10.253.251.0/29"],
            tls_targets=["api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"],
            dns="1.1.1.1:53",
            relay_total_bytes=1048576,
            relay_connections=16,
            relay_active=4,
            retries=False,
            api_fallback=False,
            context_isolation="NOT_PROVED",
            provider_cancellation="NOT_PROVED",
            local_auth_mode=bool(os.environ.get('CAS_LOCAL_OWNER_AUTH_FILE')),
            approval_template=self.backend.approval(d, d["plan_hash"], False),
        )

    def command(self, d):
        def q(value):
            return "'" + str(value).replace("\\", "/").replace("'", "''") + "'"

        args = ["&", q(sys.executable), "-B", "-m", "agent_runtime"]
        if self.root:
            args += ["--root", q(self.root)]
        args += [
            "--data-dir",
            q(self.data_dir),
            "working-session",
            "run",
            q(d["session_id"]),
            "--allow-live",
        ]
        if not self.local_auth_mode(d):
            args += ['--approval', q(self.folder(d['session_id']) / 'owner-approval.json')]
        return " ".join(args)

    def request(self, sid, plan_hash, *, end=False):
        with self.mutex, self.guard():
            d = self.load(sid)
            if d["plan_hash"] != plan_hash:
                raise ValueError("STALE_WORKING_SESSION_ACTION")
            if d["status"] in TERMINAL:
                return self.view(d)
            if d["status"] in {"DRAFT", "PREPARED"} and not self._claim(d).exists():
                d["status"] = "CLOSED"
                d["cleanup"] = "NOT_STARTED"
                self.save(d)
                return self.view(d)
            if d["status"] not in ACTIVE:
                raise ValueError("WORKING_SESSION_NOT_ACTIVE")
            atomic_json(
                self.bundle(d) / "cancel.request.json",
                dict(session_id=sid, attempt=d["attempt_id"], manifest_sha256=d["plan_hash"]),
            )
            d["status"] = "ENDING" if end else "CANCEL_REQUESTED"
            self.save(d)
            return self.view(d)

    def recover(self, sid=None):
        try:
            owner = RunLock(safe_path(self.directory / ".active"))
            owner.__enter__()
        except RuntimeError:
            return
        try:
            with self.mutex, self.guard():
                paths = [self.folder(sid) / "session.json"] if sid else self.directory.glob("*/session.json")
                for p in paths:
                    d = self.load(p.parent.name)
                    if (
                        d["status"] in ACTIVE
                        or d["status"] == "PREPARED"
                        and self._claim(d).exists()
                    ):
                        if d['schema_version'] == 2 and not finite_projection.enabled():
                            raise PermissionError('FINITE_PROJECTION_GATE_CLOSED')
                        try:
                            progress = self.read_progress(d)
                            if progress:
                                d["results"] = progress[0]
                        except (ValueError, OSError, TypeError, KeyError, RecursionError):
                            pass
                        d.update(
                            status="INTERRUPTED", cleanup="UNCONFIRMED", code="OWNER_LOST_NO_REPLAY"
                        )
                        if d['schema_version'] == 2:
                            d['projection'] = finite_projection.append(d['projection'], 'terminal', 'INTERRUPTED')
                        self.save(d)
        finally:
            owner.__exit__()

    def run(self, sid, approval_path, *, allow_live=False):
        if not allow_live:
            raise PermissionError("EXPLICIT_WORKING_SESSION_LIVE_CONSENT_REQUIRED")
        if not os.environ.get('CAS_LOCAL_OWNER_AUTH_FILE') and not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)):
            raise PermissionError("PRIVATE_LOCAL_TERMINAL_REQUIRED")
        with RunLock(safe_path(self.directory / ".active")):
            with self.mutex, self.guard():
                d = self.load(sid)
                if d["status"] != "PREPARED" or self._claim(d).exists():
                    raise ValueError("WORKING_SESSION_NO_REPLAY")
                self.validate_new_input(d)
                self.backend.verify(self.bundle(d), d)
                if approval_path is None:
                    if not os.environ.get('CAS_LOCAL_OWNER_AUTH_FILE'):
                        raise PermissionError('EXACT_WORKING_SESSION_APPROVAL_REQUIRED')
                    approval = self.backend.approval(d, d['plan_hash'], True)
                else:
                    approval = read_json(approval_path, 4096)
                if approval != self.backend.approval(d, d["plan_hash"], True):
                    raise PermissionError("EXACT_WORKING_SESSION_APPROVAL_REQUIRED")
                with self._claim(d).open("x", encoding="utf-8") as f:
                    json.dump(
                        dict(
                            attempt=d["attempt_id"],
                            manifest_sha256=d["plan_hash"],
                            state="CONSUMED_NO_REPLAY",
                        ),
                        f,
                    )
                    f.flush()
                    os.fsync(f.fileno())
                d.update(status="STARTING", cleanup="PENDING")
                if finite_projection.enabled():
                    d['schema_version'] = 2
                    d['projection'] = finite_projection.empty()
                self.save(d)
            callback = fault = None
            if d['schema_version'] == 2:
                callback, fault = self._issue_finite_callback(d)
            try:
                if callback is None:
                    outcome = self.backend.run(self.bundle(d), d, approval)
                else:
                    outcome = self.backend.run(self.bundle(d), d, approval, projection_callback=callback)
                self.backend.project_stages(
                    {s: r for s, r in zip(("first", "second"), outcome["stages"], strict=False)}, d
                )
                stages = outcome["stages"]
                complete = (
                    outcome["completed"] is True
                    and outcome["cleanup_confirmed"] is True
                    and complete_results(d, stages)
                )
                status = (
                    "COMPLETED"
                    if complete
                    else "CANCELLED"
                    if outcome["cancelled"] and outcome["cleanup_confirmed"]
                    else "FAILED"
                    if outcome["cleanup_confirmed"]
                    else "INTERRUPTED"
                )
                d.update(
                    status=status,
                    results=outcome["stages"],
                    cleanup="CONFIRMED" if outcome["cleanup_confirmed"] else "UNCONFIRMED",
                    code=outcome["code"],
                )
            except BaseException:
                d.update(
                    status="INTERRUPTED",
                    cleanup="UNCONFIRMED",
                    code="EXECUTION_UNCONFIRMED_NO_REPLAY",
                )
                try:
                    progress = self.read_progress(d)
                    if progress:
                        d["results"] = progress[0]
                except (ValueError, OSError, TypeError, KeyError, RecursionError):
                    pass
            if fault is not None and fault['uncertain']:
                raise ValueError('FINITE_PROJECTION_UNCONFIRMED') from None
            d = self.commit_terminal(sid, d)
            return self.view(d)

    def close(self):
        pass  # This reader/controller owns no background execution or auth session.
