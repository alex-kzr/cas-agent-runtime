"""Opt-in console task control using the existing executor; no queue or automatic replay."""

import asyncio
import json
import threading
from dataclasses import asdict
from itertools import islice
from pathlib import Path
from uuid import UUID, uuid4

from agent_runtime.tasks.coding import PROFILE, CodingWorkspace, digest
from agent_runtime.tasks.executor import Executor
from agent_runtime.tasks.models import TERMINAL, ExecutionRequest, Limits, validate_document
from agent_runtime.telemetry.recorder import RunLock, atomic_json, reconcile

MODEL = "claude-haiku-5-5"
LIMITS = Limits(6, "0.10", 60)
INSTRUCTIONS = (
    "Fix add(a, b) in calc.py so it adds the two inputs. Use only the three "
    "cas_workspace tools. Read calc.py, replace the function, run the fixed tests "
    "and summarize the change. Do not request any other files or tools."
)


def identity(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Invalid task identity")
    return value


class ContinuationUnavailable(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class TaskControl:
    def __init__(self, data_dir, *, adapter_factory=None):
        self.data_dir = Path(data_dir).resolve()
        self.directory = self.data_dir / "control"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.owner = RunLock(self.directory)
        self.owner.__enter__()
        self.lock = threading.RLock()
        self.thread = None
        self.loop = None
        self.execution = None
        self.active_id = None
        self.closing = False
        self.adapter_factory = adapter_factory
        try:
            with RunLock(self.data_dir):
                reconcile(self.data_dir, locked=True)
                for path in self.directory.glob("*.json"):
                    job = self.load(path.stem)
                    self.recover_job(job)
        except BaseException:
            self.owner.__exit__()
            raise

    def load(self, task_id):
        path = self.directory / f"{identity(task_id)}.json"
        if path.is_symlink() or path.stat().st_size > 16_384:
            raise ValueError("Unsafe task record")
        job = json.loads(path.read_text(encoding="utf-8"))
        required = {
            "schema_version",
            "task_id",
            "status",
            "run_id",
            "resumes_run_id",
            "workspace_id",
            "instructions",
            "model",
            "limits",
            "profile",
            "auth_mode",
            "context_isolation",
        }
        if (
            not isinstance(job, dict)
            or set(job) - required - {"error", "recovery"}
            or not required.issubset(job)
            or job["task_id"] != task_id
            or job["schema_version"] != 1
            or job["profile"] != PROFILE
            or job["model"] != MODEL
            or job["limits"] != asdict(LIMITS)
            or job["instructions"] != INSTRUCTIONS
            or job["auth_mode"] != "subscription"
            or job["context_isolation"] != "unverified"
            or job["status"]
            not in {
                "DRAFT",
                "STARTING",
                "RUNNING",
                "STOPPING",
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "INTERRUPTED",
            }
        ):
            raise ValueError("Task identity/schema mismatch")
        identity(job["workspace_id"])
        for field in ("run_id", "resumes_run_id"):
            if job[field] is not None:
                identity(job[field])
        return job

    def save(self, job):
        atomic_json(self.directory / f"{job['task_id']}.json", job)

    def recover_job(self, job):
        claim = self.directory / f"{job['task_id']}.started"
        if job["status"] == "DRAFT" and claim.exists():
            if not claim.is_symlink() and claim.stat().st_size <= 128:
                try:
                    job["run_id"] = identity(claim.read_text(encoding="utf-8"))
                except ValueError:
                    pass
        elif job["status"] not in {"STARTING", "RUNNING", "STOPPING"}:
            return
        previous_status = job["status"]
        recovered_status = "INTERRUPTED"
        reason = "writer-lost"
        if job["run_id"] is not None:
            path = self.data_dir / "runs" / identity(job["run_id"]) / "run.json"
            try:
                if path.stat().st_size > 1_000_000:
                    raise ValueError("Unsafe canonical run")
                record = json.loads(path.read_text(encoding="utf-8"))
                validate_document("run", record)
                if record["run_id"] != job["run_id"] or record["task_id"] != job["task_id"]:
                    raise ValueError("Canonical identity differs")
                if record["status"] in TERMINAL:
                    recovered_status = record["status"]
                    reason = (
                        "writer-lost"
                        if (record["error"] or {}).get("code") == "process_lost"
                        else "canonical-terminal"
                    )
            except (ValueError, OSError):
                pass
        job["status"] = recovered_status
        job["recovery"] = {
            "reason": reason,
            "previous_status": previous_status,
            "automatic_restart": False,
        }
        self.save(job)

    def records(self):
        paths = list(islice(self.directory.glob("*.json"), 101))
        if len(paths) > 100:
            raise ValueError("Console task capacity exceeded; choose a fresh data directory")
        return [self.load(path.stem) for path in sorted(paths)]

    def list(self):
        with self.lock:
            records = self.records()
            values = []
            for job in records:
                status = {
                    "eligible": False,
                    "code": "not-terminal",
                    "reason": "No eligible terminal run yet.",
                    "native_history_verified": False,
                }
                if job["run_id"] and job["status"] in TERMINAL:
                    try:
                        self.previous(job["run_id"], jobs=records)
                        status.update(
                            eligible=True,
                            code="local-checks-passed",
                            reason="Local checks passed; native history availability is unverified.",
                        )
                    except ContinuationUnavailable as error:
                        status.update(code=error.code, reason=str(error))
                values.append(dict(job, continuation=status))
            return values

    def create(self, *, resumes_run_id=None):
        with self.lock:
            if resumes_run_id is not None:
                identity(resumes_run_id)
            if self.closing:
                raise ValueError("Controller is closing")
            if len(self.list()) >= 100:
                raise ValueError(
                    "Console supports at most 100 drafts; choose a fresh data directory"
                )
            task_id = str(uuid4())
            job = {
                "schema_version": 1,
                "task_id": task_id,
                "status": "DRAFT",
                "run_id": None,
                "resumes_run_id": resumes_run_id,
                "workspace_id": task_id,
                "instructions": INSTRUCTIONS,
                "model": MODEL,
                "limits": asdict(LIMITS),
                "profile": PROFILE,
                "auth_mode": "subscription",
                "context_isolation": "unverified",
            }
            if resumes_run_id:
                previous, workspace_id = self.previous(resumes_run_id)
                job["workspace_id"] = workspace_id
            else:
                CodingWorkspace.create(self.workspace(job))
            self.save(job)
            return job

    def workspace(self, job):
        workspace = self.data_dir / "workspaces" / identity(job["workspace_id"])
        if workspace.parent.is_symlink() or workspace.parent.is_junction():
            raise ValueError("Linked workspace root rejected")
        return workspace

    def previous(self, run_id, *, jobs=None):
        try:
            if self.active_id is not None:
                raise ContinuationUnavailable(
                    "active-execution", "An execution is active; wait for cleanup."
                )
            return self._previous(run_id, jobs=jobs)
        except ContinuationUnavailable:
            raise
        except (ValueError, OSError, KeyError, TypeError, SyntaxError) as error:
            raise ContinuationUnavailable(
                "missing-or-invalid-evidence",
                "Saved run/session evidence is unavailable or invalid; no automatic replay.",
            ) from error

    def _previous(self, run_id, *, jobs=None):
        run_id = identity(run_id)
        path = self.data_dir / "runs" / run_id / "run.json"
        if path.stat().st_size > 1_000_000:
            raise ValueError("Previous run exceeds limit")
        previous = json.loads(path.read_text(encoding="utf-8"))
        validate_document("run", previous)
        if (
            previous["run_id"] != run_id
            or previous["status"] not in TERMINAL
            or previous["configuration"].get("agent") != PROFILE
            or previous["configuration"].get("auth_mode") != "subscription"
            or not isinstance(previous["session_id"], str)
            or not 1 <= len(previous["session_id"]) <= 128
        ):
            raise ContinuationUnavailable(
                "missing-session", "Previous run has no eligible saved native session."
            )
        cleanup = (previous["usage"]["application"] or {}).get("cleanup", {})
        if not isinstance(cleanup, dict) or cleanup.get("tree_empty") is not True:
            raise ContinuationUnavailable(
                "cleanup-unconfirmed", "Previous owned-tree cleanup is unconfirmed."
            )
        jobs = [
            job for job in (self.records() if jobs is None else jobs) if job["run_id"] == run_id
        ]
        if len(jobs) != 1:
            raise ValueError("Previous run is not owned by console control")
        if previous["task_id"] != jobs[0]["task_id"]:
            raise ContinuationUnavailable(
                "identity-mismatch", "Saved task/run identity differs from its controller."
            )
        workspace_id = jobs[0]["workspace_id"]
        workspace = self.workspace(jobs[0])
        if Path(previous["workspace"]) != workspace:
            raise ValueError("Previous workspace identity changed")
        report_path = path.parent / "coding" / "coding.json"
        if report_path.stat().st_size > 8192:
            raise ValueError("Unsafe previous coding evidence")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if digest(CodingWorkspace.inspect(workspace)) != report["after_sha256"]:
            raise ContinuationUnavailable(
                "workspace-changed", "Workspace changed after the previous run; no replay."
            )
        return previous, workspace_id

    def start(self, task_id, *, allow_live=False, allow_existing_login=False):
        with self.lock:
            if allow_live is not True or allow_existing_login is not True:
                raise ValueError("Fresh per-run live and native-session consent required")
            if self.closing or self.active_id is not None:
                raise ValueError("Another console task is active or controller is closing")
            job = self.load(task_id)
            if job["status"] != "DRAFT":
                raise ValueError("This draft was already started; create a new explicit task")
            session_id = None
            if job["resumes_run_id"]:
                previous, workspace_id = self.previous(job["resumes_run_id"])
                if workspace_id != job["workspace_id"]:
                    raise ValueError("Continuation workspace changed")
                session_id = previous["session_id"]
            CodingWorkspace(self.workspace(job), self.directory / "preflight" / task_id)
            run_id = str(uuid4())
            request = ExecutionRequest(
                "task",
                INSTRUCTIONS,
                self.workspace(job),
                LIMITS,
                model=MODEL,
                live_authorized=True,
                agent_name=PROFILE,
                auth_mode="subscription",
                allow_existing_login=True,
                run_id=run_id,
                task_id=task_id,
                resumes_run_id=job["resumes_run_id"],
                resume_session_id=session_id,
            )
            # Exclusive durable claim survives restart and prevents duplicate POST/replay.
            with (self.directory / f"{task_id}.started").open("x", encoding="utf-8") as claim:
                claim.write(run_id)
            job.update(status="STARTING", run_id=run_id)
            self.save(job)
            self.active_id = task_id
            self.thread = threading.Thread(target=self.run, args=(job, request), daemon=False)
            self.thread.start()
            return job

    def run(self, job, request):
        async def execute():
            with self.lock:
                self.loop = asyncio.get_running_loop()
                self.execution = asyncio.current_task()
                if self.load(job["task_id"])["status"] == "STOPPING":
                    return None
                job["status"] = "RUNNING"
                self.save(job)
            if self.adapter_factory is None:
                import os

                from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter

                adapter = SupervisedClaudeAdapter(os.environ)
            else:
                adapter = self.adapter_factory()
            return await Executor(self.data_dir, adapter).execute(request)

        try:
            result = asyncio.run(execute())
            with self.lock:
                job["status"] = result["status"] if result else "CANCELLED"
        except Exception:
            with self.lock:
                job["status"] = "FAILED"
                job["error"] = "Execution unavailable; inspect run evidence. No automatic retry."
        finally:
            with self.lock:
                self.save(job)
                self.execution = self.loop = self.active_id = None

    def stop(self, task_id):
        with self.lock:
            if self.active_id != identity(task_id):
                raise ValueError("Task is not active in this controller")
            job = self.load(task_id)
            if job["status"] == "STOPPING":
                return job
            job["status"] = "STOPPING"
            self.save(job)
            # run() holds a separate mutable job; state on disk is authoritative.
            if (
                self.execution is not None
                and not self.execution.done()
                and not self.loop.is_closed()
            ):
                self.loop.call_soon_threadsafe(self.execution.cancel)
            return job

    def close(self):
        with self.lock:
            self.closing = True
            active = self.active_id
            if active:
                self.stop(active)
        if self.thread is not None:
            self.thread.join(timeout=12)
            if self.thread.is_alive():
                raise RuntimeError("Controller cleanup not finished; ownership lock retained")
        self.owner.__exit__()
