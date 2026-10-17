"""Owned synthetic analysis through Executor, with a default-closed SDK path."""

import ast
import asyncio
import hashlib
import io
import json
import threading
import zipfile
from pathlib import Path
from uuid import UUID, uuid4

from agent_runtime.tasks.executor import Executor, NativeResult
from agent_runtime.tasks.models import TERMINAL, ExecutionRequest, Limits, validate_document
from agent_runtime.telemetry.recorder import RunLock, atomic_json, now

PROFILE = "repository-analysis-offline-v1"
SAMPLE = {
    "README.md": "# Tiny Shop\n\nA small price and tax calculation library.\n",
    "inventory.py": (
        "def subtotal(price, quantity):\n    return price * quantity\n\n\n"
        "def with_tax(amount, rate):\n    return amount * (1 + rate)\n"
    ),
}
QUESTIONS = {
    "overview": "Explain the project and its calculations.",
    "functions": "Describe the public functions and their calculations.",
}


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def identity(value):
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("Invalid analysis identity")
    return value


def guarded(path):
    path = Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError("Linked analysis paths are forbidden")
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("Hardlinked analysis file rejected")
    return path


def selected_files(names=None):
    names = list(SAMPLE) if names is None else names
    if (
        type(names) is not list
        or not names
        or any(type(n) is not str or n not in SAMPLE for n in names)
        or len(names) != len(set(names))
    ):
        raise ValueError("Select unique allowlisted sample files")
    return sorted(names)


def read_sources(directory, names=None, *, exact=True):
    names = selected_files(names)
    directory = guarded(directory)
    if exact and {p.name for p in directory.iterdir()} != set(names):
        raise ValueError("Only selected approved sample files may exist")
    result = {}
    for name in names:
        path = guarded(directory / name)
        if not path.is_file() or path.stat().st_size > 8192:
            raise ValueError("Source unavailable or too large")
        with path.open("rb") as stream:
            content = stream.read(8193)
        if len(content) > 8192:
            raise ValueError("Source too large")
        result[name] = content.decode("utf-8")
    if sum(len(v.encode("utf-8")) for v in result.values()) > 16384:
        raise ValueError("Snapshot too large")
    return result


def expected_fixture_output():
    """Explicit scripted fixture output, deliberately independent of AST validation."""
    return {
        "repository": "tiny-shop",
        "claims": [
            {
                "id": "project",
                "file": "README.md",
                "line": 1,
                "value": "Tiny Shop",
                "sha256": sha(SAMPLE["README.md"]),
            },
            {
                "id": "function:subtotal",
                "file": "inventory.py",
                "line": 1,
                "value": "price * quantity",
                "sha256": sha(SAMPLE["inventory.py"]),
            },
            {
                "id": "function:with_tax",
                "file": "inventory.py",
                "line": 5,
                "value": "amount * (1 + rate)",
                "sha256": sha(SAMPLE["inventory.py"]),
            },
        ],
    }


def validate_report(value, sources):
    """Require exact source-grounded facts, coverage, identity, line and content hash."""
    if (
        not sources
        or not set(sources).issubset(SAMPLE)
        or any(type(v) is not str or len(v.encode()) > 8192 for v in sources.values())
    ):
        raise ValueError("Invalid approved sources")
    tree = ast.parse(sources.get("inventory.py", ""))
    expected = {}
    if "README.md" in sources:
        expected["project"] = (
            "README.md",
            1,
            sources["README.md"].splitlines()[0].removeprefix("# "),
        )
    for function in tree.body:
        if (
            not isinstance(function, ast.FunctionDef)
            or len(function.body) != 1
            or not isinstance(function.body[0], ast.Return)
        ):
            raise ValueError("Unsupported sample function")
        expected["function:" + function.name] = (
            "inventory.py",
            function.lineno,
            ast.unparse(function.body[0].value),
        )
    if (
        type(value) is not dict
        or set(value) != {"repository", "claims"}
        or value["repository"] != "tiny-shop"
        or type(value["claims"]) is not list
        or len(value["claims"]) != len(expected)
    ):
        raise ValueError("Report identity/coverage invalid")
    seen = set()
    for claim in value["claims"]:
        if type(claim) is not dict or set(claim) != {"id", "file", "line", "value", "sha256"}:
            raise ValueError("Unknown report fields")
        key = claim["id"]
        if type(key) is not str or key not in expected or key in seen:
            raise ValueError("Unknown or duplicate source claim")
        name, line, fact = expected[key]
        if (
            type(claim["line"]) is not int
            or (claim["file"], claim["line"], claim["value"]) != (name, line, fact)
            or claim["sha256"] != sha(sources[name])
        ):
            raise ValueError("Claim contradicts approved source/hash/reference")
        seen.add(key)
    if seen != set(expected):
        raise ValueError("Missing source facts")
    return value["claims"]


def markdown(value, sources, run_id, *, mode="offline"):
    claims = validate_report(value, sources)
    lines = [
        "# Tiny Shop repository analysis",
        "",
        {
            "offline": "Offline scripted sample; no model request.",
            "mock-sdk": "Mock SDK test only; no real model request.",
            "sdk": "SDK response validated against selected synthetic snapshots.",
        }[mode],
        "",
        f"CAS run: {identity(run_id)}",
        "",
    ]
    for item in claims:
        lines.append(
            f"- **{item['id']}**: `{item['value']}` — [{item['file']}:{item['line']}](files/{item['file']}#L{item['line']})"
        )
    lines += ["", "## Approved source hashes", ""]
    lines += [f"- {name}: `{sha(source)}`" for name, source in sources.items()]
    return "\n".join(lines) + "\n"


class SampleAdapter:
    local_validation = True

    def __init__(self, snapshot, question, producer=None, on_report=lambda value: None):
        self.snapshot, self.question, self.producer = snapshot, question, producer
        self.on_report = on_report
        self.report = None

    async def run(self, request, recorder):
        cleanup = {"mechanism": "in-process-no-children", "tree_empty": True, "forced": False}
        recorder.record["configuration"].update(analysis_profile=PROFILE, model_requests=0)
        try:
            if read_sources(request.workspace, list(self.snapshot), exact=False) != self.snapshot:
                raise ValueError("Approved source changed before execution")
            recorder.event(
                "analysis.sources",
                {
                    "files": list(self.snapshot),
                    "sha256": {n: sha(v) for n, v in self.snapshot.items()},
                },
                "application",
            )
            await asyncio.sleep(0)
            value = (
                await self.producer(self.snapshot, self.question)
                if self.producer
                else {
                    "repository": "tiny-shop",
                    "claims": [
                        c for c in expected_fixture_output()["claims"] if c["file"] in self.snapshot
                    ],
                }
            )
            validate_report(value, self.snapshot)
            if read_sources(request.workspace, list(self.snapshot), exact=False) != self.snapshot:
                raise ValueError("Read-only source changed during execution")
            self.report = value
            self.on_report(value)
            recorder.event(
                "analysis.validation",
                {"validator": PROFILE, "passed": True, "claims": len(value["claims"])},
                "validator",
            )
            return NativeResult(
                markdown(value, self.snapshot, recorder.run_id),
                None,
                None,
                None,
                source="application",
                checks=[
                    {
                        "id": "source-grounded-report",
                        "expected": True,
                        "observed": True,
                        "outcome": "pass",
                        "evidence_refs": [f"runs/{recorder.run_id}/events.jsonl"],
                    }
                ],
                application_usage={
                    "cleanup": cleanup,
                    "model_requests": 0,
                    "analysis_validator": PROFILE,
                },
            )
        finally:
            recorder.record["usage"]["application"] = {"cleanup": cleanup, "model_requests": 0}


class AnalysisControl:
    """One local Executor operation at a time; reload/restart never replays a claim."""

    def __init__(self, data_dir, *, producer=None, supervised_factory=None):
        self.root = guarded(data_dir)
        marker = self.root / "analysis-profile.json"
        if self.root.exists():
            if (
                not guarded(marker).is_file()
                or marker.stat().st_size > 256
                or json.loads(marker.read_text()) != {"profile": PROFILE}
            ):
                raise ValueError("Use a fresh dedicated analysis data directory")
        else:
            self.root.mkdir(parents=True)
            atomic_json(marker, {"profile": PROFILE})
        self.directory = guarded(self.root / "analysis")
        self.directory.mkdir(exist_ok=True)
        self.owner = RunLock(self.directory)
        self.owner.__enter__()
        self.lock = threading.RLock()
        self.thread, self.loop, self.execution, self.active = None, None, None, None
        self.producer, self.closing = producer, False
        self.supervised_factory = supervised_factory
        self.workspace = guarded(self.root / "workspaces/tiny-shop")
        try:
            if not self.workspace.exists():
                self.workspace.mkdir(parents=True)
                for name, source in SAMPLE.items():
                    with (self.workspace / name).open(
                        "x", encoding="utf-8", newline="\n"
                    ) as stream:
                        stream.write(source)
            if read_sources(self.workspace) != SAMPLE:
                raise ValueError("Sample source differs; never overwrite it")
            for job in self.list():
                claim = guarded(self.directory / (job["job_id"] + ".started"))
                if job["status"] == "DRAFT" and claim.exists():
                    if claim.stat().st_size <= 128:
                        job["run_id"] = identity(claim.read_text(encoding="ascii"))
                    job["status"] = "STARTING"
                if job["status"] in {"STARTING", "RUNNING", "STOPPING"}:
                    status = "INTERRUPTED"
                    try:
                        record = self.canonical(job)
                        if record["status"] not in TERMINAL:
                            with RunLock(self.root):
                                record.update(
                                    status="INTERRUPTED",
                                    evidence_status="partial",
                                    ended_at=now(),
                                    updated_at=now(),
                                )
                                record["error"] = {
                                    "category": "interrupted",
                                    "code": "process_lost",
                                    "message": "Offline writer lost; no replay",
                                    "retryable": False,
                                    "evidence_refs": [],
                                }
                                validate_document("run", record)
                                atomic_json(
                                    guarded(self.root / "runs" / job["run_id"] / "run.json"), record
                                )
                        if record["status"] in TERMINAL:
                            status = record["status"]
                            if status == "COMPLETED" and job["report"] is None:
                                path = guarded(
                                    self.directory / job["job_id"] / "validated-report.json"
                                )
                                if path.stat().st_size > 8192:
                                    raise ValueError("Report too large")
                                saved = json.loads(path.read_text(encoding="utf-8"))
                                if saved["run_id"] != job["run_id"]:
                                    raise ValueError("Report belongs to a different run")
                                validate_report(saved["report"], self.sources(job["job_id"]))
                                job["report"] = saved["report"]
                    except (ValueError, OSError, KeyError, TypeError):
                        status = "INTERRUPTED"
                    job.update(status=status, recovery="no automatic replay")
                    self.save(job)
        except BaseException:
            self.owner.__exit__()
            raise

    def load(self, job_id):
        path = guarded(self.directory / (identity(job_id) + ".json"))
        if path.stat().st_size > 32768:
            raise ValueError("Analysis record too large")
        job = json.loads(path.read_text(encoding="utf-8"))
        if (
            type(job) is not dict
            or set(job)
            - {
                "job_id",
                "profile",
                "repository",
                "question",
                "status",
                "run_id",
                "created_at",
                "report",
                "error",
                "recovery",
                "files",
                "mode",
                "snapshot_sha256",
            }
            or not {
                "job_id",
                "profile",
                "repository",
                "question",
                "status",
                "run_id",
                "created_at",
                "report",
            }.issubset(job)
            or job.get("job_id") != job_id
            or job.get("profile")
            != ("repository-analysis-sdk-v1" if job.get("mode") == "sdk" else PROFILE)
            or job.get("repository") != "tiny-shop"
            or type(job.get("question")) is not str
            or job.get("question") not in QUESTIONS
            or job.get("status")
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
            raise ValueError("Invalid analysis record")
        if job["run_id"] is not None:
            identity(job["run_id"])
        selected_files(job.get("files"))
        if job.get("mode", "offline") not in {"offline", "sdk"}:
            raise ValueError("Invalid analysis mode")
        if job.get("mode") == "sdk" and (
            not job.get("files")
            or type(job.get("snapshot_sha256")) is not str
            or len(job["snapshot_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in job["snapshot_sha256"])
        ):
            raise ValueError("SDK records require explicit selected snapshot identity")
        return job

    def save(self, job):
        atomic_json(guarded(self.directory / (identity(job["job_id"]) + ".json")), job)

    def list(self):
        with self.lock:
            paths = list(self.directory.glob("*.json"))
            if len(paths) > 100:
                raise ValueError("Analysis capacity reached")
            return [self.load(path.stem) for path in sorted(paths)]

    def create(self, repository, question, files=None, mode="offline"):
        with self.lock:
            if (
                repository != "tiny-shop"
                or type(question) is not str
                or question not in QUESTIONS
                or self.closing
                or len(self.list()) >= 100
            ):
                raise ValueError("Select an approved repository/question")
            from agent_runtime.tasks.repository_analysis_sdk import checked_sources, snapshot_digest

            names = selected_files(files)
            if mode not in {"offline", "sdk"}:
                raise ValueError("Unsupported mode")
            source = checked_sources(read_sources(self.workspace, names, exact=False))
            job = {
                "job_id": str(uuid4()),
                "profile": "repository-analysis-sdk-v1" if mode == "sdk" else PROFILE,
                "repository": repository,
                "question": question,
                "status": "DRAFT",
                "run_id": None,
                "created_at": now(),
                "report": None,
                "files": names,
                "mode": mode,
                "snapshot_sha256": snapshot_digest(source),
            }
            snapshots = guarded(self.directory / job["job_id"] / "files")
            snapshots.mkdir(parents=True, exist_ok=False)
            for name, content in source.items():
                with (snapshots / name).open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(content)
            self.save(job)
            return job

    def start(self, job_id, *, allow_live=False, allow_existing_login=False, snapshot_sha256=None):
        with self.lock:
            job = self.load(job_id)
            if self.active or self.closing or job["status"] != "DRAFT":
                raise ValueError("Only a fresh draft can start; no queue or replay")
            from agent_runtime.tasks.repository_analysis_sdk import require_release

            sdk = job.get("mode") == "sdk"
            if sdk:
                require_release()
                if (
                    allow_live is not True
                    or allow_existing_login is not True
                    or snapshot_sha256 != job.get("snapshot_sha256")
                ):
                    raise PermissionError("Fresh consents and exact snapshot digest required")
            source = self.sources(job_id) if job.get("files") else read_sources(self.workspace)
            if read_sources(self.workspace, list(source), exact=False) != source:
                raise ValueError("Approved source changed")
            claim = guarded(self.directory / (job_id + ".started"))
            run_id = str(uuid4())
            if sdk:
                with guarded(self.directory / "sdk-attempt.started").open(
                    "x", encoding="ascii"
                ) as stream:
                    stream.write(run_id)
            with claim.open("x", encoding="ascii") as stream:
                stream.write(run_id)
            job.update(status="STARTING", run_id=run_id)
            snapshots = guarded(self.directory / job_id / "files")
            if not job.get("files"):
                snapshots.mkdir(parents=True, exist_ok=False)
                for name, content in source.items():
                    with (snapshots / name).open("x", encoding="utf-8", newline="\n") as stream:
                        stream.write(content)
            self.save(job)
            self.active = job_id
            self.thread = threading.Thread(target=self._execute, args=(job, source), daemon=True)
            self.thread.start()
            return job

    def _execute(self, job, source):
        loop = asyncio.new_event_loop()
        try:

            def persist(value):
                if self.sources(job["job_id"]) != source:
                    raise ValueError("Snapshot changed")
                atomic_json(
                    guarded(self.directory / job["job_id"] / "validated-report.json"),
                    {"run_id": job["run_id"], "report": value},
                )

            adapter = SampleAdapter(source, job["question"], self.producer, persist)
            request = ExecutionRequest(
                "scenario",
                QUESTIONS[job["question"]],
                self.workspace,
                Limits(1, "0.02", 15),
                "platform.repository-analysis",
                agent_name="read-only-v1",
                run_id=job["run_id"],
            )
            if job.get("mode") == "sdk":
                from agent_runtime.tasks.repository_analysis_sdk import (
                    LIMITS,
                    MODEL,
                    SnapshotSDKAdapter,
                    query_text,
                )

                adapter = SnapshotSDKAdapter(
                    source,
                    job["question"],
                    persist,
                    supervised_factory=self.supervised_factory,
                    environment={} if self.supervised_factory is not None else None,
                )
                workspace = guarded(self.root / "workspaces" / ("sdk-" + job["run_id"]))
                workspace.mkdir(exist_ok=False)
                request = ExecutionRequest(
                    "scenario",
                    query_text(source, job["question"]),
                    workspace,
                    LIMITS,
                    "sdk.repository-analysis",
                    model=MODEL,
                    live_authorized=True,
                    allow_existing_login=True,
                    agent_name="text-only-v1",
                    run_id=job["run_id"],
                )
            with self.lock:
                if self.closing:
                    raise ValueError("Controller closed before execution")
                self.loop = loop
                job["status"] = "RUNNING"
                self.save(job)
                self.execution = loop.create_task(Executor(self.root, adapter).execute(request))
            record = loop.run_until_complete(self.execution)
            with self.lock:
                job.update(
                    status=record["status"],
                    report=adapter.report if record["status"] == "COMPLETED" else None,
                )
                self.save(job)
        except Exception:
            with self.lock:
                job.update(status="FAILED", error="Local analysis failed; no replay")
                self.save(job)
        finally:
            loop.close()
            with self.lock:
                self.active, self.loop, self.execution = None, None, None

    def stop(self, job_id):
        with self.lock:
            job = self.load(job_id)
            if (
                self.active != job_id
                or self.loop is None
                or self.execution is None
                or self.loop.is_closed()
                or self.execution.done()
            ):
                raise ValueError("No running analysis to stop")
            self.loop.call_soon_threadsafe(self.execution.cancel)
            job["status"] = "STOPPING"
            self.save(job)
            return job

    def canonical(self, job):
        path = guarded(self.root / "runs" / identity(job["run_id"]) / "run.json")
        if path.stat().st_size > 1000000:
            raise ValueError("Run too large")
        record = json.loads(path.read_text(encoding="utf-8"))
        validate_document("run", record)
        sdk = job.get("mode") == "sdk"
        if (
            record["run_id"] != job["run_id"]
            or record["scenario_id"]
            != ("sdk.repository-analysis" if sdk else "platform.repository-analysis")
            or record["provider"]["name"] != ("claude" if sdk else "local-validation")
            or record["configuration"].get("execution_mode") != ("sdk" if sdk else "offline")
            or record["workspace"]
            != str(
                (
                    self.root / "workspaces" / ("sdk-" + job["run_id"]) if sdk else self.workspace
                ).resolve()
            )
        ):
            raise ValueError("Analysis run identity differs")
        if sdk:
            from dataclasses import asdict

            from agent_runtime.tasks.models import sdk_succeeded
            from agent_runtime.tasks.repository_analysis_sdk import LIMITS, MODEL

            if (
                record["configuration"].get("snapshot_sha256") != job["snapshot_sha256"]
                or record["provider"]["requested_model"] != MODEL
                or record["limits"] != asdict(LIMITS)
            ):
                raise ValueError("SDK scope identity differs")
            if record["status"] == "COMPLETED":
                application = record["usage"].get("application") or {}
                if (
                    not sdk_succeeded(record["sdk_outcome"])
                    or application.get("model_requests") != 1
                    or (application.get("cleanup") or {}).get("tree_empty") is not True
                ):
                    raise ValueError("SDK completion evidence is incomplete")
        return record

    def sources(self, job_id):
        job = self.load(job_id)
        if job["run_id"] is None and not job.get("files"):
            raise ValueError("No source snapshot yet")
        from agent_runtime.tasks.repository_analysis_sdk import checked_sources, snapshot_digest

        source = checked_sources(
            read_sources(self.directory / identity(job_id) / "files", job.get("files"))
        )
        if job.get("snapshot_sha256") and snapshot_digest(source) != job["snapshot_sha256"]:
            raise ValueError("Source snapshot digest mismatch")
        return source

    def preview(self, job_id):
        from dataclasses import asdict

        from agent_runtime.tasks.repository_analysis_sdk import (
            LIMITS,
            LIVE_ANALYSIS_ENABLED,
            MODEL,
            build_payload,
            query_text,
        )

        job = self.load(job_id)
        sources = self.sources(job_id)
        query = query_text(sources, job["question"])
        return {
            "payload": build_payload(sources, job["question"]),
            "query_text": query,
            "query_sha256": sha(query),
            "snapshot_sha256": job.get("snapshot_sha256"),
            "model": MODEL,
            "recipient": "Anthropic via existing claude.ai subscription",
            "limits": asdict(LIMITS),
            "live_enabled": LIVE_ANALYSIS_ENABLED,
            "tools": [],
            "one_attempt_per_data_directory": True,
        }

    def report(self, job_id):
        job = self.load(job_id)
        if job["status"] != "COMPLETED" or self.canonical(job)["status"] != "COMPLETED":
            raise ValueError("No validated completed report")
        source = self.sources(job_id)
        validate_report(job["report"], source)
        application = self.canonical(job)["usage"].get("application") or {}
        mode = "mock-sdk" if application.get("mock_sdk_test_only") else job.get("mode", "offline")
        return {
            "run_id": job["run_id"],
            "profile": "repository-analysis-sdk-v1" if mode != "offline" else PROFILE,
            "mode": mode,
            "model_requests": application.get("model_requests", 0),
            "real_model_requests": 0 if mode in {"offline", "mock-sdk"} else None,
            "report": job["report"],
            "markdown": markdown(job["report"], source, job["run_id"], mode=mode),
        }

    def bundle(self, job_id):
        report = self.report(job_id)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.md", report["markdown"])
            archive.writestr("report.json", json.dumps(report, indent=2))
            for name, source in self.sources(job_id).items():
                archive.writestr("files/" + name, source)
        return output.getvalue()

    def close(self):
        with self.lock:
            self.closing = True
            if (
                self.loop
                and self.execution
                and not self.loop.is_closed()
                and not self.execution.done()
            ):
                self.loop.call_soon_threadsafe(self.execution.cancel)
        if self.thread:
            self.thread.join(timeout=20)
            if self.thread.is_alive():
                raise RuntimeError("Analysis did not stop; do not restart it")
        self.owner.__exit__()
