"""Owned read-only sample analysis through Executor; no native/model execution path."""

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


def read_sources(directory):
    directory = guarded(directory)
    if {p.name for p in directory.iterdir()} != set(SAMPLE):
        raise ValueError("Only the two approved sample files may exist")
    result = {}
    for name in SAMPLE:
        path = guarded(directory / name)
        if not path.is_file() or path.stat().st_size > 8192:
            raise ValueError("Source unavailable or too large")
        result[name] = path.read_bytes().decode("utf-8")
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
    if set(sources) != set(SAMPLE) or any(
        type(v) is not str or len(v.encode()) > 8192 for v in sources.values()
    ):
        raise ValueError("Invalid approved sources")
    tree = ast.parse(sources["inventory.py"])
    expected = {
        "project": ("README.md", 1, sources["README.md"].splitlines()[0].removeprefix("# "))
    }
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


def markdown(value, sources, run_id):
    claims = validate_report(value, sources)
    lines = [
        "# Tiny Shop repository analysis",
        "",
        "Offline scripted sample; no model request.",
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
            if read_sources(request.workspace) != self.snapshot:
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
                else expected_fixture_output()
            )
            validate_report(value, self.snapshot)
            if read_sources(request.workspace) != self.snapshot:
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

    def __init__(self, data_dir, *, producer=None):
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
            or job.get("profile") != PROFILE
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
        return job

    def save(self, job):
        atomic_json(guarded(self.directory / (identity(job["job_id"]) + ".json")), job)

    def list(self):
        with self.lock:
            paths = list(self.directory.glob("*.json"))
            if len(paths) > 100:
                raise ValueError("Analysis capacity reached")
            return [self.load(path.stem) for path in sorted(paths)]

    def create(self, repository, question):
        with self.lock:
            if (
                repository != "tiny-shop"
                or type(question) is not str
                or question not in QUESTIONS
                or self.closing
                or len(self.list()) >= 100
            ):
                raise ValueError("Select an approved repository/question")
            job = {
                "job_id": str(uuid4()),
                "profile": PROFILE,
                "repository": repository,
                "question": question,
                "status": "DRAFT",
                "run_id": None,
                "created_at": now(),
                "report": None,
            }
            self.save(job)
            return job

    def start(self, job_id):
        with self.lock:
            job = self.load(job_id)
            if self.active or self.closing or job["status"] != "DRAFT":
                raise ValueError("Only a fresh draft can start; no queue or replay")
            source = read_sources(self.workspace)
            if source != SAMPLE:
                raise ValueError("Approved source changed")
            claim = guarded(self.directory / (job_id + ".started"))
            run_id = str(uuid4())
            with claim.open("x", encoding="ascii") as stream:
                stream.write(run_id)
            job.update(status="STARTING", run_id=run_id)
            snapshots = guarded(self.directory / job_id / "files")
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
        if (
            record["run_id"] != job["run_id"]
            or record["scenario_id"] != "platform.repository-analysis"
            or record["provider"]["name"] != "local-validation"
            or record["configuration"].get("execution_mode") != "offline"
            or record["workspace"] != str(self.workspace.resolve())
        ):
            raise ValueError("Analysis run identity differs")
        return record

    def sources(self, job_id):
        job = self.load(job_id)
        if job["run_id"] is None:
            raise ValueError("No source snapshot yet")
        source = read_sources(self.directory / identity(job_id) / "files")
        if source != SAMPLE:
            raise ValueError("Source snapshot hash mismatch")
        return source

    def report(self, job_id):
        job = self.load(job_id)
        if job["status"] != "COMPLETED" or self.canonical(job)["status"] != "COMPLETED":
            raise ValueError("No validated completed report")
        source = self.sources(job_id)
        validate_report(job["report"], source)
        return {
            "run_id": job["run_id"],
            "profile": PROFILE,
            "model_requests": 0,
            "report": job["report"],
            "markdown": markdown(job["report"], source, job["run_id"]),
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
