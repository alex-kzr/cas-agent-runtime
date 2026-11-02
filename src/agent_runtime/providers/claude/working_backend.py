"""Product deployment backend: reviewed resources + immutable finite session data.

Preparation is filesystem-only. Execution requires a new exact approval and private TTY.
No SDK import occurs in the host; each guarded Linux cell uses the production Executor.
"""

import hashlib
import importlib.util
import json
import os
import re
import sys
from importlib.resources import files
from pathlib import Path

from agent_runtime.telemetry.recorder import atomic_json

MODEL = "claude-haiku-4-5-20251001"
PRIVATE = re.compile(
    r'''(?i)(sk-ant-[\w-]{12,}|\bbearer\s+\S{12,}|-----BEGIN [\w ]*PRIVATE KEY|(?:access_?token|refresh_?token|client_?secret|password)["']?\s*[:=]|https?://\S*(?:oauth|[?&]code=|[?&]token=|/auth/))'''
)
LEGACY_PRIVATE = re.compile(
    r"(?i)(sk-ant-[\w-]{12,}|\bbearer\s+\S{12,}|-----BEGIN [\w ]*PRIVATE KEY|(?:access_token|refresh_token|client_secret|password)\s*[:=]|https?://\S*(?:oauth|[?&]code=|[?&]token=|/auth/))"
)
SOURCES = (
    "__init__.py",
    "auth.py",
    "controller.py",
    "core.py",
    "diagnostics.py",
    "host_routes.py",
    "inventory_gate.py",
    "network_contract.py",
    "ready_channel.py",
    "ready_wire.py",
    "relay.py",
    "spec.py",
    "validate.py",
    "safe_work.py",
    "work_cell.py",
)
METADATA = (
    "client.json",
    "backend.json",
    "server-version.json",
    "image.json",
    "image-env.json",
    "image-defaults.json",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path, maximum=65536):
    path = Path(path)
    if path.is_symlink() or path.is_junction() or path.stat().st_size > maximum:
        raise ValueError("UNSAFE_WORKING_SESSION_DATA")

    def unique(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError("INVALID_WORKING_SESSION_DATA")
            d[k] = v
        return d

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def stage_valid(d, task, stage, *, legacy=False):
    keys = {
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
    try:
        return (
            isinstance(d, dict)
            and set(d) == keys
            and d["scope"] == "cas-working-task-v1"
            and d["stage"] == stage
            and d["run_id"] == task["run_id"]
            and d["result"] in {"PASS", "FAIL"}
            and type(d["query_count"]) is int
            and d["query_count"] == 1
            and all(
                type(d[k]) is bool for k in ["native_success", "tree_empty", "auth_profile_shared"]
            )
            and d["auth_profile_shared"] is True
            and isinstance(d["text"], str)
            and len(d["text"].encode("utf-8")) <= 4096
            and not (LEGACY_PRIVATE if legacy else PRIVATE).search(d["text"])
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


def task_stages(record):
    tasks = record.get("tasks")
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 2:
        raise ValueError("ONE_OR_TWO_WORKING_SESSION_TASKS_REQUIRED")
    return ("first", "second")[: len(tasks)]


def complete_results(record, results):
    names = task_stages(record)
    return (
        len(results) == len(names)
        and all(
            r["result"] == "PASS" and r["native_success"] and r["tree_empty"]
            and r["text"].strip() and r["failure_code"] is None and r["session_hash"]
            for r in results
        )
        and len({r["session_hash"] for r in results}) == len(names)
    )


class DockerWorkingBackend:
    version = "docker-working-session-v1"

    @staticmethod
    def local_auth_file():
        value = os.environ.get("CAS_LOCAL_OWNER_AUTH_FILE")
        if not value:
            return None
        path = Path(value).resolve(strict=True)
        if not path.is_file() or any(c in str(path) for c in ',\r\n'):
            raise ValueError("INVALID_LOCAL_AUTH_FILE")
        return str(path)

    def prepare(self, bundle, record):
        names = task_stages(record)
        bundle = Path(bundle)
        bundle.mkdir(exist_ok=False)
        source = files("agent_runtime.providers.claude").joinpath("working_cells")
        for name in SOURCES:
            (bundle / name).write_bytes(source.joinpath(name).read_bytes())
        (bundle / "metadata").mkdir()
        for name in METADATA:
            (bundle / "metadata" / name).write_bytes(source.joinpath("metadata", name).read_bytes())
        policy = dict(
            schema=1,
            backend_version=self.version,
            session_id=record["session_id"],
            attempt_id=record["attempt_id"],
            bundle_root=str(bundle.resolve()),
            model=MODEL,
            tasks=record["tasks"],
            prompt_utf8_max=2048,
            result_utf8_max=4096,
            aggregate_result_utf8_max=4096 * len(names),
            profile="shared-ephemeral-auth-native-history-64MiB",
            persistent_auth=False,
            main_seconds=420,
            cleanup_seconds=45,
            main_operations=72,
            total_operations=112,
        )
        local_auth = self.local_auth_file()
        if local_auth:
            policy['local_auth_file'] = local_auth
        atomic_json(bundle / "policy.json", policy)
        for stage, task in zip(names, record["tasks"], strict=True):
            atomic_json(
                bundle / (stage + ".json"),
                dict(
                    stage=stage,
                    run_id=task["run_id"],
                    task_id=task["task_id"],
                    prompt=task["prompt"],
                ),
            )
        rows = [
            dict(path=p.relative_to(bundle).as_posix(), sha256=sha(p), bytes=p.stat().st_size)
            for p in sorted(bundle.rglob("*"))
            if p.is_file()
        ]
        atomic_json(
            bundle / "manifest.json", dict(schema=1, backend_version=self.version, files=rows)
        )
        digest = sha(bundle / "manifest.json")
        atomic_json(bundle / "approval.template.json", self.approval(record, digest, False))
        return digest

    def approval(self, record, digest, approved=False):
        return dict(
            approved=approved,
            manifest_sha256=digest,
            attempt=record["attempt_id"],
            scope="cas-product-working-session-v1",
            allow_live=approved,
            extra_usage_disabled=approved if not self.local_auth_file() else False,
            accept_shared_native_history_and_credentials=approved,
            accept_local_prompt_result_retention=approved,
            accept_112_operations_and_displayed_resource_limits=approved,
        )

    def verify(self, bundle, record):
        bundle = Path(bundle).resolve()
        digest = sha(bundle / "manifest.json")
        if digest != record["plan_hash"]:
            raise ValueError("PREPARED_SESSION_CHANGED")
        manifest = read_json(bundle / "manifest.json")
        expected = (
            set(SOURCES)
            | {"metadata/" + n for n in METADATA}
            | {"policy.json"}
            | {stage + ".json" for stage in task_stages(record)}
        )
        if (
            manifest.get("schema") != 1
            or manifest.get("backend_version") != self.version
            or {r["path"] for r in manifest["files"]} != expected
            or len(manifest["files"]) != len(expected)
        ):
            raise ValueError("INVALID_WORKING_SESSION_MANIFEST")
        for row in manifest["files"]:
            declared = bundle / row["path"]
            if any(
                x.is_symlink() or x.is_junction()
                for x in [
                    declared,
                    *[p for p in declared.parents if p != bundle and p.is_relative_to(bundle)],
                ]
            ):
                raise ValueError("LINKED_WORKING_SESSION_RESOURCE")
            p = declared.resolve()
            if (
                not p.is_relative_to(bundle)
                or p.is_symlink()
                or len(p.read_bytes()) != row["bytes"]
                or sha(p) != row["sha256"]
            ):
                raise ValueError("PREPARED_SESSION_CHANGED")
        if any(p.name == "__pycache__" or p.suffix == ".pyc" for p in bundle.rglob("*")):
            raise ValueError("UNEXPECTED_BACKEND_CACHE")
        policy = read_json(bundle / "policy.json")
        if (
            policy["session_id"] != record["session_id"]
            or policy["attempt_id"] != record["attempt_id"]
            or policy["tasks"] != record["tasks"]
            or policy["bundle_root"] != str(bundle)
        ):
            raise ValueError("PREPARED_SESSION_CHANGED")
        if policy.get('local_auth_file') != self.local_auth_file():
            raise ValueError('WORKING_SESSION_AUTH_MODE_CHANGED')
        return policy

    def progress(self, bundle, record):
        path = Path(bundle) / "progress.json"
        if not path.exists():
            return None
        d = read_json(path)
        if (
            set(d) != {"session_id", "attempt", "status", "stages"}
            or d["session_id"] != record["session_id"]
            or d["attempt"] != record["attempt_id"]
            or d["status"] not in {"LOGIN_REQUIRED", "RUNNING"}
        ):
            raise ValueError("INVALID_WORKING_SESSION_PROGRESS")
        return self.project_stages(d["stages"], record), d["status"]

    def project_stages(self, stages, record, *, legacy=False):
        names = task_stages(record)
        if not isinstance(stages, dict) or list(stages) not in [list(names[:i]) for i in range(len(names) + 1)]:
            raise ValueError("INVALID_WORKING_SESSION_STAGES")
        values = []
        for i, stage in enumerate(names):
            if stage in stages:
                value = stages[stage]
                if not stage_valid(value, record["tasks"][i], stage, legacy=legacy):
                    raise ValueError("INVALID_WORKING_SESSION_RESULT")
                values.append(value)
        return values

    def result(self, bundle, record):
        d = read_json(Path(bundle) / "runtime-evidence/outcome.json")
        if (
            d.get("attempt") != record["attempt_id"]
            or d.get("result") not in {"COMPLETED_WORKING_SESSION_ONLY", "FAIL_OR_INCONCLUSIVE"}
            or d.get("no_retry") is not True
        ):
            raise ValueError("INVALID_WORKING_SESSION_OUTCOME")
        stages = self.project_stages(d.get("stages"), record)
        clean = d.get("cleanup_errors") == [] and d.get("evidence_errors") == []
        complete = (
            d["result"] == "COMPLETED_WORKING_SESSION_ONLY"
            and d.get("reason") is None
            and clean
            and complete_results(record, stages)
        )
        cancelled = d.get("cancellation_local_expected") is True
        diagnostic = d.get('diagnostic')
        task = diagnostic.get('work_task') if isinstance(diagnostic, dict) else None
        missing_text = (isinstance(task, dict) and task.get('native_success') is True
                        and task.get('selected_text_state') == 'EMPTY')
        return dict(
            completed=bool(complete),
            cleanup_confirmed=clean,
            stages=stages,
            cancelled=cancelled,
            code=(None if complete or (cancelled and clean) else
                  'WORKING_SESSION_RESULT_UNAVAILABLE' if missing_text else
                  'WORKING_SESSION_NOT_COMPLETED'),
        )

    def run(self, bundle, record, approval, *, projection_callback=None):
        if projection_callback is not None:
            from agent_runtime.tasks import finite_projection
            if not finite_projection.enabled():
                raise PermissionError('FINITE_PROJECTION_GATE_CLOSED')
        if not self.local_auth_file() and not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)):
            raise PermissionError("PRIVATE_LOCAL_TERMINAL_REQUIRED")
        self.verify(bundle, record)
        if approval != self.approval(record, record["plan_hash"], True):
            raise PermissionError("EXACT_WORKING_SESSION_APPROVAL_REQUIRED")
        path = Path(bundle) / "owner-approval.json"
        with path.open("x", encoding="utf-8") as f:
            json.dump(approval, f)
            f.flush()
            os.fsync(f.fileno())
        name = "agent_runtime.providers.claude._working_" + record["attempt_id"].replace("-", "")
        definition = importlib.util.spec_from_file_location(
            name, Path(bundle) / "__init__.py", submodule_search_locations=[str(bundle)]
        )
        module = importlib.util.module_from_spec(definition)
        sys.modules[name] = module
        old = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            definition.loader.exec_module(module)
            controller = __import__(name + ".controller", fromlist=["main"])
            if projection_callback is None:
                controller.main(["--execute", "--approval", str(path)], emit_result=False)
            else:
                controller.main(["--execute", "--approval", str(path)], emit_result=False,
                                projection_callback=projection_callback)
            return self.result(bundle, record)
        finally:
            sys.dont_write_bytecode = old
            for key in list(sys.modules):
                if key == name or key.startswith(name + "."):
                    sys.modules.pop(key, None)
