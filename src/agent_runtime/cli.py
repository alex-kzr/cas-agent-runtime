"""Manual CLI: live calls are opt-in, offline commands never construct SDK clients."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import UUID, uuid4

from agent_runtime.config import Configuration
from agent_runtime.tasks.models import ExecutionRequest, Limits, validate_document
from agent_runtime.telemetry.recorder import SENSITIVE, atomic_json, read_events, reconcile, redact


def identifier(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Expected a canonical UUID")
    return value


def discover_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "config/repositories.yaml").is_file():
            return parent
    raise ValueError("Installed application requires explicit --root <CAS umbrella>")


def load_run(data_dir: Path, run_id: str) -> dict:
    path = data_dir / "runs" / identifier(run_id) / "run.json"
    if path.stat().st_size > 1_000_000:
        raise ValueError("Run metadata exceeds size limit")
    record = json.loads(path.read_text(encoding="utf-8"))
    validate_document("run", record)
    return record


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="cas-cli", description="CAS manual runtime; live calls need --allow-live"
    )
    result.add_argument("--root", type=Path)
    result.add_argument("--data-dir", type=Path)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Offline installation and repository diagnostics")
    agents = commands.add_parser("agents").add_subparsers(dest="action", required=True)
    agents.add_parser("list")
    task = (
        commands.add_parser("task").add_subparsers(dest="action", required=True).add_parser("run")
    )
    task.add_argument("--file", type=Path, required=True)
    task.add_argument("--allow-live", action="store_true", help="Authorize this model invocation")
    task.add_argument("--model")
    task.add_argument("--agent", choices=["text-only-v1", "read-only-v1"], default="text-only-v1")
    task.add_argument(
        "--workspace",
        type=Path,
        help="Existing/created directory below the approved CAS workspace root",
    )
    task.add_argument("--max-turns", type=int)
    task.add_argument("--max-budget-usd")
    task.add_argument("--timeout-seconds", type=int, default=120)
    runs = commands.add_parser("runs").add_subparsers(dest="action", required=True)
    runs.add_parser("list")
    runs.add_parser("recover", help="Mark abandoned runs interrupted; never rerun them")
    runs.add_parser("inspect").add_argument("run_id")
    scenarios = commands.add_parser("scenarios").add_subparsers(dest="action", required=True)
    scenarios.add_parser("list")
    scenario_run = scenarios.add_parser("run")
    scenario_run.add_argument("scenario_id")
    scenario_run.add_argument("--allow-live", action="store_true")
    scenario_run.add_argument(
        "--model", help="Explicit native model ID; required for live research"
    )
    scenario_run.add_argument("--max-turns", type=int)
    scenario_run.add_argument("--max-budget-usd")
    scenario_run.add_argument("--timeout-seconds", type=int, default=30)
    commands.add_parser("report").add_argument("run_id")
    commands.add_parser("console", help="Launch independently installed read-only console")
    return result


def output(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        root = args.root.resolve(strict=True) if args.root else discover_root()
        cfg = Configuration.load(
            root,
            os.environ,
            {
                "data_dir": args.data_dir,
                "max_turns": getattr(args, "max_turns", None),
                "max_budget_usd": getattr(args, "max_budget_usd", None),
            },
        )
        if args.command == "doctor":
            checks = []
            for package in ("claude-agent-sdk", "jsonschema"):
                try:
                    installed = version(package)
                except PackageNotFoundError:
                    installed = None
                checks.append(
                    {
                        "dependency": package,
                        "version": installed,
                        "available": installed is not None,
                    }
                )
            output(
                {
                    "mode": "offline",
                    "dependencies": checks,
                    "configuration": cfg.public(),
                    "components": {
                        name: (root / "repositories" / name / "pyproject.toml").is_file()
                        for name in ("agent-runtime", "agent-console", "mcp-services")
                    },
                    "live_verified": False,
                    "component_remotes": "not configured by this command",
                }
            )
        elif args.command == "agents":
            output(
                [
                    {
                        "name": "text-only-v1",
                        "provider": "claude",
                        "tools": [],
                        "validation": "nonempty text only",
                        "live_verified": False,
                    },
                    {
                        "name": "read-only-v1",
                        "provider": "claude",
                        "tools": ["Read"],
                        "validation": "nonempty text only; bounded path policy tested offline",
                        "live_verified": False,
                    },
                ]
            )
        elif args.command == "task":
            if not args.allow_live:
                raise PermissionError("Use --allow-live only after approving this model invocation")
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise ValueError("ANTHROPIC_API_KEY must be supplied externally")
            limits = cfg.live_limits(timeout_seconds=args.timeout_seconds)
            if args.file.stat().st_size > 256_000:
                raise ValueError("Task file exceeds 256 KB")
            instructions = args.file.read_text(encoding="utf-8")
            from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter
            from agent_runtime.tasks.executor import Executor

            request = ExecutionRequest(
                "task",
                instructions,
                args.workspace.resolve() if args.workspace else cfg.workspace_root / str(uuid4()),
                limits,
                model=args.model,
                live_authorized=True,
                agent_name=args.agent,
            )
            run = asyncio.run(
                Executor(
                    cfg.data_dir,
                    SupervisedClaudeAdapter(os.environ),
                    secrets=[os.environ["ANTHROPIC_API_KEY"]],
                    workspace_root=cfg.workspace_root,
                ).execute(request)
            )
            output(run)
            return 0 if run["status"] == "COMPLETED" else 1
        elif args.command == "runs":
            if args.action == "recover":
                output({"interrupted_runs": reconcile(cfg.data_dir)})
            elif args.action == "inspect":
                run = load_run(cfg.data_dir, args.run_id)
                events, warnings = read_events(cfg.data_dir / "runs" / args.run_id / "events.jsonl")
                output({"run": run, "events": events, "warnings": warnings})
            else:
                records, warnings = [], []
                for path in sorted((cfg.data_dir / "runs").glob("*/run.json"), reverse=True)[:1000]:
                    try:
                        records.append(load_run(cfg.data_dir, path.parent.name))
                    except (ValueError, OSError):
                        warnings.append(f"Unreadable run {path.parent.name}")
                output({"runs": records, "warnings": warnings})
        elif args.command == "scenarios":
            from agent_runtime.scenarios.registry import SCENARIOS, LocalValidation, write_catalog

            if args.action == "list":
                output(
                    {
                        "mode": "local checks plus explicitly gated live baseline",
                        "scenarios": SCENARIOS,
                    }
                )
            else:
                if args.scenario_id not in SCENARIOS:
                    raise ValueError("Unknown/unimplemented scenario; use scenarios list")
                from agent_runtime.tasks.executor import Executor

                live = SCENARIOS[args.scenario_id].get("execution_mode") == "live"
                if live:
                    if not args.allow_live:
                        raise PermissionError("Live SDK baseline requires explicit --allow-live")
                    if not os.environ.get("ANTHROPIC_API_KEY"):
                        raise ValueError("ANTHROPIC_API_KEY must be supplied externally")
                    if not args.model:
                        raise ValueError("Live SDK baseline requires explicit --model")
                    from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter

                    limits = cfg.live_limits(timeout_seconds=args.timeout_seconds)
                    client = SupervisedClaudeAdapter(os.environ)
                    secrets = [os.environ["ANTHROPIC_API_KEY"]]
                else:
                    limits = Limits(1, "0.01", 10)
                    client, secrets = LocalValidation(), []
                request = ExecutionRequest(
                    "scenario",
                    SCENARIOS[args.scenario_id]["title"],
                    cfg.workspace_root / str(uuid4()),
                    limits,
                    args.scenario_id,
                    model=args.model if live else None,
                    live_authorized=live,
                )
                run = asyncio.run(
                    Executor(
                        cfg.data_dir, client, secrets=secrets, workspace_root=cfg.workspace_root
                    ).execute(request)
                )
                write_catalog(cfg.data_dir, run)
                output(run)
                return 0 if run["status"] == "COMPLETED" else 1
        elif args.command == "report":
            run = load_run(cfg.data_dir, args.run_id)
            path = cfg.data_dir / "reports" / args.run_id / "report.json"
            atomic_json(
                path,
                {
                    "schema_version": 1,
                    "run": run,
                    "warning": "SDK live behavior unverified; missing usage is unknown, not zero",
                },
            )
            output({"report": str(path)})
        elif args.command == "console":
            executable = shutil.which("cas-console")
            if not executable:
                candidate = (
                    root
                    / "repositories/agent-console/.venv"
                    / ("Scripts/cas-console.exe" if os.name == "nt" else "bin/cas-console")
                )
                executable = str(candidate) if candidate.is_file() else None
            if not executable:
                raise ValueError("Install agent-console in its own uv environment before launching")
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.upper()
                in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT"}
            }
            return subprocess.call(  # noqa: S603 - trusted installed executable and argv; no shell
                [
                    executable,
                    "--data-dir",
                    str(cfg.data_dir),
                    "--host",
                    cfg.console_host,
                    "--port",
                    str(cfg.console_port),
                ],
                env=environment,
            )
        return 0
    except (ValueError, OSError, PermissionError, RuntimeError) as error:
        # Config/operational errors contain fixed safe diagnostics, never env dumps.
        secret_values = [value for key, value in os.environ.items() if SENSITIVE.search(key)]
        output({"error": type(error).__name__, "message": redact(str(error), secret_values)[:1000]})
        return 2
