"""Manual CLI: live calls are opt-in, offline commands never construct SDK clients."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
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
    result.add_argument(
        "--auth-mode", choices=["subscription", "api"], help="Default subscription; API is explicit"
    )
    result.add_argument(
        "--native-config-dir",
        dest="login_config_dir",
        help="Existing native login store outside CAS; never copied",
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Offline installation and repository diagnostics")
    agents = commands.add_parser("agents").add_subparsers(dest="action", required=True)
    agents.add_parser("list")
    task = (
        commands.add_parser("task").add_subparsers(dest="action", required=True).add_parser("run")
    )
    task.add_argument("--file", type=Path, required=True)
    task.add_argument("--allow-live", action="store_true", help="Authorize this model invocation")
    task.add_argument(
        "--allow-existing-login",
        action="store_true",
        help="Authorize native subscription session reuse for this invocation",
    )
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
    scenario_run.add_argument("--allow-existing-login", action="store_true")
    scenario_run.add_argument(
        "--model", help="Explicit native model ID; required for live research"
    )
    scenario_run.add_argument("--max-turns", type=int)
    scenario_run.add_argument("--max-budget-usd")
    scenario_run.add_argument("--timeout-seconds", type=int, default=30)
    commands.add_parser("report").add_argument("run_id")
    console = commands.add_parser("console", help="Launch independently installed console")
    console.add_argument(
        "--enable-tasks", action="store_true", help="Opt in to coding fixture task control"
    )
    console.add_argument(
        "--enable-working-sessions",
        action="store_true",
        help="Finite prepared text tasks for one local owner",
    )
    working = commands.add_parser(
        "working-session", help="One temporary profile for one or two prepared text tasks"
    ).add_subparsers(dest="action", required=True)
    create = working.add_parser("create")
    create.add_argument("--title", default="Working session")
    add = working.add_parser("add")
    add.add_argument("session_id")
    add.add_argument("--title", required=True)
    add.add_argument("--file", type=Path, required=True)
    for name in ("prepare", "inspect", "scope", "end", "cancel"):
        item = working.add_parser(name)
        item.add_argument("session_id")
        if name in {"end", "cancel"}:
            item.add_argument("--plan-hash")
    working.add_parser("list")
    run = working.add_parser("run")
    run.add_argument("session_id")
    run.add_argument("--approval", type=Path)
    run.add_argument("--allow-live", action="store_true")
    return result


def output(value) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    stream = sys.stdout
    try:
        stream.write(text)
    except UnicodeEncodeError:
        # Legacy Windows code pages (cp1251/cp1252) cannot encode all result characters.
        stream.flush()
        stream.buffer.write(text.encode("utf-8"))
    stream.flush()


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        root = args.root.resolve(strict=True) if args.root else discover_root()
        cfg = Configuration.load(
            root,
            os.environ,
            {
                "data_dir": args.data_dir,
                "auth_mode": args.auth_mode,
                "login_config_dir": args.login_config_dir,
                "max_turns": getattr(args, "max_turns", None),
                "max_budget_usd": getattr(args, "max_budget_usd", None),
            },
        )
        if args.command == "working-session":
            if cfg.auth_mode != "subscription" or cfg.login_config_dir is not None:
                raise PermissionError(
                    "Working sessions use only a new isolated subscription profile"
                )
            from agent_runtime.tasks.working_sessions import WorkingSessions, safe_path

            sessions = WorkingSessions(cfg.data_dir, root=root)
            if args.action == "create":
                value = sessions.create(args.title)
            elif args.action == "add":
                file = safe_path(args.file)
                if (
                    file.name.lower().find("credential") >= 0
                    or any(p.lower() in {".claude", ".codex", ".aws", ".ssh"} for p in file.parts)
                    or file.stat().st_size > 2048
                ):
                    raise ValueError("BOUNDED_NONSENSITIVE_TASK_FILE_REQUIRED")
                value = sessions.add(
                    args.session_id, title=args.title, prompt=file.read_text(encoding="utf-8")
                )
            elif args.action == "prepare":
                value = sessions.prepare(args.session_id)
            elif args.action == "list":
                value = sessions.list()
            elif args.action == "inspect":
                value = sessions.get(args.session_id)
            elif args.action == "scope":
                value = sessions.scope(args.session_id)
            elif args.action in {"end", "cancel"}:
                value = sessions.request(args.session_id, args.plan_hash, end=args.action == "end")
            else:
                value = sessions.run(args.session_id, args.approval, allow_live=args.allow_live)
                output(value)
                return 0 if value["status"] == "COMPLETED" else 1
            output(value)
        elif args.command == "doctor":
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
                    "authentication": {
                        "selected": cfg.auth_mode,
                        "session_status": "not-checked",
                        "existing_login_reuse": "requires --allow-existing-login",
                        "api_fallback": "disabled",
                    },
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
            if cfg.auth_mode == "subscription" and not args.allow_existing_login:
                raise PermissionError(
                    "Subscription mode requires separate --allow-existing-login consent"
                )
            if cfg.auth_mode == "api" and not os.environ.get("ANTHROPIC_API_KEY"):
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
                auth_mode=cfg.auth_mode,
                allow_existing_login=args.allow_existing_login,
                login_config_dir=cfg.login_config_dir,
            )
            run = asyncio.run(
                Executor(
                    cfg.data_dir,
                    SupervisedClaudeAdapter(os.environ),
                    secrets=[os.environ["ANTHROPIC_API_KEY"]] if cfg.auth_mode == "api" else [],
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
                    if cfg.auth_mode == "subscription" and not args.allow_existing_login:
                        raise PermissionError(
                            "Subscription mode requires separate --allow-existing-login consent"
                        )
                    if cfg.auth_mode == "api" and not os.environ.get("ANTHROPIC_API_KEY"):
                        raise ValueError("ANTHROPIC_API_KEY must be supplied externally")
                    if not args.model:
                        raise ValueError("Live SDK baseline requires explicit --model")
                    from agent_runtime.providers.claude.supervised import SupervisedClaudeAdapter

                    limits = cfg.live_limits(timeout_seconds=args.timeout_seconds)
                    client = SupervisedClaudeAdapter(os.environ)
                    secrets = [os.environ["ANTHROPIC_API_KEY"]] if cfg.auth_mode == "api" else []
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
                    auth_mode=cfg.auth_mode,
                    allow_existing_login=args.allow_existing_login,
                    login_config_dir=cfg.login_config_dir,
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
            if args.enable_tasks and args.enable_working_sessions:
                raise ValueError("Choose one console control mode")
            if args.enable_working_sessions and (
                cfg.auth_mode != "subscription" or cfg.login_config_dir is not None
            ):
                raise PermissionError(
                    "Working sessions use only a new isolated subscription profile"
                )
            if args.enable_tasks or args.enable_working_sessions:
                from importlib.util import find_spec

                if find_spec("agent_console") is None:
                    raise ValueError(
                        "Task controls require agent-console installed in the runtime Python environment; see coding guide"
                    )
                return subprocess.call(  # noqa: S603 - current interpreter and fixed module/argv, no shell
                    [
                        sys.executable,
                        "-m",
                        "agent_console",
                        "--data-dir",
                        str(cfg.data_dir),
                        "--host",
                        cfg.console_host,
                        "--port",
                        str(cfg.console_port),
                        "--enable-working-sessions"
                        if args.enable_working_sessions
                        else "--enable-tasks",
                        *(["--root", str(root)] if args.enable_working_sessions else []),
                    ]
                )
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
