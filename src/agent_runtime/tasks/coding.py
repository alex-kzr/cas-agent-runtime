"""Disposable single-file fixture policy and bounded artifacts, not an OS sandbox."""

import asyncio
import difflib
import hashlib
import json
import os
import sys
from pathlib import Path

from agent_runtime.providers.claude.supervision import OwnedProcess
from agent_runtime.tasks.testing_worker import validate_source
from agent_runtime.telemetry.recorder import atomic_json

BASELINE = "def add(a, b):\n    return a - b\n"
PROFILE = "coding-fixture-v1"
TOOLS = {
    "mcp__cas_workspace__read_file",
    "mcp__cas_workspace__write_file",
    "mcp__cas_workspace__run_tests",
}


def digest(source):
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class CodingWorkspace:
    @classmethod
    def inspect(cls, workspace):
        """Validate/read existing source without creating evidence directories."""
        instance = cls.__new__(cls)
        instance.workspace = Path(workspace)
        return instance.read("calc.py")

    @staticmethod
    def create(workspace):
        workspace.mkdir(parents=True, exist_ok=False)
        (workspace / "calc.py").write_text(BASELINE, encoding="utf-8", newline="\n")

    def __init__(self, workspace, directory):
        self.workspace = Path(workspace)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.before = self.read("calc.py")
        self.latest = None
        self.invocations = 0
        self.testing = False

    def check(self):
        if self.workspace.is_symlink() or self.workspace.is_junction():
            raise ValueError("Linked workspace rejected")
        entries = list(self.workspace.iterdir())
        if len(entries) != 1 or entries[0].name != "calc.py":
            raise ValueError("Only calc.py may exist in the disposable workspace")
        path = entries[0]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_nlink != 1
            or path.stat().st_size > 4096
        ):
            raise ValueError("Unsafe fixture file")
        return path

    def read(self, path):
        if path != "calc.py":
            raise ValueError("Only calc.py is approved")
        source = self.check().read_bytes().decode("utf-8")
        validate_source(source)
        return source

    def write(self, path, source):
        if self.testing:
            raise ValueError("Cannot write while the fixed test is running")
        if path != "calc.py":
            raise ValueError("Only calc.py is approved")
        validate_source(source)
        self.check().write_bytes(source.encode("utf-8"))
        return {"sha256": digest(source)}

    async def test(self):
        if self.testing:
            raise ValueError("Fixed test is already running")
        self.testing = True
        try:
            return await self._test()
        finally:
            self.testing = False

    async def _test(self):
        self.read("calc.py")
        self.invocations += 1
        if self.invocations > 3:
            raise ValueError("At most three fixed test invocations per run")
        output = self.directory / f"test-{self.invocations}.json"
        owner = OwnedProcess()
        payload = json.dumps({"workspace": str(self.workspace), "output": str(output)}).encode()
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC"}
        }
        code = None
        try:
            async with asyncio.timeout(5):
                code = await owner.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        str(Path(__file__).with_name("testing_worker.py")),
                    ],
                    payload,
                    environment,
                )
        finally:
            self.latest = {
                "schema_version": 1,
                "exit_code": code,
                "source_sha256": digest(self.read("calc.py")),
                "validated": False,
                "cleanup": owner.cleanup,
                "stdout": "",
                "stderr": "No result",
            }
            atomic_json(self.directory / "tests.json", self.latest)
        if not owner.cleanup["tree_empty"] or not output.is_file() or output.stat().st_size > 8192:
            raise ValueError("Fixed test command did not produce safe evidence/cleanup")
        result = json.loads(output.read_text(encoding="utf-8"))
        if (
            result["exit_code"] != code
            or result["source_sha256"] != digest(self.read("calc.py"))
            or not isinstance(result.get("checks"), list)
            or len(result["checks"]) != 3
            or {check.get("id") for check in result["checks"]} != {"0", "1", "2"}
            or any(type(check.get("passed")) is not bool for check in result["checks"])
            or (code == 0) != all(check["passed"] for check in result["checks"])
        ):
            raise ValueError("Test evidence does not match source or process exit")
        self.latest = dict(result, cleanup=owner.cleanup, validated=True)
        atomic_json(self.directory / "tests.json", self.latest)
        return self.latest

    def capture(self):
        after = self.read("calc.py")
        (self.directory / "before.py").write_bytes(self.before.encode("utf-8"))
        (self.directory / "after.py").write_bytes(after.encode("utf-8"))
        diff = "".join(
            difflib.unified_diff(
                self.before.splitlines(True),
                after.splitlines(True),
                fromfile="before/calc.py",
                tofile="after/calc.py",
            )
        )
        (self.directory / "changes.diff").write_bytes(diff.encode("utf-8"))
        test_path = self.directory / "tests.json"
        if self.latest is None and test_path.is_file() and test_path.stat().st_size <= 8192:
            self.latest = json.loads(test_path.read_text(encoding="utf-8"))
        passed = bool(
            self.latest
            and self.latest.get("validated") is True
            and self.latest["exit_code"] == 0
            and self.latest["source_sha256"] == digest(after)
            and self.latest["cleanup"]["tree_empty"]
        )
        report = {
            "schema_version": 1,
            "profile": PROFILE,
            "before_sha256": digest(self.before),
            "after_sha256": digest(after),
            "changed": self.before != after,
            "tests_passed": passed,
            "context_isolation": "unverified",
        }
        atomic_json(self.directory / "coding.json", report)
        return report


def sdk_server(coding, recorder):
    from claude_agent_sdk import create_sdk_mcp_server, tool

    async def invoke(name, arguments):
        recorder.event(
            "permission.decision",
            {"tool": name, "decision": "allow", "reason": PROFILE},
            "permission",
        )
        recorder.event("tool.request", {"tool_name": name}, "hook")
        try:
            expected = (
                {"path", "source"}
                if name.endswith("write_file")
                else {"path"}
                if name.endswith("read_file")
                else set()
            )
            if not isinstance(arguments, dict) or set(arguments) != expected:
                raise ValueError("Unexpected fixture tool arguments")
            if name.endswith("read_file"):
                value = coding.read(arguments["path"])
            elif name.endswith("write_file"):
                value = coding.write(arguments["path"], arguments["source"])
            else:
                value = await coding.test()
            recorder.event("tool.result", {"tool_name": name, "result": value}, "hook")
            return {"content": [{"type": "text", "text": json.dumps(value)}]}
        except (ValueError, OSError, SyntaxError) as error:
            recorder.event(
                "permission.decision",
                {"tool": name, "decision": "deny", "reason": type(error).__name__},
                "permission",
            )
            return {
                "isError": True,
                "content": [{"type": "text", "text": "Fixture policy rejected operation"}],
            }

    @tool("read_file", "Read the approved calc.py fixture.", {"path": str})
    async def read_file(arguments):
        return await invoke("mcp__cas_workspace__read_file", arguments)

    @tool(
        "write_file",
        "Replace calc.py with one pure def add(a, b) arithmetic function.",
        {"path": str, "source": str},
    )
    async def write_file(arguments):
        return await invoke("mcp__cas_workspace__write_file", arguments)

    @tool("run_tests", "Run the fixed three-case Python fixture test; no command argument.", {})
    async def run_tests(arguments):
        return await invoke("mcp__cas_workspace__run_tests", arguments)

    return create_sdk_mcp_server(name="cas_workspace", tools=[read_file, write_file, run_tests])
