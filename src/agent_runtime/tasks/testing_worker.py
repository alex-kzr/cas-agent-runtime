"""Fixed synthetic Python test command; stdin ownership handshake precedes work."""

import ast
import hashlib
import json
import sys
from pathlib import Path


def validate_source(source):
    if not isinstance(source, str) or len(source.encode("utf-8")) > 4096:
        raise ValueError("Fixture source exceeds limit")
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    allowed = (
        ast.Module,
        ast.FunctionDef,
        ast.arguments,
        ast.arg,
        ast.Return,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Name,
        ast.Load,
        ast.Constant,
    )
    if len(nodes) > 64 or any(not isinstance(node, allowed) for node in nodes):
        raise ValueError("Only a bounded pure arithmetic fixture is accepted")
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("Expected one add function")
    function = tree.body[0]
    args = function.args
    if (
        function.name != "add"
        or function.decorator_list
        or function.returns
        or function.type_params
        or args.defaults
        or args.kw_defaults
        or args.kwonlyargs
        or args.posonlyargs
        or args.vararg
        or args.kwarg
        or [arg.arg for arg in args.args] != ["a", "b"]
        or any(arg.annotation for arg in args.args)
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Return)
    ):
        raise ValueError("Expected def add(a, b) with one return expression")
    if any(isinstance(node, ast.Name) and node.id not in {"a", "b"} for node in nodes):
        raise ValueError("Only a and b are allowed")
    if any(
        isinstance(node, ast.Constant) and (type(node.value) is not int or abs(node.value) > 100)
        for node in nodes
    ):
        raise ValueError("Only small integer constants are allowed")


def main():
    payload = json.loads(sys.stdin.buffer.read(16_385))
    source_path = Path(payload["workspace"]) / "calc.py"
    if source_path.is_symlink() or source_path.stat().st_nlink != 1:
        raise ValueError("Linked fixture rejected")
    raw = source_path.read_bytes()
    source = raw.decode("utf-8")
    validate_source(source)
    namespace = {"__builtins__": {}}
    # Execute exactly the validated snapshot, never reread a potentially changed file.
    # AST permits only one pure arithmetic function; no imports/calls/loops/attributes.
    exec(compile(source, "calc.py", "exec"), namespace)  # noqa: S102 - reviewed AST allowlist
    cases = [(2, 3, 5), (-1, 1, 0), (0, 0, 0)]
    checks = [
        {"id": str(index), "passed": namespace["add"](a, b) == expected}
        for index, (a, b, expected) in enumerate(cases)
    ]
    passed = all(check["passed"] for check in checks)
    result = {
        "schema_version": 1,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "exit_code": 0 if passed else 1,
        "checks": checks,
        "stdout": f"{sum(c['passed'] for c in checks)}/3 fixture checks passed",
        "stderr": "",
    }
    Path(payload["output"]).write_text(json.dumps(result), encoding="utf-8")
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
