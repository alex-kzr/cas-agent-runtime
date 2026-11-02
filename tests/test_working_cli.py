"""Product command routing without starting a console, Docker, SDK or native process."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_console import server

from agent_runtime.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("CAS_TEST_TMP"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def call(self, *args):
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
            code = main(["--root", str(self.root), *args])
        return code, json.loads(out.getvalue())

    def test_cli_prepare_and_default_closed_live(self):
        code, d = self.call("working-session", "create", "--title", "Ordinary work")
        self.assertEqual(code, 0)
        sid = d["session_id"]
        file = self.root / "ordinary.txt"
        file.write_text("A bounded synthetic task")
        for i in range(2):
            code, _ = self.call(
                "working-session", "add", sid, "--title", str(i), "--file", str(file)
            )
            self.assertEqual(code, 0)
        code, d = self.call("working-session", "prepare", sid)
        self.assertEqual(code, 0)
        self.assertIn("--root", d["local_command"])
        code, _ = self.call("working-session", "run", sid, "--approval", "absent.json")
        self.assertEqual(code, 2)
        self.assertFalse(
            (self.root / "data/working-sessions" / sid / "attempt.claim.json").exists()
        )
        code, d = self.call("working-session", "end", sid, "--plan-hash", d["plan_hash"])
        self.assertEqual(code, 0)
        self.assertEqual(d["status"], "CLOSED")

    def test_console_launcher_propagates_explicit_root(self):
        with patch("subprocess.call", return_value=0) as call:
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(
                    main(["--root", str(self.root), "console", "--enable-working-sessions"]), 0
                )
        argv = call.call_args.args[0]
        self.assertEqual(argv[argv.index("--root") + 1], str(self.root))

    def test_console_entry_requires_root_and_passes_it_without_binding(self):
        with patch.object(server, "serve", return_value=0) as serve:
            self.assertEqual(
                server.main(
                    [
                        "--data-dir",
                        str(self.root / "data"),
                        "--root",
                        str(self.root),
                        "--enable-working-sessions",
                    ]
                ),
                0,
            )
            self.assertEqual(serve.call_args.args[1].root, self.root)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                server.main(["--data-dir", str(self.root / "data"), "--enable-working-sessions"])


if __name__ == "__main__":
    unittest.main()
