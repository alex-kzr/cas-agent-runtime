import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime.providers.claude.auth import native_cli


class NativeCliTests(unittest.TestCase):
    def test_platform_bundled_names_no_path_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "_bundled").mkdir()
            for system, name in (("Windows", "claude.exe"), ("Linux", "claude")):
                with self.subTest(system=system), patch("agent_runtime.providers.claude.auth.platform.system", return_value=system), patch("agent_runtime.providers.claude.auth.files", return_value=root), patch("agent_runtime.providers.claude.auth.os.access", return_value=True):
                    with self.assertRaises(ValueError):
                        native_cli()
                    path = root / "_bundled" / name
                    path.write_bytes(b"synthetic")
                    self.assertEqual(native_cli(), path)
                    path.unlink()

    def test_linux_requires_executable_and_unknown_platform_fails_closed(self):
        with patch("agent_runtime.providers.claude.auth.platform.system", return_value="Linux"), patch("agent_runtime.providers.claude.auth.os.access", return_value=False), self.assertRaises(ValueError):
            native_cli()
        with patch("agent_runtime.providers.claude.auth.platform.system", return_value="Unknown"), self.assertRaises(ValueError):
            native_cli()
