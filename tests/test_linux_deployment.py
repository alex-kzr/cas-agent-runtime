import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("cas_inspect_check", ROOT / "deploy/validate_inspect.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class InspectTests(unittest.TestCase):
    def record(self):
        return [{"HostConfig": {
            "PidMode": "", "NetworkMode": "none", "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"], "ReadonlyRootfs": True,
            "Privileged": False, "Init": False, "Binds": [],
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,mode=1777", "/home/cas": "rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001", "/var/lib/cas": "rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001"},
            "PidsLimit": 64, "Memory": 1073741824, "NanoCpus": 1000000000,
        }, "Config": {"User": "10001:10001", "Entrypoint": ["python", "-B", "/opt/cas/deploy/entrypoint.py"], "Env": ["HOME=/home/cas", "CLAUDE_CONFIG_DIR=/home/cas/.claude", "XDG_CONFIG_HOME=/home/cas/.config", "CAS_DATA_DIR=/var/lib/cas"]}, "Mounts": []}]

    def test_accepts_only_reviewed_boundary(self):
        self.assertEqual(validator.validate(self.record())["outcome"], "PASS")
        record = self.record()
        record[0]["Config"]["Env"].append("GPG_KEY=public-release-verification-fingerprint")
        self.assertEqual(validator.validate(record)["outcome"], "PASS")

    def test_rejects_privileged_shared_network_pid_mounts_devices_and_credentials(self):
        mutations = [
            ("HostConfig", "PidMode", "host"), ("HostConfig", "NetworkMode", "default"),
            ("HostConfig", "Init", True), ("HostConfig", "Privileged", True),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]), ("HostConfig", "CapDrop", []),
            ("HostConfig", "SecurityOpt", ["seccomp:unconfined"]),
            ("HostConfig", "ReadonlyRootfs", False), ("HostConfig", "Binds", ["host:/host"]),
            ("HostConfig", "Devices", [{"PathOnHost": "/dev/sda"}]),
            ("HostConfig", "PortBindings", {"8765/tcp": [{}]}),
            ("HostConfig", "Tmpfs", {}), ("HostConfig", "Memory", 0),
            ("Config", "User", "root"), ("Config", "Entrypoint", ["sh"]),
            ("Config", "Env", ["ANTHROPIC_API_KEY=synthetic"]),
        ]
        for area, key, value in mutations:
            record = self.record()
            record[0][area][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validator.validate(record)
        record = self.record()
        record[0]["Mounts"] = [{"Type": "bind", "Destination": "/home/cas"}]
        with self.assertRaises(ValueError):
            validator.validate(record)

    def test_rejects_weakened_tmpfs_or_profile_paths(self):
        for target, options in (("/home/cas", "rw,exec,nosuid,nodev,mode=0700,uid=10001,gid=10001"), ("/home/cas", "rw,noexec,nosuid,nodev,mode=0777,uid=10001,gid=10001"), ("/var/lib/cas", "rw,noexec,nosuid,nodev,mode=0700,uid=0,gid=0"), ("/tmp", "")):
            record = self.record()
            record[0]["HostConfig"]["Tmpfs"][target] = options
            with self.subTest(target=target, options=options), self.assertRaises(ValueError):
                validator.validate(record)
        for key in ("HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "CAS_DATA_DIR"):
            record = self.record()
            record[0]["Config"]["Env"] = [v if not v.startswith(key + "=") else key + "=/host-profile" for v in record[0]["Config"]["Env"]]
            with self.subTest(key=key), self.assertRaises(ValueError):
                validator.validate(record)
