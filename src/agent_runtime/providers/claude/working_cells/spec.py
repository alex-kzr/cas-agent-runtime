"""Fixed one-owner subscription experiment; no runtime operations on import."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
POLICY = json.loads((ROOT / "policy.json").read_text(encoding="utf-8"))
if not isinstance(POLICY.get("tasks"), list) or not 1 <= len(POLICY["tasks"]) <= 2:
    raise ValueError("ONE_OR_TWO_WORKING_SESSION_TASKS_REQUIRED")
STAGES = dict(zip(("first", "second")[:len(POLICY["tasks"])], ("work_a", "work_b"), strict=False))
EXPECTED_ROOT = Path(POLICY["bundle_root"])
LOCAL_AUTH = POLICY.get("local_auth_file")
CLAIM = EXPECTED_ROOT / "attempt.claim.json"
EVIDENCE = EXPECTED_ROOT / "runtime-evidence"
ATTEMPT = POLICY["attempt_id"]
OWNER = "cas-working-session-" + ATTEMPT
IMAGE = "sha256:7d7021a2980964ffee2776efb3705a17bc7406569d1cc6fd7d740f4630a0d877"
ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
MODEL = "claude-haiku-4-5-20251001"
INTERNAL, EXTERNAL = "10.253.250.0/29", "10.253.251.0/29"
RELAY_IP, WORK_IP, AUTH_IP = "10.253.250.2", "10.253.250.3", "10.253.250.4"
IP = {"relay": RELAY_IP, "work_a": WORK_IP, "work_b": WORK_IP, "auth": AUTH_IP}
HOSTS = ("api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com")
WORK_HOSTS = ("api.anthropic.com", "platform.claude.com")
LABELS = {
    "cas.working1.owner": OWNER,
    "cas.working1.scope": "personal-one-task-shared-profile" if len(STAGES) == 1 else "personal-two-stage-shared-profile-series",
}
CONTAINERS = {role: OWNER + "-" + role for role in ("relay", "auth", *STAGES.values())}
NETWORKS = {role: OWNER + "-" + role for role in ("internal", "external")}
VOLUME = OWNER + "-profile"
VOLUME_OPTIONS = {
    "type": "tmpfs",
    "device": "tmpfs",
    "o": "size=67108864,uid=10001,gid=10001,mode=0700,nosuid,nodev,noexec",
}


def hashfile(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name):
    return json.loads((ROOT / "metadata" / name).read_text(encoding="utf-8-sig"))


def labels():
    return [part for k, v in LABELS.items() for part in ("--label", k + "=" + v)]


def network_create(role):
    return [
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        INTERNAL if role == "internal" else EXTERNAL,
        *(
            ["--internal", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated"]
            if role == "internal"
            else []
        ),
        *labels(),
        NETWORKS[role],
    ]


def volume_create():
    return [
        "volume",
        "create",
        "--driver",
        "local",
        *labels(),
        *[part for key, value in VOLUME_OPTIONS.items() for part in ("--opt", key + "=" + value)],
        VOLUME,
    ]


def create(role, network_id):
    if role not in CONTAINERS:
        raise ValueError("UNPLANNED_WORKING_SESSION_ROLE")
    source = str(
        (ROOT / ("work_cell.py" if role in {"work_a", "work_b"} else role + ".py")).resolve()
    )
    if any(c in source for c in ",\r\n"):
        raise ValueError("Unsafe source path")
    hosts = HOSTS if role == "auth" else WORK_HOSTS if role in {"work_a", "work_b"} else ()
    return [
        "create",
        "--name",
        CONTAINERS[role],
        "--pull=never",
        *labels(),
        "--label",
        "cas.working1.role=" + role,
        "--user",
        "10001:10001",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--network",
        network_id,
        "--ip",
        IP[role],
        "--dns",
        "1.1.1.1" if role == "relay" else "127.0.0.1",
        *[part for host in hosts for part in ("--add-host", host + ":" + RELAY_IP)],
        *(
            ["--interactive", "--tty"]
            if role == "auth"
            else ["--interactive"]
            if role in {"work_a", "work_b"}
            else []
        ),
        "--init=false",
        "--no-healthcheck",
        "--stop-signal",
        "SIGTERM",
        "--ipc=private",
        "--cgroupns=private",
        "--runtime=runc",
        "--pids-limit=64",
        "--memory=1g",
        "--memory-swap=1g",
        "--cpus=1",
        "--shm-size=64m",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "fsize=16777216:16777216",
        "--restart=no",
        "--stop-timeout=5",
        "--log-driver=none",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777",
        "--tmpfs",
        "/var/lib/cas:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
        *(
            ["--tmpfs", "/home/cas:rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700"]
            if role == "relay"
            else ["--mount", "type=volume,src=" + VOLUME + ",dst=/home/cas,volume-nocopy"]
        ),
        "--mount",
        "type=bind,src=" + source + ",dst=/cas-sub7.py,readonly",
        *(
            [
                "--mount",
                "type=bind,src="
                + str((ROOT / "ready_wire.py").resolve())
                + ",dst=/cas-ready-wire.py,readonly",
            ]
            if role == "auth"
            else []
        ),
        *(["--mount", "type=bind,src=" + LOCAL_AUTH + ",dst=/cas-local-auth,readonly"] if role == "auth" and LOCAL_AUTH else []),
        *(
            [
                "--mount",
                "type=bind,src="
                + str((ROOT / ("first.json" if role == "work_a" else "second.json")).resolve())
                + ",dst=/cas-task.json,readonly",
            ]
            if role in {"work_a", "work_b"}
            else []
        ),
        "--env",
        "CAS_PHASE1_ACTIVATION=one-approved-finite-working-session",
        "--workdir",
        "/var/lib/cas",
        "--entrypoint",
        "python",
        IMAGE,
        "-I",
        "-B",
        "/cas-sub7.py",
    ]


def image_defaults():
    fmt = '{"Id":{{json .Id}},"HasVolumes":{{if (index .Config "Volumes")}}true{{else}}false{{end}},"HasExposedPorts":{{if (index .Config "ExposedPorts")}}true{{else}}false{{end}}}'
    return ["image", "inspect", "--format", fmt, IMAGE]


def inspect_container(target):
    # Root .Id intentionally selects Docker inspect raw-JSON fallback; index handles omitempty.
    prefix = '{{$env := index .Config "Env"}}'
    prefix += "".join(
        "{{$e%d := false}}{{range $env}}{{if eq . %s}}{{$e%d = true}}{{end}}{{end}}"  # noqa: UP031 - Go template braces
        % (i, json.dumps(value), i)
        for i, value in enumerate(expected_env())
    )
    env_test = "{{if $env}}{{and (eq (len $env) %d) %s}}{{else}}false{{end}}" % (  # noqa: UP031 - Go template braces
        len(expected_env()),
        " ".join(f"$e{i}" for i in range(len(expected_env()))),
    )
    fields = [
        "Labels",
        "User",
        "Entrypoint",
        "Cmd",
        "WorkingDir",
        "OpenStdin",
        "Tty",
        "ExposedPorts",
        "StopTimeout",
        "StopSignal",
        "Healthcheck",
    ]
    config = ",".join(
        json.dumps(key) + ":{{json (index .Config " + json.dumps(key) + ")}}" for key in fields
    )
    fmt = (
        prefix
        + '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Config":{'
        + config
        + '},"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},"NetworkSettings":{{json .NetworkSettings}},"EnvExact":'
        + env_test
        + "}"
    )
    return ["container", "inspect", "--format", fmt, target]


def expected_env():
    values = load("image-env.json").copy()
    key = "CAS_PHASE1_ACTIVATION="
    values = [v for v in values if not v.startswith(key)]
    return values + [key + "one-approved-finite-working-session"]


def ready_exec(identifier):
    return [
        "exec",
        "--user",
        "10001:10001",
        "--workdir",
        "/var/lib/cas",
        identifier,
        "python",
        "-I",
        "-B",
        "/cas-ready-wire.py",
    ]


def authorize(args):
    import re

    def isid(v):
        return isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)

    ok = False
    if args == ["network", "ls", "--no-trunc", "--quiet"]:
        ok = True
    elif args[:3] == ["network", "inspect", "--format"]:
        from .inventory_gate import FORMAT

        ok = (
            len(args) >= 5
            and args[3] == FORMAT
            and len(args[4:]) <= 32
            and all(isid(v) for v in args[4:])
        )
    elif args[:2] == ["network", "inspect"]:
        ok = len(args) == 3 and (args[2] in NETWORKS.values() or isid(args[2]))
    elif args[:2] == ["container", "inspect"]:
        ok = (
            len(args) >= 4
            and (args[-1] in CONTAINERS.values() or isid(args[-1]))
            and args == inspect_container(args[-1])
        )
    elif args[:2] == ["volume", "inspect"]:
        ok = args == ["volume", "inspect", VOLUME]
    elif args[:2] == ["image", "inspect"]:
        fmt = '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}}}'
        ok = args in (["image", "inspect", "--format", fmt, IMAGE], image_defaults())
    elif args[:1] == ["info"]:
        ok = args == [
            "info",
            "--format",
            '{"ServerVersion":{{json .ServerVersion}},"OSType":{{json .OSType}},"Architecture":{{json .Architecture}},"KernelVersion":{{json .KernelVersion}},"CgroupVersion":{{json .CgroupVersion}},"SecurityOptions":{{json .SecurityOptions}},"DefaultRuntime":{{json .DefaultRuntime}}}',
        ]
    elif args[:1] == ["version"]:
        ok = args == ["version", "--format", "{{json .Server}}"]
    elif args[:2] == ["volume", "create"]:
        ok = args == volume_create()
    elif args[:2] == ["network", "create"]:
        ok = args in [network_create(v) for v in NETWORKS]
    elif args[:1] == ["create"]:
        try:
            n = args[args.index("--network") + 1]
            ok = bool(isid(n)) and args in [create(v, n) for v in CONTAINERS]
        except (ValueError, IndexError):
            pass
    elif args[:2] == ["network", "connect"]:
        ok = (
            len(args) == 6
            and args[2:4] == ["--ip", "10.253.251.2"]
            and all(isid(v) for v in args[-2:])
        )
    elif args[:1] == ["exec"]:
        ok = len(args) == 10 and bool(isid(args[5])) and args == ready_exec(args[5])
    elif args[:1] == ["wait"]:
        ok = len(args) == 2 and bool(isid(args[1]))
    elif args[:1] == ["start"]:
        ok = bool(isid(args[-1])) and args in [
            *([["start", args[-1]]] if LOCAL_AUTH else []),
            ["start", "--attach", args[-1]],
            ["start", "--attach", "--interactive", args[-1]],
            ["start", "--attach", "--interactive", "--detach-keys=ctrl-p,ctrl-q", args[-1]],
        ]
    elif args[:2] == ["stop", "--timeout"]:
        ok = len(args) == 4 and args[2] == "5" and bool(isid(args[3]))
    elif args[:1] in (["kill"], ["rm"]):
        ok = (
            len(args) == 2
            and bool(isid(args[1]))
            or len(args) == 4
            and args[:3] == ["kill", "--signal", "USR1"]
            and bool(isid(args[3]))
        )
    elif args[:2] == ["network", "rm"]:
        ok = len(args) == 3 and bool(isid(args[2]))
    elif args[:2] == ["volume", "rm"]:
        ok = args == ["volume", "rm", VOLUME]
    if not ok:
        raise ValueError("EXACT_DOCKER_CONTRACT_REJECTED")


PHASE = "series"

RUNS = {s: POLICY["tasks"][i]["run_id"] for i, s in enumerate(STAGES)}


def approval(digest, approved=False):
    return dict(
        approved=approved,
        manifest_sha256=digest,
        attempt=ATTEMPT,
        scope="cas-product-working-session-v1",
        allow_live=approved,
        extra_usage_disabled=approved if not LOCAL_AUTH else False,
        accept_shared_native_history_and_credentials=approved,
        accept_local_prompt_result_retention=approved,
        accept_112_operations_and_displayed_resource_limits=approved,
    )
