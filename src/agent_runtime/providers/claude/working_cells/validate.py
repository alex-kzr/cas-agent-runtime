"""Offline validation of exact future owned Docker objects."""

import re

from . import spec


def one(doc):
    if isinstance(doc, list) and len(doc) == 1:
        return doc[0]
    if isinstance(doc, dict):
        return doc
    raise ValueError("One object required")


def owned(doc, name):
    doc = one(doc)
    labels = doc.get("Config", {}).get("Labels", doc.get("Labels", {})) or {}
    if (
        not re.fullmatch(r"[0-9a-f]{64}", doc.get("Id", ""))
        or doc.get("Name", "").lstrip("/") != name
        or any(labels.get(k) != v for k, v in spec.LABELS.items())
    ):
        raise ValueError("Ownership mismatch")
    return doc["Id"]


def network(doc, role):
    from . import network_contract

    doc = one(doc)
    identifier = owned(doc, spec.NETWORKS[role])
    network_contract.policy(doc, role)
    return identifier


def cleanup_network(doc, role, expected=None):
    from . import network_contract

    doc = one(doc)
    identifier = owned(doc, spec.NETWORKS[role])
    network_contract.cleanup_safe(doc, expected)
    return identifier


def container_owner(doc, role, expected=None):
    doc = one(doc)
    identifier = owned(doc, spec.CONTAINERS[role])
    if doc.get("Image") != spec.IMAGE or expected is not None and identifier != expected:
        raise ValueError("CONTAINER_OWNER_IMAGE_ID")
    return identifier


def container(doc, role, networks, *, created=False, exited=False):
    doc = one(doc)
    identifier = owned(doc, spec.CONTAINERS[role])
    cfg, host = doc["Config"], doc["HostConfig"]
    command = spec.create(role, networks["internal"])
    source = (
        next(
            command[i + 1]
            for i, v in enumerate(command)
            if v == "--mount" and command[i + 1].startswith("type=bind,")
        )
        .split("src=", 1)[1]
        .split(",dst=", 1)[0]
    )
    allowed_sources = {source, source.replace("\\", "/")}
    if re.match(r"^[A-Za-z]:[\\/]", source):
        drive, rest = source[0].lower(), source[3:].replace("\\", "/")
        allowed_sources.update(
            {"/run/desktop/mnt/host/" + drive + "/" + rest, "/host_mnt/" + drive + "/" + rest}
        )
    spec.load("image-env.json")
    endpoints = doc.get("NetworkSettings", {}).get("Networks", {})
    expected_ips = {networks["internal"]: spec.IP[role]}
    if role == "relay":
        expected_ips[networks["external"]] = "10.253.251.2"
    endpoint_ips = {v.get("NetworkID"): v.get("IPAddress") for v in endpoints.values()}
    endpoint_ok = len(endpoints) == len(expected_ips) and endpoint_ips == expected_ips
    if created or exited:
        requested = {
            spec.NETWORKS["internal"]: (networks["internal"], expected_ips[networks["internal"]])
        }
        if role == "relay":
            requested[spec.NETWORKS["external"]] = (
                networks["external"],
                expected_ips[networks["external"]],
            )
        endpoint_ok = set(endpoints) == set(requested) and all(
            (
                value.get("NetworkID", "") in {"", requested[name][0]}
                if created
                else value.get("NetworkID") == requested[name][0]
            )
            and value.get("IPAddress", "") in {"", requested[name][1]}
            and (value.get("IPAMConfig") or {}).get("IPv4Address") == requested[name][1]
            for name, value in endpoints.items()
        )
    checks = {
        "image": doc.get("Image") == spec.IMAGE,
        "identity": cfg.get("User") == "10001:10001"
        and cfg.get("Entrypoint") == ["python"]
        and cfg.get("Cmd") == ["-I", "-B", "/cas-sub7.py"]
        and cfg.get("WorkingDir") == "/var/lib/cas",
        "role": cfg.get("Labels", {}).get("cas.working1.role") == role,
        "environment": doc.get("EnvExact") is True,
        "stdin": cfg.get("OpenStdin") is (role in {"work_a", "work_b", "auth"})
        and cfg.get("Tty") is (role == "auth"),
        "readonly": host.get("ReadonlyRootfs") is True,
        "security": host.get("CapDrop") == ["ALL"]
        and not host.get("CapAdd")
        and host.get("SecurityOpt") == ["no-new-privileges=true"]
        and not host.get("Privileged")
        and host.get("Init") is False,
        "namespaces": host.get("PidMode") == ""
        and host.get("IpcMode") == "private"
        and host.get("CgroupnsMode") == "private"
        and not host.get("UTSMode")
        and not host.get("UsernsMode"),
        "network": host.get("NetworkMode") in {networks["internal"], spec.NETWORKS["internal"]}
        and endpoint_ok
        and all(
            not e.get("IPv6Gateway")
            and not e.get("GlobalIPv6Address")
            and (role == "relay" or not e.get("Gateway"))
            for e in endpoints.values()
        ),
        "dns": host.get("Dns") == (["1.1.1.1"] if role == "relay" else ["127.0.0.1"])
        and not host.get("DnsSearch")
        and not host.get("DnsOptions"),
        "hosts": sorted(host.get("ExtraHosts") or [])
        == sorted(
            [
                h + ":" + spec.RELAY_IP
                for h in (
                    spec.HOSTS
                    if role == "auth"
                    else spec.WORK_HOSTS
                    if role in {"work_a", "work_b"}
                    else []
                )
            ]
        ),
        "no_extra": not host.get("Binds")
        and not host.get("VolumesFrom")
        and not host.get("Devices")
        and not host.get("DeviceRequests")
        and not host.get("DeviceCgroupRules")
        and not host.get("Sysctls")
        and not host.get("Links")
        and not host.get("PortBindings")
        and not cfg.get("ExposedPorts"),
        "resources": host.get("Memory") == 1073741824
        and host.get("MemorySwap") == 1073741824
        and host.get("NanoCpus") == 1000000000
        and host.get("PidsLimit") == 64
        and host.get("ShmSize") == 67108864,
        "runtime": host.get("Runtime") == "runc"
        and host.get("AutoRemove") is False
        and host.get("RestartPolicy", {}).get("Name") == "no"
        and cfg.get("StopTimeout") == 5,
        "logs": isinstance(host.get("LogConfig"), dict)
        and host["LogConfig"].get("Type") == "none"
        and host["LogConfig"].get("Config") in (None, {}),
        "init_stop_health": host.get("Init") is False
        and cfg.get("StopSignal") == "SIGTERM"
        and isinstance(cfg.get("Healthcheck"), dict)
        and cfg["Healthcheck"].get("Test") == ["NONE"],
        "tmpfs": host.get("Tmpfs")
        == (
            {"/home/cas": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700"}
            if role == "relay"
            else {}
        )
        | {
            "/tmp": "rw,nosuid,nodev,noexec,size=128m,mode=1777",
            "/var/lib/cas": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700",
        },
        "ulimits": ulimits_valid(host.get("Ulimits")),
    }
    mounts = doc.get("Mounts", [])
    binds = [m for m in mounts if m.get("Type") == "bind"]
    volumes = [m for m in mounts if m.get("Type") == "volume"]
    wanted_volume = role in {"auth", "work_a", "work_b"}
    expected_binds = {"/cas-sub7.py": allowed_sources}
    if role == "auth":
        wire = str((spec.ROOT / "ready_wire.py").resolve())
        aliases = {wire, wire.replace("\\", "/")}
        if re.match(r"^[A-Za-z]:[\\/]", wire):
            aliases |= {
                "/run/desktop/mnt/host/" + wire[0].lower() + "/" + wire[3:].replace("\\", "/"),
                "/host_mnt/" + wire[0].lower() + "/" + wire[3:].replace("\\", "/"),
            }
        expected_binds["/cas-ready-wire.py"] = aliases
        if spec.LOCAL_AUTH:
            source = spec.LOCAL_AUTH
            aliases = {source, source.replace('\\', '/')}
            if re.match(r'^[A-Za-z]:[\\/]', source):
                aliases |= {'/run/desktop/mnt/host/' + source[0].lower() + '/' + source[3:].replace('\\', '/'), '/host_mnt/' + source[0].lower() + '/' + source[3:].replace('\\', '/')}
            expected_binds['/cas-local-auth'] = aliases
    if role in {"work_a", "work_b"}:
        task = str((spec.ROOT / ("first.json" if role == "work_a" else "second.json")).resolve())
        aliases = {task, task.replace("\\", "/")}
        if re.match(r"^[A-Za-z]:[\\/]", task):
            aliases |= {
                "/run/desktop/mnt/host/" + task[0].lower() + "/" + task[3:].replace("\\", "/"),
                "/host_mnt/" + task[0].lower() + "/" + task[3:].replace("\\", "/"),
            }
        expected_binds["/cas-task.json"] = aliases
    checks["mounts"] = (
        len(binds) == len(expected_binds)
        and len({m.get("Destination") for m in binds}) == len(binds)
        and {m.get("Destination") for m in binds} == set(expected_binds)
        and all(
            m.get("Source") in expected_binds[m["Destination"]] and m.get("RW") is False
            for m in binds
        )
        and len(volumes) == int(wanted_volume)
        and all(
            m.get("Name") == spec.VOLUME
            and m.get("Destination") == "/home/cas"
            and m.get("RW") is True
            for m in volumes
        )
        and all(
            m.get("Type") in {"bind", "volume"}
            or m.get("Type") == "tmpfs"
            and m.get("Destination") in host.get("Tmpfs", {})
            for m in mounts
        )
    )
    requests = host.get("Mounts") or []
    volume_requests = [m for m in requests if m.get("Type") == "volume"]
    checks["volume_nocopy"] = len(volume_requests) == int(wanted_volume) and all(
        m.get("Source") == spec.VOLUME
        and m.get("Target") == "/home/cas"
        and m.get("VolumeOptions", {}).get("NoCopy") is True
        and not m.get("ReadOnly")
        for m in volume_requests
    )
    if created:
        checks["created"] = (
            doc.get("State", {}).get("Status") == "created"
            and doc["State"].get("Running") is False
            and doc["State"].get("Pid") == 0
        )
    if exited:
        checks["exited"] = (
            doc.get("State", {}).get("Status") == "exited"
            and doc["State"].get("Running") is False
            and doc["State"].get("Pid") == 0
        )
    failed = [name for name, value in checks.items() if not value]
    if failed:
        raise ValueError("Container mismatch: " + ",".join(failed))
    return identifier


def volume_owner(doc):
    doc = one(doc)
    if (
        doc.get("Name") != spec.VOLUME
        or doc.get("Driver") != "local"
        or doc.get("Scope") != "local"
        or any((doc.get("Labels") or {}).get(k) != v for k, v in spec.LABELS.items())
    ):
        raise ValueError("PROFILE_OWNERSHIP_MISMATCH")
    return spec.VOLUME


def volume(doc):
    volume_owner(doc)
    if one(doc).get("Options") != spec.VOLUME_OPTIONS:
        raise ValueError("PROFILE_OPTIONS_MISMATCH")
    return spec.VOLUME


def stopped(doc):
    state = one(doc).get("State", {})
    return (
        state.get("Status") in {"exited", "created"}
        and state.get("Running") is False
        and state.get("Pid") == 0
    )


def success_exit(doc):
    state = one(doc).get("State", {})
    return (
        stopped(doc)
        and state.get("Status") == "exited"
        and state.get("ExitCode") == 0
        and not state.get("OOMKilled")
        and not state.get("Error")
    )


def ulimits_valid(values):
    if not isinstance(values, list):
        return False
    required = {"core": (0, 0), "fsize": (16777216, 16777216), "nofile": (256, 256)}
    resource_defaults = {
        "cpu",
        "data",
        "locks",
        "memlock",
        "msgqueue",
        "nproc",
        "rss",
        "rttime",
        "sigpending",
        "stack",
    }
    found = {}
    for item in values:
        if not isinstance(item, dict):
            return False
        name = item.get("Name")
        soft = item.get("Soft")
        hard = item.get("Hard")
        if (
            not isinstance(name, str)
            or name in found
            or type(soft) is not int
            or type(hard) is not int
            or soft < -1
            or hard < -1
        ):
            return False
        if hard != -1 and (soft == -1 or soft > hard):
            return False
        if (
            name not in required
            and name not in resource_defaults
            and not (name in {"nice", "rtprio"} and soft == hard == 0)
        ):
            return False
        found[name] = (soft, hard)
    return all(found.get(name) == value for name, value in required.items())
