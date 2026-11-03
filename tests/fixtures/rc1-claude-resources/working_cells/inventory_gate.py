"""Pure validation plus read-only inventory adapter; no create/login/runtime."""

import ipaddress
import json
import re

CODES = frozenset(
    {
        "NETWORK_LIST_UNAVAILABLE",
        "NETWORK_INVENTORY_INVALID_OR_OVER_BUDGET",
        "NETWORK_INVENTORY_INCOMPLETE",
        "NETWORK_IPAM_UNAVAILABLE",
        "REQUESTED_SCOPE_INVALID",
        "ROUTE_METADATA_INVALID",
        "NETWORK_POOL_OR_ROUTE_OVERLAP",
        "NETWORK_INSPECT_UNAVAILABLE",
        "NETWORK_INSPECT_INVALID",
        "NETWORK_INVENTORY_CHANGED",
    }
)


class ReadinessError(RuntimeError):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code, self.details = code, details or []


def ids(result):
    if (
        not isinstance(result, dict)
        or type(result.get("rc")) is not int
        or result["rc"] != 0
        or not isinstance(result.get("err"), bytes)
        or result["err"].strip()
        or not isinstance(result.get("out"), bytes)
    ):
        raise ReadinessError("NETWORK_LIST_UNAVAILABLE")
    try:
        values = result["out"].decode("utf-8").split()
    except UnicodeError:
        raise ReadinessError("NETWORK_INVENTORY_INVALID_OR_OVER_BUDGET") from None
    if (
        len(values) > 32
        or len(set(values)) != len(values)
        or any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in values)
    ):
        raise ReadinessError("NETWORK_INVENTORY_INVALID_OR_OVER_BUDGET")
    return set(values)


def assess(requested, routes, documents, expected_ids):
    if not isinstance(requested, (list, tuple)) or any(not isinstance(x, str) for x in requested):
        raise ReadinessError("REQUESTED_SCOPE_INVALID")
    try:
        wanted = [ipaddress.ip_network(value, strict=True) for value in requested]
    except ValueError:
        raise ReadinessError("REQUESTED_SCOPE_INVALID") from None
    private = [
        ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ]
    if (
        len(wanted) != 2
        or any(
            x.version != 4 or x.prefixlen != 29 or not any(x.subnet_of(p) for p in private)
            for x in wanted
        )
        or wanted[0].overlaps(wanted[1])
    ):
        raise ReadinessError("REQUESTED_SCOPE_INVALID")
    if not isinstance(routes, (list, tuple)) or any(not isinstance(x, str) for x in routes):
        raise ReadinessError("ROUTE_METADATA_INVALID")
    try:
        route_networks = [ipaddress.ip_network(value, strict=True) for value in routes]
    except ValueError:
        raise ReadinessError("ROUTE_METADATA_INVALID") from None
    if (
        not isinstance(documents, list)
        or len(documents) > 32
        or any(
            not isinstance(doc, dict)
            or not isinstance(doc.get("Id"), str)
            or not isinstance(doc.get("Driver"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", doc["Id"])
            for doc in documents
        )
    ):
        raise ReadinessError("NETWORK_INVENTORY_INCOMPLETE")
    if (
        not isinstance(expected_ids, (set, list, tuple))
        or len(expected_ids) > 32
        or any(not isinstance(x, str) or not re.fullmatch(r"[0-9a-f]{64}", x) for x in expected_ids)
    ):
        raise ReadinessError("NETWORK_INVENTORY_INCOMPLETE")
    if len(set(expected_ids)) != len(expected_ids):
        raise ReadinessError("NETWORK_INVENTORY_INCOMPLETE")
    if {doc.get("Id") for doc in documents} != set(expected_ids) or len(documents) != len(
        expected_ids
    ):
        raise ReadinessError("NETWORK_INVENTORY_INCOMPLETE")
    pools = []
    for doc in documents:
        configs = doc.get("IPAMConfig")
        if doc.get("Driver") in {"host", "null"} and configs in (None, []):
            continue
        if not isinstance(configs, list) or not configs:
            raise ReadinessError("NETWORK_IPAM_UNAVAILABLE")
        for config in configs:
            if not isinstance(config, dict) or not isinstance(config.get("Subnet"), str):
                raise ReadinessError("NETWORK_IPAM_UNAVAILABLE")
            try:
                subnet = ipaddress.ip_network(config["Subnet"], strict=True)
            except (KeyError, ValueError, TypeError):
                raise ReadinessError("NETWORK_IPAM_UNAVAILABLE") from None
            pools.append((doc["Id"], subnet))
    conflicts = []
    for candidate in wanted:
        for identifier, subnet in pools:
            if subnet.version == candidate.version and candidate.overlaps(subnet):
                conflicts.append(
                    dict(
                        requested=str(candidate),
                        existing_network_id=identifier,
                        existing_subnet=str(subnet),
                    )
                )
        for subnet in route_networks:
            if (
                subnet.prefixlen
                and subnet.version == candidate.version
                and candidate.overlaps(subnet)
            ):
                conflicts.append(dict(requested=str(candidate), host_route=str(subnet)))
    if conflicts:
        raise ReadinessError("NETWORK_POOL_OR_ROUTE_OVERLAP", conflicts)
    return dict(
        code="READ_ONLY_NETWORK_READINESS_PASS",
        networks=len(documents),
        requested=requested,
        race="SNAPSHOT_ONLY_RECHECK_BEFORE_MUTATION_NO_RESERVATION",
    )


FORMAT = '{"Id":{{json .Id}},"Driver":{{json .Driver}},"IPAMConfig":{{json .IPAM.Config}}}'


def check_live(docker, routes, requested):
    """Three bounded read-only calls; existing transport operation/output limits still apply."""
    first = ids(docker.run(["network", "ls", "--no-trunc", "--quiet"]))
    documents = []
    if first:
        result = docker.run(["network", "inspect", "--format", FORMAT, *sorted(first)])
        if (
            not isinstance(result, dict)
            or type(result.get("rc")) is not int
            or result["rc"] != 0
            or not isinstance(result.get("err"), bytes)
            or result["err"].strip()
            or not isinstance(result.get("out"), bytes)
        ):
            raise ReadinessError("NETWORK_INSPECT_UNAVAILABLE")
        try:
            documents = [
                json.loads(line) for line in result["out"].decode("utf-8").splitlines() if line
            ]
        except (ValueError, UnicodeError):
            raise ReadinessError("NETWORK_INSPECT_INVALID") from None
    second = ids(docker.run(["network", "ls", "--no-trunc", "--quiet"]))
    if first != second:
        raise ReadinessError("NETWORK_INVENTORY_CHANGED")
    return assess(requested, routes, documents, first)
