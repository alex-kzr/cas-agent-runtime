"""Typed semantic network policy; identity and zero-consumer cleanup kept separate."""

import ipaddress
import re

from . import spec

POLICY_CODES = frozenset(
    {
        "NETWORK_ROLE_INVALID",
        "NETWORK_METADATA_INVALID",
        "NETWORK_IDENTITY_MISMATCH",
        "NETWORK_ISOLATION_MISMATCH",
        "NETWORK_OPTIONS_MISMATCH",
        "NETWORK_IPAM_MISMATCH",
        "NETWORK_ISOLATED_GATEWAY_PRESENT",
        "NETWORK_NAT_GATEWAY_MISMATCH",
        "NETWORK_CREATE_ID_INVALID",
        "NETWORK_CLEANUP_ID_MISMATCH",
        "NETWORK_CLEANUP_HAS_CONSUMERS",
        "NETWORK_CLEANUP_METADATA_INVALID",
    }
)


class NetworkPolicyError(ValueError):
    def __init__(self, code):
        if code not in POLICY_CODES:
            raise ValueError("Unknown fixed network policy code")
        self.code = code
        super().__init__(code)


def create_id(raw):
    try:
        value = raw.decode("ascii").strip()
    except (AttributeError, UnicodeError):
        raise NetworkPolicyError("NETWORK_CREATE_ID_INVALID") from None
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise NetworkPolicyError("NETWORK_CREATE_ID_INVALID")
    return value


def policy(doc, role):
    if role not in {"internal", "external"}:
        raise NetworkPolicyError("NETWORK_ROLE_INVALID")
    if not isinstance(doc, dict):
        raise NetworkPolicyError("NETWORK_METADATA_INVALID")
    internal = role == "internal"
    if (
        doc.get("Driver") != "bridge"
        or doc.get("Scope") != "local"
        or doc.get("Internal") is not internal
        or doc.get("EnableIPv4") is not True
        or doc.get("EnableIPv6") is not False
        or doc.get("Attachable") is not False
    ):
        raise NetworkPolicyError("NETWORK_ISOLATION_MISMATCH")
    options = doc.get("Options")
    gateway_key = "com.docker.network.bridge.gateway_mode_ipv4"
    automatic = {
        "com.docker.network.enable_ipv4": "true",
        "com.docker.network.enable_ipv6": "false",
    }
    if (
        not isinstance(options, dict)
        or set(options) - set(automatic) - {gateway_key}
        or any(key in options and options[key] != value for key, value in automatic.items())
    ):
        raise NetworkPolicyError("NETWORK_OPTIONS_MISMATCH")
    if (
        internal
        and options.get(gateway_key) != "isolated"
        or not internal
        and options.get(gateway_key, "nat") != "nat"
    ):
        raise NetworkPolicyError("NETWORK_OPTIONS_MISMATCH")
    ipam = doc.get("IPAM")
    if (
        not isinstance(ipam, dict)
        or ipam.get("Driver") != "default"
        or ipam.get("Options") not in (None, {})
    ):
        raise NetworkPolicyError("NETWORK_IPAM_MISMATCH")
    configs = ipam.get("Config")
    subnet = spec.INTERNAL if internal else spec.EXTERNAL
    if (
        not isinstance(configs, list)
        or len(configs) != 1
        or not isinstance(configs[0], dict)
        or configs[0].get("Subnet") != subnet
        or set(configs[0]) not in ({"Subnet"}, {"Subnet", "Gateway"})
    ):
        raise NetworkPolicyError("NETWORK_IPAM_MISMATCH")
    gateway = configs[0].get("Gateway")
    if internal and gateway not in (None, ""):
        raise NetworkPolicyError("NETWORK_ISOLATED_GATEWAY_PRESENT")
    if not internal and gateway != str(ipaddress.ip_network(subnet).network_address + 1):
        raise NetworkPolicyError("NETWORK_NAT_GATEWAY_MISMATCH")


def cleanup_safe(doc, expected_id=None):
    """Caller separately proves exact name+owner labels via unchanged owned() gate."""
    if expected_id is not None and doc.get("Id") != expected_id:
        raise NetworkPolicyError("NETWORK_CLEANUP_ID_MISMATCH")
    if (
        doc.get("Driver") != "bridge"
        or doc.get("Scope") != "local"
        or not isinstance(doc.get("Containers"), dict)
    ):
        raise NetworkPolicyError("NETWORK_CLEANUP_METADATA_INVALID")
    if doc["Containers"]:
        raise NetworkPolicyError("NETWORK_CLEANUP_HAS_CONSUMERS")
