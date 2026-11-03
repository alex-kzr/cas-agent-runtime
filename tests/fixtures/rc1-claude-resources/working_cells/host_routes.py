"""Future read-only Windows IP Helper route check; no commands or policy changes."""

import ctypes
import ipaddress
import socket
import struct
import sys


def parse_table(raw):
    count = struct.unpack_from("<I", raw)[0]
    if count > 65536 or len(raw) < 4 + count * 56:
        raise ValueError("Route table size")
    networks = []
    for index in range(count):
        destination, mask = struct.unpack_from("<II", raw, 4 + index * 56)
        if not mask:
            continue  # The ordinary default route does not reserve every possible subnet.
        address = socket.inet_ntoa(struct.pack("<I", destination))
        netmask = socket.inet_ntoa(struct.pack("<I", mask))
        networks.append(str(ipaddress.IPv4Network((address, netmask), strict=False)))
    return networks


def read_routes():
    if sys.platform != "win32":
        raise RuntimeError("This host controller is pinned to Windows; route check unavailable")
    get_table = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800).GetIpForwardTable
    get_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_int]
    get_table.restype = ctypes.c_ulong
    size = ctypes.c_ulong(0)
    if get_table(None, ctypes.byref(size), False) != 122 or not 4 <= size.value <= 1048576:
        raise RuntimeError("Route metadata unavailable; no fallback")
    buffer = ctypes.create_string_buffer(size.value)
    if get_table(buffer, ctypes.byref(size), False) != 0:
        raise RuntimeError("Route metadata changed/unavailable; no retry")
    return parse_table(buffer.raw[: size.value])


def assert_no_overlap(routes, requested):
    for candidate in requested:
        if any(
            ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(route))
            for route in routes
        ):
            raise ValueError(
                "Owned subnet overlaps host/VPN route; select a new reviewed sealed scope"
            )
