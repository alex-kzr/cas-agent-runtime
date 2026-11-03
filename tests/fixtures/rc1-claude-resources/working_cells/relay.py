"""Fixed TLS pass-through relay. No TLS termination, credential parsing or traffic logs."""

import errno
import ipaddress
import json
import os
import select
import signal
import socket
import struct
import sys
import threading
import time

HOST = "api.anthropic.com"
BIND = "10.253.250.2"
PEERS = {
    "10.253.250.3": {"api.anthropic.com", "platform.claude.com"},
    "10.253.250.4": {"api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"},
}
MAX_BYTES = 1048576  # Aggregate both directions, all connections.
MAX_CONNECTIONS = 16
SECONDS = 400
MAX_ACTIVE = 4


FAILURE_CODE = "UNCLASSIFIED"
FAILURE_LOCK = threading.Lock()


class RelayBudgetError(ValueError):
    pass


def failure_code(stage, error):
    # Fixed category only. Neither exception strings nor traffic leave RAM.
    if isinstance(error, RelayBudgetError):
        return "BYTE_BUDGET"
    if isinstance(error, TimeoutError):
        return "TIMEOUT"
    if stage == "hello":
        return "HELLO_REJECTED"
    if stage == "peer":
        return "PEER_POLICY"
    if stage == "connect":
        return "UPSTREAM_CONNECT"
    if stage == "forward" and isinstance(error, OSError):
        return "ESTABLISHED_IO"
    return "UNCLASSIFIED"


def record_failure(stage, error):
    global FAILURE_CODE
    with FAILURE_LOCK:
        if FAILURE_CODE == "UNCLASSIFIED":
            FAILURE_CODE = failure_code(stage, error)


def close_category(error):
    """TCP closure only, never a policy/budget/timeout exemption or cancel proof."""
    if isinstance(error, ConnectionResetError) and error.errno == errno.ECONNRESET:
        return "RESET"
    if isinstance(error, BrokenPipeError) and error.errno == errno.EPIPE:
        return "BROKEN_PIPE"
    return None


def pump(
    client,
    upstream,
    budget,
    deadline,
    idle_seconds,
    failure,
    *,
    clock=time.monotonic,
    choose=select.select,
):
    """Already validated and connected TLS flow. Close both sides on EOF/RST/EPIPE."""
    idle = clock() + idle_seconds
    while clock() < min(deadline, idle) and not failure.is_set():
        ready, _, _ = choose([client, upstream], [], [], 0.25)
        for source in ready:
            try:
                chunk = source.recv(min(16384, budget.remaining() + 1))
                if not chunk:
                    return "EOF"
                budget.take(len(chunk))  # No reset/partial send can refund this charge.
                (upstream if source is client else client).sendall(chunk)
            except OSError as error:
                category = close_category(error)
                if category is None:
                    raise
                return category
            idle = clock() + idle_seconds
    if clock() >= min(deadline, idle):
        raise TimeoutError()
    return "ABORTED_BY_GLOBAL_FAILURE"


def handle_connection(
    client,
    peer,
    addresses,
    budget,
    deadline,
    failure,
    *,
    connect=socket.create_connection,
    hello_reader=None,
    pump_fn=pump,
):
    stage = "hello"
    try:
        with client:
            hello = (hello_reader or receive_hello)(client, min(deadline, time.monotonic() + 3))
            sni = client_hello(hello)
            stage = "peer"
            if peer not in PEERS or sni not in PEERS[peer]:
                raise ValueError("Peer SNI forbidden")
            budget.take(len(hello))
            stage = "connect"
            with connect((addresses[sni], 443), timeout=3) as upstream:
                # Failure while sending ClientHello remains fatal, before established pump.
                upstream.sendall(hello)
                stage = "forward"
                for sock in (client, upstream):
                    sock.settimeout(3)
                category = pump_fn(
                    client,
                    upstream,
                    budget,
                    deadline,
                    300 if peer == "10.253.250.4" else 50,
                    failure,
                )
                if category not in {"EOF", "RESET", "BROKEN_PIPE", "ABORTED_BY_GLOBAL_FAILURE"}:
                    raise ValueError("Bad close state")
                return category
    except Exception as error:
        record_failure(stage, error)
        failure.set()
        return "FATAL"


class Budget:
    def __init__(self, maximum=MAX_BYTES):
        self.maximum, self.total, self.lock = maximum, 0, threading.Lock()

    def take(self, amount):
        with self.lock:
            if type(amount) is not int or amount < 0 or self.total + amount > self.maximum:
                raise RelayBudgetError("Relay byte budget")
            self.total += amount

    def remaining(self):
        with self.lock:
            return self.maximum - self.total


def client_hello(record):
    """Strict single-record complete ClientHello; ambiguous/fragmented/ECH input fails closed."""
    if len(record) < 9 or record[0] != 22 or record[1:3] not in (b"\x03\x01", b"\x03\x03"):
        raise ValueError("TLS record")
    length = int.from_bytes(record[3:5], "big")
    if (
        length > 16384
        or len(record) != length + 5
        or record[5] != 1
        or int.from_bytes(record[6:9], "big") != length - 4
    ):
        raise ValueError("Fragmented/oversized TLS hello")
    body = record[9:]
    position = 34

    def field(length_bytes):
        nonlocal position
        if position + length_bytes > len(body):
            raise ValueError("Truncated hello")
        n = int.from_bytes(body[position : position + length_bytes], "big")
        position += length_bytes
        if position + n > len(body):
            raise ValueError("Truncated vector")
        result = body[position : position + n]
        position += n
        return result

    field(1)  # session id
    ciphers = field(2)
    if not ciphers or len(ciphers) % 2:
        raise ValueError("Ciphers")
    field(1)  # compression
    extensions = field(2)
    if position != len(body):
        raise ValueError("Trailing hello")
    seen, sni = set(), None
    position = 0
    while position < len(extensions):
        if position + 4 > len(extensions):
            raise ValueError("Extension header")
        kind, size = struct.unpack("!HH", extensions[position : position + 4])
        position += 4
        if kind in seen or kind == 0xFE0D or position + size > len(extensions):
            raise ValueError("Duplicate/ECH/truncated extension")
        seen.add(kind)
        value = extensions[position : position + size]
        position += size
        if kind == 0:
            if (
                len(value) < 5
                or int.from_bytes(value[:2], "big") != len(value) - 2
                or value[2] != 0
                or int.from_bytes(value[3:5], "big") != len(value) - 5
            ):
                raise ValueError("SNI list")
            sni = value[5:].decode("ascii")
    if sni not in {"api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com"}:
        raise ValueError("SNI target")
    return sni


def public_ipv4(addresses):
    valid = sorted(set(addresses))
    if not valid or any(
        not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
        or not ipaddress.ip_address(ip).is_global
        or ipaddress.ip_address(ip).is_multicast
        or ipaddress.ip_address(ip).is_reserved
        for ip in valid
    ):
        raise ValueError("Nonpublic/missing DNS answer")
    return valid[0]


def receive_hello(client, deadline):
    result = bytearray()
    target = 5
    while len(result) < target:
        client.settimeout(max(0.01, min(3, deadline - time.monotonic())))
        part = client.recv(target - len(result))
        if not part:
            raise ValueError("Closed hello")
        result.extend(part)
        if len(result) == 5:
            size = int.from_bytes(result[3:5], "big")
            if size > 16384:
                raise ValueError("Oversized hello")
            target = size + 5
        if time.monotonic() >= deadline:
            raise TimeoutError()
    client_hello(bytes(result))
    return bytes(result)


def main():
    if (
        sys.platform != "linux"
        or os.getpid() != 1
        or os.getuid() != 10001
        or os.environ.get("CAS_PHASE1_ACTIVATION") != "one-approved-finite-working-session"
    ):
        raise RuntimeError("Dedicated activated nonroot Linux PID1 required")
    signal.signal(signal.SIGTERM, lambda number, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda number, frame: sys.exit(130))
    # No root, sysctl or NET_BIND_SERVICE workaround: bind failure terminates this attempt.
    addresses = {
        host: public_ipv4(socket.gethostbyname_ex(host + ".")[2])
        for host in ("api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com")
    }
    deadline = time.monotonic() + SECONDS
    budget = Budget()
    failure = threading.Event()
    workers = []

    def handle(client, peer):
        category = handle_connection(client, peer, addresses, budget, deadline, failure)
        # At most MAX_CONNECTIONS fixed records; no traffic, host, URL or exception text.
        print(
            json.dumps(
                dict(
                    scope="cas-working-session-relay",
                    status="FAIL" if category == "FATAL" else "CONNECTION_CLOSED",
                    code=category,
                )
            ),
            flush=True,
        )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((BIND, 443))
        listener.listen(1)
        listener.settimeout(0.25)
        print(
            json.dumps(
                {
                    "scope": "cas-working-session-relay",
                    "status": "READY",
                    "addresses": addresses,
                    "port": 443,
                    "sni": HOST,
                }
            ),
            flush=True,
        )
        connections = 0
        while time.monotonic() < deadline:
            if failure.is_set():
                raise ValueError("Relay worker failed")
            workers = [thread for thread in workers if thread.is_alive()]
            if connections >= MAX_CONNECTIONS or len(workers) >= MAX_ACTIVE:
                if not workers:
                    break
                time.sleep(0.02)
                continue
            try:
                client, peer = listener.accept()
            except TimeoutError:
                continue
            connections += 1
            if peer[0] not in PEERS:
                client.close()
                raise ValueError("Unexpected source")
            thread = threading.Thread(target=handle, args=(client, peer[0]), daemon=True)
            thread.start()
            workers.append(thread)
    if failure.is_set() or workers:
        raise ValueError("Relay incomplete")
    print(
        json.dumps(
            {
                "scope": "cas-working-session-relay",
                "status": "CLOSED",
                "connections": connections,
                "bytes": budget.total,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            json.dumps(dict(scope="cas-working-session-relay", status="FAIL", code=FAILURE_CODE)),
            flush=True,
        )
        raise SystemExit(1) from None
