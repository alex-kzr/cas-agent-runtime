"""Windows x64 / local-NTFS handle-reader capability spike (WP-01).

Reader capability only: existing objects are opened read-only, relative to a retained
parent HANDLE, and every metadata decision comes from the handle that is then read.
There is no staging store, write/publish/delete API, product wiring or root enrollment
of arbitrary paths. Failures carry numeric codes only: never paths, names or contents.

The native boundary (``WindowsNative``) is small and injectable; tests substitute fakes.
The cooperative ``Deadline`` is checked between native calls and cannot preempt a
blocking kernel call. See docs/contracts/WINDOWS_PATH_POLICY.md.
"""

import ctypes
import hashlib
import hmac
import os
import struct
import sys
import sysconfig
import time
from dataclasses import dataclass

# Numeric failure codes (stable, documented in WINDOWS_PATH_POLICY.md).
UNSUPPORTED_PLATFORM = 1
ABI_MISMATCH = 2
BAD_COMPONENT = 3
NATIVE_STATUS = 4
PENDING_STATUS = 5
BAD_HANDLE = 6
QUERY_FAILED = 7
BAD_METADATA = 8
REPARSE = 9
WRONG_TYPE = 10
IDENTITY_MISMATCH = 11
LINK_COUNT = 12
SIZE_MISMATCH = 13
HASH_MISMATCH = 14
DELETE_PENDING = 15
UNSUPPORTED_FS = 16
DEADLINE = 17
READ_FAILED = 18
READ_OVERRUN = 19
CLOSE_FAILED = 20
ROOT_UNTRUSTED = 21
BAD_MANIFEST = 22
INHERITABLE = 23
HANDLE_NOT_OWNED = 24
UNSUPPORTED_ATTRIBUTES = 25
LIMIT_EXCEEDED = 26
ROOT_OPEN_FAILED = 27

STATUS_SUCCESS = 0
STATUS_PENDING = 0x103
FILE_OPENED = 1

FILE_OPEN = 1
FILE_DIRECTORY_FILE = 0x1
FILE_NON_DIRECTORY_FILE = 0x40
FILE_SYNCHRONOUS_IO_NONALERT = 0x20
FILE_OPEN_REPARSE_POINT = 0x200000
OBJ_INHERIT = 0x2
OBJ_CASE_INSENSITIVE = 0x40
OBJ_DONT_REPARSE = 0x1000
FILE_SHARE_READ = 0x1
FILE_READ_DATA = 0x1
FILE_LIST_DIRECTORY = 0x1
FILE_READ_ATTRIBUTES = 0x80
FILE_TRAVERSE = 0x20
SYNCHRONIZE = 0x100000
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x2000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x200000
HANDLE_FLAG_INHERIT = 0x1
FILE_TYPE_DISK = 1
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF

FILE_STANDARD_INFO = 1
FILE_ATTRIBUTE_TAG_INFO = 9
FILE_ID_INFO = 18

ATTR_READONLY = 0x1
ATTR_HIDDEN = 0x2
ATTR_SYSTEM = 0x4
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_NORMAL = 0x80
ATTR_TEMPORARY = 0x100
ATTR_REPARSE_POINT = 0x400
ATTR_NOT_CONTENT_INDEXED = 0x2000
ALLOWED_ATTRIBUTES = (
    ATTR_READONLY
    | ATTR_HIDDEN
    | ATTR_SYSTEM
    | ATTR_DIRECTORY
    | ATTR_ARCHIVE
    | ATTR_NORMAL
    | ATTR_TEMPORARY
    | ATTR_NOT_CONTENT_INDEXED
)

ROOT_ACCESS = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
FILE_ACCESS = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
DIRECTORY_ACCESS = ROOT_ACCESS

DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024
MAX_COMPONENT_CHARS = 255

_STANDARD_LAYOUT = struct.Struct("<qqIBB2x")
_TAG_LAYOUT = struct.Struct("<II")
_ID_LAYOUT = struct.Struct("<Q16s")

_FORBIDDEN_CHARS = frozenset('\\/:*?"<>|')
_RESERVED_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)


class PathHandleError(Exception):
    """Numeric-only failure: ``code`` is a module constant, ``detail`` an int."""

    def __init__(self, code, detail=0):
        super().__init__(f"path handle error code={code} detail={detail}")
        self.code = code
        self.detail = detail


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", ctypes.c_uint32),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _StatusOrPointer(ctypes.Union):
    _fields_ = [("Status", ctypes.c_int32), ("Pointer", ctypes.c_void_p)]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("u", _StatusOrPointer), ("Information", ctypes.c_size_t)]


def check_abi():
    """Return the number of x64 layout mismatches (0 means the declared ABI holds)."""
    expected = [
        (ctypes.sizeof(ctypes.c_void_p), 8),
        (ctypes.sizeof(UNICODE_STRING), 16),
        (UNICODE_STRING.Buffer.offset, 8),
        (ctypes.sizeof(OBJECT_ATTRIBUTES), 48),
        (OBJECT_ATTRIBUTES.RootDirectory.offset, 8),
        (OBJECT_ATTRIBUTES.ObjectName.offset, 16),
        (OBJECT_ATTRIBUTES.Attributes.offset, 24),
        (OBJECT_ATTRIBUTES.SecurityDescriptor.offset, 32),
        (OBJECT_ATTRIBUTES.SecurityQualityOfService.offset, 40),
        (ctypes.sizeof(IO_STATUS_BLOCK), 16),
        (IO_STATUS_BLOCK.u.offset, 0),
        (_StatusOrPointer.Status.size, 4),
        (IO_STATUS_BLOCK.Information.offset, 8),
        (_STANDARD_LAYOUT.size, 24),
        (_TAG_LAYOUT.size, 8),
        (_ID_LAYOUT.size, 24),
    ]
    return sum(1 for actual, wanted in expected if actual != wanted)


def platform_code(os_name=None, pointer_bytes=None, platform_tag=None):
    """0 only for Windows x64 CPython; arguments are a test seam."""
    os_name = os.name if os_name is None else os_name
    pointer_bytes = ctypes.sizeof(ctypes.c_void_p) if pointer_bytes is None else pointer_bytes
    platform_tag = sysconfig.get_platform() if platform_tag is None else platform_tag
    if os_name != "nt" or pointer_bytes != 8 or platform_tag != "win-amd64":
        return UNSUPPORTED_PLATFORM
    return 0


def build_open_request(directory):
    """Pure description of the relative NtCreateFile request (no handle inheritance)."""
    return {
        "access": DIRECTORY_ACCESS if directory else FILE_ACCESS,
        "object_attributes": OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        "file_attributes": 0,
        "share": FILE_SHARE_READ,
        "disposition": FILE_OPEN,
        "options": FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | (FILE_DIRECTORY_FILE if directory else FILE_NON_DIRECTORY_FILE),
    }


@dataclass(frozen=True)
class OpenResult:
    status: int  # NtCreateFile return value
    handle: int
    information: int  # IO_STATUS_BLOCK.Information (create disposition)
    io_status: int = STATUS_SUCCESS  # IO_STATUS_BLOCK.u.Status, checked as well


class WindowsNative:
    """ctypes binding of the minimal handle APIs. Opens existing objects only."""

    def __init__(self, _platform_args=()):
        if platform_code(*_platform_args):
            raise PathHandleError(UNSUPPORTED_PLATFORM)
        if check_abi():
            raise PathHandleError(ABI_MISMATCH, 1)
        try:
            self._nt = ctypes.WinDLL("ntdll", use_last_error=True)
            self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._bind()
        except (OSError, AttributeError, ValueError):
            raise PathHandleError(ABI_MISMATCH, 2) from None

    def _bind(self):
        ptr, u32 = ctypes.c_void_p, ctypes.c_uint32
        nt, k32 = self._nt, self._k32
        nt.NtCreateFile.argtypes = [
            ctypes.POINTER(ptr),
            u32,
            ctypes.POINTER(OBJECT_ATTRIBUTES),
            ctypes.POINTER(IO_STATUS_BLOCK),
            ptr,
            u32,
            u32,
            u32,
            u32,
            ptr,
            u32,
        ]
        nt.NtCreateFile.restype = ctypes.c_int32
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, u32, u32, ptr, u32, u32, ptr]
        k32.CreateFileW.restype = ptr
        k32.GetFileInformationByHandleEx.argtypes = [ptr, ctypes.c_int, ptr, u32]
        k32.GetFileInformationByHandleEx.restype = ctypes.c_int32
        k32.ReadFile.argtypes = [ptr, ptr, u32, ctypes.POINTER(u32), ptr]
        k32.ReadFile.restype = ctypes.c_int32
        k32.GetFileType.argtypes = [ptr]
        k32.GetFileType.restype = u32
        k32.GetVolumeInformationByHandleW.argtypes = [ptr, ptr, u32, ptr, ptr, ptr, ptr, u32]
        k32.GetVolumeInformationByHandleW.restype = ctypes.c_int32
        k32.GetHandleInformation.argtypes = [ptr, ctypes.POINTER(u32)]
        k32.GetHandleInformation.restype = ctypes.c_int32
        k32.CloseHandle.argtypes = [ptr]
        k32.CloseHandle.restype = ctypes.c_int32

    def open_root(self, path):
        """Trusted-root bootstrap by absolute path; callers must pin identity."""
        handle = self._k32.CreateFileW(
            path,
            ROOT_ACCESS,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if not handle or handle == INVALID_HANDLE:
            raise PathHandleError(ROOT_OPEN_FAILED, ctypes.get_last_error())
        return handle

    def open_relative(self, parent, component, directory):
        request = build_open_request(directory)
        raw = component.encode("utf-16-le")
        buffer = ctypes.create_unicode_buffer(component)
        name = UNICODE_STRING(len(raw), len(raw), ctypes.addressof(buffer))
        attributes = OBJECT_ATTRIBUTES(
            ctypes.sizeof(OBJECT_ATTRIBUTES),
            parent,
            ctypes.pointer(name),
            request["object_attributes"],
            None,
            None,
        )
        out = ctypes.c_void_p()
        block = IO_STATUS_BLOCK()
        status = self._nt.NtCreateFile(
            ctypes.byref(out),
            request["access"],
            ctypes.byref(attributes),
            ctypes.byref(block),
            None,
            request["file_attributes"],
            request["share"],
            request["disposition"],
            request["options"],
            None,
            0,
        )
        return OpenResult(
            status & 0xFFFFFFFF,
            out.value or 0,
            block.Information,
            block.u.Status & 0xFFFFFFFF,
        )

    def query(self, handle, info_class, size):
        buffer = ctypes.create_string_buffer(size)
        if not self._k32.GetFileInformationByHandleEx(handle, info_class, buffer, size):
            raise PathHandleError(QUERY_FAILED, ctypes.get_last_error())
        return buffer.raw

    def file_type(self, handle):
        return self._k32.GetFileType(handle)

    def filesystem_name(self, handle):
        buffer = ctypes.create_unicode_buffer(261)
        ok = self._k32.GetVolumeInformationByHandleW(handle, None, 0, None, None, None, buffer, 261)
        if not ok:
            raise PathHandleError(QUERY_FAILED, ctypes.get_last_error())
        return buffer.value

    def is_inheritable(self, handle):
        flags = ctypes.c_uint32()
        if not self._k32.GetHandleInformation(handle, ctypes.byref(flags)):
            raise PathHandleError(QUERY_FAILED, ctypes.get_last_error())
        return bool(flags.value & HANDLE_FLAG_INHERIT)

    def read(self, handle, count):
        buffer = ctypes.create_string_buffer(count)
        done = ctypes.c_uint32()
        if not self._k32.ReadFile(handle, buffer, count, ctypes.byref(done), None):
            raise PathHandleError(READ_FAILED, ctypes.get_last_error())
        return buffer.raw[: done.value]

    def close(self, handle):
        return bool(self._k32.CloseHandle(handle))


class Deadline:
    """Cooperative deadline: checked between native calls, never preempts one."""

    def __init__(self, seconds=None, clock=time.monotonic):
        self._clock = clock
        self._limit = None if seconds is None else clock() + seconds

    def check(self):
        if self._limit is not None and self._clock() > self._limit:
            raise PathHandleError(DEADLINE)


def valid_handle(handle):
    return isinstance(handle, int) and not isinstance(handle, bool) and 0 < handle < INVALID_HANDLE


class HandleContext:
    """Owns every handle it adopts; closes each exactly once, newest first."""

    def __init__(
        self,
        native,
        deadline=None,
        max_file_bytes=DEFAULT_MAX_FILE_BYTES,
        chunk_bytes=DEFAULT_CHUNK_BYTES,
    ):
        self.native = native
        self.deadline = deadline or Deadline()
        self.max_file_bytes = max_file_bytes
        self.chunk_bytes = chunk_bytes
        self.close_calls = 0
        self.unknown_closes = 0
        self._records = []

    @property
    def open_count(self):
        return sum(1 for record in self._records if record[1] == "open")

    def adopt(self, handle):
        if not valid_handle(handle) or self.is_open(handle):
            raise PathHandleError(BAD_HANDLE)
        self._records.append([handle, "open"])
        return handle

    def is_open(self, handle):
        return any(r[0] == handle and r[1] == "open" for r in self._records)

    def close(self, handle):
        for record in reversed(self._records):
            if record[0] == handle and record[1] == "open":
                self._close_record(record)
                return
        raise PathHandleError(HANDLE_NOT_OWNED)

    def _close_record(self, record):
        # State leaves "open" before the call: a failed or unknown close is final.
        record[1] = "closing"
        self.close_calls += 1
        try:
            closed = self.native.close(record[0]) is True
        except Exception:
            closed = False
        if closed:
            record[1] = "closed"
            return
        record[1] = "unknown"
        self.unknown_closes += 1
        raise PathHandleError(CLOSE_FAILED, 1)

    def close_all(self):
        failures = 0
        for record in reversed(self._records):
            if record[1] == "open":
                try:
                    self._close_record(record)
                except PathHandleError:
                    failures += 1
        return failures

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        failures = self.close_all()
        if failures and exc_type is None:
            raise PathHandleError(CLOSE_FAILED, failures)
        return False


@dataclass(frozen=True)
class Identity:
    volume_serial: int
    file_id: bytes


@dataclass(frozen=True)
class HandleMetadata:
    is_directory: bool
    attributes: int
    link_count: int
    size: int
    delete_pending: bool
    identity: Identity


@dataclass(frozen=True)
class OpenedDirectory:
    handle: int
    metadata: HandleMetadata


@dataclass(frozen=True)
class ManifestEntry:
    component: str
    size: int
    sha256: str


@dataclass(frozen=True)
class FileResult:
    component: str
    data: bytes
    sha256: str
    size: int
    identity: Identity


def validate_component(component):
    """One clean component: no separator, ADS, dot, device or trailing dot/space form."""
    if not isinstance(component, str) or not 0 < len(component) <= MAX_COMPONENT_CHARS:
        raise PathHandleError(BAD_COMPONENT)
    if component in {".", ".."} or component[-1] in {".", " "}:
        raise PathHandleError(BAD_COMPONENT)
    if any(ord(ch) < 32 or ch in _FORBIDDEN_CHARS for ch in component):
        raise PathHandleError(BAD_COMPONENT)
    if component.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_DEVICES:
        raise PathHandleError(BAD_COMPONENT)
    try:
        component.encode("utf-16-le")
    except UnicodeEncodeError:
        raise PathHandleError(BAD_COMPONENT) from None
    return component


def _status_value(status):
    # A 32-bit NTSTATUS, signed or unsigned; anything wider or non-int is malformed.
    if not isinstance(status, int) or isinstance(status, bool):
        raise PathHandleError(BAD_METADATA)
    if not -0x80000000 <= status <= 0xFFFFFFFF:
        raise PathHandleError(BAD_METADATA)
    return status & 0xFFFFFFFF


def _unpack(native, handle, info_class, layout):
    raw = native.query(handle, info_class, layout.size)
    if raw is None:
        raise PathHandleError(QUERY_FAILED)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != layout.size:
        raise PathHandleError(BAD_METADATA, len(raw) if hasattr(raw, "__len__") else 0)
    return layout.unpack(bytes(raw))


def inspect_handle(ctx, handle, expect_directory):
    """Metadata of the handle itself; any unknown or unsupported value rejects."""
    native = ctx.native
    inheritable = native.is_inheritable(handle)
    if inheritable is None:
        raise PathHandleError(QUERY_FAILED)
    if inheritable is not False:
        raise PathHandleError(INHERITABLE if inheritable is True else BAD_METADATA)
    file_type = native.file_type(handle)
    if file_type != FILE_TYPE_DISK:
        raise PathHandleError(WRONG_TYPE, file_type if isinstance(file_type, int) else 0)
    filesystem = native.filesystem_name(handle)
    if not isinstance(filesystem, str):
        raise PathHandleError(QUERY_FAILED)
    if filesystem.upper() != "NTFS":
        raise PathHandleError(UNSUPPORTED_FS)
    _alloc, end_of_file, links, pending, directory = _unpack(
        native, handle, FILE_STANDARD_INFO, _STANDARD_LAYOUT
    )
    attributes, tag = _unpack(native, handle, FILE_ATTRIBUTE_TAG_INFO, _TAG_LAYOUT)
    volume, file_id = _unpack(native, handle, FILE_ID_INFO, _ID_LAYOUT)
    if attributes & ATTR_REPARSE_POINT or tag != 0:
        raise PathHandleError(REPARSE, tag)
    if attributes & ~ALLOWED_ATTRIBUTES:
        raise PathHandleError(UNSUPPORTED_ATTRIBUTES, attributes)
    if pending not in (0, 1) or directory not in (0, 1):
        raise PathHandleError(BAD_METADATA)
    if bool(attributes & ATTR_DIRECTORY) != bool(directory):
        raise PathHandleError(BAD_METADATA)
    if end_of_file < 0 or _alloc < 0 or file_id == bytes(16):
        raise PathHandleError(BAD_METADATA)
    if bool(directory) != expect_directory:
        raise PathHandleError(WRONG_TYPE)
    if pending:
        raise PathHandleError(DELETE_PENDING)
    if not directory and links != 1:
        raise PathHandleError(LINK_COUNT, links)
    return HandleMetadata(
        bool(directory), attributes, links, end_of_file, False, Identity(volume, file_id)
    )


def _adopt_open_result(ctx, result):
    if not isinstance(result, OpenResult):
        raise PathHandleError(BAD_METADATA)
    handle = result.handle
    adopted = valid_handle(handle)
    if adopted:
        ctx.adopt(handle)  # a returned handle is always closed exactly once
    # Strict completed synchronous I/O: both statuses must be STATUS_SUCCESS before
    # the handle is inspected or read.
    status = _status_value(result.status)
    if status == STATUS_PENDING:
        raise PathHandleError(PENDING_STATUS)
    if status != STATUS_SUCCESS:
        raise PathHandleError(NATIVE_STATUS, status)
    io_status = _status_value(result.io_status)
    if io_status == STATUS_PENDING:
        raise PathHandleError(PENDING_STATUS, 1)
    if io_status != STATUS_SUCCESS:
        raise PathHandleError(NATIVE_STATUS, io_status)
    if not adopted:
        raise PathHandleError(BAD_HANDLE)
    information = result.information
    if (
        not isinstance(information, int)
        or isinstance(information, bool)
        or information != FILE_OPENED
    ):
        raise PathHandleError(BAD_METADATA, 1)
    return handle


def _open_relative(ctx, parent_handle, component, directory):
    validate_component(component)
    ctx.deadline.check()
    if not ctx.is_open(parent_handle):
        raise PathHandleError(HANDLE_NOT_OWNED)
    result = ctx.native.open_relative(parent_handle, component, directory)
    return _adopt_open_result(ctx, result)


def open_trusted_root(ctx, path, expected_identity):
    """Open an owner-created root and pin it to an identity the owner supplied.

    No arbitrary path is enrolled: without ``expected_identity`` there is no API.
    Ancestors of ``path`` are not verified (documented limit).
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        raise PathHandleError(ROOT_UNTRUSTED)
    if not (
        isinstance(expected_identity, Identity)
        and isinstance(expected_identity.volume_serial, int)
        and isinstance(expected_identity.file_id, bytes)
        and len(expected_identity.file_id) == 16
    ):
        raise PathHandleError(ROOT_UNTRUSTED)
    ctx.deadline.check()
    handle = ctx.adopt(ctx.native.open_root(path))
    metadata = inspect_handle(ctx, handle, True)
    if metadata.identity != expected_identity:
        raise PathHandleError(IDENTITY_MISMATCH)
    return OpenedDirectory(handle, metadata)


def observe_identity_for_tests(ctx, path):
    """Test-only: learn an owned root's identity. This trusts ``path`` as given."""
    handle = ctx.adopt(ctx.native.open_root(path))
    identity = inspect_handle(ctx, handle, True).identity
    ctx.close(handle)
    return identity


def open_child_directory(ctx, parent, component):
    handle = _open_relative(ctx, parent.handle, component, True)
    metadata = inspect_handle(ctx, handle, True)
    if metadata.identity.volume_serial != parent.metadata.identity.volume_serial:
        raise PathHandleError(IDENTITY_MISMATCH)
    return OpenedDirectory(handle, metadata)


def _read_bounded(ctx, handle, expected_size):
    wanted = expected_size + 1
    chunks = []
    total = 0
    while total < wanted:
        ctx.deadline.check()
        count = min(wanted - total, ctx.chunk_bytes)
        part = ctx.native.read(handle, count)
        if not isinstance(part, (bytes, bytearray)) or len(part) > count:
            raise PathHandleError(READ_OVERRUN)
        if not part:
            break
        chunks.append(bytes(part))
        total += len(part)
    if total > expected_size:
        raise PathHandleError(READ_OVERRUN, expected_size)
    if total < expected_size:
        raise PathHandleError(SIZE_MISMATCH, total)
    return b"".join(chunks)


def read_file(ctx, parent, component, expected_size, expected_sha256):
    """Open one child relative to ``parent``, read it from that handle and verify it."""
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or not 0 <= expected_size <= ctx.max_file_bytes
    ):
        raise PathHandleError(LIMIT_EXCEEDED)
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_sha256)
    ):
        raise PathHandleError(BAD_MANIFEST)
    handle = _open_relative(ctx, parent.handle, component, False)
    before = inspect_handle(ctx, handle, False)
    if before.identity.volume_serial != parent.metadata.identity.volume_serial:
        raise PathHandleError(IDENTITY_MISMATCH)
    if before.size != expected_size:
        raise PathHandleError(SIZE_MISMATCH, before.size)
    data = _read_bounded(ctx, handle, expected_size)
    after = inspect_handle(ctx, handle, False)
    if after.identity != before.identity:
        raise PathHandleError(IDENTITY_MISMATCH)
    if after.link_count != before.link_count:
        raise PathHandleError(LINK_COUNT, after.link_count)
    if after.size != before.size or after.size != len(data):
        raise PathHandleError(SIZE_MISMATCH, after.size)
    if after != before:
        raise PathHandleError(BAD_METADATA)
    if inspect_handle(ctx, parent.handle, True).identity != parent.metadata.identity:
        raise PathHandleError(IDENTITY_MISMATCH)
    digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise PathHandleError(HASH_MISMATCH)
    ctx.close(handle)
    return FileResult(component, data, digest, len(data), before.identity)


def read_manifest(ctx, root, entries):
    """Two-file synthetic manifest; results are returned only after both pass."""
    entries = tuple(entries)
    if len(entries) != 2 or not all(isinstance(e, ManifestEntry) for e in entries):
        raise PathHandleError(BAD_MANIFEST)
    names = [validate_component(e.component).casefold() for e in entries]
    if len(set(names)) != len(names):
        raise PathHandleError(BAD_MANIFEST)
    results = [read_file(ctx, root, e.component, e.size, e.sha256) for e in entries]
    return tuple(results)


def native_capability():
    """0 when the real binding can be constructed here, else a numeric failure code."""
    try:
        WindowsNative()
    except PathHandleError as exc:
        return exc.code
    return 0


if __name__ == "__main__":  # pragma: no cover - never executed as a tool
    sys.exit("library module only")
