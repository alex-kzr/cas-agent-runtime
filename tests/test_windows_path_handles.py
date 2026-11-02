"""WP-01 handle-reader tests.

Two distinct groups:
* Fake-boundary cases (``FakeCase`` subclasses): an in-memory fake native boundary. Their
  metadata is invented and is NEVER native evidence.
* ``NativeOrdinaryTests`` (``NATIVE = True``): actual Windows calls on ordinary files and
  directories this test creates in its own Temp root. No link, junction or reparse
  fixture is created or attempted. The first unexpected native refusal blocks the rest, and
  so does the first unexpected fixture/setup/test/cleanup exception (finite projection only).
* ``NativeDiagnosticTests`` / ``FixtureHardeningTests``: injected regressions for that
  diagnostic machinery. They use fake filesystem, environment, name and checkpoint-sink
  seams and never create a real file or make a native call.
"""

import dataclasses
import hashlib
import importlib.util
import io
import itertools
import json
import ntpath
import os
import pathlib
import re
import secrets
import struct
import types
import unittest
from unittest import mock

from agent_runtime.tasks import windows_path_handles as wph

DATA_A = b"alpha-invented-bytes"
DATA_B = b"beta-invented-bytes!!"
PASS = object()
_IDS = itertools.count(1)

NATIVE_CASE_NAMES = (
    "test_native_capability",
    "test_native_root_and_metadata",
    "test_native_relative_read_exact",
    "test_native_mismatch_rejection",
    "test_native_sharing_violation",
    "test_native_handle_close",
)
NATIVE_LEDGER = {"blocked": None, "failure": None}
CLEANUP_LEDGER = {
    "created": 0,
    "removed": 0,
    "failed": 0,  # unlink/rmdir raised; split into absent + present + unknown below
    "absent": 0,  # lstat said FileNotFoundError after the failed removal
    "present": 0,  # lstat succeeded after the failed removal
    "unknown": 0,  # lstat itself failed (PermissionError, other OSError): NOT absence
    "unreported": 0,  # owned entries beyond MAX_OWNED_RECORDS (counted, not listed)
}
OWNED_RECORDS = []
MAX_OWNED_RECORDS = 32
MAX_PATH_CHARS = 260
# Root planning: exactly the CURRENT process's explicit TEMP value, one generated child.
TEMP_VARIABLE = "TEMP"
ROOT_MODE = 0o700
MAX_PARENT_CHARS = 200
NAME_PATTERN = re.compile(r"[0-9a-f]{16}")
PLAN_REFUSALS = frozenset(
    {"environment", "missing", "type", "empty", "length", "syntax", "relative", "name"}
)
# Bounded checkpoint evidence (finite phases, counters and reasons).
CHECKPOINT_VERSION = 1
MAX_CHECKPOINTS = 512
MAX_COUNT = 9999
CHECKPOINT_PHASES = frozenset(
    {
        "pre_dispatch", "root_intent", "root_owned", "child_intent", "child_owned",
        "cleanup_begin", "cleanup_entry", "cleanup_done",
    }
)  # fmt: skip
CHECKPOINT_REASONS = frozenset(
    {
        "no_sink", "limit", "pre_existing", "claim_failed", "write_failed", "replace_failed",
        "too_large", "sink_failed", "latched",
    }
)  # fmt: skip
CHECKPOINT_LEDGER = {"saved": 0, "failed": 0, "reason": None, "last_phase": None}
MAX_LINE = 100000
OWNED_PREFIX = "cas-wp01-"
FIXTURE_NAMES = frozenset({"alpha.txt", "beta.bin", "sub"})
STAGES = frozenset({"setup", "mkdtemp", "create", "test", "cleanup"})
SAFE_TYPE_NAMES = frozenset(
    {
        "FileNotFoundError", "FileExistsError", "PermissionError", "NotADirectoryError",
        "IsADirectoryError", "OSError", "AssertionError", "PathHandleError", "TypeError",
        "ValueError", "AttributeError", "KeyError", "IndexError", "RuntimeError",
        "ImportError", "UnicodeError", "OverflowError", "MemoryError",
    }
)  # fmt: skip
KNOWN_OPERATIONS = frozenset(
    set(NATIVE_CASE_NAMES)
    | {
        "mkdtemp", "make_file", "make_dir", "cleanup_unlink", "cleanup_rmdir", "cleanup_lstat",
        "checkpoint", "sharing_open", "reopen_check", "WindowsNative", "observe_identity_for_tests",
        "open_trusted_root", "open_child_directory", "read_manifest", "read_file",
    }
)  # fmt: skip
# Only the three WP-01 CAS files may appear as a failure location (file label + line).
LOCATION_SUFFIXES = (
    ("agent_runtime/tasks/windows_path_handles.py", "windows_path_handles.py"),
    ("agent-runtime/tests/test_windows_path_handles.py", "test_windows_path_handles.py"),
    ("tools/run_path_policy_checks.py", "run_path_policy_checks.py"),
)
# Documented NTSTATUS values the negative controls may accept (not discovered natively).
MISSING_STATUSES = frozenset({0xC0000034})  # STATUS_OBJECT_NAME_NOT_FOUND
WRONG_TYPE_STATUSES = frozenset({0xC00000BA})  # STATUS_FILE_IS_A_DIRECTORY
BLOCKING_CODES = {
    wph.UNSUPPORTED_PLATFORM,
    wph.ABI_MISMATCH,
    wph.QUERY_FAILED,
    wph.READ_FAILED,
    wph.ROOT_OPEN_FAILED,
}
DENIAL_STATUSES = {0xC0000022, 0xC0000002, 0xC00000BB, 0xC000000D, 0xC0000008}
API_BY_CODE = {
    wph.UNSUPPORTED_PLATFORM: "platform",
    wph.ABI_MISMATCH: "ntdll/kernel32 binding",
    wph.NATIVE_STATUS: "NtCreateFile",
    wph.QUERY_FAILED: "query/handle-information API",
    wph.READ_FAILED: "ReadFile",
    wph.CLOSE_FAILED: "CloseHandle",
    wph.ROOT_OPEN_FAILED: "CreateFileW",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


# Immutable defaults for FakeCase.read (evaluated once, not per call).
SIZE_A = len(DATA_A)
DIGEST_A = sha(DATA_A)


class Node:
    def __init__(self, directory=False, data=b""):
        self.directory = directory
        self.data = data
        self.attributes = wph.ATTR_DIRECTORY if directory else wph.ATTR_ARCHIVE
        self.tag = 0
        self.links = 1
        self.pending = 0
        self.volume = 0xABCD
        self.file_id = next(_IDS).to_bytes(16, "little")
        self.size = None
        self.dir_flag = None


class FakeNative:
    """Invented metadata only; records every call so tests can prove what happened."""

    def __init__(self):
        self.root = Node(True)
        self.children = {}
        self.handles = {}
        self.offsets = {}
        self._next = 0x100
        self.calls = []
        self.read_requests = []
        self.close_log = []
        self.fs = "NTFS"
        self.ftype = 1
        self.inheritable = False
        self.close_fail = set()
        self.close_raise = set()
        self.open_hook = None
        self.query_hook = None
        self.read_hook = None
        self.read_override = None

    @property
    def reads(self):
        return len(self.read_requests)

    def alloc(self, node):
        handle = self._next
        self._next += 4
        self.handles[handle] = node
        self.offsets[handle] = 0
        return handle

    def open_root(self, path):
        self.calls.append(("open_root",))
        return self.alloc(self.root)

    def open_relative(self, parent, component, directory):
        self.calls.append(("open_relative", parent, component, directory))
        if self.open_hook:
            result = self.open_hook(self, parent, component, directory)
            if result is not PASS:
                return result
        node = self.children.get(component.lower())
        if node is None:
            return wph.OpenResult(0xC0000034, 0, 0)
        if node.directory != directory:
            return wph.OpenResult(0xC0000103 if directory else 0xC00000BA, 0, 0)
        return wph.OpenResult(0, self.alloc(node), 1)

    def query(self, handle, info_class, size):
        if self.query_hook:
            result = self.query_hook(handle, info_class, size)
            if result is not PASS:
                return result
        node = self.handles[handle]
        if info_class == wph.FILE_STANDARD_INFO:
            length = len(node.data) if node.size is None else node.size
            flag = int(node.directory) if node.dir_flag is None else node.dir_flag
            return struct.pack("<qqIBB2x", length, length, node.links, node.pending, flag)
        if info_class == wph.FILE_ATTRIBUTE_TAG_INFO:
            return struct.pack("<II", node.attributes, node.tag)
        return struct.pack("<Q16s", node.volume, node.file_id)

    def file_type(self, handle):
        return self.ftype

    def filesystem_name(self, handle):
        return self.fs

    def is_inheritable(self, handle):
        return self.inheritable

    def read(self, handle, count):
        self.read_requests.append(count)
        if self.read_override:
            return self.read_override(handle, count)
        node = self.handles[handle]
        offset = self.offsets[handle]
        part = node.data[offset : offset + count]
        self.offsets[handle] += len(part)
        if self.read_hook:
            self.read_hook(self, handle)
        return part

    def close(self, handle):
        self.close_log.append(handle)
        if handle in self.close_raise:
            raise OSError("invented close failure")
        return handle not in self.close_fail


class FakeCase(unittest.TestCase):
    def setUp(self):
        self.fresh()

    def fresh(self, **ctx_kwargs):
        self.native = FakeNative()
        self.native.children["alpha.txt"] = Node(data=DATA_A)
        self.native.children["beta.bin"] = Node(data=DATA_B)
        self.native.children["sub"] = Node(True)
        self.ctx = wph.HandleContext(self.native, **ctx_kwargs)
        self.addCleanup(lambda ctx=self.ctx: ctx.close_all())
        root = self.native.root
        self.identity = wph.Identity(root.volume, root.file_id)
        self.entries = (
            wph.ManifestEntry("alpha.txt", len(DATA_A), sha(DATA_A)),
            wph.ManifestEntry("beta.bin", len(DATA_B), sha(DATA_B)),
        )

    def root(self):
        return wph.open_trusted_root(self.ctx, "invented-root", self.identity)

    def read(self, root, name="alpha.txt", size=SIZE_A, digest=DIGEST_A):
        return wph.read_file(self.ctx, root, name, size, digest)

    def rejected(self, code, func, *args, detail=None):
        with self.assertRaises(wph.PathHandleError) as caught:
            func(*args)
        self.assertEqual(caught.exception.code, code)
        if detail is not None:
            self.assertEqual(caught.exception.detail, detail)
        return caught.exception

    def rejected_before_read(self, code, mutate, detail=None):
        self.fresh()
        mutate(self.native.children["alpha.txt"])
        root = self.root()
        self.rejected(code, self.read, root, detail=detail)
        self.assertEqual(self.native.reads, 0)


class PlatformAndAbiTests(FakeCase):
    def test_abi_layout_matches_declared_x64_contract(self):
        if wph.ctypes.sizeof(wph.ctypes.c_void_p) == 8:
            self.assertEqual(wph.check_abi(), 0)
        else:
            self.assertGreater(wph.check_abi(), 0)

    def test_platform_gate(self):
        self.assertEqual(wph.platform_code("nt", 8, "win-amd64"), 0)
        for args in (("posix", 8, "win-amd64"), ("nt", 4, "win32"), ("nt", 8, "win-arm64")):
            self.assertEqual(wph.platform_code(*args), wph.UNSUPPORTED_PLATFORM)
            self.rejected(wph.UNSUPPORTED_PLATFORM, wph.WindowsNative, args)

    def test_open_request_is_relative_nonfollow_and_read_sharing_only(self):
        for directory in (False, True):
            request = wph.build_open_request(directory)
            self.assertEqual(request["share"], wph.FILE_SHARE_READ)
            self.assertEqual(request["disposition"], wph.FILE_OPEN)
            self.assertEqual(request["object_attributes"] & wph.OBJ_INHERIT, 0)
            self.assertTrue(request["object_attributes"] & wph.OBJ_DONT_REPARSE)
            self.assertTrue(request["options"] & wph.FILE_OPEN_REPARSE_POINT)
            self.assertTrue(request["options"] & wph.FILE_SYNCHRONOUS_IO_NONALERT)
            self.assertEqual(request["options"] & wph.FILE_DIRECTORY_FILE, int(directory))
            self.assertEqual(bool(request["options"] & wph.FILE_NON_DIRECTORY_FILE), not directory)
        self.assertEqual(wph.build_open_request(False)["access"], 0x1 | 0x80 | 0x100000)

    def test_native_case_names_are_the_planned_set(self):
        found = tuple(sorted(n for n in dir(NativeOrdinaryTests) if n.startswith("test_native_")))
        self.assertEqual(found, tuple(sorted(NATIVE_CASE_NAMES)))


class ComponentTests(FakeCase):
    def test_clean_components_accepted(self):
        for name in ("alpha.txt", "a b", "naïve.txt", "name.with.dots", ".hidden"):
            self.assertEqual(wph.validate_component(name), name)

    def test_dirty_components_rejected_before_any_native_call(self):
        root = self.root()
        before = len(self.native.calls)
        dirty = [
            "", ".", "..", "a/b", "a\\b", "a:b", "a:ds:$DATA", "C:", "con", "NUL.txt",
            "com1", "Lpt9.log", "COM\u00b9", "a.", "a ", "a*", "a?", "a\x00b", "a\nb",
            "\\\\?\\x", "x" * 256, b"alpha.txt", None, "a\ud800",
        ]  # fmt: skip
        for name in dirty:
            with self.subTest(name=repr(name)[:20]):
                self.rejected(wph.BAD_COMPONENT, self.read, root, name)
                self.rejected(wph.BAD_COMPONENT, wph.open_child_directory, self.ctx, root, name)
        self.assertEqual(len(self.native.calls), before)


class HappyPathTests(FakeCase):
    def test_manifest_reads_relative_to_retained_parent_and_closes_in_order(self):
        with self.ctx:
            root = self.root()
            results = wph.read_manifest(self.ctx, root, self.entries)
        self.assertEqual([r.data for r in results], [DATA_A, DATA_B])
        self.assertEqual([r.sha256 for r in results], [sha(DATA_A), sha(DATA_B)])
        opens = [c for c in self.native.calls if c[0] == "open_relative"]
        self.assertEqual(
            [(c[1], c[2], c[3]) for c in opens],
            [(root.handle, "alpha.txt", False), (root.handle, "beta.bin", False)],
        )
        self.assertEqual(self.native.calls.count(("open_root",)), 1)
        self.assertEqual(self.native.read_requests[0], len(DATA_A) + 1)
        self.assertEqual(self.native.read_requests[2], len(DATA_B) + 1)
        self.assertEqual(self.native.close_log[-1], root.handle)
        self.assertEqual(len(self.native.close_log), 3)
        self.assertEqual(len(set(self.native.close_log)), 3)
        self.assertEqual((self.ctx.open_count, self.ctx.close_calls), (0, 3))

    def test_close_order_is_reverse_of_opening(self):
        with self.ctx:
            root = self.root()
            sub = wph.open_child_directory(self.ctx, root, "sub")
        self.assertEqual(self.native.close_log, [sub.handle, root.handle])

    def test_result_is_immutable(self):
        with self.ctx:
            results = wph.read_manifest(self.ctx, self.root(), self.entries)
        self.assertIsInstance(results, tuple)
        self.assertIs(type(results[0].data), bytes)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            results[0].data = b""
        self.native.children["alpha.txt"].data = b"changed"
        self.assertEqual(results[0].data, DATA_A)


class RejectionBeforeReadTests(FakeCase):
    def test_metadata_rejections(self):
        cases = {
            "reparse attribute": (wph.REPARSE, lambda n: setattr(n, "attributes", n.attributes | 0x400)),
            "reparse tag only": (wph.REPARSE, lambda n: setattr(n, "tag", 0xA000000C)),
            "unknown attribute": (wph.UNSUPPORTED_ATTRIBUTES, lambda n: setattr(n, "attributes", n.attributes | 0x80000000)),
            "directory flag mismatch": (wph.BAD_METADATA, lambda n: setattr(n, "dir_flag", 1)),
            "bad boolean byte": (wph.BAD_METADATA, lambda n: setattr(n, "pending", 2)),
            "delete pending": (wph.DELETE_PENDING, lambda n: setattr(n, "pending", 1)),
            "hard link": (wph.LINK_COUNT, lambda n: setattr(n, "links", 2)),
            "size differs": (wph.SIZE_MISMATCH, lambda n: setattr(n, "size", len(DATA_A) - 1)),
            "negative size": (wph.BAD_METADATA, lambda n: setattr(n, "size", -1)),
            "zero file id": (wph.BAD_METADATA, lambda n: setattr(n, "file_id", bytes(16))),
            "other volume": (wph.IDENTITY_MISMATCH, lambda n: setattr(n, "volume", 1)),
        }  # fmt: skip
        for label, (code, mutate) in cases.items():
            with self.subTest(label):
                self.rejected_before_read(code, mutate)

    def test_directory_handle_for_file_request_is_wrong_type(self):
        self.fresh()
        root = self.root()
        self.native.open_hook = lambda n, p, c, d: wph.OpenResult(0, n.alloc(n.root), 1)
        self.rejected(wph.WRONG_TYPE, self.read, root)
        self.assertEqual(self.native.reads, 0)

    def test_native_type_refusal_is_a_status_not_a_fallback(self):
        self.fresh()
        root = self.root()
        self.rejected(wph.NATIVE_STATUS, self.read, root, "sub", 0, sha(b""), detail=0xC00000BA)
        self.assertEqual(self.native.reads, 0)

    def test_root_must_be_a_directory_and_not_reparse(self):
        for label, mutate, code in (
            ("reparse", lambda n: setattr(n, "attributes", n.attributes | 0x400), wph.REPARSE),
            ("file", lambda n: (setattr(n, "directory", False), setattr(n, "attributes", wph.ATTR_ARCHIVE)), wph.WRONG_TYPE),
        ):  # fmt: skip
            with self.subTest(label):
                self.fresh()
                mutate(self.native.root)
                self.rejected(code, self.root)
                self.assertEqual(self.native.calls, [("open_root",)])

    def test_handle_environment_rejections(self):
        cases = (
            ("fat", lambda n: setattr(n, "fs", "FAT32"), wph.UNSUPPORTED_FS),
            ("refs", lambda n: setattr(n, "fs", "ReFS"), wph.UNSUPPORTED_FS),
            ("pipe", lambda n: setattr(n, "ftype", 3), wph.WRONG_TYPE),
            ("inheritable", lambda n: setattr(n, "inheritable", True), wph.INHERITABLE),
            ("unknown inherit", lambda n: setattr(n, "inheritable", None), wph.QUERY_FAILED),
            ("weird inherit", lambda n: setattr(n, "inheritable", 0), wph.BAD_METADATA),
        )
        for label, mutate, code in cases:
            with self.subTest(label):
                self.fresh()
                mutate(self.native)
                self.rejected(code, self.root)

    def test_malformed_or_short_metadata_never_authorizes_a_read(self):
        bad_values = {"short": b"\x00" * 5, "long": b"\x00" * 64, "text": "xx", "none": None}
        for info_class in (wph.FILE_STANDARD_INFO, wph.FILE_ATTRIBUTE_TAG_INFO, wph.FILE_ID_INFO):
            for label, value in bad_values.items():
                with self.subTest(info_class=info_class, kind=label):
                    self.fresh()
                    root = self.root()
                    self.native.query_hook = lambda h, c, s, k=info_class, v=value: (
                        v if c == k else PASS
                    )
                    code = wph.QUERY_FAILED if value is None else wph.BAD_METADATA
                    self.rejected(code, self.read, root)
                    self.assertEqual(self.native.reads, 0)

    def test_native_query_error_propagates_and_blocks_read(self):
        root = self.root()

        def failing(handle, info_class, size):
            raise wph.PathHandleError(wph.QUERY_FAILED, 5)

        self.native.query_hook = failing
        self.rejected(wph.QUERY_FAILED, self.read, root, detail=5)
        self.assertEqual(self.native.reads, 0)

    def test_invalid_limits_and_manifest_digest_rejected_without_open(self):
        root = self.root()
        before = len(self.native.calls)
        for size in (-1, True, "3", wph.DEFAULT_MAX_FILE_BYTES + 1):
            self.rejected(wph.LIMIT_EXCEEDED, self.read, root, "alpha.txt", size, sha(DATA_A))
        for digest in (sha(DATA_A).upper(), "abc", None):
            self.rejected(wph.BAD_MANIFEST, self.read, root, "alpha.txt", 3, digest)
        self.assertEqual(len(self.native.calls), before)


class NativeStatusTests(FakeCase):
    def open_with(self, result):
        root = self.root()
        self.native.open_hook = lambda n, p, c, d: result(n)
        return root

    def test_pending_is_not_success_and_returned_handle_is_closed_once(self):
        handles = []

        def pending(native):
            handles.append(native.alloc(native.children["alpha.txt"]))
            return wph.OpenResult(0x103, handles[0], 0)

        root = self.open_with(pending)
        self.rejected(wph.PENDING_STATUS, self.read, root)
        self.assertEqual(self.native.reads, 0)
        self.ctx.close_all()
        self.assertEqual(self.native.close_log.count(handles[0]), 1)

    def test_unexpected_and_sharing_statuses_fail_once_without_downgrade(self):
        for status, expected in ((-1073741790, 0xC0000022), (0xC0000043, 0xC0000043)):
            with self.subTest(hex(expected)):
                self.fresh()
                root = self.open_with(lambda n, s=status: wph.OpenResult(s, 0, 0))
                self.rejected(wph.NATIVE_STATUS, self.read, root, detail=expected)
                opens = [c for c in self.native.calls if c[0] == "open_relative"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(self.native.reads, 0)

    def test_success_with_unusable_handle_or_information_is_rejected(self):
        cases = (
            (wph.OpenResult(0, 0, 1), wph.BAD_HANDLE),
            (wph.OpenResult(0, 0xFFFFFFFFFFFFFFFF, 1), wph.BAD_HANDLE),
            (wph.OpenResult(0, True, 1), wph.BAD_HANDLE),
            (wph.OpenResult(0, "x", 1), wph.BAD_HANDLE),
            (("tuple",), wph.BAD_METADATA),
        )
        for value, code in cases:
            with self.subTest(code=code):
                self.fresh()
                root = self.open_with(lambda n, v=value: v)
                self.rejected(code, self.read, root)
                self.assertEqual(self.native.reads, 0)
        self.fresh()
        root = self.open_with(lambda n: wph.OpenResult(0, n.alloc(n.children["alpha.txt"]), 2))
        self.rejected(wph.BAD_METADATA, self.read, root)

    def assert_unauthorized(self, result, code, detail=None):
        """A result that must never authorize inspection or reads; handle closed once."""
        self.fresh()
        root = self.root()
        returned = []
        queried = []

        def hook(native, parent, component, directory):
            handle = native.alloc(native.children["alpha.txt"])
            returned.append(handle)
            return dataclasses.replace(result, handle=handle)

        self.native.open_hook = hook
        self.native.query_hook = lambda h, c, s: (queried.append(h), PASS)[1]
        self.rejected(code, self.read, root, detail=detail)
        self.assertEqual(self.native.reads, 0)
        self.assertNotIn(returned[0], queried)
        self.ctx.close_all()
        self.assertEqual(self.native.close_log.count(returned[0]), 1)
        self.assertEqual(self.ctx.open_count, 0)

    def test_success_with_pending_or_error_io_status_never_authorizes_a_read(self):
        cases = (
            (0x103, wph.PENDING_STATUS, 1),
            (0xC0000022, wph.NATIVE_STATUS, 0xC0000022),
            (-1073741790, wph.NATIVE_STATUS, 0xC0000022),
            (0x40000000, wph.NATIVE_STATUS, 0x40000000),
            (0x80000005, wph.NATIVE_STATUS, 0x80000005),
            (1, wph.NATIVE_STATUS, 1),
        )
        for io_status, code, detail in cases:
            with self.subTest(hex(io_status & 0xFFFFFFFF)):
                self.assert_unauthorized(wph.OpenResult(0, 0, 1, io_status), code, detail)

    def test_unexpected_return_status_with_handle_never_authorizes_a_read(self):
        cases = (
            (0x103, wph.PENDING_STATUS),
            (0xC0000043, wph.NATIVE_STATUS),
            (0x40000000, wph.NATIVE_STATUS),
            (0x80000005, wph.NATIVE_STATUS),
            (1, wph.NATIVE_STATUS),
        )
        for status, code in cases:
            with self.subTest(hex(status)):
                self.assert_unauthorized(wph.OpenResult(status, 0, 1, 0), code)

    def test_malformed_statuses_and_disposition_never_authorize_a_read(self):
        bad = (None, True, False, "0", b"\x00", 1.0, 1 << 32, 1 << 40, -(1 << 31) - 1)
        for value in bad:
            with self.subTest(status=repr(value)):
                self.assert_unauthorized(wph.OpenResult(value, 0, 1, 0), wph.BAD_METADATA)
            with self.subTest(io_status=repr(value)):
                self.assert_unauthorized(wph.OpenResult(0, 0, 1, value), wph.BAD_METADATA)
        for value in (None, True, "1", 1.0, 0, 2, 3, -1, 1 << 40):
            with self.subTest(information=repr(value)):
                self.assert_unauthorized(wph.OpenResult(0, 0, value, 0), wph.BAD_METADATA, 1)

    def test_binding_surfaces_the_actual_io_status_block(self):
        class FakeNt:
            def __init__(self, status, io_status, information):
                self.values = (status, io_status, information)

            def NtCreateFile(self, out, access, attributes, block, *rest):  # noqa: N802
                status, io_status, information = self.values
                out._obj.value = 0x500
                block._obj.u.Status = io_status
                block._obj.Information = information
                return status

        for status, io_status, information in (
            (0, 0x103, 1),
            (0, -1073741790, 1),
            (-1073741790, 0, 0),
            (0, 0, 1),
        ):
            with self.subTest(hex(io_status & 0xFFFFFFFF), status=hex(status & 0xFFFFFFFF)):
                native = object.__new__(wph.WindowsNative)
                native._nt = FakeNt(status, io_status, information)
                result = native.open_relative(0x400, "alpha.txt", False)
                self.assertEqual(
                    (result.status, result.handle, result.information, result.io_status),
                    (status & 0xFFFFFFFF, 0x500, information, io_status & 0xFFFFFFFF),
                )

    def test_duplicate_live_handle_is_rejected(self):
        root = self.open_with(lambda n: wph.OpenResult(0, 0x100, 1))
        self.rejected(wph.BAD_HANDLE, self.read, root)

    def test_no_path_based_fallback_after_relative_failure(self):
        root = self.open_with(lambda n: wph.OpenResult(0xC0000022, 0, 0))
        boom = AssertionError("path-based fallback attempted")
        with (
            mock.patch("builtins.open", side_effect=boom),
            mock.patch("io.open", side_effect=boom),
            mock.patch("os.open", side_effect=boom),
            mock.patch.object(pathlib.Path, "open", side_effect=boom),
            mock.patch.object(pathlib.Path, "read_bytes", side_effect=boom),
        ):
            self.rejected(wph.NATIVE_STATUS, self.read, root)
        self.assertEqual({c[0] for c in self.native.calls}, {"open_root", "open_relative"})
        self.assertEqual(self.native.reads, 0)

    def test_parent_must_be_an_owned_open_handle(self):
        root = self.root()
        self.ctx.close(root.handle)
        before = len(self.native.calls)
        self.rejected(wph.HANDLE_NOT_OWNED, self.read, root)
        self.rejected(wph.HANDLE_NOT_OWNED, self.ctx.close, root.handle)
        self.assertEqual(len(self.native.calls), before)
        self.assertEqual(self.native.close_log.count(root.handle), 1)


class ReadVerificationTests(FakeCase):
    def test_wrong_bytes_with_correct_size_fail_hash(self):
        self.native.children["alpha.txt"].data = b"X" * len(DATA_A)
        self.rejected(wph.HASH_MISMATCH, self.read, self.root())

    def test_growth_is_bounded_to_expected_size_plus_one(self):
        node = self.native.children["alpha.txt"]
        node.data = DATA_A + b"-grown-beyond-expected"
        node.size = len(DATA_A)
        self.rejected(wph.READ_OVERRUN, self.read, self.root())
        self.assertEqual(self.native.read_requests, [len(DATA_A) + 1])

    def test_short_read_and_native_overreturn(self):
        node = self.native.children["alpha.txt"]
        node.size = len(DATA_A)
        node.data = DATA_A[:-3]
        self.rejected(wph.SIZE_MISMATCH, self.read, self.root())
        self.fresh()
        root = self.root()
        self.native.read_override = lambda h, count: b"y" * (count + 1)
        self.rejected(wph.READ_OVERRUN, self.read, root)

    def test_changes_seen_on_the_same_handle_after_read(self):
        cases = {
            "identity": (wph.IDENTITY_MISMATCH, lambda n, h: setattr(n.handles[h], "file_id", b"\x07" * 16)),
            "links": (wph.LINK_COUNT, lambda n, h: setattr(n.handles[h], "links", 2)),
            "size": (wph.SIZE_MISMATCH, lambda n, h: setattr(n.handles[h], "size", 99)),
            "attributes": (wph.BAD_METADATA, lambda n, h: setattr(n.handles[h], "attributes", wph.ATTR_ARCHIVE | wph.ATTR_HIDDEN)),
        }  # fmt: skip
        for label, (code, hook) in cases.items():
            with self.subTest(label):
                self.fresh()
                root = self.root()
                self.native.read_hook = hook
                self.rejected(code, self.read, root)

    def test_root_identity_change_during_read_is_rejected(self):
        root = self.root()
        self.native.read_hook = lambda n, h: setattr(n.root, "file_id", b"\x09" * 16)
        self.rejected(wph.IDENTITY_MISMATCH, self.read, root)

    def test_wrong_root_identity_blocks_every_child_open(self):
        self.identity = wph.Identity(self.identity.volume_serial, b"\x05" * 16)
        self.rejected(wph.IDENTITY_MISMATCH, self.root)
        self.assertEqual(self.native.calls, [("open_root",)])

    def test_root_requires_an_expected_identity(self):
        for identity in ("notidentity", None, wph.Identity(1, b"short")):
            self.rejected(wph.ROOT_UNTRUSTED, wph.open_trusted_root, self.ctx, "p", identity)
        self.rejected(wph.ROOT_UNTRUSTED, wph.open_trusted_root, self.ctx, "", self.identity)
        self.assertEqual(self.native.calls, [])

    def test_cooperative_deadline(self):
        class Clock:
            now = 0

            def __call__(self):
                return self.now

        clock = Clock()
        self.fresh(deadline=wph.Deadline(10, clock))
        root = self.root()
        clock.now = 11
        self.rejected(wph.DEADLINE, self.read, root)
        self.assertEqual([c[0] for c in self.native.calls].count("open_relative"), 0)
        second = Clock()
        self.fresh(deadline=wph.Deadline(10, second), chunk_bytes=4)
        root = self.root()
        self.native.read_hook = lambda n, h: setattr(second, "now", 11)
        self.rejected(wph.DEADLINE, self.read, root)
        self.assertEqual(self.native.reads, 1)


class CloseTests(FakeCase):
    def test_close_failure_is_unknown_and_never_retried(self):
        for mode in ("close_fail", "close_raise"):
            with self.subTest(mode):
                self.fresh()
                with self.assertRaises(wph.PathHandleError) as caught:
                    with self.ctx:
                        root = self.root()
                        getattr(self.native, mode).add(root.handle)
                self.assertEqual(caught.exception.code, wph.CLOSE_FAILED)
                self.assertEqual(self.native.close_log.count(root.handle), 1)
                self.assertEqual((self.ctx.unknown_closes, self.ctx.open_count), (1, 0))
                self.rejected(wph.HANDLE_NOT_OWNED, self.ctx.close, root.handle)
                self.assertEqual(self.native.close_log.count(root.handle), 1)

    def test_other_handles_still_close_after_one_failure(self):
        with self.assertRaises(wph.PathHandleError):
            with self.ctx:
                root = self.root()
                sub = wph.open_child_directory(self.ctx, root, "sub")
                self.native.close_fail.add(sub.handle)
        self.assertEqual(self.native.close_log, [sub.handle, root.handle])

    def test_original_error_is_not_masked_by_close_failure(self):
        with self.assertRaises(RuntimeError):
            with self.ctx:
                self.native.close_fail.add(self.root().handle)
                raise RuntimeError("original")

    def test_file_close_failure_yields_no_result(self):
        root = self.root()
        self.native.close_fail.add(root.handle + 4)
        self.rejected(wph.CLOSE_FAILED, self.read, root)
        self.ctx.close_all()
        self.assertEqual(self.native.close_log.count(root.handle + 4), 1)


class ManifestTests(FakeCase):
    def test_second_file_failure_returns_no_partial_result(self):
        self.native.children["beta.bin"].data = b"Z" * len(DATA_B)
        root = self.root()
        self.rejected(wph.HASH_MISMATCH, wph.read_manifest, self.ctx, root, self.entries)
        self.assertIn(root.handle + 4, self.native.close_log)

    def test_missing_second_file_returns_no_partial_result(self):
        del self.native.children["beta.bin"]
        self.rejected(
            wph.NATIVE_STATUS, wph.read_manifest, self.ctx, self.root(), self.entries,
            detail=0xC0000034,
        )  # fmt: skip

    def test_manifest_shape_is_exactly_two_distinct_entries(self):
        root = self.root()
        before = len(self.native.calls)
        first, second = self.entries
        dup = wph.ManifestEntry("ALPHA.TXT", second.size, second.sha256)
        for entries in ((first,), (first, second, first), (first, "x"), (first, dup)):
            self.rejected(wph.BAD_MANIFEST, wph.read_manifest, self.ctx, root, entries)
        self.assertEqual(len(self.native.calls), before)


class SafeErrorTests(FakeCase):
    def test_errors_never_carry_paths_names_or_contents(self):
        secret_root, secret_name, secret_data = (
            "C:\\invented-secret-root",
            "secret-name.txt",
            b"secret-content-bytes",
        )
        self.native.children[secret_name] = Node(data=secret_data)
        root = wph.open_trusted_root(self.ctx, secret_root, self.identity)
        errors = [
            self.rejected(wph.HASH_MISMATCH, wph.read_file, self.ctx, root, secret_name, len(secret_data), sha(b"other")),
            self.rejected(wph.SIZE_MISMATCH, wph.read_file, self.ctx, root, secret_name, 1, sha(b"x")),
            self.rejected(wph.NATIVE_STATUS, wph.read_file, self.ctx, root, "missing-" + secret_name, 1, sha(b"x")),
            self.rejected(wph.BAD_COMPONENT, wph.read_file, self.ctx, root, "bad\\" + secret_name, 1, sha(b"x")),
            self.rejected(wph.ROOT_UNTRUSTED, wph.open_trusted_root, self.ctx, secret_root, "x"),
        ]  # fmt: skip
        for error in errors:
            text = f"{error!s}|{error!r}|{error.args}|{vars(error)}"
            for marker in ("invented-secret", "secret-name", "secret-content"):
                self.assertNotIn(marker, text)
            self.assertTrue(all(isinstance(v, int) for v in (error.code, error.detail)))


def _finite_int(value):
    """A real 32-bit-range int, else None (bool, str, float, wider ints are rejected)."""
    if isinstance(value, int) and not isinstance(value, bool):
        if -(1 << 31) <= value <= 0xFFFFFFFF:
            return value
    return None


def _attr_int(obj, name):
    try:
        return _finite_int(getattr(obj, name, None))
    except Exception:
        return None


def _exception_type(exc):
    """A name from the finite builtin allow-list (or PathHandleError), else ``other``."""
    for cls in type(exc).__mro__:
        if cls.__name__ in SAFE_TYPE_NAMES and (
            cls.__module__ == "builtins" or cls is wph.PathHandleError
        ):
            return cls.__name__
    return "other"


def own_relative(root, filename):
    """``.`` for the owned root, a known fixture name directly below it, else None."""
    if not isinstance(root, str) or not isinstance(filename, str):
        return None
    try:
        base = os.path.normcase(os.path.normpath(root))
        head, tail = os.path.split(os.path.normcase(os.path.normpath(filename)))
    except (ValueError, TypeError):
        return None
    if os.path.join(head, tail) == base:
        return "."
    if head == base and tail in FIXTURE_NAMES:
        return tail
    return None


def _location(exc):
    """Innermost traceback frame inside one of the three WP-01 CAS files, else None."""
    try:
        found = None
        tb = exc.__traceback__
        while tb is not None:
            text = str(tb.tb_frame.f_code.co_filename).replace("\\", "/")
            for suffix, label in LOCATION_SUFFIXES:
                if text.endswith("/" + suffix) and 0 < tb.tb_lineno <= MAX_LINE:
                    found = {"file": label, "line": tb.tb_lineno}
            tb = tb.tb_next
        return found
    except Exception:
        return None


def project_exception(exc, stage, op, root=None, path_error=None):
    """Finite, path-free description of an exception. Never str/repr/args/traceback text."""
    source = path_error if isinstance(path_error, wph.PathHandleError) else exc
    code = detail = None
    if isinstance(source, wph.PathHandleError):
        code, detail = _attr_int(source, "code"), _attr_int(source, "detail")
    try:
        target = own_relative(root, getattr(exc, "filename", None))
    except Exception:
        target = None
    return {
        "type": _exception_type(exc),
        "stage": stage if isinstance(stage, str) and stage in STAGES else "unknown",
        "operation": op if isinstance(op, str) and op in KNOWN_OPERATIONS else "unknown",
        "errno": _attr_int(exc, "errno"),
        "winerror": _attr_int(exc, "winerror"),
        "code": code,
        "detail": detail,
        "target": target,
        "location": _location(exc),
    }


def op_name(func):
    name = getattr(func, "__name__", None)
    return name if isinstance(name, str) and name in KNOWN_OPERATIONS else "unknown"


def _bounded_text(value):
    return value if isinstance(value, str) and len(value) <= MAX_PATH_CHARS else None


def owned_report(records):
    """Bounded root/cleanup records. Only the owned root path is listed; entries below it
    are reported by fixture name. TEMP context is the root's parent as metadata only."""
    report = []
    for entry in list(records)[:MAX_OWNED_RECORDS]:
        item = {
            "kind": entry["kind"],
            "name": entry["name"] if entry["name"] in FIXTURE_NAMES else None,
            "state": entry["state"],
            "error": entry["error"],
            "verification_error": entry.get("verification_error"),
        }
        if entry["kind"] == "root":
            path = _bounded_text(entry["path"])
            trusted = path is not None and os.path.basename(path).startswith(OWNED_PREFIX)
            item["path"] = os.path.normpath(path) if trusted else None
            item["parent"] = os.path.dirname(os.path.normpath(path)) if trusted else None
        report.append(item)
    return report


class CheckpointError(RuntimeError):
    """A checkpoint could not be persisted. Carries one fixed reason, never sink text."""

    def __init__(self, reason):
        reason = reason if reason in CHECKPOINT_REASONS else "sink_failed"
        super().__init__(reason)
        self.reason = reason


def _count(value):
    value = _finite_int(value)
    return 0 if value is None else max(0, min(value, MAX_COUNT))


def _intent_root(path):
    path = _bounded_text(path)
    if path is None or not os.path.basename(path).startswith(OWNED_PREFIX):
        return None
    return os.path.normpath(path)


def checkpoint_state(seq, phase, step, intent, records, ledger):
    """Finite, path-bounded receipt. Intent (planned) is kept apart from ownership (confirmed)
    and anything planned but unconfirmed is listed as ``unconfirmed`` (never cleaned)."""
    planned_root = intent.get("root")
    children = sorted(n for n in intent.get("children", ()) if n in FIXTURE_NAMES)
    entries = list(records)
    unconfirmed = []
    if planned_root is not None and not any(
        e["kind"] == "root" and e["path"] == planned_root for e in entries
    ):
        unconfirmed.append(".")
    for name in children:
        child = os.path.join(planned_root, name) if planned_root is not None else None
        if not any(e["kind"] != "root" and e["path"] == child for e in entries):
            unconfirmed.append(name)
    return {
        "version": CHECKPOINT_VERSION,
        "consumed": True,
        "seq": _count(seq),
        "phase": phase if phase in CHECKPOINT_PHASES else "unknown",
        "step": step if step in FIXTURE_NAMES else None,
        "intent": {"root": _intent_root(planned_root), "children": children},
        "unconfirmed": unconfirmed,
        "owned": owned_report(entries),
        "cleanup": {key: _count(ledger.get(key)) for key in CLEANUP_LEDGER},
    }


def _checkpoint_reason(error):
    reason = getattr(error, "reason", None)
    return reason if isinstance(reason, str) and reason in CHECKPOINT_REASONS else "sink_failed"


class Checkpointer:
    """Persists a state through an injected sink before the next side effect.

    One failure latches: later saves do not call the sink again (no replay, no duplicate
    writes) and the sink's last complete state stays the evidence. The claim is single-use.
    """

    def __init__(self, sink=None, ledger=None):
        self.sink = sink  # injected tests pass a fake sink; the real one arrives via claim()
        self.seq = 0
        self.latched = None
        self.claimed = False
        self.ledger = ledger if ledger is not None else CHECKPOINT_LEDGER

    def _fail(self, reason):
        self.latched = reason
        self.ledger["failed"] += 1
        if self.ledger["reason"] is None:
            self.ledger["reason"] = reason
        raise CheckpointError(reason)

    def _saved(self, phase):
        self.seq += 1
        self.ledger["saved"] += 1
        self.ledger["last_phase"] = phase

    def claim(self, sink):
        """Exclusive consumed marker plus the first state, once, before native dispatch."""
        if self.claimed or self.sink is not None or self.latched is not None:
            raise CheckpointError("pre_existing")
        self.claimed = True
        state = checkpoint_state(1, "pre_dispatch", None, {"root": None, "children": []}, [], {})
        try:
            sink.claim(state)
        except Exception as error:
            self._fail(_checkpoint_reason(error))
        self.sink = sink
        self._saved("pre_dispatch")

    def save(self, phase, step, intent, records, ledger):
        if self.latched is not None:
            raise CheckpointError("latched")
        if self.sink is None:
            self._fail("no_sink")
        if self.seq >= MAX_CHECKPOINTS:
            self._fail("limit")
        state = checkpoint_state(self.seq + 1, phase, step, intent, records, ledger)
        try:
            self.sink.write(state)
        except Exception as error:
            self._fail(_checkpoint_reason(error))
        self._saved(phase)


CHECKPOINT = Checkpointer()


class RootPlanRefused(ValueError):
    """Root planning refused before any mutation. Carries one fixed reason, never a value."""

    def __init__(self, reason):
        reason = reason if reason in PLAN_REFUSALS else "syntax"
        super().__init__(reason)
        self.reason = reason


def select_parent(environ):
    """The one parent: this process's explicit ``TEMP`` value, syntax-checked, never explored.

    No TMPDIR/TMP/OS/cwd fallback, no existence probe and no alternative after a refusal.
    Only an absolute drive-letter path with clean components is accepted.
    """
    try:
        value = environ.get(TEMP_VARIABLE)
    except Exception:
        raise RootPlanRefused("environment") from None
    if value is None:
        raise RootPlanRefused("missing")
    if not isinstance(value, str):
        raise RootPlanRefused("type")
    if not value.strip():
        raise RootPlanRefused("empty")
    if len(value) > MAX_PARENT_CHARS:
        raise RootPlanRefused("length")
    drive, rest = ntpath.splitdrive(value)
    if not (len(drive) == 2 and drive[1] == ":" and drive[0].isascii() and drive[0].isalpha()):
        raise RootPlanRefused("relative")  # also refuses UNC and \\?\ forms
    if not rest.startswith(("\\", "/")):
        raise RootPlanRefused("relative")
    if any(ord(c) < 32 or c in '<>"|?*:' for c in rest):
        raise RootPlanRefused("syntax")
    parts = [p for p in re.split(r"[\\/]+", rest) if p]
    if not parts or any(p in (".", "..") or p.endswith((" ", ".")) for p in parts):
        raise RootPlanRefused("syntax")
    return ntpath.normpath(value)


class RealFs:
    """The only real filesystem operations the native fixture performs.

    ``environ``/``name_source``/``make_dir`` are injection seams (default: the current
    process environment, ``secrets`` and ``os.mkdir``). There is no root override.
    """

    def __init__(self, environ=None, name_source=None, make_dir=None):
        self._environ = environ
        self._name_source = name_source
        self._make_dir = make_dir

    def plan_root(self, prefix):
        """Pure planning: one parent, one generated child name. Mutates nothing."""
        parent = select_parent(os.environ if self._environ is None else self._environ)
        token = (self._name_source or (lambda: secrets.token_hex(8)))()
        if not isinstance(token, str) or not NAME_PATTERN.fullmatch(token):
            raise RootPlanRefused("name")
        return ntpath.join(parent, prefix + token)

    def make_root(self, path):
        """Exactly one creation attempt with the intended mode; any refusal is terminal."""
        (self._make_dir or os.mkdir)(path, ROOT_MODE)

    def create_file(self, path):
        return open(path, "xb")

    def mkdir(self, path):
        os.mkdir(path)

    def unlink(self, path):
        os.unlink(path)

    def rmdir(self, path):
        os.rmdir(path)

    def lstat(self, path):
        return os.lstat(path)


class _NativeFixture:
    NATIVE = True
    fs = RealFs()
    platform_gate = staticmethod(wph.platform_code)
    native_ledger = NATIVE_LEDGER
    cleanup_ledger = CLEANUP_LEDGER
    owned = OWNED_RECORDS
    checkpoint = CHECKPOINT
    root_path = None
    created = ()
    intent = None  # planned, NOT owned: never consulted by cleanup
    cleanup_started = False
    stage = "setup"
    op = "unknown"
    path_error = None

    def setUp(self):
        if self.native_ledger["blocked"] is not None or self.native_ledger["failure"] is not None:
            self.skipTest("BLOCKED")
        self.created = []
        self.intent = {"root": None, "children": []}
        self.cleanup_started = False
        self.root_path = None
        self.stage, self.op = "setup", "unknown"
        try:
            self.addCleanup(self.cleanup_owned)
            if self.platform_gate():
                self.block(wph.PathHandleError(wph.UNSUPPORTED_PLATFORM))
            self.stage, self.op = "mkdtemp", "mkdtemp"
            planned = self.fs.plan_root(OWNED_PREFIX)  # one parent, one name; mutates nothing
            self.intent["root"] = planned
            self.save_checkpoint("root_intent")  # persisted before the one creation attempt
            self.fs.make_root(planned)  # a single attempt: collision/refusal is terminal
            self.root_path = planned
            self.register_owned("root", planned)  # ownership only now, before the checkpoint
            self.save_checkpoint("root_owned")
            self.stage = "create"
            self.make_file("alpha.txt", DATA_A)
            self.make_file("beta.bin", bytes(range(256)))
            self.make_dir("sub")
        except unittest.SkipTest:
            raise
        except Exception as error:
            self.note_failure(error)
            raise

    def _callTestMethod(self, method):  # noqa: N802
        self.stage, self.op = "test", self._testMethodName
        try:
            super()._callTestMethod(method)
        except unittest.SkipTest:
            raise
        except Exception as error:
            self.note_failure(error)
            raise

    def note_failure(self, error):
        """Keep only the first projection; the group stops and the error still propagates."""
        if self.native_ledger["failure"] is None:
            self.native_ledger["failure"] = project_exception(
                error, self.stage, self.op, self.root_path, self.path_error
            )

    def register_owned(self, kind, path, name=None):
        entry = {
            "kind": kind, "name": name, "path": path, "state": "created", "error": None,
            "verification_error": None,
        }  # fmt: skip
        self.created.append(entry)
        self.cleanup_ledger["created"] += 1
        if len(self.owned) < MAX_OWNED_RECORDS:
            self.owned.append(entry)
        else:
            self.cleanup_ledger["unreported"] += 1

    def save_checkpoint(self, phase, step=None):
        """Persist finite evidence before the next side effect; failure raises CheckpointError."""
        previous, self.op = self.op, "checkpoint"
        self.checkpoint.save(phase, step, self.intent, self.owned, self.cleanup_ledger)
        self.op = previous

    def make_file(self, name, data):
        self.op = "make_file"
        path = os.path.join(self.root_path, name)
        self.intent["children"].append(name)
        self.save_checkpoint("child_intent", name)
        with self.fs.create_file(path) as handle:
            self.register_owned("file", path, name)  # the file exists once open returns
            self.save_checkpoint("child_owned", name)
            handle.write(data)

    def make_dir(self, name):
        self.op = "make_dir"
        path = os.path.join(self.root_path, name)
        self.intent["children"].append(name)
        self.save_checkpoint("child_intent", name)
        self.fs.mkdir(path)
        self.register_owned("dir", path, name)
        self.save_checkpoint("child_owned", name)

    def cleanup_checkpoint(self, phase, step=None):
        """Best effort: a failed checkpoint is recorded, never stops or masks cleanup."""
        try:
            self.save_checkpoint(phase, step)
        except CheckpointError as error:
            self.note_failure(error)

    def cleanup_owned(self):
        # Only confirmed entries, newest first, exactly once; no sweep, no retry, no ACL change.
        # Planned-only intent is never cleaned.
        if self.cleanup_started:
            return
        self.cleanup_started = True
        self.stage = "cleanup"
        track = bool(self.created) or (self.intent or {}).get("root") is not None
        if track:
            self.cleanup_checkpoint("cleanup_begin")
        for entry in reversed(self.created):
            self.cleanup_entry(entry)
            self.cleanup_checkpoint("cleanup_entry", entry["name"])
        if track:
            self.cleanup_checkpoint("cleanup_done")

    def cleanup_entry(self, entry):
        ledger = self.cleanup_ledger
        self.op = "cleanup_unlink" if entry["kind"] == "file" else "cleanup_rmdir"
        remove = self.fs.unlink if entry["kind"] == "file" else self.fs.rmdir
        try:
            remove(entry["path"])
        except Exception as error:
            entry["error"] = project_exception(error, "cleanup", self.op, self.root_path)
            self.op = "cleanup_lstat"
            try:
                self.fs.lstat(entry["path"])
            except FileNotFoundError:
                entry["state"] = "absent"  # the only outcome that means absence
            except Exception as verify_error:
                entry["state"] = "unknown"  # PermissionError/other OSError: not absence
                entry["verification_error"] = project_exception(
                    verify_error, "cleanup", self.op, self.root_path
                )  # kept apart from the removal error and from first_failure
            else:
                entry["state"] = "present"
            ledger["failed"] += 1
            ledger[entry["state"]] += 1
            if self.native_ledger["failure"] is None:
                self.native_ledger["failure"] = entry["error"]
        else:
            entry["state"] = "removed"
            ledger["removed"] += 1

    def block(self, error):
        self.native_ledger["blocked"] = {
            "api": API_BY_CODE.get(error.code, "policy"),
            "code": error.code,
            "detail": error.detail,
        }
        self.skipTest("BLOCKED")

    def step(self, func, *args):
        self.op = op_name(func)
        try:
            return func(*args)
        except wph.PathHandleError as error:
            self.block(error)

    def expect(self, code, detail, func, *args):
        """``detail`` is None (any), one int, or a set/frozenset of accepted ints."""
        self.op = op_name(func)
        try:
            func(*args)
        except wph.PathHandleError as error:
            accepted = (
                detail is None
                or error.detail == detail
                or (isinstance(detail, (set, frozenset)) and error.detail in detail)
            )
            if error.code == code and accepted:
                return
            if error.code in BLOCKING_CODES or (
                error.code == wph.NATIVE_STATUS and error.detail in DENIAL_STATUSES
            ):
                self.block(error)
            self.path_error = error
            self.fail(f"unexpected rejection code={error.code} detail={error.detail}")
        self.fail(f"no rejection, wanted code={code}")

    def session(self):
        native = self.step(wph.WindowsNative)
        return wph.HandleContext(native, wph.Deadline(30))

    def entries(self):
        return (
            wph.ManifestEntry("alpha.txt", len(DATA_A), sha(DATA_A)),
            wph.ManifestEntry("beta.bin", 256, sha(bytes(range(256)))),
        )


class NativeOrdinaryTests(_NativeFixture, unittest.TestCase):
    """Actual Windows calls on ordinary owned Temp objects. Not reparse coverage."""

    def test_native_capability(self):
        self.step(wph.WindowsNative)
        self.assertEqual(wph.check_abi(), 0)
        self.assertEqual(wph.native_capability(), 0)

    def test_native_root_and_metadata(self):
        ctx = self.session()
        with ctx:
            identity = self.step(wph.observe_identity_for_tests, ctx, self.root_path)
            root = self.step(wph.open_trusted_root, ctx, self.root_path, identity)
            self.assertTrue(root.metadata.is_directory)
            self.assertEqual(root.metadata.attributes & wph.ATTR_REPARSE_POINT, 0)
            self.assertNotEqual(identity.file_id, bytes(16))
            sub = self.step(wph.open_child_directory, ctx, root, "sub")
            self.assertTrue(sub.metadata.is_directory)
            self.assertEqual(sub.metadata.identity.volume_serial, identity.volume_serial)
            self.assertNotEqual(sub.metadata.identity, identity)
            self.assertEqual(ctx.open_count, 2)
        self.assertEqual((ctx.open_count, ctx.unknown_closes), (0, 0))

    def test_native_relative_read_exact(self):
        ctx = self.session()
        with ctx:
            identity = self.step(wph.observe_identity_for_tests, ctx, self.root_path)
            root = self.step(wph.open_trusted_root, ctx, self.root_path, identity)
            results = self.step(wph.read_manifest, ctx, root, self.entries())
        self.assertEqual([r.data for r in results], [DATA_A, bytes(range(256))])
        self.assertEqual(results[0].sha256, sha(DATA_A))
        self.assertEqual([r.size for r in results], [len(DATA_A), 256])
        self.assertNotEqual(results[0].identity, results[1].identity)

    def test_native_mismatch_rejection(self):
        ctx = self.session()
        with ctx:
            identity = self.step(wph.observe_identity_for_tests, ctx, self.root_path)
            root = self.step(wph.open_trusted_root, ctx, self.root_path, identity)
            args = (ctx, root, "alpha.txt", len(DATA_A), sha(DATA_A))
            self.expect(wph.HASH_MISMATCH, None, wph.read_file, *args[:4], sha(b"other"))
            self.expect(wph.SIZE_MISMATCH, None, wph.read_file, *args[:3], len(DATA_A) + 1, args[4])
            # Explicit documented statuses only: any other status (including an unrelated
            # access denial) is a block or a failure, never a silent pass.
            self.expect(
                wph.NATIVE_STATUS, MISSING_STATUSES, wph.read_file,
                ctx, root, "missing.txt", 1, sha(b"x"),
            )  # fmt: skip
            self.expect(
                wph.NATIVE_STATUS, WRONG_TYPE_STATUSES, wph.read_file,
                ctx, root, "sub", 0, sha(b""),
            )  # fmt: skip
            self.expect(wph.BAD_COMPONENT, None, wph.read_file, ctx, root, "..", 1, sha(b"x"))
            other = wph.Identity(identity.volume_serial, b"\x01" * 16)
            self.expect(
                wph.IDENTITY_MISMATCH, None, wph.open_trusted_root, ctx, self.root_path, other
            )

    def test_native_sharing_violation(self):
        ctx = self.session()
        with ctx:
            identity = self.step(wph.observe_identity_for_tests, ctx, self.root_path)
            root = self.step(wph.open_trusted_root, ctx, self.root_path, identity)
            self.op = "sharing_open"
            with open(os.path.join(self.root_path, "alpha.txt"), "ab"):
                self.expect(
                    wph.NATIVE_STATUS, 0xC0000043, wph.read_file,
                    ctx, root, "alpha.txt", len(DATA_A), sha(DATA_A),
                )  # fmt: skip

    def test_native_handle_close(self):
        ctx = self.session()
        with ctx:
            identity = self.step(wph.observe_identity_for_tests, ctx, self.root_path)
            root = self.step(wph.open_trusted_root, ctx, self.root_path, identity)
            self.step(wph.read_manifest, ctx, root, self.entries())
        self.assertEqual((ctx.open_count, ctx.unknown_closes), (0, 0))
        self.assertEqual(ctx.close_calls, 4)  # observation root, bootstrap root, two files
        for name in ("alpha.txt", "beta.bin"):
            self.op = "reopen_check"
            # A leaked read-only handle (read share only) would block write access.
            with open(os.path.join(self.root_path, name), "r+b"):
                pass


CANARY = "canary-secret-xyz"
FAKE_ROOT = os.path.join(os.sep + "invented-temp", OWNED_PREFIX + "fake")


def os_error(cls, err, winerror=None, filename=None):
    """An OSError carrying a canary message; ``winerror`` only where the platform has it."""
    if winerror is not None and os.name == "nt":
        return cls(err, CANARY, filename, winerror)
    return cls(err, CANARY, filename)


class FakeFs:
    """In-memory stand-in for ``RealFs``: records every call, creates nothing real."""

    def __init__(self):
        self.present = set()
        self.log = []
        self.fail = {}  # (operation, path or None) -> exception to raise

    def _go(self, op, path):
        self.log.append((op, path))
        error = self.fail.get((op, path)) or self.fail.get((op, None))
        if error is not None:
            raise error

    def plan_root(self, prefix):
        return FAKE_ROOT

    def make_root(self, path):
        self._go("mkdtemp", None)
        self.present.add(path)

    def create_file(self, path):
        self._go("create", path)
        self.present.add(path)
        return io.BytesIO()

    def mkdir(self, path):
        self._go("mkdir", path)
        self.present.add(path)

    def _remove(self, op, path):
        self._go(op, path)
        if path not in self.present:
            raise FileNotFoundError(2, CANARY)
        self.present.discard(path)

    def unlink(self, path):
        self._remove("unlink", path)

    def rmdir(self, path):
        self._remove("rmdir", path)

    def lstat(self, path):
        self._go("lstat", path)
        if path not in self.present:
            raise FileNotFoundError(2, CANARY)
        return object()


class _Harness(_NativeFixture, unittest.TestCase):
    """The native fixture over a fake filesystem and private ledgers (not a test case)."""

    NATIVE = False

    def probe(self):
        pass


class FakeSink:
    """In-memory checkpoint sink: keeps JSON copies of what it was given, writes nothing."""

    def __init__(self, fail_phases=None, log=None):
        self.fail_phases = fail_phases or {}  # phase -> exception to raise instead of storing
        self.log = log  # optional shared list to prove ordering against filesystem calls
        self.writes = []
        self.claims = []

    def claim(self, state):
        self.claims.append(json.loads(json.dumps(state)))

    def write(self, state):
        if self.log is not None:
            self.log.append(("checkpoint", state["phase"]))
        error = self.fail_phases.get(state["phase"])
        if error is not None:
            raise error
        self.writes.append(json.loads(json.dumps(state)))


def fresh_checkpointer(sink):
    return Checkpointer(sink, {"saved": 0, "failed": 0, "reason": None, "last_phase": None})


def make_harness(ledger=None, fs=None, sink=None):
    harness = _Harness("probe")
    harness.fs = fs if fs is not None else FakeFs()
    harness.platform_gate = lambda: 0
    harness.native_ledger = ledger if ledger is not None else {"blocked": None, "failure": None}
    harness.cleanup_ledger = dict.fromkeys(CLEANUP_LEDGER, 0)
    harness.owned = []
    harness.checkpoint = fresh_checkpointer(sink if sink is not None else FakeSink())
    return harness


class NativeDiagnosticTests(unittest.TestCase):
    """Pure/injected regressions for the failure-reporting machinery. No native call."""

    def assert_safe(self, value):
        self.assertNotIn(CANARY, json.dumps(value, sort_keys=True))

    def path(self, name):
        return os.path.join(FAKE_ROOT, name)

    def test_projection_is_finite_and_path_free(self):
        error = os_error(PermissionError, 13, 5, self.path("alpha.txt"))
        got = project_exception(error, "cleanup", "cleanup_unlink", FAKE_ROOT)
        keys = "type stage operation errno winerror code detail target location".split()
        self.assertEqual(sorted(got), sorted(keys))
        self.assertEqual(
            (got["type"], got["stage"], got["operation"], got["target"]),
            ("PermissionError", "cleanup", "cleanup_unlink", "alpha.txt"),
        )
        self.assertEqual(got["errno"], error.errno)
        self.assertEqual(got["winerror"], 5 if os.name == "nt" else None)
        self.assert_safe(got)
        root_error = os_error(OSError, 5, None, FAKE_ROOT)
        self.assertEqual(
            project_exception(root_error, "setup", "mkdtemp", FAKE_ROOT)["target"], "."
        )
        try:
            raise error
        except PermissionError as raised:
            location = project_exception(raised, "test", "unknown", FAKE_ROOT)["location"]
        self.assertEqual(location["file"], "test_windows_path_handles.py")
        self.assertTrue(0 < location["line"] <= MAX_LINE)

    def test_projection_rejects_canary_and_non_finite_values(self):
        class PermissionError(Exception):  # noqa: A001 - lookalike, not the builtin
            pass

        class Odd(Exception):
            errno = CANARY
            winerror = True
            filename = os.path.join(FAKE_ROOT, CANARY + ".txt")

        for exc in (PermissionError(CANARY), Odd(CANARY)):
            got = project_exception(exc, "../" + CANARY, CANARY, FAKE_ROOT)
            self.assertEqual(got["type"], "other")
            self.assertEqual((got["stage"], got["operation"]), ("unknown", "unknown"))
            self.assertEqual((got["errno"], got["winerror"], got["target"]), (None, None, None))
            self.assert_safe(got)
        outside = os_error(OSError, 5, None, os.path.join(os.sep + "elsewhere", "alpha.txt"))
        nested = os_error(OSError, 5, None, os.path.join(FAKE_ROOT, "sub", "alpha.txt"))
        for exc in (outside, nested):
            self.assertIsNone(project_exception(exc, "test", "unknown", FAKE_ROOT)["target"])
        for root in (None, 5):
            self.assertIsNone(project_exception(outside, "test", "unknown", root)["target"])
        wide = wph.PathHandleError(wph.NATIVE_STATUS, 1 << 40)
        negative = wph.PathHandleError(wph.NATIVE_STATUS, -(1 << 40))
        textual = wph.PathHandleError("x", CANARY)
        self.assertEqual(project_exception(wide, "test", "unknown")["code"], wph.NATIVE_STATUS)
        for exc in (wide, negative):
            self.assertIsNone(project_exception(exc, "test", "unknown")["detail"])
        got = project_exception(textual, "test", "unknown")
        self.assertEqual((got["code"], got["detail"]), (None, None))
        self.assert_safe(got)
        known = project_exception(
            wph.PathHandleError(wph.NATIVE_STATUS, 0xC0000034), "test", "read_file"
        )
        self.assertEqual(
            (known["type"], known["code"], known["detail"], known["errno"]),
            ("PathHandleError", wph.NATIVE_STATUS, 0xC0000034, None),
        )

    def test_first_setup_exception_stops_the_group(self):
        harness = make_harness()
        harness.fs.fail[("create", self.path("beta.bin"))] = RuntimeError(CANARY)
        with self.assertRaises(RuntimeError):
            harness.setUp()
        failure = harness.native_ledger["failure"]
        self.assertEqual(
            (failure["type"], failure["stage"], failure["operation"]),
            ("RuntimeError", "create", "make_file"),
        )
        self.assert_safe(failure)
        harness.note_failure(ValueError(CANARY))  # a later error never replaces the first
        self.assertEqual(harness.native_ledger["failure"]["type"], "RuntimeError")
        later = make_harness(harness.native_ledger)
        with self.assertRaises(unittest.SkipTest):
            later.setUp()
        self.assertEqual(later.fs.log, [])
        blocked = make_harness({"blocked": {"api": "x", "code": 1, "detail": 0}, "failure": None})
        with self.assertRaises(unittest.SkipTest):
            blocked.setUp()
        self.assertEqual(blocked.fs.log, [])
        harness.doCleanups()

    def test_test_body_exceptions_are_projected_and_still_raised(self):
        def boom():
            raise TypeError(CANARY)

        harness = make_harness()
        with self.assertRaises(TypeError):
            harness._callTestMethod(boom)
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["type"], failure["stage"]), ("TypeError", "test"))
        self.assertEqual(failure["location"]["file"], "test_windows_path_handles.py")
        self.assert_safe(failure)
        parent = wph.OpenedDirectory(5, None)
        ctx = wph.HandleContext(FakeNative())
        failing = make_harness()
        with self.assertRaises(AssertionError):
            failing._callTestMethod(
                lambda: failing.expect(
                    wph.HASH_MISMATCH, None, wph.open_child_directory, ctx, parent, "x"
                )
            )
        failure = failing.native_ledger["failure"]
        self.assertEqual(
            (failure["type"], failure["operation"], failure["code"], failure["detail"]),
            ("AssertionError", "open_child_directory", wph.HANDLE_NOT_OWNED, 0),
        )
        self.assert_safe(failure)

    def test_negative_controls_accept_only_explicit_statuses(self):
        def refuse(status):
            raise wph.PathHandleError(wph.NATIVE_STATUS, status)

        self.assertIsNone(
            make_harness().expect(wph.NATIVE_STATUS, MISSING_STATUSES, refuse, 0xC0000034)
        )
        self.assertIsNone(
            make_harness().expect(wph.NATIVE_STATUS, WRONG_TYPE_STATUSES, refuse, 0xC00000BA)
        )
        for accepted, status in (
            (MISSING_STATUSES, 0xC0000043),  # unrelated, non-denial status
            (MISSING_STATUSES, 0xC00000BA),
            (WRONG_TYPE_STATUSES, 0xC0000034),
        ):
            with self.subTest(hex(status)):
                with self.assertRaises(AssertionError):
                    make_harness().expect(wph.NATIVE_STATUS, accepted, refuse, status)
        denied = make_harness()
        with self.assertRaises(unittest.SkipTest):  # unrelated denial: honest block
            denied.expect(wph.NATIVE_STATUS, MISSING_STATUSES, refuse, 0xC0000022)
        self.assertEqual(denied.native_ledger["blocked"]["detail"], 0xC0000022)

    def test_owned_root_is_registered_before_any_later_setup_step(self):
        harness = make_harness()
        harness.fs.fail[("create", self.path("alpha.txt"))] = RuntimeError(CANARY)
        with self.assertRaises(RuntimeError):
            harness.setUp()
        self.assertEqual([e["kind"] for e in harness.owned], ["root"])
        self.assertEqual(harness.cleanup_ledger["created"], 1)
        report = owned_report(harness.owned)
        self.assertEqual(report[0]["path"], os.path.normpath(FAKE_ROOT))
        self.assertEqual(report[0]["parent"], os.path.dirname(os.path.normpath(FAKE_ROOT)))
        self.assertEqual(report[0]["state"], "created")
        harness.doCleanups()
        self.assertEqual(harness.owned[0]["state"], "removed")
        self.assertEqual(
            (harness.cleanup_ledger["removed"], harness.cleanup_ledger["failed"]), (1, 0)
        )
        self.assertIn(("rmdir", FAKE_ROOT), harness.fs.log)
        self.assert_safe(owned_report(harness.owned))

    def test_failed_mkdtemp_registers_nothing(self):
        harness = make_harness()
        harness.fs.fail[("mkdtemp", None)] = os_error(
            PermissionError, 13, 5, os.path.join(os.sep + "somewhere", "else")
        )
        with self.assertRaises(PermissionError):
            harness.setUp()
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["stage"], failure["operation"]), ("mkdtemp", "mkdtemp"))
        self.assertIsNone(failure["target"])
        self.assertEqual((harness.owned, harness.cleanup_ledger["created"]), ([], 0))
        harness.doCleanups()
        self.assertEqual([c[0] for c in harness.fs.log], ["mkdtemp"])
        self.assert_safe(failure)

    def test_children_are_reported_by_fixture_name_only(self):
        harness = make_harness()
        harness.setUp()
        report = owned_report(harness.owned)
        self.assertEqual([r["kind"] for r in report], ["root", "file", "file", "dir"])
        self.assertEqual([r["name"] for r in report[1:]], ["alpha.txt", "beta.bin", "sub"])
        self.assertTrue(all("path" not in r for r in report[1:]))
        harness.doCleanups()
        self.assertEqual({r["state"] for r in owned_report(harness.owned)}, {"removed"})

    def test_cleanup_distinguishes_absent_from_unknown_without_retry(self):
        harness = make_harness()
        harness.setUp()
        alpha, beta, sub = (self.path(n) for n in ("alpha.txt", "beta.bin", "sub"))
        denial = lambda p: os_error(PermissionError, 13, 5, p)  # noqa: E731
        harness.fs.fail[("unlink", alpha)] = denial(alpha)
        harness.fs.fail[("lstat", alpha)] = denial(alpha)  # lstat denied: unknown, NOT absent
        harness.fs.fail[("unlink", beta)] = denial(beta)  # lstat succeeds: still present
        harness.fs.present.discard(sub)  # rmdir raises FileNotFoundError; lstat confirms absent
        harness.doCleanups()
        states = {e["name"]: e["state"] for e in harness.created}
        self.assertEqual(
            states,
            {None: "removed", "alpha.txt": "unknown", "beta.bin": "present", "sub": "absent"},
        )
        ledger = harness.cleanup_ledger
        self.assertEqual((ledger["created"], ledger["removed"], ledger["failed"]), (4, 1, 3))
        self.assertEqual((ledger["absent"], ledger["present"], ledger["unknown"]), (1, 1, 1))
        for op, path in (("unlink", alpha), ("lstat", alpha), ("unlink", beta), ("lstat", sub)):
            self.assertEqual(harness.fs.log.count((op, path)), 1)
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["type"], failure["stage"]), ("FileNotFoundError", "cleanup"))
        alpha_entry = next(e for e in harness.created if e["name"] == "alpha.txt")
        self.assertEqual(alpha_entry["error"]["errno"], 13)
        self.assertEqual(alpha_entry["error"]["target"], "alpha.txt")
        self.assert_safe(owned_report(harness.owned))
        self.assert_safe(failure)

    def test_real_fixture_uses_the_real_seam_and_harness_never_does(self):
        self.assertIsInstance(_NativeFixture.fs, RealFs)
        harness = make_harness()
        self.assertIsInstance(harness.fs, FakeFs)
        for private, shared in (
            (harness.native_ledger, NATIVE_LEDGER),
            (harness.cleanup_ledger, CLEANUP_LEDGER),
            (harness.owned, OWNED_RECORDS),
            (harness.checkpoint, CHECKPOINT),
            (harness.checkpoint.ledger, CHECKPOINT_LEDGER),
        ):
            self.assertIsNot(private, shared)
        self.assertIs(_NativeFixture.checkpoint, CHECKPOINT)


TEMP_ENV = {
    "TEMP": "C:\\invented-temp\\scratch",
    "TMPDIR": "D:\\other-tmp",
    "TMP": "E:\\other-tmp",
}
NAME = "0123456789abcdef"
PLANNED = "C:\\invented-temp\\scratch\\" + OWNED_PREFIX + NAME
JOURNAL_PATH = "X:\\invented\\journal.json"
PENDING_PATH = JOURNAL_PATH + ".pending"
_RUNNER = {}


def load_runner():
    """The runner module, loaded by file location for injected tests only (no sys.path use)."""
    if "module" not in _RUNNER:
        path = pathlib.Path(__file__).resolve().parents[3] / "tools" / "run_path_policy_checks.py"
        spec = importlib.util.spec_from_file_location("wp01_runner_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _RUNNER["module"] = module
    return _RUNNER["module"]


class GuardedRealFs(RealFs):
    """The real planning/creation code over injected seams; every other real call is barred."""

    def _barred(self, *args):
        raise AssertionError("real filesystem call")

    create_file = mkdir = unlink = rmdir = lstat = _barred


class Spy:
    """A fake mkdir (or name source) that records calls and may raise."""

    def __init__(self, error=None, value=None):
        self.calls, self.error, self.value = [], error, value

    def __call__(self, *args):
        self.calls.append(args)
        if self.error is not None:
            raise self.error
        return self.value


class FakeIo:
    """In-memory journal I/O for the real FileSink. Ordinals count per operation name."""

    def __init__(self):
        self.files, self.log, self.counts = {}, [], {}
        self.fail = {}  # (operation, ordinal) -> exception
        self.torn = set()  # (operation, ordinal): store half the bytes, then raise

    def _go(self, op, path):
        self.log.append((op, path))
        self.counts[op] = self.counts.get(op, 0) + 1
        ordinal = self.counts[op]
        error = self.fail.get((op, ordinal))
        if error is not None:
            raise error
        return ordinal

    def exists(self, path):
        self._go("exists", path)
        return path in self.files

    def write_new(self, path, data):
        ordinal = self._go("write_new", path)
        if path in self.files:
            raise FileExistsError(17, CANARY)
        if ("write_new", ordinal) in self.torn:
            self.files[path] = data[: len(data) // 2]
            raise OSError(5, CANARY)
        self.files[path] = data

    def replace(self, source, target):
        self._go("replace", source)
        self.files[target] = self.files.pop(source)

    def writes(self):
        return [entry for entry in self.log if entry[0] == "write_new"]


class FixtureHardeningTests(unittest.TestCase):
    """F1-F3 regressions over fake fs/env/name/sink/io seams. Nothing real is touched."""

    def assert_safe(self, value):
        self.assertNotIn(CANARY, json.dumps(value, sort_keys=True))

    def path(self, name):
        return os.path.join(FAKE_ROOT, name)

    def real_harness(self, environ, mkdir=None, names=None, sink=None):
        fs = GuardedRealFs(environ, names or Spy(value=NAME), mkdir or Spy())
        return make_harness(fs=fs, sink=sink)

    # --- F1: one explicit parent, one child, one creation attempt -------------------------

    def test_missing_or_invalid_temp_refuses_before_any_mutation(self):
        bad = (
            {}, {"TMPDIR": "C:\\ok", "TMP": "C:\\ok"}, {"TEMP": None}, {"TEMP": 5}, {"TEMP": ""},
            {"TEMP": "   "}, {"TEMP": "relative\\dir"}, {"TEMP": CANARY}, {"TEMP": "C:rel"},
            {"TEMP": "\\\\server\\share\\x"}, {"TEMP": "\\\\?\\C:\\x"}, {"TEMP": "C:\\a\\..\\b"},
            {"TEMP": "C:\\a\\.\\b"}, {"TEMP": "C:\\a\x00b"}, {"TEMP": "C:\\a\\b*"},
            {"TEMP": "C:\\a\\b."}, {"TEMP": "C:\\"}, {"TEMP": "C:\\a" + "x" * 300},
        )  # fmt: skip
        for environ in bad:
            with self.subTest(repr(environ)[:30]):
                mkdir, names = Spy(), Spy(value=NAME)
                fs = GuardedRealFs(environ, names, mkdir)
                with self.assertRaises(RootPlanRefused) as caught:
                    fs.plan_root(OWNED_PREFIX)
                error = caught.exception
                self.assertIn(error.reason, PLAN_REFUSALS)
                self.assert_safe(f"{error!s}|{error!r}|{error.args}|{vars(error)}")
                self.assertEqual((mkdir.calls, names.calls), ([], []))
        broken = types.SimpleNamespace(get=Spy(error=RuntimeError(CANARY)))
        with self.assertRaises(RootPlanRefused):
            GuardedRealFs(broken, Spy(value=NAME), Spy()).plan_root(OWNED_PREFIX)

    def test_missing_temp_stops_the_fixture_with_nothing_owned_or_cleaned(self):
        mkdir, names = Spy(), Spy(value=NAME)
        harness = self.real_harness({"TMPDIR": "C:\\ok", "TMP": "C:\\ok"}, mkdir, names)
        with self.assertRaises(ValueError):
            harness.setUp()
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["stage"], failure["operation"]), ("mkdtemp", "mkdtemp"))
        self.assertEqual(failure["type"], "ValueError")
        harness.doCleanups()
        self.assertEqual((mkdir.calls, names.calls), ([], []))
        self.assertEqual((harness.owned, harness.created), ([], []))
        self.assertEqual(harness.checkpoint.sink.writes, [])
        self.assert_safe(failure)

    def test_plan_uses_only_the_explicit_temp_parent_and_one_generated_name(self):
        for value in (TEMP_ENV["TEMP"], "C:/invented-temp/scratch/", "c:\\invented-temp\\scratch"):
            with self.subTest(value):
                mkdir, names = Spy(), Spy(value=NAME)
                fs = GuardedRealFs({**TEMP_ENV, "TEMP": value}, names, mkdir)
                planned = fs.plan_root(OWNED_PREFIX)
                self.assertEqual(ntpath.normcase(planned), ntpath.normcase(PLANNED))
                self.assertEqual((names.calls, mkdir.calls), ([()], []))  # planning mutates nothing
                fs.make_root(planned)
                self.assertEqual(mkdir.calls, [(planned, ROOT_MODE)])
        self.assertEqual(ROOT_MODE, 0o700)
        for token in (CANARY, "0123456789ABCDEF", "..", "0123", 5, None, "0123456789abcdef0"):
            with self.subTest(repr(token)):
                mkdir = Spy()
                with self.assertRaises(RootPlanRefused) as caught:
                    GuardedRealFs(TEMP_ENV, Spy(value=token), mkdir).plan_root(OWNED_PREFIX)
                self.assertEqual(caught.exception.reason, "name")
                self.assertEqual(mkdir.calls, [])

    def test_default_seams_resolve_without_real_calls_until_used(self):
        fs = RealFs()
        self.assertEqual((fs._environ, fs._name_source, fs._make_dir), (None, None, None))
        self.assertRegex(secrets.token_hex(8), NAME_PATTERN)

    def test_mkdir_refusal_or_collision_is_terminal_with_no_second_attempt(self):
        errors = (
            os_error(PermissionError, 13, 5, PLANNED),
            FileExistsError(17, CANARY, PLANNED),
        )
        for error in errors:
            with self.subTest(type(error).__name__):
                mkdir, names = Spy(error=error), Spy(value=NAME)
                harness = self.real_harness(TEMP_ENV, mkdir, names)
                with self.assertRaises(type(error)):
                    harness.setUp()
                harness.doCleanups()
                self.assertEqual(mkdir.calls, [(PLANNED, 0o700)])  # one attempt, mode unchanged
                self.assertEqual(names.calls, [()])  # no resampling
                self.assertEqual((harness.created, harness.owned), ([], []))
                failure = harness.native_ledger["failure"]
                self.assertEqual(
                    (failure["type"], failure["stage"], failure["errno"]),
                    (type(error).__name__, "mkdtemp", error.errno),
                )
                self.assert_safe(failure)
                self.assertEqual(harness.cleanup_ledger["created"], 0)

    def test_planned_only_paths_are_never_cleaned(self):
        harness = make_harness()
        harness.fs.fail[("mkdtemp", None)] = os_error(PermissionError, 13, 5, FAKE_ROOT)
        with self.assertRaises(PermissionError):
            harness.setUp()
        harness.doCleanups()
        self.assertEqual([c[0] for c in harness.fs.log], ["mkdtemp"])  # no rmdir/unlink/lstat
        phases = [w["phase"] for w in harness.checkpoint.sink.writes]
        self.assertEqual(phases, ["root_intent", "cleanup_begin", "cleanup_done"])
        last = harness.checkpoint.sink.writes[-1]
        self.assertEqual(last["unconfirmed"], ["."])
        self.assertEqual((last["owned"], last["intent"]["root"]), ([], os.path.normpath(FAKE_ROOT)))
        alpha = self.path("alpha.txt")
        child = make_harness()
        child.fs.fail[("create", alpha)] = RuntimeError(CANARY)
        with self.assertRaises(RuntimeError):
            child.setUp()
        child.doCleanups()
        self.assertNotIn(("unlink", alpha), child.fs.log)
        self.assertNotIn(("lstat", alpha), child.fs.log)
        self.assertEqual(child.fs.log.count(("rmdir", FAKE_ROOT)), 1)
        last = child.checkpoint.sink.writes[-1]
        self.assertEqual(last["unconfirmed"], ["alpha.txt"])
        self.assertEqual([e["kind"] for e in last["owned"]], ["root"])
        self.assert_safe(last)

    def test_checkpoint_precedes_each_side_effect_and_ownership_precedes_checkpoint(self):
        log = []
        harness = make_harness(sink=FakeSink(log=log))
        harness.fs.log = log
        harness.setUp()
        harness.doCleanups()
        alpha, beta, sub = (self.path(n) for n in ("alpha.txt", "beta.bin", "sub"))
        self.assertEqual(
            log,
            [
                ("checkpoint", "root_intent"), ("mkdtemp", None), ("checkpoint", "root_owned"),
                ("checkpoint", "child_intent"), ("create", alpha), ("checkpoint", "child_owned"),
                ("checkpoint", "child_intent"), ("create", beta), ("checkpoint", "child_owned"),
                ("checkpoint", "child_intent"), ("mkdir", sub), ("checkpoint", "child_owned"),
                ("checkpoint", "cleanup_begin"),
                ("rmdir", sub), ("checkpoint", "cleanup_entry"),
                ("unlink", beta), ("checkpoint", "cleanup_entry"),
                ("unlink", alpha), ("checkpoint", "cleanup_entry"),
                ("rmdir", FAKE_ROOT), ("checkpoint", "cleanup_entry"),
                ("checkpoint", "cleanup_done"),
            ],
        )  # fmt: skip
        owned_states = [e["state"] for e in harness.checkpoint.sink.writes[-1]["owned"]]
        self.assertEqual(set(owned_states), {"removed"})

    # --- F2: sink failures stop setup; cleanup still runs once on confirmed objects --------

    def test_sink_failure_before_root_creation_creates_and_owns_nothing(self):
        harness = make_harness(sink=FakeSink({"root_intent": RuntimeError(CANARY)}))
        with self.assertRaises(CheckpointError):
            harness.setUp()
        harness.doCleanups()
        self.assertEqual(harness.fs.log, [])
        self.assertEqual((harness.created, harness.owned), ([], []))
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["operation"], failure["type"]), ("checkpoint", "RuntimeError"))
        self.assertEqual(harness.checkpoint.ledger["reason"], "sink_failed")
        self.assert_safe(failure)
        self.assert_safe(harness.checkpoint.ledger)

    def test_sink_failure_after_root_creation_keeps_exact_owned_cleanup_once(self):
        harness = make_harness(sink=FakeSink({"root_owned": RuntimeError(CANARY)}))
        with self.assertRaises(CheckpointError):
            harness.setUp()
        self.assertEqual([e["kind"] for e in harness.created], ["root"])  # owned before the save
        harness.doCleanups()
        self.assertEqual(harness.fs.log, [("mkdtemp", None), ("rmdir", FAKE_ROOT)])
        self.assertEqual(harness.created[0]["state"], "removed")
        self.assertEqual(
            [w["phase"] for w in harness.checkpoint.sink.writes], ["root_intent"]
        )  # latched: no further sink calls, last complete state kept
        ledger = harness.checkpoint.ledger
        self.assertEqual((ledger["failed"], ledger["reason"]), (1, "sink_failed"))
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["stage"], failure["operation"]), ("mkdtemp", "checkpoint"))
        self.assert_safe(failure)

    def test_sink_failure_after_file_creation_cleans_that_file_without_duplicates(self):
        harness = make_harness(sink=FakeSink({"child_owned": RuntimeError(CANARY)}))
        with self.assertRaises(CheckpointError):
            harness.setUp()
        alpha, beta = self.path("alpha.txt"), self.path("beta.bin")
        harness.doCleanups()
        self.assertNotIn(("create", beta), harness.fs.log)  # preparation stopped
        for call in (("create", alpha), ("unlink", alpha), ("rmdir", FAKE_ROOT)):
            self.assertEqual(harness.fs.log.count(call), 1)
        self.assertEqual({e["state"] for e in harness.created}, {"removed"})
        last = harness.checkpoint.sink.writes[-1]
        self.assertEqual((last["phase"], last["step"]), ("child_intent", "alpha.txt"))
        self.assertEqual(last["unconfirmed"], ["alpha.txt"])  # uncertainty kept, not erased

    def test_cleanup_checkpoint_failure_never_masks_the_original_first_error(self):
        harness = make_harness(sink=FakeSink({"cleanup_begin": RuntimeError(CANARY)}))
        harness.fs.fail[("create", self.path("alpha.txt"))] = RuntimeError(CANARY)
        with self.assertRaises(RuntimeError):
            harness.setUp()
        harness.doCleanups()
        failure = harness.native_ledger["failure"]
        self.assertEqual(
            (failure["type"], failure["stage"], failure["operation"]),
            ("RuntimeError", "create", "make_file"),
        )
        self.assertEqual(harness.fs.log.count(("rmdir", FAKE_ROOT)), 1)
        self.assertEqual(harness.checkpoint.ledger["failed"], 1)
        harness.doCleanups()  # nothing left to run: no repeated removal
        self.assertEqual(harness.fs.log.count(("rmdir", FAKE_ROOT)), 1)
        self.assert_safe(failure)

    def test_checkpoint_limit_and_missing_sink_stop_preparation(self):
        harness = make_harness()
        harness.checkpoint.sink = None
        with self.assertRaises(CheckpointError):
            harness.setUp()
        self.assertEqual((harness.fs.log, harness.checkpoint.ledger["reason"]), ([], "no_sink"))
        limited = make_harness()
        limited.checkpoint.seq = MAX_CHECKPOINTS
        with self.assertRaises(CheckpointError):
            limited.setUp()
        self.assertEqual((limited.fs.log, limited.checkpoint.ledger["reason"]), ([], "limit"))
        state = checkpoint_state(10**9, "bogus", "x", {"root": CANARY, "children": ["q"]}, [], {})
        self.assertEqual(
            (state["seq"], state["phase"], state["step"], state["intent"]),
            (MAX_COUNT, "unknown", None, {"root": None, "children": []}),
        )
        self.assert_safe(state)

    # --- F2: real FileSink logic over fake io: interruption and refusal --------------------

    def claimed_harness(self, io):
        runner = load_runner()
        checkpoint = fresh_checkpointer(None)
        checkpoint.claim(runner.FileSink(io, JOURNAL_PATH, PENDING_PATH))
        harness = make_harness()
        harness.checkpoint = checkpoint
        return harness

    def journal(self, io):
        return json.loads(io.files[JOURNAL_PATH])

    def test_complete_run_leaves_one_valid_bounded_journal_and_no_pending(self):
        runner = load_runner()
        io = FakeIo()
        harness = self.claimed_harness(io)
        self.assertEqual(self.journal(io)["phase"], "pre_dispatch")
        harness.setUp()
        harness.doCleanups()
        final = self.journal(io)
        self.assertEqual((final["phase"], final["consumed"]), ("cleanup_done", True))
        self.assertEqual(final["seq"], harness.checkpoint.seq)
        self.assertEqual({e["state"] for e in final["owned"]}, {"removed"})
        self.assertLess(len(io.files[JOURNAL_PATH]), runner.MAX_CHECKPOINT_BYTES)
        self.assertNotIn(PENDING_PATH, io.files)
        self.assertEqual(set(io.files), {JOURNAL_PATH})
        self.assert_safe(final)

    def test_interrupted_replace_retains_last_complete_receipt_and_never_replays(self):
        io = FakeIo()
        harness = self.claimed_harness(io)
        io.fail[("replace", 4)] = OSError(5, CANARY)  # root_intent, root_owned, child_intent ok
        with self.assertRaises(CheckpointError):
            harness.setUp()
        kept = self.journal(io)  # still complete, valid JSON: the last good state
        self.assertEqual((kept["phase"], kept["step"]), ("child_intent", "alpha.txt"))
        self.assertEqual(kept["unconfirmed"], ["alpha.txt"])
        self.assertIn(PENDING_PATH, io.files)  # stale pending: ambiguity for the next run
        before = len(io.writes())
        harness.doCleanups()
        self.assertEqual(len(io.writes()), before)  # latched: no further journal writes
        alpha = self.path("alpha.txt")
        self.assertEqual(harness.fs.log.count(("unlink", alpha)), 1)  # in-memory ownership
        self.assertEqual(harness.fs.log.count(("rmdir", FAKE_ROOT)), 1)
        self.assertEqual(self.journal(io), kept)
        self.assertEqual(harness.checkpoint.ledger["reason"], "replace_failed")
        # No dispatch replay: a second claim or a fresh claimed journal is refused outright.
        with self.assertRaises(CheckpointError) as again:
            harness.checkpoint.claim(load_runner().FileSink(io, JOURNAL_PATH, PENDING_PATH))
        self.assertEqual(again.exception.reason, "pre_existing")
        fresh = Checkpointer(None, {"saved": 0, "failed": 0, "reason": None, "last_phase": None})
        with self.assertRaises(CheckpointError) as refused:
            fresh.claim(load_runner().FileSink(io, JOURNAL_PATH, PENDING_PATH))
        self.assertEqual(refused.exception.reason, "pre_existing")
        self.assertEqual(len(io.writes()), before)

    def test_torn_pending_write_keeps_previous_journal_valid(self):
        io = FakeIo()
        harness = self.claimed_harness(io)
        io.torn.add(("write_new", 3))  # claim=1, root_intent=2, root_owned pending torn
        with self.assertRaises(CheckpointError):
            harness.setUp()
        self.assertEqual(self.journal(io)["phase"], "root_intent")
        with self.assertRaises(ValueError):
            json.loads(io.files[PENDING_PATH])
        harness.doCleanups()
        self.assertEqual(harness.fs.log.count(("rmdir", FAKE_ROOT)), 1)
        self.assertEqual(harness.checkpoint.ledger["reason"], "write_failed")
        self.assertEqual(self.journal(io)["phase"], "root_intent")

    def test_claim_refuses_preexisting_or_ambiguous_journal_without_writing(self):
        runner = load_runner()
        cases = (
            {JOURNAL_PATH: b"{}"},
            {PENDING_PATH: b"{"},
            {JOURNAL_PATH: b"", PENDING_PATH: b""},
        )
        for files in cases:
            with self.subTest(sorted(files)):
                io = FakeIo()
                io.files.update(files)
                checkpoint = fresh_checkpointer(None)
                with self.assertRaises(CheckpointError) as caught:
                    checkpoint.claim(runner.FileSink(io, JOURNAL_PATH, PENDING_PATH))
                self.assertEqual(caught.exception.reason, "pre_existing")
                self.assertEqual(io.writes(), [])
                self.assertIsNone(checkpoint.sink)
                self.assertEqual(io.files, files)  # no reset, no delete
        racing = FakeIo()
        racing.fail[("write_new", 1)] = FileExistsError(17, CANARY)
        broken = FakeIo()
        broken.fail[("exists", 1)] = OSError(5, CANARY)
        for io, reason in ((racing, "pre_existing"), (broken, "claim_failed")):
            checkpoint = fresh_checkpointer(None)
            with self.assertRaises(CheckpointError) as caught:
                checkpoint.claim(runner.FileSink(io, JOURNAL_PATH, PENDING_PATH))
            self.assertEqual(caught.exception.reason, reason)
            self.assert_safe(f"{caught.exception!s}|{caught.exception.args}")
        big = FakeIo()
        with self.assertRaises(runner.CheckpointRefused) as caught:
            runner.FileSink(big, JOURNAL_PATH, PENDING_PATH).write({"x": "a" * 70000})
        self.assertEqual((caught.exception.reason, big.writes()), ("too_large", []))

    def test_injected_only_never_instantiates_a_real_sink_or_dispatches_native(self):
        runner = load_runner()
        begin = Spy()
        log = []
        tests = [runner._FakeTest("inj", log), runner._FakeTest("nat", log, native=True)]
        module = types.SimpleNamespace(NATIVE_LEDGER={"blocked": None, "failure": None})
        with mock.patch.object(runner, "FileOps", side_effect=AssertionError("real sink")):
            groups = runner.run_groups(module, tests, True, begin)
            for name, ok in runner._dispatch_checks():
                self.assertTrue(ok, name)
        self.assertEqual((begin.calls, log), ([], ["inj"]))
        self.assertEqual(
            (groups["dispatched"], groups["not_run"], groups["checkpoint_refused"]),
            (False, ["nat"], None),
        )
        self.assertIsNone(CHECKPOINT.sink)  # the shared checkpointer never got a real sink
        self.assertEqual(
            CHECKPOINT_LEDGER, {"saved": 0, "failed": 0, "reason": None, "last_phase": None}
        )

    def test_history_and_first_failure_are_preserved(self):
        runner = load_runner()
        self.assertEqual(
            {k: runner.HISTORICAL_NATIVE_STAGE[k] for k in ("native_errors", "native_passed")},
            {"native_errors": 6, "native_passed": 0},
        )
        self.assertEqual(
            (
                runner.HISTORICAL_NATIVE_STAGE["cleanup"],
                runner.HISTORICAL_NATIVE_STAGE["cleanup_failed"],
                runner.HISTORICAL_NATIVE_STAGE["counts_as_pass"],
            ),
            ("UNCONFIRMED", 6, False),
        )
        self.assertEqual(len(runner.DEFERRED), 2)
        self.assertFalse(any(item["counts_as_pass"] for item in runner.DEFERRED))
        harness = make_harness(sink=FakeSink({"cleanup_done": RuntimeError(CANARY)}))
        harness.fs.fail[("create", self.path("beta.bin"))] = os_error(PermissionError, 13, 5)
        with self.assertRaises(PermissionError):
            harness.setUp()
        harness.doCleanups()
        failure = harness.native_ledger["failure"]
        self.assertEqual((failure["type"], failure["operation"]), ("PermissionError", "make_file"))
        self.assertEqual(harness.checkpoint.ledger["failed"], 1)

    # --- F3: verification error kept apart from the removal error -------------------------

    def test_lstat_verification_error_is_separate_from_removal_error(self):
        harness = make_harness()
        harness.setUp()
        alpha, beta = self.path("alpha.txt"), self.path("beta.bin")
        harness.fs.fail[("unlink", alpha)] = os_error(PermissionError, 13, 5, alpha)
        harness.fs.fail[("lstat", alpha)] = os_error(OSError, 22, 87, alpha)
        harness.fs.fail[("unlink", beta)] = os_error(PermissionError, 13, 5, beta)
        harness.fs.fail[("lstat", beta)] = RuntimeError(CANARY)
        harness.doCleanups()
        entries = {e["name"]: e for e in harness.created}
        removal = entries["alpha.txt"]["error"]
        verification = entries["alpha.txt"]["verification_error"]
        self.assertEqual(
            (removal["operation"], removal["errno"], removal["winerror"]),
            ("cleanup_unlink", 13, 5 if os.name == "nt" else None),
        )
        self.assertEqual(
            (verification["operation"], verification["stage"], verification["type"]),
            ("cleanup_lstat", "cleanup", "OSError"),
        )
        self.assertEqual(
            (verification["errno"], verification["winerror"], verification["target"]),
            (22, 87 if os.name == "nt" else None, "alpha.txt"),
        )
        other = entries["beta.bin"]["verification_error"]
        self.assertEqual(
            (other["type"], other["errno"], other["operation"]),
            ("RuntimeError", None, "cleanup_lstat"),
        )
        self.assertEqual({entries[n]["state"] for n in ("alpha.txt", "beta.bin")}, {"unknown"})
        for name in (None, "sub"):
            self.assertIsNone(entries[name]["verification_error"])
        # One removal call and one verification call per entry: no retry.
        for call in (("unlink", alpha), ("lstat", alpha), ("unlink", beta), ("lstat", beta)):
            self.assertEqual(harness.fs.log.count(call), 1)
        failure = harness.native_ledger["failure"]  # first failure stays the removal projection
        self.assertEqual(failure, entries["beta.bin"]["error"])
        self.assertEqual((failure["operation"], failure["errno"]), ("cleanup_unlink", 13))
        ledger = harness.cleanup_ledger
        self.assertEqual((ledger["failed"], ledger["unknown"]), (2, 2))
        report = owned_report(harness.owned)
        self.assertEqual(
            [r["verification_error"]["operation"] for r in report if r["verification_error"]],
            ["cleanup_lstat", "cleanup_lstat"],
        )
        self.assert_safe(report)
        self.assert_safe(harness.created)
        self.assert_safe(failure)

    def test_only_file_not_found_means_absent_and_success_means_present(self):
        harness = make_harness()
        harness.setUp()
        alpha, beta = self.path("alpha.txt"), self.path("beta.bin")
        harness.fs.fail[("unlink", alpha)] = os_error(PermissionError, 13, 5, alpha)
        harness.fs.fail[("unlink", beta)] = os_error(PermissionError, 13, 5, beta)
        harness.fs.present.discard(alpha)  # lstat -> FileNotFoundError
        harness.doCleanups()
        entries = {e["name"]: e for e in harness.created}
        alpha_entry, beta_entry = entries["alpha.txt"], entries["beta.bin"]
        self.assertEqual((alpha_entry["state"], beta_entry["state"]), ("absent", "present"))
        self.assertEqual(
            (alpha_entry["verification_error"], beta_entry["verification_error"]), (None, None)
        )
        for call in (("lstat", alpha), ("lstat", beta)):
            self.assertEqual(harness.fs.log.count(call), 1)
        refused = make_harness()
        refused.setUp()
        refused.fs.fail[("unlink", alpha)] = os_error(PermissionError, 13, 5, alpha)
        refused.fs.fail[("lstat", alpha)] = os_error(PermissionError, 13, 5, alpha)
        refused.doCleanups()
        entry = next(e for e in refused.created if e["name"] == "alpha.txt")
        self.assertEqual(entry["state"], "unknown")  # a refused lstat is never absence
        self.assertEqual(entry["verification_error"]["errno"], 13)
        self.assertEqual(refused.cleanup_ledger["absent"], 0)


if __name__ == "__main__":
    unittest.main()
