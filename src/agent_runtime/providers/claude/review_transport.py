"""Bounded raw SDK transport for the mean-review scope (RV-01).

The pinned SDK's own line guard counts decoded CHARACTERS and parses JSON before we see it. This
module uses the public custom ``Transport`` seam instead: it owns the NDJSON framing, counts
UTF-8 BYTES for every incoming protocol frame (not only Assistant/Result), and rejects before any
JSON parse or message expansion. Only a complete, valid, in-budget frame resets the idle clock;
raw chunks and stderr never do.

The default subprocess behaviour is delegated to the pinned ``SubprocessCLITransport`` built from
the SAME complete options, wrapped by a narrow subclass that replaces only ``_handle_stderr`` with a
raw byte reader (stderr has its own fixed cap, outside the wire total). That integration reads the
private ``_stdout_stream`` and ``_process.stderr``; it fails closed on an unexpected SDK version or
layout and never widens or edits the installed SDK. Frames are strict JSON (no duplicate keys, no
NaN/Infinity) and every frame/chunk is refused once the idle or stream bound has passed, even if the
awaited read never yielded to the event loop. ``close()`` is bounded by ``cleanup_seconds``; a
failed or timed-out close is recorded as ``cleanup_unknown`` rather than hidden.

Nothing raw is retained: frames are parsed and dropped, failures keep a numeric reason code and
bounded counters only. Provider cancellation is NOT claimed; closing the delegate ends the local
process and the owning Job Object remains the cleanup authority.
"""

import asyncio
import codecs
import json
import time
from dataclasses import replace
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version

from agent_runtime.tasks import review_profile as rp
from agent_runtime.tasks.review_profile import BudgetExceeded

PIN_MODULE = "claude_agent_sdk._internal.transport.subprocess_cli"
PIN_CLASS = "SubprocessCLITransport"
WRAPPER_CLASS = "RawStderrDelegate"


def _strict_pairs(pairs):
    """Duplicate keys (at any depth) make a frame ambiguous, so they are malformed."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name):
    raise ValueError("non-finite constant")


def _finite_float(text):
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    return value


def strict_loads(line):
    """json.loads that rejects duplicate keys, NaN/Infinity and overflowing floats."""
    return json.loads(
        line,
        object_pairs_hook=_strict_pairs,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


class StreamAccountant:
    """Pure, synchronous bound accounting; the unit under test for every raw-stream limit."""

    def __init__(self, profile, clock=time.monotonic):
        self.profile, self.clock = profile, clock
        self.frames = self.blank = self.wire = self.max_frame = self.stderr = 0
        self.results = 0
        self.failure = None
        self.cleanup_unknown = False
        self.on_failure = None
        self.started = self.last_frame = None
        self._parts, self._pending = [], 0
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")

    def start(self):
        self.started = self.last_frame = self.clock()

    # -- failure ------------------------------------------------------------------------
    def fail(self, code):
        if self.failure is None:
            self.failure = code
            if self.on_failure is not None:
                self.on_failure()
        raise BudgetExceeded(self.failure)

    def raise_if_failed(self):
        if self.failure is not None:
            raise BudgetExceeded(self.failure)

    # -- time ---------------------------------------------------------------------------
    def remaining(self):
        """Seconds until the nearer of idle (since the last valid frame) and the deadline."""
        now = self.clock()
        idle = self.last_frame + self.profile.idle_seconds - now
        deadline = self.started + self.profile.stream_deadline_seconds - now
        return max(0.0, min(idle, deadline))

    def check_time(self, now=None):
        """Refuse work after the idle or stream bound, even if the awaited read never checkpointed
        (an immediately ready chunk does not let asyncio.timeout fire). Returns the clock reading
        so an accepted frame resets idle from the same instant it was checked."""
        if self.started is None:
            return now
        now = self.clock() if now is None else now
        if now - self.started >= self.profile.stream_deadline_seconds:
            self.fail(rp.STREAM_DEADLINE)
        if now - self.last_frame >= self.profile.idle_seconds:
            self.fail(rp.IDLE)
        return now

    def expire(self):
        """Attribute a timeout to the nearer bound; timers may fire a clock tick early."""
        now = self.clock()
        idle = self.last_frame + self.profile.idle_seconds - now
        deadline = self.started + self.profile.stream_deadline_seconds - now
        self.fail(rp.STREAM_DEADLINE if deadline <= idle else rp.IDLE)

    # -- incoming bytes -----------------------------------------------------------------
    def feed(self, data):
        """Account one raw chunk (str or bytes); return the complete valid frames (dicts)."""
        self.raise_if_failed()
        self.check_time()
        limits = self.profile
        size = text = None
        try:
            if type(data) is bytes:
                size, text = len(data), self._decoder.decode(data)
            elif type(data) is str:
                size, text = len(data.encode("utf-8")), data
        except UnicodeError:
            # Dropped without chaining: UnicodeError objects carry the raw input.
            size = text = None
        if text is None:
            self.fail(rp.MALFORMED)
        if self.wire + size > limits.max_wire_bytes:
            self.fail(rp.WIRE_BYTES)
        self.wire += size
        frames = []
        parts = text.split("\n")
        for index, part in enumerate(parts):
            # Bounded BEFORE the frame is joined or parsed, even while its newline is missing.
            pending = self._pending + len(part.encode("utf-8"))
            if pending > limits.max_frame_bytes:
                self.fail(rp.FRAME_BYTES)
            self._pending = pending
            self._parts.append(part)
            if index < len(parts) - 1:
                frame = self._complete()
                if frame is not None:
                    frames.append(frame)
        return frames

    def _complete(self):
        line = "".join(self._parts)
        self.max_frame = max(self.max_frame, self._pending)
        self._parts, self._pending = [], 0
        return self._frame(line)

    def _frame(self, line):
        if self.frames + 1 > self.profile.max_frames:
            self.fail(rp.FRAMES)
        self.frames += 1
        if not line.strip():
            self.blank += 1
            return None
        try:
            frame = strict_loads(line)
        except (ValueError, RecursionError):
            frame = None  # JSONDecodeError keeps the whole document; never chain or retain it
        if type(frame) is not dict or type(frame.get("type")) is not str:
            self.fail(rp.MALFORMED)
        now = self.check_time()  # a late frame is refused and can never reset idle
        if frame["type"] == "result":
            self._result(frame)
        if now is not None:
            self.last_frame = now
        return frame

    def _result(self, frame):
        self.results += 1
        if self.results > 1:
            self.fail(rp.TURNS)  # a second terminal result conflicts with exactly one turn
        text = frame.get("result")
        if text is not None and (
            type(text) is not str or len(text.encode("utf-8")) > self.profile.max_raw_final_bytes
        ):
            self.fail(rp.FINAL_BYTES)
        turns = frame.get("num_turns")
        if type(turns) is not int or turns != self.profile.observed_turns:
            self.fail(rp.TURNS)

    def finish(self):
        """End of stream: flush a final unterminated frame under the same bounds, then require
        exactly one terminal result."""
        self.raise_if_failed()
        self.check_time()
        try:
            tail = self._decoder.decode(b"", final=True)
        except UnicodeError:
            tail = None
        if tail is None:
            self.fail(rp.MALFORMED)
        if tail:
            self._parts.append(tail)
            self._pending += len(tail.encode("utf-8"))
            if self._pending > self.profile.max_frame_bytes:
                self.fail(rp.FRAME_BYTES)
        frames = []
        if "".join(self._parts).strip():
            frame = self._complete()
            if frame is not None:
                frames.append(frame)
        if self.results != 1:
            self.fail(rp.NO_RESULT)
        return frames

    # -- stderr -------------------------------------------------------------------------
    def stderr_line(self, line):
        """Decoded-line callback form (not used by the pinned delegate). Never raises."""
        try:
            size = len(str(line).encode("utf-8", errors="replace")) + 1
        except Exception:  # noqa: BLE001 - a hostile object must not break the callback
            size = 1
        self.stderr_bytes(size)

    def stderr_layout_failure(self):
        """The raw reader found an unexpected SDK layout; fail closed, never raise to the reader."""
        if self.failure is None:
            try:
                self.fail(rp.LAYOUT)
            except BudgetExceeded:
                pass

    def stderr_bytes(self, size):
        """Count RAW stderr bytes (whitespace and unterminated data included). Stderr has its OWN
        fixed cap and is not part of the wire total. A chunk that would cross the cap is not added,
        so the counter is bytes accepted within the cap, never a clamped estimate of the overshoot.
        Retains nothing, never resets idle, never raises into the reader."""
        if self.failure is not None:
            return
        if self.stderr + size > self.profile.max_stderr_bytes:
            try:
                self.fail(rp.STDERR_BYTES)
            except BudgetExceeded:
                pass
            return
        self.stderr += size

    def snapshot(self):
        counters = {
            "frames": self.frames,
            "blank_frames": self.blank,
            "wire_bytes": self.wire,
            "max_frame_bytes": self.max_frame,
            "stderr_bytes": self.stderr,
        }
        if self.cleanup_unknown:
            counters["cleanup_unknown"] = True
        if self.failure is not None:
            counters["reason_code"] = self.failure
        return counters


async def _no_prompt():
    return
    yield  # pragma: no cover - makes this an async generator (streaming mode, no prompt)


def verify_sdk():
    try:
        found = version("claude-agent-sdk")
    except PackageNotFoundError:
        raise BudgetExceeded(rp.LAYOUT) from None
    if found != rp.PINNED_SDK_VERSION:
        raise BudgetExceeded(rp.LAYOUT)


def _discard_stderr(_line):
    """Enables the SDK's stderr pipe; the text is never used (the raw reader below owns stderr)."""


def delegate_options(options):
    """The default SDK client adds the stdio permission-prompt flag only for ITS transport.
    A custom transport does not get that, so mirror it. The stderr pipe is also requested (with a
    discarding callback unless the caller set one) so the raw reader has a stream to bound. Every
    other option is forwarded as is."""
    changes = {}
    if getattr(options, "can_use_tool", None) and not getattr(
        options, "permission_prompt_tool_name", None
    ):
        changes["permission_prompt_tool_name"] = "stdio"
    if getattr(options, "stderr", None) is None:
        changes["stderr"] = _discard_stderr
    return replace(options, **changes) if changes else options


@lru_cache(maxsize=1)
def _wrapper_class(base):
    """The intentional wrapper of the pinned class. The SDK's own stderr handler buffers DECODED
    characters and drops whitespace-only lines before any callback, so it cannot enforce a raw byte
    cap. This subclass replaces ONLY that handler with a reader of the raw byte stream that counts
    every chunk (whitespace and unterminated data included) before any framing or decoding."""

    class RawStderrDelegate(base):
        review_accountant = None

        async def _handle_stderr(self):
            counter = self.review_accountant
            stream = getattr(getattr(self, "_process", None), "stderr", None)
            if counter is None or not hasattr(stream, "__aiter__"):
                if counter is not None:
                    counter.stderr_layout_failure()
                return
            try:
                async for chunk in stream:
                    if type(chunk) not in (bytes, bytearray):
                        counter.stderr_layout_failure()
                        return
                    counter.stderr_bytes(len(chunk))
                    if counter.failure is not None:
                        return
            except Exception:  # noqa: BLE001 - a closed pipe at shutdown ends the reader
                return

    return RawStderrDelegate


def default_delegate(options, accountant):
    verify_sdk()
    from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

    base = SubprocessCLITransport
    if (base.__module__, base.__name__) != (PIN_MODULE, PIN_CLASS) or not callable(
        getattr(base, "_handle_stderr", None)
    ):
        raise BudgetExceeded(rp.LAYOUT)
    delegate = _wrapper_class(base)(prompt=_no_prompt(), options=delegate_options(options))
    delegate.review_accountant = accountant
    return delegate


def is_pinned_wrapper(delegate):
    kind = type(delegate)
    base = kind.__mro__[1] if len(kind.__mro__) > 1 else None
    return (
        (kind.__module__, kind.__name__) == (__name__, WRAPPER_CLASS)
        and base is not None
        and (base.__module__, base.__name__) == (PIN_MODULE, PIN_CLASS)
    )


class ReviewTransport:
    """Duck-typed SDK Transport: connect/write/read_messages/close/is_ready/end_input."""

    def __init__(self, profile, options, *, accountant=None, delegate_factory=None):
        self.profile = profile
        self.accountant = accountant or StreamAccountant(profile)
        self._pinned = delegate_factory is None
        if self._pinned and profile.test_only:
            raise PermissionError("Test-only review profiles never reach a real provider")
        self._delegate = (
            delegate_factory(options)
            if delegate_factory is not None
            else default_delegate(options, self.accountant)
        )
        self._closed = False
        self._outgoing = 0
        self._closer = None
        self.accountant.on_failure = self._close_soon

    def _layout_ok(self):
        stream = getattr(self._delegate, "_stdout_stream", None)
        if stream is None or not hasattr(stream, "__aiter__"):
            return False
        return not self._pinned or is_pinned_wrapper(self._delegate)

    def _close_soon(self):
        try:
            self._closer = asyncio.get_running_loop().create_task(self.close())
        except RuntimeError:
            self._closer = None

    async def connect(self):
        self.accountant.start()  # the stream deadline runs from connect
        await self._delegate.connect()
        if not self._layout_ok():
            await self.close()
            self.accountant.fail(rp.LAYOUT)

    async def write(self, data):
        self.accountant.raise_if_failed()
        size = len(str(data).encode("utf-8"))
        if self._outgoing + size > self.profile.max_input_bytes:
            await self.close()
            self.accountant.fail(rp.OUTGOING_BYTES)
        self._outgoing += size
        await self._delegate.write(data)

    def read_messages(self):
        return self._read()

    async def _read(self):
        accountant = self.accountant
        iterator = self._delegate._stdout_stream.__aiter__()
        try:
            while True:
                accountant.raise_if_failed()
                try:
                    async with asyncio.timeout(accountant.remaining()):
                        chunk = await iterator.__anext__()
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    accountant.expire()
                for frame in accountant.feed(chunk):
                    yield frame
            for frame in accountant.finish():
                yield frame
        except BudgetExceeded:
            await self.close()
            raise

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            async with asyncio.timeout(self.profile.cleanup_seconds):
                await self._delegate.close()
        # The budget code is never masked; unconfirmed cleanup is recorded (not hidden) so the
        # owning Job Object stays the cleanup authority and the outcome can be reported honestly.
        except Exception:  # noqa: BLE001
            self.accountant.cleanup_unknown = True

    def is_ready(self):
        return not self._closed and self.accountant.failure is None and self._delegate.is_ready()

    async def end_input(self):
        await self._delegate.end_input()
