"""Synthetic raw-stream tests: fake delegate only. No SDK client, CLI process, network or auth."""

import asyncio
import itertools
import json
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from claude_agent_sdk import ClaudeAgentOptions

from agent_runtime.providers.claude import review_transport as rt
from agent_runtime.tasks import review_profile as rp

BASE = rp.canonical()
PREFIX, SUFFIX = '{"type":"x","p":"', '"}'


def variant(**bounds):
    return BASE.variant(**bounds)


def frame_of(size, wide=False):
    """One JSON object line body of exactly `size` UTF-8 bytes (optionally with 2-byte chars)."""
    room = size - len(PREFIX) - len(SUFFIX)
    padding = ("é" * (room // 2) + "a" * (room % 2)) if wide else "a" * room
    text = PREFIX + padding + SUFFIX
    assert len(text.encode("utf-8")) == size
    return text


def result(turns=1, text="ok", **extra):
    body = {"type": "result", "subtype": "success", "result": text, **extra}
    if turns is not None:
        body["num_turns"] = turns
    return json.dumps(body)


def whole(data):
    return [data]


def per_char(data):
    return list(data)


def per_byte(data):
    raw = data.encode("utf-8")
    return [raw[i : i + 1] for i in range(len(raw))]


def newline_apart(data):
    return [data[:-1], data[-1:]]


def feed_all(acct, chunks):
    frames = []
    for chunk in chunks:
        frames += acct.feed(chunk)
    return frames


def expect_code(test, code, call):
    with test.assertRaises(rp.BudgetExceeded) as caught:
        call()
    test.assertEqual(caught.exception.code, code)
    return caught.exception


class AccountantBoundaryTests(unittest.TestCase):
    def accountant(self, **bounds):
        acct = rt.StreamAccountant(variant(**bounds))
        acct.start()
        return acct

    def test_utf8_frame_boundary_minus_one_exact_plus_one(self):
        limit = 64
        for wide in (False, True):
            for chunker in (whole, per_char, per_byte, newline_apart):
                for size, accepted in ((limit - 1, True), (limit, True), (limit + 1, False)):
                    with self.subTest(wide=wide, chunker=chunker.__name__, size=size):
                        acct = self.accountant(max_frame_bytes=limit)
                        chunks = chunker(frame_of(size, wide) + "\n")
                        if accepted:
                            self.assertEqual(len(feed_all(acct, chunks)), 1)
                            self.assertEqual(acct.max_frame, size)
                        else:
                            expect_code(
                                self,
                                rp.FRAME_BYTES,
                                lambda acct=acct, chunks=chunks: feed_all(acct, chunks),
                            )

    def test_multibyte_frame_under_the_character_limit_is_still_rejected_by_bytes(self):
        acct = self.accountant(max_frame_bytes=64)
        text = frame_of(65, wide=True)
        self.assertLess(len(text), 64)  # the SDK's own character guard would accept this frame
        expect_code(self, rp.FRAME_BYTES, lambda: acct.feed(text + "\n"))

    def test_oversize_is_rejected_before_its_newline_arrives(self):
        acct = self.accountant(max_frame_bytes=64)
        acct.feed("a" * 64)
        expect_code(self, rp.FRAME_BYTES, lambda: acct.feed("a"))
        # A failure is sticky: later input never revives the stream.
        expect_code(self, rp.FRAME_BYTES, lambda: acct.feed(frame_of(20) + "\n"))

    def test_total_wire_boundary_counts_every_byte_including_newlines(self):
        for wide in (False, True):
            line = frame_of(99, wide) + "\n"
            with self.subTest(wide=wide):
                acct = self.accountant(max_frame_bytes=100, max_wire_bytes=300)
                self.assertEqual(len(acct.feed(line * 3)), 3)
                self.assertEqual(acct.wire, 300)
                expect_code(self, rp.WIRE_BYTES, lambda acct=acct: acct.feed("\n"))
                self.assertEqual(acct.wire, 300)  # nothing past the cap is counted as accepted
                acct = self.accountant(max_frame_bytes=100, max_wire_bytes=300)
                expect_code(
                    self, rp.WIRE_BYTES, lambda acct=acct, line=line: acct.feed(line * 3 + "\n")
                )

    def test_frame_count_includes_blank_lines_and_duplicates(self):
        acct = self.accountant(max_frames=5, max_messages=5)
        line = frame_of(30) + "\n"
        self.assertEqual(len(acct.feed(line * 4 + "\n")), 4)
        self.assertEqual((acct.frames, acct.blank), (5, 1))
        expect_code(self, rp.FRAMES, lambda: acct.feed(line))
        acct = self.accountant(max_frames=5, max_messages=5)
        expect_code(self, rp.FRAMES, lambda: acct.feed("\n" * 6))
        self.assertLessEqual(acct.frames, 5)

    def test_empty_bad_and_non_object_frames_fail_closed(self):
        for chunk in (
            "not json\n",
            "[1]\n",
            "{}\n",
            '{"type":5}\n',
            '{"type":"x"\n',
            "null\n",
            "[" * 20000 + "\n",
            b"\xff\xfe\n",
            "\ud800\n",
            5,
            None,
        ):
            with self.subTest(chunk=repr(chunk)[:30]):
                acct = self.accountant()
                expect_code(self, rp.MALFORMED, lambda acct=acct, chunk=chunk: acct.feed(chunk))

    def test_result_frame_guards_turns_and_final_output_size(self):
        for turns in (2, True, False, 0, -1, None, "1", 1.0):
            with self.subTest(turns=turns):
                acct = self.accountant()
                expect_code(
                    self, rp.TURNS, lambda acct=acct, turns=turns: acct.feed(result(turns) + "\n")
                )
        acct = self.accountant()
        self.assertEqual(len(acct.feed(result(1, "x" * 16384) + "\n")), 1)
        expect_code(
            self, rp.FINAL_BYTES, lambda: self.accountant().feed(result(1, "x" * 16385) + "\n")
        )
        # Bytes, not characters: 8192 two-byte characters are exactly the limit.
        self.assertEqual(len(self.accountant().feed(result(1, "é" * 8192) + "\n")), 1)
        expect_code(
            self, rp.FINAL_BYTES, lambda: self.accountant().feed(result(1, "é" * 8193) + "\n")
        )
        expect_code(self, rp.FINAL_BYTES, lambda: self.accountant().feed(result(1, 5) + "\n"))
        acct = self.accountant()
        expect_code(self, rp.TURNS, lambda: acct.feed(result() + "\n" + result() + "\n"))

    def test_finish_requires_exactly_one_result_and_flushes_an_unterminated_tail(self):
        acct = self.accountant()
        expect_code(self, rp.NO_RESULT, acct.finish)
        acct = self.accountant()
        acct.feed(frame_of(30) + "\n")
        expect_code(self, rp.NO_RESULT, acct.finish)
        acct = self.accountant()
        self.assertEqual(acct.feed(result()), [])  # no newline yet
        self.assertEqual(len(acct.finish()), 1)
        acct = self.accountant()
        acct.feed('{"type":"result","num_turns":1')
        expect_code(self, rp.MALFORMED, acct.finish)
        acct = self.accountant(max_frame_bytes=64)
        acct.feed(b"a" * 63 + b"\xc3")  # split character still pending at the end of the stream
        expect_code(self, rp.MALFORMED, acct.finish)

    def test_snapshot_is_bounded_numeric_counters_only(self):
        acct = self.accountant()
        acct.feed(frame_of(40) + "\n" + result() + "\n")
        acct.stderr_line("CANARY_STDERR")
        snapshot = acct.snapshot()
        self.assertEqual(
            set(snapshot),
            {"frames", "blank_frames", "wire_bytes", "max_frame_bytes", "stderr_bytes"},
        )
        self.assertTrue(all(type(v) is int for v in snapshot.values()))
        self.assertEqual(snapshot["stderr_bytes"], len("CANARY_STDERR") + 1)
        self.assertEqual(snapshot["frames"], 2)

    def test_nothing_raw_is_retained_after_success_or_failure(self):
        acct = self.accountant()
        acct.feed('{"type":"x","p":"CANARY_FRAME"}\n')
        acct.stderr_line("CANARY_STDERR")
        self.assertNotIn("CANARY", repr(vars(acct)))
        acct = self.accountant()
        error = expect_code(self, rp.MALFORMED, lambda: acct.feed("CANARY_BAD_JSON\n"))
        self.assertNotIn("CANARY", repr(vars(acct)) + str(error) + repr(error.__context__))
        self.assertIsNone(error.__context__)
        acct = self.accountant()
        error = expect_code(self, rp.MALFORMED, lambda: acct.feed(b"CANARY\xff\n"))
        self.assertIsNone(error.__context__)

    def test_stderr_is_counted_with_its_own_cap_and_never_resets_idle(self):
        acct = rt.StreamAccountant(
            variant(max_stderr_bytes=10), clock=iter([0, 5, 6, 7, 8]).__next__
        )
        acct.start()
        acct.stderr_line("abcd")
        self.assertIsNone(acct.failure)
        self.assertEqual(acct.last_frame, 0)  # stderr never touches the frame clock
        acct.stderr_line("abcdefgh")
        self.assertEqual(acct.failure, rp.STDERR_BYTES)
        expect_code(self, rp.STDERR_BYTES, lambda: acct.feed(frame_of(30) + "\n"))

        class Hostile:
            def __str__(self):
                raise RuntimeError("hostile")

        self.accountant().stderr_line(Hostile())  # never raises into the SDK


class StrictJsonTests(unittest.TestCase):
    def accountant(self):
        acct = rt.StreamAccountant(variant())
        acct.start()
        return acct

    def test_duplicate_keys_at_any_depth_are_malformed(self):
        for line in (
            '{"type":"result","num_turns":2,"num_turns":1,"result":"{}"}',
            '{"type":"result","num_turns":1,"num_turns":1,"result":"{}"}',
            '{"type":"result","type":"x","num_turns":1}',
            '{"type":"assistant","message":{"model":"claude-haiku-5-5","model":"other"}}',
            '{"type":"x","a":{"b":{"c":1,"c":1}}}',
            '{"type":"x","a":[{"k":1,"k":2}]}',
        ):
            with self.subTest(line=line[:50]):
                acct = self.accountant()
                error = expect_code(
                    self, rp.MALFORMED, lambda acct=acct, line=line: acct.feed(line + "\n")
                )
                self.assertEqual(str(error), "analysis_budget_12")
                self.assertIsNone(error.__context__)
        # A duplicate-turn result can never finish successfully.
        acct = self.accountant()
        expect_code(
            self,
            rp.MALFORMED,
            lambda: acct.feed('{"type":"result","num_turns":2,"num_turns":1,"result":"{}"}\n'),
        )
        expect_code(self, rp.MALFORMED, acct.finish)

    def test_non_finite_json_constants_and_numbers_are_malformed(self):
        for line in (
            '{"type":"x","v":NaN}',
            '{"type":"x","v":Infinity}',
            '{"type":"x","v":-Infinity}',
            '{"type":"x","v":[NaN]}',
            '{"type":"x","v":1e999}',
            '{"type":"result","num_turns":1,"cost":NaN,"result":"{}"}',
        ):
            with self.subTest(line=line[:40]):
                acct = self.accountant()
                expect_code(self, rp.MALFORMED, lambda acct=acct, line=line: acct.feed(line + "\n"))

    def test_ordinary_numbers_and_unique_keys_still_pass(self):
        acct = self.accountant()
        frames = acct.feed('{"type":"x","a":{"b":1.5,"c":[1,2,{"d":-3e2}]}}\n' + result() + "\n")
        self.assertEqual(len(frames), 2)
        self.assertEqual(len(acct.finish()), 0)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class LateFrameTests(unittest.IsolatedAsyncioTestCase):
    async def run_stream(self, chunks, advance_to, profile=None, advance_on=0):
        clock = FakeClock()
        profile = profile or BASE.variant()
        accountant = rt.StreamAccountant(profile, clock=clock)

        class Jump(FakeStream):
            count = 0

            async def __anext__(self):
                if self.count == advance_on:
                    clock.now = advance_to  # time passes inside an immediately ready read
                self.count += 1
                return await super().__anext__()

        delegate = FakeDelegate(Jump(chunks))
        transport = rt.ReviewTransport(
            profile, None, accountant=accountant, delegate_factory=lambda options: delegate
        )
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await asyncio.wait_for(read_all(transport), 5)
        return caught.exception.code, accountant, delegate

    async def test_valid_result_after_the_stream_deadline_is_refused(self):
        code, accountant, delegate = await self.run_stream([result() + "\n"], 100.0)
        self.assertEqual(code, rp.STREAM_DEADLINE)
        self.assertEqual(accountant.frames, 0)
        self.assertGreaterEqual(delegate.closed, 1)

    async def test_frame_after_the_idle_bound_is_refused_and_cannot_reset_idle(self):
        code, accountant, _ = await self.run_stream([result() + "\n"], 50.0)
        self.assertEqual(code, rp.IDLE)
        self.assertEqual(accountant.last_frame, 0.0)

    async def test_late_blank_malformed_and_drip_chunks_are_refused(self):
        for chunk in ("\n", "not json\n", "a", "", b""):
            with self.subTest(chunk=chunk):
                code, accountant, _ = await self.run_stream([chunk, result() + "\n"], 100.0)
                self.assertIn(code, (rp.STREAM_DEADLINE, rp.IDLE))
                self.assertEqual(accountant.last_frame, 0.0)

    async def test_expiry_between_frames_of_one_chunk_is_refused(self):
        clock = FakeClock()
        accountant = rt.StreamAccountant(BASE.variant(), clock=clock)
        accountant.start()
        accountant.feed(frame_of(30) + "\n")  # accepted at t=0
        clock.now = 100.0
        expect_code(self, rp.STREAM_DEADLINE, lambda: accountant.feed(result() + "\n"))
        self.assertEqual(accountant.results, 0)
        accountant = rt.StreamAccountant(BASE.variant(), clock=clock)
        clock.now = 0.0
        accountant.start()
        clock.now = 100.0
        expect_code(self, rp.STREAM_DEADLINE, accountant.finish)

    async def test_expiry_inside_one_chunk_refuses_the_second_frame(self):
        # Clock reads: start, chunk check, frame 1 check, frame 2 check (late).
        accountant = rt.StreamAccountant(BASE.variant(), clock=iter([0, 1, 2, 100]).__next__)
        accountant.start()
        text = frame_of(30) + "\n" + result() + "\n"
        expect_code(self, rp.STREAM_DEADLINE, lambda: accountant.feed(text))
        self.assertEqual((accountant.frames, accountant.results), (2, 0))
        self.assertEqual(accountant.last_frame, 2)

    async def test_frame_just_inside_the_bounds_is_accepted(self):
        clock = FakeClock()
        accountant = rt.StreamAccountant(BASE.variant(), clock=clock)
        accountant.start()
        clock.now = 44.9
        self.assertEqual(len(accountant.feed(frame_of(30) + "\n")), 1)  # idle resets at 44.9
        clock.now = 84.0
        self.assertEqual(len(accountant.feed(result() + "\n")), 1)


class RawStderrTests(unittest.IsolatedAsyncioTestCase):
    def wrapper(self, chunks, accountant, process=True):
        class ByteStream:
            def __init__(self):
                self.items = iter(chunks)

            def __aiter__(self):
                return self

            async def __anext__(self):
                try:
                    return next(self.items)
                except StopIteration:
                    raise StopAsyncIteration from None

        class Base:
            def __init__(self, prompt=None, options=None):
                self._process = type("P", (), {"stderr": ByteStream()})() if process else None

            async def _handle_stderr(self):  # replaced by the wrapper
                raise AssertionError("the SDK handler must not run")

        delegate = rt._wrapper_class(Base)()
        delegate.review_accountant = accountant
        return delegate

    async def test_whitespace_only_stderr_is_counted_before_the_sdk_could_drop_it(self):
        accountant = rt.StreamAccountant(BASE)
        accountant.start()
        delegate = self.wrapper([b" " * 65536] * 5, accountant)
        await delegate._handle_stderr()
        self.assertEqual(accountant.failure, rp.STDERR_BYTES)
        self.assertEqual(accountant.stderr, 262144)  # the breaching chunk is NOT added or clamped
        self.assertEqual(accountant.snapshot()["stderr_bytes"], 262144)
        self.assertEqual(accountant.snapshot()["reason_code"], rp.STDERR_BYTES)

    async def test_exact_cap_is_accepted_and_one_more_byte_fails(self):
        for extra, failed in ((b"", False), (b"x", True)):
            with self.subTest(extra=extra):
                accountant = rt.StreamAccountant(BASE)
                accountant.start()
                delegate = self.wrapper([b"\n" * 262143 + b"\r", extra], accountant)
                await delegate._handle_stderr()
                self.assertEqual(accountant.failure == rp.STDERR_BYTES, failed)
                self.assertEqual(accountant.stderr, 262144)

    async def test_unterminated_data_and_no_newline_are_counted_and_nothing_is_retained(self):
        accountant = rt.StreamAccountant(BASE.variant(max_stderr_bytes=10))
        accountant.start()
        delegate = self.wrapper([b"CANARY12", b"34"], accountant)  # 10 bytes, no newline
        await delegate._handle_stderr()
        self.assertIsNone(accountant.failure)
        self.assertEqual(accountant.stderr, 10)
        self.assertNotIn("CANARY", repr(vars(accountant)))

    async def test_stderr_never_resets_the_frame_clock(self):
        clock = FakeClock()
        accountant = rt.StreamAccountant(BASE, clock=clock)
        accountant.start()
        clock.now = 30.0
        await self.wrapper([b"noise"] * 3, accountant)._handle_stderr()
        self.assertEqual(accountant.last_frame, 0.0)

    async def test_missing_process_or_non_bytes_fail_closed(self):
        accountant = rt.StreamAccountant(BASE)
        await self.wrapper([], accountant, process=False)._handle_stderr()
        self.assertEqual(accountant.failure, rp.LAYOUT)
        accountant = rt.StreamAccountant(BASE)
        await self.wrapper(["text"], accountant)._handle_stderr()
        self.assertEqual(accountant.failure, rp.LAYOUT)

    async def test_overflow_closes_the_transport_and_fails_the_stream(self):
        profile = BASE.variant(max_stderr_bytes=10)
        accountant = rt.StreamAccountant(profile)
        delegate = FakeDelegate(FakeStream([], hang=True))
        transport = rt.ReviewTransport(
            profile, None, accountant=accountant, delegate_factory=lambda options: delegate
        )
        task = asyncio.create_task(read_all(transport))
        await asyncio.sleep(0.05)
        await self.wrapper([b" " * 11], accountant)._handle_stderr()
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await asyncio.wait_for(task, 3)
        self.assertEqual(caught.exception.code, rp.STDERR_BYTES)
        self.assertGreaterEqual(delegate.closed, 1)


class CleanupBoundTests(unittest.IsolatedAsyncioTestCase):
    async def test_hanging_close_is_bounded_by_the_profile_and_recorded(self):
        profile = BASE.variant(cleanup_seconds=1)
        delegate = FakeDelegate(FakeStream([]))
        release = asyncio.Event()

        async def hang():
            await release.wait()

        delegate.close = hang
        transport = rt.ReviewTransport(profile, None, delegate_factory=lambda options: delegate)
        started = time.monotonic()
        await transport.close()
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertTrue(transport.accountant.cleanup_unknown)
        self.assertTrue(transport.accountant.snapshot()["cleanup_unknown"])
        self.assertIsNone(transport.accountant.failure)  # never masks or invents a budget code
        release.set()

    async def test_failing_close_is_recorded_and_budget_code_is_kept(self):
        transport, delegate = transport_for(["CANARY not json\n"])

        async def broken():
            raise RuntimeError("CANARY")

        delegate.close = broken
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await asyncio.wait_for(read_all(transport), 5)
        self.assertEqual(caught.exception.code, rp.MALFORMED)
        self.assertTrue(transport.accountant.cleanup_unknown)
        self.assertNotIn("CANARY", repr(transport.accountant.snapshot()))


class FakeStream:
    def __init__(self, chunks, *, delay=0.0, hang=False):
        self.iterator = iter(chunks)
        self.delay, self.hang = delay, hang
        self.released = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        try:
            return next(self.iterator)
        except StopIteration:
            if self.hang:
                await self.released.wait()
            raise StopAsyncIteration from None


class FakeDelegate:
    def __init__(self, stream):
        self._stdout_stream = stream
        self.written, self.closed, self.connected = [], 0, False

    async def connect(self):
        self.connected = True

    async def write(self, data):
        self.written.append(data)

    async def close(self):
        self.closed += 1
        if self._stdout_stream is not None:
            self._stdout_stream.released.set()

    def is_ready(self):
        return self.connected and not self.closed

    async def end_input(self):
        pass


def transport_for(chunks, profile=None, **stream):
    delegate = FakeDelegate(FakeStream(chunks, **stream))
    profile = profile or BASE
    return rt.ReviewTransport(profile, None, delegate_factory=lambda options: delegate), delegate


async def read_all(transport):
    await transport.connect()
    return [frame async for frame in transport.read_messages()]


class TransportStreamTests(unittest.IsolatedAsyncioTestCase):
    async def fails(self, transport, code, timeout=6):
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await asyncio.wait_for(read_all(transport), timeout)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    async def test_valid_stream_is_accepted_whole_and_counted(self):
        lines = [frame_of(40) + "\n", frame_of(50) + "\n", result() + "\n"]
        transport, delegate = transport_for(lines)
        frames = await asyncio.wait_for(read_all(transport), 5)
        self.assertEqual([f["type"] for f in frames], ["x", "x", "result"])
        snapshot = transport.accountant.snapshot()
        self.assertEqual(snapshot["frames"], 3)
        self.assertEqual(snapshot["wire_bytes"], sum(len(line.encode()) for line in lines))
        self.assertNotIn("reason_code", snapshot)
        self.assertEqual(delegate.closed, 0)

    async def test_outer_limits_never_truncate_an_exact_full_stream_late(self):
        lines = [frame_of(100) + "\n", frame_of(100, wide=True) + "\n", result() + "\n"]
        total = sum(len(line.encode()) for line in lines)
        exact = variant(max_frames=3, max_messages=3, max_frame_bytes=200, max_wire_bytes=total)
        transport, _ = transport_for(lines, exact)
        self.assertEqual(len(await asyncio.wait_for(read_all(transport), 5)), 3)
        short = variant(max_frames=3, max_messages=3, max_frame_bytes=200, max_wire_bytes=total - 1)
        transport, delegate = transport_for(lines, short)
        await self.fails(transport, rp.WIRE_BYTES)
        self.assertGreaterEqual(delegate.closed, 1)
        fewer = variant(max_frames=2, max_messages=2, max_frame_bytes=200, max_wire_bytes=total)
        transport, _ = transport_for(lines, fewer)
        await self.fails(transport, rp.FRAMES)

    async def test_empty_and_bad_streams_fail_and_close_the_delegate(self):
        for chunks, code in (
            ([], rp.NO_RESULT),
            (["\n", "\n"], rp.NO_RESULT),
            (["CANARY not json\n"], rp.MALFORMED),
            ([frame_of(30) + "\n"], rp.NO_RESULT),
        ):
            with self.subTest(chunks=chunks):
                transport, delegate = transport_for(chunks)
                error = await self.fails(transport, code)
                self.assertNotIn("CANARY", str(error))
                self.assertGreaterEqual(delegate.closed, 1)

    async def test_infinite_streams_stop_at_the_frame_wire_or_frame_byte_cap(self):
        for chunks, code in (
            (itertools.repeat(frame_of(30) + "\n"), rp.FRAMES),
            (itertools.repeat("\n"), rp.FRAMES),
            (itertools.repeat("a" * 1000), rp.FRAME_BYTES),
            (itertools.repeat(frame_of(1_000_000) + "\n"), rp.WIRE_BYTES),
        ):
            transport, delegate = transport_for(chunks)
            await self.fails(transport, code, timeout=30)
            self.assertGreaterEqual(delegate.closed, 1)

    async def test_silent_stream_ends_at_the_idle_bound(self):
        transport, delegate = transport_for(
            [], variant(idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3), hang=True
        )
        started = time.monotonic()
        await self.fails(transport, rp.IDLE)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertGreaterEqual(delegate.closed, 1)

    async def test_drip_of_chunks_without_a_complete_frame_does_not_reset_idle(self):
        profile = variant(idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3)
        transport, _ = transport_for(itertools.repeat("a"), profile, delay=0.2)
        started = time.monotonic()
        await self.fails(transport, rp.IDLE)
        self.assertLess(time.monotonic() - started, 2.0)

    async def test_stderr_noise_does_not_reset_idle(self):
        profile = variant(idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3)
        transport, _ = transport_for([], profile, hang=True)

        async def noise():
            while True:
                transport.accountant.stderr_line("x")
                await asyncio.sleep(0.1)

        task = asyncio.create_task(noise())
        try:
            started = time.monotonic()
            await self.fails(transport, rp.IDLE)
            self.assertLess(time.monotonic() - started, 2.0)
        finally:
            task.cancel()

    async def test_valid_frames_forever_still_end_at_the_stream_deadline(self):
        profile = variant(idle_seconds=1, stream_deadline_seconds=2, execution_seconds=3)
        transport, _ = transport_for(itertools.repeat(frame_of(30) + "\n"), profile, delay=0.4)
        started = time.monotonic()
        await self.fails(transport, rp.STREAM_DEADLINE)
        self.assertLess(time.monotonic() - started, 3.5)

    async def test_stderr_overflow_closes_the_delegate_and_fails_the_stream(self):
        transport, delegate = transport_for([], variant(max_stderr_bytes=10), hang=True)
        task = asyncio.create_task(read_all(transport))
        await asyncio.sleep(0.1)
        transport.accountant.stderr_line("x" * 20)
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await asyncio.wait_for(task, 3)
        self.assertEqual(caught.exception.code, rp.STDERR_BYTES)
        self.assertGreaterEqual(delegate.closed, 1)

    async def test_budget_failure_never_yields_a_late_result(self):
        # A result that would otherwise be accepted must not survive a later frame breach.
        lines = [result() + "\n", frame_of(20) + "\n", frame_of(20) + "\n"]
        transport, _ = transport_for(lines, variant(max_frames=2, max_messages=2))
        await transport.connect()
        seen = []
        with self.assertRaises(rp.BudgetExceeded):
            async for frame in transport.read_messages():
                seen.append(frame["type"])
        self.assertEqual(seen, ["result", "x"])
        self.assertEqual(transport.accountant.failure, rp.FRAMES)
        self.assertFalse(transport.is_ready())

    async def test_unexpected_layout_fails_closed_and_closes(self):
        for stream in (None,):
            delegate = FakeDelegate(stream)
            transport = rt.ReviewTransport(
                BASE.variant(max_messages=8), None, delegate_factory=lambda o, d=delegate: d
            )
            with self.assertRaises(rp.BudgetExceeded) as caught:
                await transport.connect()
            self.assertEqual(caught.exception.code, rp.LAYOUT)
            self.assertGreaterEqual(delegate.closed, 1)
        delegate = FakeDelegate(FakeStream([]))
        del delegate._stdout_stream
        transport = rt.ReviewTransport(
            BASE.variant(max_messages=8), None, delegate_factory=lambda o: delegate
        )
        with self.assertRaises(rp.BudgetExceeded):
            await transport.connect()

    async def test_pinned_class_is_required_without_an_injected_delegate(self):
        delegate = FakeDelegate(FakeStream([]))
        with patch.object(rt, "default_delegate", lambda options, accountant: delegate):
            transport = rt.ReviewTransport(BASE, None)
            with self.assertRaises(rp.BudgetExceeded) as caught:
                await transport.connect()
        self.assertEqual(caught.exception.code, rp.LAYOUT)

    async def test_outgoing_writes_are_bounded(self):
        transport, delegate = transport_for([], variant(max_input_bytes=10))
        await transport.connect()
        await transport.write("12345")
        await transport.write("éé")  # 4 bytes: exactly 9 so far
        self.assertEqual(delegate.written, ["12345", "éé"])
        with self.assertRaises(rp.BudgetExceeded) as caught:
            await transport.write("ab")
        self.assertEqual(caught.exception.code, rp.OUTGOING_BYTES)
        self.assertGreaterEqual(delegate.closed, 1)
        self.assertEqual(delegate.written, ["12345", "éé"])

    async def test_close_is_idempotent_even_if_the_delegate_fails(self):
        transport, delegate = transport_for([])

        async def broken():
            raise RuntimeError("CANARY")

        delegate.close = broken
        await transport.close()
        await transport.close()
        self.assertFalse(transport.is_ready())


class PinnedIntegrationTests(unittest.TestCase):
    def test_test_only_profiles_never_build_the_real_delegate(self):
        with self.assertRaises(PermissionError):
            rt.ReviewTransport(variant(max_messages=8), None)

    def test_sdk_version_pin_fails_closed(self):
        with patch.object(rt, "version", return_value="0.0.1"):
            expect_code(self, rp.LAYOUT, rt.verify_sdk)
        with patch.object(rt, "version", side_effect=rt.PackageNotFoundError()):
            expect_code(self, rp.LAYOUT, rt.verify_sdk)

    def test_installed_sdk_matches_the_pin(self):
        rt.verify_sdk()

    def test_complete_options_are_forwarded_with_the_default_stdio_permission_flag(self):
        async def permit(*args):
            return None

        options = ClaudeAgentOptions(model="m", can_use_tool=permit, cli_path="mock-never-executed")
        forwarded = rt.delegate_options(options)
        self.assertEqual(forwarded.permission_prompt_tool_name, "stdio")
        self.assertIs(forwarded.stderr, rt._discard_stderr)  # the stderr pipe is requested
        restored = replace(forwarded, permission_prompt_tool_name=None, stderr=None)
        self.assertEqual(restored, options)
        plain = ClaudeAgentOptions(model="m", cli_path="mock-never-executed")
        self.assertEqual(replace(rt.delegate_options(plain), stderr=None), plain)
        own = ClaudeAgentOptions(model="m", cli_path="x", stderr=print)
        self.assertIs(rt.delegate_options(own), own)  # a caller's callback is preserved

    def test_default_delegate_is_the_pinned_wrapper_and_starts_nothing(self):
        options = ClaudeAgentOptions(model="m", cli_path="mock-never-executed")
        accountant = rt.StreamAccountant(BASE)
        with (
            patch("subprocess.Popen", side_effect=AssertionError("no process")),
            patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
        ):
            delegate = rt.default_delegate(options, accountant)
        self.assertTrue(rt.is_pinned_wrapper(delegate))
        self.assertEqual(
            (type(delegate).__mro__[1].__module__, type(delegate).__mro__[1].__name__),
            (rt.PIN_MODULE, rt.PIN_CLASS),
        )
        self.assertIs(delegate.review_accountant, accountant)
        self.assertIsNone(delegate._stdout_stream)
        # The intentional wrapper is accepted; an unrelated look-alike class is not.
        self.assertFalse(rt.is_pinned_wrapper(FakeDelegate(None)))


if __name__ == "__main__":
    unittest.main()
