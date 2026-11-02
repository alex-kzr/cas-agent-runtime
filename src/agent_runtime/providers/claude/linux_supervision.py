"""Linux ownership implementation backed by a dedicated container PID namespace."""

import asyncio
import subprocess
import time

from agent_runtime.providers.claude.linux_namespace import LinuxNamespace


async def run_linux(owner, command, payload, environment, stderr_sink=None):
    boundary = LinuxNamespace()  # Fail before spawning, with tree_empty still false.
    owner.cleanup["mechanism"] = "linux-pid-namespace"
    owner.cleanup["boundary"] = "dedicated-container-pid1-single-execution"
    spawn = None
    stderr_task = None
    stderr_failure = None
    cleanup_task = None
    try:
        spawn = asyncio.create_task(asyncio.create_subprocess_exec(
            *command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE if stderr_sink is not None else subprocess.DEVNULL,
            env=environment, start_new_session=True,
        ))
        owner.process = await asyncio.shield(spawn)
        # The fixed worker reads stdin before importing the SDK. Namespace
        # containment is already active at fork; no parent-side assignment race.
        owner.released = True

        async def drain_stderr():
            nonlocal stderr_failure
            while chunk := await owner.process.stderr.read(4096):
                if stderr_failure is None:
                    try:
                        stderr_sink(chunk)
                    except Exception as error:
                        stderr_failure = error

        if stderr_sink is not None:
            stderr_task = asyncio.create_task(drain_stderr())
        try:
            owner.process.stdin.write(payload)
            await owner.process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            owner.process.stdin.close()
        while owner.process.returncode is None:
            await asyncio.sleep(0.01)
        # Do not wait for stderr EOF here: an escaped descendant can hold it
        # open. Namespace cleanup kills the descendants before draining EOF.
        return owner.process.returncode
    finally:
        started = time.monotonic()

        async def cleanup():
            try:
                async with asyncio.timeout(owner.cleanup_seconds):
                    if owner.process is None and spawn is not None:
                        owner.process = await asyncio.shield(spawn)
                    while True:
                        members = boundary.members()
                        owner.cleanup["forced"] |= bool(members)
                        boundary.terminate()
                        if owner.process is not None:
                            await owner.process.wait()
                        boundary.reap()
                        if not boundary.members():
                            owner.cleanup["tree_empty"] = True
                            break
                        await asyncio.sleep(0.01)
                    if stderr_task is not None:
                        await stderr_task
                    if stderr_failure is not None:
                        raise RuntimeError("Stderr sink failed") from stderr_failure
            except (OSError, TimeoutError):
                owner.cleanup["tree_empty"] = False
            finally:
                # Always issue a synchronous namespace kill, even after repeated
                # cancellation. PID 1 exit is the outer kernel cleanup backstop.
                boundary.terminate()
                if stderr_task is not None and not stderr_task.done():
                    stderr_task.cancel()
                if owner.process is None and spawn is not None:
                    def reap_late_worker(future):
                        if not future.cancelled() and future.exception() is None:
                            process = future.result()
                            if process.returncode is None:
                                process.kill()
                    spawn.add_done_callback(reap_late_worker)
                owner.cleanup["duration_ms"] = round((time.monotonic() - started) * 1000)

        cleanup_task = asyncio.create_task(cleanup())
        # Preserve caller cancellation while letting the bounded cleanup finish,
        # including a second cancellation during cleanup.
        cancelled = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                cancelled = True
        cleanup_task.result()
        if cancelled:
            raise asyncio.CancelledError
