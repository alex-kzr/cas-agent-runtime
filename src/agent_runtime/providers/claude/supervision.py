"""Bounded SDK-worker ownership. Windows verified; other platforms fail closed."""

import asyncio
import os
import subprocess
import time

CLEANUP_SECONDS = 3.0


class OwnedProcess:
    def __init__(self, cleanup_seconds=CLEANUP_SECONDS):
        if type(cleanup_seconds) not in (int, float) or not 0 < cleanup_seconds <= 10:
            raise ValueError("cleanup_seconds must be a number in (0, 10]")
        self.cleanup_seconds = cleanup_seconds
        self.process = None
        self.released = False
        self.cleanup = {
            "mechanism": "windows-job",
            "tree_empty": False,
            "forced": False,
            "deadline_seconds": cleanup_seconds,
        }

    async def run(self, command, payload, environment, *, stderr_sink=None):
        if os.name != "nt":
            raise RuntimeError(
                "Supervised live execution currently requires Windows Job Object support"
            )
        if len(payload) > 1_000_000:
            raise ValueError("Worker input exceeds 1 MB")
        from agent_runtime.providers.claude.windows_job import WindowsJob

        job = WindowsJob()
        spawn = None
        stderr_task = None
        stderr_failure = None
        try:
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(  # noqa: S603 - trusted interpreter argv, no shell
                    *command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE if stderr_sink is not None else subprocess.DEVNULL,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW | 0x00000004,  # CREATE_SUSPENDED
                )
            )
            self.process = await asyncio.shield(spawn)
            # The fixed worker waits for stdin before importing/calling the SDK. No
            # inference process can start before successful containment; failure is closed.
            job.assign(self.process.pid)
            job.resume(self.process.pid)
            self.released = True
            if stderr_sink is None:
                await self.process.communicate(payload)
            else:
                # Drain incrementally; never buffer raw stderr in communicate(). The
                # caller must sanitize chunks before storing anything on disk.
                async def drain_stderr():
                    nonlocal stderr_failure
                    while chunk := await self.process.stderr.read(4096):
                        if stderr_failure is None:
                            try:
                                stderr_sink(chunk)
                            except Exception as error:
                                # Keep draining even when a caller's sink fails.
                                stderr_failure = error

                stderr_task = asyncio.create_task(drain_stderr())
                try:
                    self.process.stdin.write(payload)
                    await self.process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    self.process.stdin.close()
                await self.process.wait()
                await stderr_task
                if stderr_failure is not None:
                    raise RuntimeError("Stderr sink failed") from stderr_failure
            return self.process.returncode
        finally:
            started = time.monotonic()
            try:
                async with asyncio.timeout(self.cleanup_seconds):
                    if self.process is None and spawn is not None:
                        self.process = await asyncio.shield(spawn)
                    if self.process is not None:
                        if not self.released and self.process.returncode is None:
                            self.process.kill()
                        active = job.active()
                        self.cleanup["forced"] = active > 0 or not self.released
                        if active:
                            job.terminate()
                        # Assignment/startup cancellation leaves only the fixed waiting
                        # worker. It has not received input and cannot start the SDK.
                        await self.process.wait()
                        while job.active():
                            await asyncio.sleep(0.01)
                        self.cleanup["tree_empty"] = True
            except (OSError, TimeoutError):
                self.cleanup["tree_empty"] = False
            finally:
                # Closing the non-inheritable job handle kills remaining members even
                # if a second cancellation interrupts the bounded observation await.
                job.close()
                if stderr_task is not None:
                    stderr_task.cancel()
                    await asyncio.gather(stderr_task, return_exceptions=True)
                if self.process is None and spawn is not None:

                    def reap_late_worker(future):
                        if not future.cancelled() and future.exception() is None:
                            process = future.result()
                            if process.returncode is None:
                                process.kill()

                    spawn.add_done_callback(reap_late_worker)
                self.cleanup["duration_ms"] = round((time.monotonic() - started) * 1000)
