"""Bounded SDK-worker ownership. Windows verified; other platforms fail closed."""

import asyncio
import os
import subprocess
import time

CLEANUP_SECONDS = 3.0


class OwnedProcess:
    def __init__(self):
        self.process = None
        self.released = False
        self.cleanup = {
            "mechanism": "windows-job",
            "tree_empty": False,
            "forced": False,
            "deadline_seconds": CLEANUP_SECONDS,
        }

    async def run(self, command, payload, environment):
        if os.name != "nt":
            raise RuntimeError(
                "Supervised live execution currently requires Windows Job Object support"
            )
        if len(payload) > 1_000_000:
            raise ValueError("Worker input exceeds 1 MB")
        from agent_runtime.providers.claude.windows_job import WindowsJob

        job = WindowsJob()
        spawn = None
        try:
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(  # noqa: S603 - trusted interpreter argv, no shell
                    *command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
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
            await self.process.communicate(payload)
            return self.process.returncode
        finally:
            started = time.monotonic()
            try:
                async with asyncio.timeout(CLEANUP_SECONDS):
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
                if self.process is None and spawn is not None:

                    def reap_late_worker(future):
                        if not future.cancelled() and future.exception() is None:
                            process = future.result()
                            if process.returncode is None:
                                process.kill()

                    spawn.add_done_callback(reap_late_worker)
                self.cleanup["duration_ms"] = round((time.monotonic() - started) * 1000)
