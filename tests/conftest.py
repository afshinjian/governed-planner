"""Shared test harness.

Design basis: design/GP-SPK-001-governance-kernel.md §12, §14.

One global fixture, `h`, over pytest's `tmp_path`, mirroring the convention proven
in governed-runtime: every path a test needs is derived from a single root, so
isolation is free and no test invents its own layout.

This module imports only the standard library and pytest. It must stay that way:
conftest is imported at collection time, so a dependency on a package module that
does not exist yet would turn a missing import into a collection error rather than
a test failure.

Process helpers (`spawn`, `wait_for_ready`, `kill9`) exist for the restart and
recovery proofs (ST-10). They are stdlib-only and carry no governance knowledge.

Lifecycle discipline (ST1-R02)
------------------------------
Killing a direct child does NOT close a stdout pipe descriptor that a descendant
inherited. Two consequences drive the design here:

1. Diagnostics are read with a **non-blocking descriptor under a deadline**
   (`os.set_blocking` + `selectors`), never on a helper thread. A background reader
   would outlive the call, keep owning the stream, and make an ordinary later
   `close()` block on the very descendant we were trying not to wait for.
2. **Reaping never depends on the pipe.** `waitpid` is independent of stdout, so
   the child's exit status is collected *before* any diagnostic read. A descendant
   holding the pipe can therefore delay diagnostics but can never delay cleanup.

Five failure categories are kept distinct, because they are five different defects:

* `readiness failure: ... never published ...`   — readiness timeout
* `readiness failure: worker exited ...`         — exited before readiness
* `diagnostic-pipe timeout: ...`                 — stdout held past its deadline
* `cleanup failure: ...`                         — direct child could not be reaped
* `SIGKILL verification failed: ...`             — the kill did not take effect

A diagnostic-pipe timeout is never reported as "worker survived SIGKILL": the
observed exit status decides that question, and it is collected first.
"""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import pytest

READY_TIMEOUT_SECONDS = 90.0
REAP_TIMEOUT_SECONDS = 10.0
DRAIN_TIMEOUT_SECONDS = 5.0
DRAIN_LIMIT_BYTES = 64 * 1024


class ChildCleanupError(RuntimeError):
    """The direct child's exit status could not be collected within the bound.

    Distinct from every readiness failure and from a SIGKILL verification failure:
    those are statements about the worker, this is a statement about cleanup.
    """


class DrainResult(NamedTuple):
    text: str
    timed_out: bool


def _drain_bounded(
    proc: subprocess.Popen[bytes],
    *,
    limit: int = DRAIN_LIMIT_BYTES,
    timeout: float = DRAIN_TIMEOUT_SECONDS,
) -> DrainResult:
    """Collect diagnostics under a hard deadline, leaving nothing running.

    Bounded in time and size, preserves whatever partial output arrived, and closes
    the read descriptor before returning. No thread is started, so nothing survives
    the call and no later operation on the stream can block on a descendant.
    """
    stream = proc.stdout
    if stream is None:
        return DrainResult("", False)

    chunks: list[bytes] = []
    total = 0
    timed_out = False
    try:
        fd = stream.fileno()
        os.set_blocking(fd, False)
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        try:
            deadline = time.monotonic() + timeout
            while total < limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if not selector.select(min(remaining, 0.05)):
                    continue
                try:
                    chunk = os.read(fd, min(65536, limit - total))
                except BlockingIOError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break  # EOF: every writer, descendants included, has closed
                chunks.append(chunk)
                total += len(chunk)
        finally:
            selector.close()
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass

    text = b"".join(chunks).decode("utf-8", errors="replace")
    if timed_out:
        text += f"\n[diagnostic-pipe timeout: stdout still open after {timeout}s]"
    elif total >= limit:
        text += f"\n[diagnostics truncated at {limit} bytes]"
    return DrainResult(text, timed_out)


def _reap(proc: subprocess.Popen[bytes]) -> None:
    """Return only once the direct child's exit status has been collected.

    Raises `ChildCleanupError` rather than swallowing a timeout: a helper that
    claims cleanup it did not perform is worse than one that fails loudly.
    """
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ChildCleanupError(
            f"cleanup failure: direct child pid {proc.pid} did not reap within "
            f"{REAP_TIMEOUT_SECONDS}s"
        ) from exc


def _release_child(proc: subprocess.Popen[bytes]) -> None:
    """Bounded, never-raising release of one spawned process (C5).

    Distinct from `_reap`, deliberately. `_reap` is an assertion about cleanup and
    must raise when it cannot keep its promise. This is teardown: it runs on paths
    where an exception is already in flight, so it terminates, reaps and closes the
    descriptor on a best-effort basis and never masks the original failure.
    """
    try:
        if proc.poll() is None:
            proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=REAP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        pass
    stream = proc.stdout
    if stream is not None and not stream.closed:
        try:
            os.set_blocking(stream.fileno(), False)
        except (OSError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass


@dataclass
class Harness:
    """Every path derived from one root, so tests never invent a layout."""

    root: Path
    _spawned: list[subprocess.Popen[bytes]] = field(default_factory=list, repr=False)

    # -- paths ---------------------------------------------------------------

    @property
    def governance_db(self) -> Path:
        """Ours: owned exclusively by gplanner (design §12)."""
        return self.root / "governance.sqlite"

    @property
    def system_db(self) -> Path:
        """DBOS's own. Opaque: never read or written by governance code."""
        return self.root / "dbos_sys.sqlite"

    @property
    def ready_dir(self) -> Path:
        d = self.root / "ready"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -- process helpers -----------------------------------------------------

    def spawn(self, *args: str, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
        """Launch a worker as a real, separate OS process.

        Binary pipes deliberately: the diagnostic drain reads the raw descriptor,
        and mixing that with a text wrapper's buffering would be unsound.
        """
        environ = dict(os.environ)
        if env:
            environ.update(env)
        proc = subprocess.Popen(
            [sys.executable, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environ,
        )
        self._spawned.append(proc)  # the harness owns its lifetime (C5)
        return proc

    def cleanup(self) -> None:
        """Release every process this harness spawned. Bounded; never raises.

        Guaranteed by the fixture's `finally`, so an exception anywhere in a test
        body -- before `wait_for_ready` or `kill9` is ever reached -- cannot leave a
        live child or an open descriptor behind.
        """
        for proc in self._spawned:
            _release_child(proc)
        self._spawned.clear()

    def wait_for_ready(
        self,
        name: str,
        proc: subprocess.Popen[bytes],
        timeout: float = READY_TIMEOUT_SECONDS,
    ) -> None:
        """Block until the worker publishes `<name>.ready`, or fail loudly.

        The marker is published only after its file *and* the directory entry are
        fsynced, so observing it means the worker genuinely reached that point.

        On both failure paths the child is reaped first (independent of the pipe),
        then diagnostics are read under a deadline.
        """
        marker = self.ready_dir / f"{name}.ready"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker.exists():
                return
            if proc.poll() is not None:
                _reap(proc)
                drained = _drain_bounded(proc)
                pytest.fail(
                    f"readiness failure: worker exited (returncode={proc.returncode}) "
                    f"before publishing {name!r}:\n{drained.text}"
                )
            time.sleep(0.05)
        _reap(proc)
        drained = _drain_bounded(proc)
        pytest.fail(
            f"readiness failure: worker never published {name!r} within {timeout}s "
            f"(returncode={proc.returncode}):\n{drained.text}"
        )

    def kill9(self, proc: subprocess.Popen[bytes]) -> str:
        """Real process termination: SIGKILL, uncatchable, no cleanup runs.

        Asserting the exact signal is the point. A process that exited on its own
        would satisfy a weaker check while proving nothing about crash recovery.

        The exit status is collected before diagnostics, so a descendant holding
        stdout cannot be mistaken for a worker that survived the kill.
        """
        proc.kill()
        _reap(proc)
        drained = _drain_bounded(proc)
        assert proc.returncode == -signal.SIGKILL, (
            f"SIGKILL verification failed: expected death by SIGKILL "
            f"({-signal.SIGKILL}), observed returncode={proc.returncode}"
        )
        return drained.text


@pytest.fixture
def h(tmp_path: Path) -> Iterator[Harness]:
    harness = Harness(root=tmp_path)
    try:
        yield harness
    finally:
        harness.cleanup()
