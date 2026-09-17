"""GP-00 — the harness failure paths (ST1-R02 remediation).

Design basis: design/GP-SPK-001-governance-kernel.md §14.

Not one of the eleven spike requirements. These cover the readiness helper's own
failure paths, which the restart proofs (ST-10) will depend on but never exercise:
a recovery test that passes tells you nothing about what happens when the worker
never arrives.

The case that motivated them: killing a direct child does not close a stdout pipe
descriptor a descendant inherited. A thread-based drain bounded the *call* but not
the reader's lifetime — measured leaving a live thread with the stream still open,
after which an ordinary `close()` blocked until the descendant released the writer.
These tests therefore assert resource lifecycle, not just elapsed time.

Every test that creates a descendant kills it deterministically in a finally, so a
failure here cannot leak a 30-second process into the rest of the suite.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    REAP_TIMEOUT_SECONDS,
    ChildCleanupError,
    Harness,
    _drain_bounded,
    _reap,
)

# Exits immediately, publishing nothing.
EXIT_AT_ONCE = "import sys; sys.exit(3)"

# Never publishes and never exits on its own.
HANG_FOREVER = "import time\nwhile True: time.sleep(3600)"

# Exits at once, leaving a descendant that inherits stdout and outlives the drain
# deadline. The descendant records its pid so the test can kill it deterministically.
LEAK_STDOUT = (
    "import subprocess, sys\n"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
    "open(sys.argv[1], 'w').write(str(p.pid))\n"
    "sys.exit(0)\n"
)

# Holds stdout open AND ignores nothing -- the parent SIGKILLs it while a
# descendant still owns the pipe.
HOLD_AND_HANG = (
    "import subprocess, sys, time\n"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
    "open(sys.argv[1], 'w').write(str(p.pid))\n"
    "time.sleep(3600)\n"
)

# Generous: the descendants above live 30s, so exceeding this means we blocked.
BOUND = 25.0


@contextlib.contextmanager
def descendant_killed(pidfile: Path, timeout: float = 10.0) -> Iterator[None]:
    """Deterministically release a descendant this test created.

    The descendant is orphaned once its parent exits, so it cannot be waited on --
    but killing it closes the inherited write descriptor, which is the resource
    that actually matters here.

    Teardown never replaces a failure already in flight. A cleanup problem that
    surfaces while the test body is raising is attached to that exception as a note
    rather than raised: the original failure is what the engineer needs to see, and
    a cleanup `AssertionError` thrown from a `finally` would silently take its
    place. With no exception in flight there is nothing to mask, so a genuine
    cleanup failure is raised normally rather than swallowed.
    """
    original: BaseException | None = None
    try:
        yield
    except BaseException as exc:
        original = exc
        raise
    finally:
        try:
            terminate_descendant(pidfile, timeout=timeout)
        except AssertionError as cleanup_error:
            if original is None:
                raise
            original.add_note(f"cleanup also failed: {cleanup_error}")


def terminate_descendant(pidfile: Path, timeout: float = 10.0) -> None:
    """Kill the recorded descendant and confirm it is gone, under a bound.

    The descendant is orphaned once its parent exits, so this process cannot
    `waitpid` it -- reaping falls to init. What matters here is that it is
    terminated and has released the inherited write descriptor, which polling
    /proc confirms.
    """
    if not pidfile.exists():
        return
    try:
        pid = int(pidfile.read_text().strip())
    except ValueError:
        return
    with contextlib.suppress(ProcessLookupError, OSError):
        os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not os.path.exists(f"/proc/{pid}"):
            return
        time.sleep(0.01)
    raise AssertionError(f"descendant pid {pid} still alive after {timeout}s")


def descendant_alive(pidfile: Path) -> bool:
    if not pidfile.exists():
        return False
    return os.path.exists(f"/proc/{int(pidfile.read_text().strip())}")


def await_descendant(pidfile: Path, timeout: float = 10.0) -> None:
    """Block until the descendant exists and owns the inherited descriptor.

    Without this the direct child can be reaped before it ever forks, leaving the
    pipe with no writer -- which reaches EOF at once and silently turns a
    held-descriptor test into a trivially passing one.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pidfile.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"descendant never recorded its pid at {pidfile}")


class _UnreapableProc:
    """A process double whose exit status can never be collected."""

    returncode: int | None = None
    pid = -1
    stdout = None

    def poll(self) -> int | None:
        return None

    def kill(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired(cmd="unreapable", timeout=timeout or 0.0)


def test_an_early_worker_exit_is_reported_not_waited_on(h: Harness) -> None:
    proc = h.spawn("-c", EXIT_AT_ONCE)
    started = time.monotonic()
    with pytest.raises(pytest.fail.Exception) as excinfo:
        h.wait_for_ready("parked", proc, timeout=BOUND)
    assert time.monotonic() - started < BOUND, "helper waited out the full timeout"
    assert "exited" in str(excinfo.value)
    assert proc.returncode == 3, "the direct child was not reaped"


def test_a_readiness_timeout_kills_and_reaps_the_worker(h: Harness) -> None:
    proc = h.spawn("-c", HANG_FOREVER)
    with pytest.raises(pytest.fail.Exception) as excinfo:
        h.wait_for_ready("parked", proc, timeout=0.2)
    assert "never published" in str(excinfo.value)
    assert proc.returncode is not None, "a timed-out worker was left unreaped"


def test_a_descendant_holding_stdout_cannot_hang_the_failure_path(h: Harness) -> None:
    """The ST1-R02 case: the direct child is gone, but its stdout lives on."""
    pidfile = h.root / "descendant.pid"
    with descendant_killed(pidfile):
        proc = h.spawn("-c", LEAK_STDOUT, str(pidfile))
        await_descendant(pidfile)
        started = time.monotonic()
        with pytest.raises(pytest.fail.Exception):
            h.wait_for_ready("parked", proc, timeout=1.0)
        elapsed = time.monotonic() - started
        assert elapsed < BOUND, (
            f"failure path blocked on an inherited descriptor for {elapsed:.3f}s"
        )
        assert proc.returncode is not None, "the direct child was not reaped"


def test_the_failure_path_abandons_no_reader_and_releases_the_descriptor(h: Harness) -> None:
    """A bounded call is not enough: nothing may outlive it holding the stream."""
    pidfile = h.root / "descendant.pid"
    with descendant_killed(pidfile):
        proc = h.spawn("-c", LEAK_STDOUT, str(pidfile))
        await_descendant(pidfile)
        threads_before = threading.active_count()
        with pytest.raises(pytest.fail.Exception):
            h.wait_for_ready("parked", proc, timeout=1.0)
        assert threading.active_count() == threads_before, "a reader thread was abandoned"
        assert proc.stdout is not None and proc.stdout.closed, "the read descriptor was retained"
        # The decisive check: with no reader left, ordinary cleanup cannot block,
        # even though the descendant still owns the write end.
        started = time.monotonic()
        with contextlib.suppress(OSError):
            proc.stdout.close()
        assert time.monotonic() - started < 1.0, "follow-up close() blocked on the descendant"


def test_a_diagnostic_pipe_timeout_is_labelled_as_such(h: Harness) -> None:
    pidfile = h.root / "descendant.pid"
    with descendant_killed(pidfile):
        proc = h.spawn("-c", LEAK_STDOUT, str(pidfile))
        await_descendant(pidfile)
        _reap(proc)
        drained = _drain_bounded(proc, timeout=0.3)
        assert drained.timed_out is True
        assert "diagnostic-pipe timeout" in drained.text


def test_a_reap_that_cannot_complete_is_reported_not_swallowed() -> None:
    """`_reap` must never return claiming cleanup it did not perform."""
    fake: Any = _UnreapableProc()
    with pytest.raises(ChildCleanupError) as excinfo:
        _reap(fake)
    assert "cleanup failure" in str(excinfo.value)
    assert fake.returncode is None


def test_kill9_reports_the_observed_status_when_a_descendant_holds_stdout(h: Harness) -> None:
    """A held pipe is a diagnostics problem, never evidence the worker survived."""
    pidfile = h.root / "descendant.pid"
    with descendant_killed(pidfile):
        proc = h.spawn("-c", HOLD_AND_HANG, str(pidfile))
        await_descendant(pidfile)
        started = time.monotonic()
        h.kill9(proc)  # must NOT raise "survived SIGKILL"
        assert time.monotonic() - started < BOUND, "kill9 blocked on the inherited descriptor"
        assert proc.returncode == -signal.SIGKILL


def test_the_two_readiness_failures_are_distinguishable_from_a_kill_failure(h: Harness) -> None:
    """A worker that never arrived is a different defect from a kill that missed."""
    exited = h.spawn("-c", EXIT_AT_ONCE)
    with pytest.raises(pytest.fail.Exception) as early:
        h.wait_for_ready("parked", exited, timeout=BOUND)
    assert str(early.value).startswith("readiness failure:")
    assert "SIGKILL verification failed" not in str(early.value)

    hung = h.spawn("-c", HANG_FOREVER)
    with pytest.raises(pytest.fail.Exception) as timed_out:
        h.wait_for_ready("parked", hung, timeout=0.2)
    assert str(timed_out.value).startswith("readiness failure:")
    assert "never published" in str(timed_out.value)
    assert "SIGKILL verification failed" not in str(timed_out.value)


def test_kill9_asserts_the_exact_signal(h: Harness) -> None:
    proc = h.spawn("-c", HANG_FOREVER)
    h.kill9(proc)
    assert proc.returncode == -signal.SIGKILL


def test_an_exceptional_path_releases_child_descendant_and_stdout(h: Harness) -> None:
    """C5: cleanup must hold on the path where no helper ever ran.

    Reproduced before the fix: an exception raised in a test body before
    `wait_for_ready` or `kill9` left the direct child alive and unreaped, its stdout
    open, and the descendant running -- because nothing owned the spawned process.
    The `h` fixture now releases what it spawned in a `finally`; `cleanup()` is that
    same teardown, called directly so the guarantee is assertable.
    """
    pidfile = h.root / "descendant.pid"
    try:
        proc = h.spawn("-c", HOLD_AND_HANG, str(pidfile))
        await_descendant(pidfile)
        assert descendant_alive(pidfile), "probe precondition: descendant should be running"

        # The exceptional path: nothing reaped, nothing drained, an error in flight.
        started = time.monotonic()
        h.cleanup()
        elapsed = time.monotonic() - started

        assert elapsed < REAP_TIMEOUT_SECONDS, f"cleanup itself blocked for {elapsed:.3f}s"
        assert proc.returncode is not None, "direct child was not reaped"
        assert proc.stdout is not None and proc.stdout.closed, "stdout was left open"
    finally:
        terminate_descendant(pidfile)
    assert not descendant_alive(pidfile), "descendant survived cleanup"


def test_the_harness_releases_spawned_children_even_if_a_test_never_does(h: Harness) -> None:
    """The fixture's `finally` is the guarantee; `cleanup()` is idempotent."""
    proc = h.spawn("-c", HANG_FOREVER)
    h.cleanup()
    assert proc.returncode is not None
    assert proc.stdout is not None and proc.stdout.closed
    h.cleanup()  # second call must be harmless
    assert proc.returncode is not None


def _zombie_pid() -> tuple[subprocess.Popen[bytes], int]:
    """A pid whose /proc entry persists and which SIGKILL cannot clear.

    An exited-but-unreaped child is a zombie: `/proc/<pid>` still exists and a
    further SIGKILL is a no-op, so `terminate_descendant` is driven deterministically
    into its timeout branch. Nothing unkillable is involved, and the caller reaps it.
    """
    proc = subprocess.Popen([sys.executable, "-c", ""])
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if proc.poll() is None and os.path.exists(f"/proc/{proc.pid}"):
            break
        if os.path.exists(f"/proc/{proc.pid}"):
            break
        time.sleep(0.01)
    time.sleep(0.2)  # let it exit; deliberately NOT reaped, so it stays a zombie
    return proc, proc.pid


def test_teardown_never_replaces_the_original_test_exception(h: Harness) -> None:
    """C5/Condition 7: a cleanup timeout must not become the reported failure."""
    zombie, pid = _zombie_pid()
    try:
        pidfile = h.root / "zombie.pid"
        pidfile.write_text(str(pid))
        assert os.path.exists(f"/proc/{pid}"), "probe precondition: zombie /proc entry"

        started = time.monotonic()
        with pytest.raises(RuntimeError, match="original failure") as excinfo:
            with descendant_killed(pidfile, timeout=0.3):
                raise RuntimeError("original failure")
        elapsed = time.monotonic() - started

        assert elapsed < 5.0, f"cleanup was not bounded: {elapsed:.3f}s"
        notes = getattr(excinfo.value, "__notes__", [])
        assert any("cleanup also failed" in n for n in notes), (
            "the cleanup problem was discarded instead of attached"
        )
    finally:
        zombie.wait(timeout=10)  # reap the zombie this probe created


def test_a_cleanup_failure_is_reported_when_the_test_body_succeeded(h: Harness) -> None:
    """With nothing to mask, a genuine cleanup failure must still surface."""
    zombie, pid = _zombie_pid()
    try:
        pidfile = h.root / "zombie.pid"
        pidfile.write_text(str(pid))
        with pytest.raises(AssertionError, match="still alive"):
            with descendant_killed(pidfile, timeout=0.3):
                pass
    finally:
        zombie.wait(timeout=10)
