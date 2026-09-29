"""`GP-AUTO-ST-07` test support: repositories, fault readers and epochs at `S1` — test code only.

Design basis: AP-11 §16 `GP-AUTO-ST-07` (Tests, Negative tests, Restart/persistence
evidence); AP-09 §6.3 (`GR9-4`, `GR9-5`), §7 (`OB9-1`…`OB9-18`); AP-07 §9.1; plan §8 and
§22 `I7`.

**Repositories are built by real `git`, in a temporary directory only** (§22 `I7`). Every
invocation runs under an isolated environment — no global or system configuration, a fixed
author, committer and date — and asserts that its `-C` target lies under the test's own
temporary base. Nothing here runs `git` against this checkout, and GP-AUTO production code
runs no `git` at all: the observation reads files.

**Fault readers** wrap the production reader. One counts every call — the evidence that a
replay reads nothing. One tampers with the *n*-th result of one operation on one path —
the way each defeat test is fired individually, without depending on a race.

**An epoch at `S1`** is an ingested authorization bound to the repository, resolved by
ST-06, with its `B1` entry written here as a fixture of ST-16's act (as `st06_world.epoch`
labels it). `B2` is left to the act under test.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import st06_world as w
from gpauto import authority, observation
from gpauto.coordination_records import M2PositionEntry
from gpauto.coordination_vocabulary import M2Edge, M2Position
from gpauto.identity import BaselineIdentityId, OwnerAuthorizationId
from gpauto.observation import FILESYSTEM, Read, Reader, Stat
from gpauto.scope_frame import BaselineIdentity, GovernedStage, Project, RepositoryBoundary
from gpauto.store import CoordinationStore
from st03_ingest import IngestRecord, ingest

GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}
"""The isolated fixture environment: no user or system configuration can reach a fixture."""

TRACKED = {"a.txt": b"alpha\n", "src/b.py": b"print('b')\n", "src/deep/c.txt": b"gamma\n"}


@contextmanager
def workspace() -> Iterator[Path]:
    """A temporary base for fixture repositories, removed afterwards. A mutation killer
    takes no pytest fixture, so it makes its own."""
    with tempfile.TemporaryDirectory(prefix="gpauto-st07-") as directory:
        yield Path(directory)


@dataclass(frozen=True)
class Repository:
    """A fixture repository under `base`, and the commit its `main` branch names."""

    base: Path
    path: Path
    commit: str

    def git(self, *args: str) -> str:
        return run_git(self.base, self.path, *args)

    def write(self, relative: str, content: bytes) -> Path:
        target = self.path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    @property
    def location(self) -> str:
        return str(self.path)


def run_git(base: Path, repository: Path, *args: str) -> str:
    """One fixture `git` invocation, confined to `base`."""
    target = repository.resolve()
    assert target.is_relative_to(base.resolve()), (target, base)
    environment = {**os.environ, **GIT_ENVIRONMENT, "HOME": str(base)}
    done = subprocess.run(
        ["git", "-C", str(target), *args],
        env=environment,
        capture_output=True,
        check=True,
    )
    return done.stdout.decode("utf-8").strip()


def repository(
    base: Path, name: str = "repo", files: dict[str, bytes] | None = None, *args: str
) -> Repository:
    """A repository with `files` committed on `main`; `args` are extra `git init` options."""
    path = base / name
    path.mkdir(parents=True)
    run_git(base, path, "init", "-q", "-b", "main", *args)
    made = Repository(base, path, "")
    for relative, content in (files if files is not None else TRACKED).items():
        made.write(relative, content)
    made.git("add", "-A")
    made.git("commit", "-q", "-m", "fixture")
    return Repository(base, path, made.git("rev-parse", "HEAD"))


def head(repo: Repository) -> str:
    return repo.git("rev-parse", "HEAD")


# --- fault readers ---------------------------------------------------------------------------


@dataclass
class CountingReader:
    """The production reader, with every call recorded."""

    base: Reader = FILESYSTEM
    calls: list[tuple[str, bytes]] = field(default_factory=list)

    def lstat(self, path: bytes) -> Stat | None:
        self.calls.append(("lstat", path))
        return self.base.lstat(path)

    def read_regular(self, path: bytes) -> Read | None:
        self.calls.append(("read_regular", path))
        return self.base.read_regular(path)

    def read_link(self, path: bytes) -> bytes | None:
        self.calls.append(("read_link", path))
        return self.base.read_link(path)

    def list_dir(self, path: bytes) -> tuple[bytes, ...] | None:
        self.calls.append(("list_dir", path))
        return self.base.list_dir(path)


Tamper = Callable[[Any], Any]


@dataclass
class FaultReader:
    """The production reader, with the `occurrence`-th result of `op` on the path ending in
    `suffix` passed through `tamper` — and every other result untouched."""

    faults: Mapping[tuple[str, bytes, int], Tamper]
    base: Reader = FILESYSTEM
    seen: dict[tuple[str, bytes], int] = field(default_factory=dict)
    fired: list[tuple[str, bytes, int]] = field(default_factory=list)

    def _through(self, op: str, path: bytes, result: Any) -> Any:
        count = self.seen.get((op, path), 0) + 1
        self.seen[(op, path)] = count
        for (wanted, suffix, occurrence), tamper in self.faults.items():
            if wanted == op and path.endswith(suffix) and occurrence == count:
                self.fired.append((op, path, count))
                return tamper(result)
        return result

    def lstat(self, path: bytes) -> Stat | None:
        return self._through("lstat", path, self.base.lstat(path))  # type: ignore[no-any-return]

    def read_regular(self, path: bytes) -> Read | None:
        return self._through("read_regular", path, self.base.read_regular(path))  # type: ignore[no-any-return]

    def read_link(self, path: bytes) -> bytes | None:
        return self._through("read_link", path, self.base.read_link(path))  # type: ignore[no-any-return]

    def list_dir(self, path: bytes) -> tuple[bytes, ...] | None:
        return self._through("list_dir", path, self.base.list_dir(path))  # type: ignore[no-any-return]


def same_length(replacement: bytes) -> Tamper:
    """A read whose bytes are `replacement` — same length, same witnesses: only the content
    differs, so no torn-read or changed-item test can fire."""

    def tamper(found: Read) -> Read:
        assert len(replacement) == len(found.data)
        return Read(replacement, found.opened, found.closed)

    return tamper


def moved(found: Stat) -> Stat:
    """The same item, with a later modification time in its witness."""
    witness = (*found.witness[:4], found.witness[4] + 1, found.witness[5])
    return Stat(found.kind, found.mode, found.size, witness)


def torn(found: Read) -> Read:
    return Read(found.data[:-1], found.opened, found.closed)


def unreadable(_: Any) -> None:
    return None


def plus(name: bytes) -> Tamper:
    def tamper(found: tuple[bytes, ...]) -> tuple[bytes, ...]:
        return tuple(sorted((*found, name)))

    return tamper


def minus(name: bytes) -> Tamper:
    def tamper(found: tuple[bytes, ...]) -> tuple[bytes, ...]:
        return tuple(n for n in found if n != name)

    return tamper


def absent(_: Any) -> Stat:
    return observation.ABSENT_ITEM


# --- index bytes --------------------------------------------------------------------------------


def rechecksummed(body: bytes) -> bytes:
    """An index body with a correct trailing checksum — a crafted representation that passes
    the integrity check, so a structural test is what must refuse it."""
    return body + hashlib.sha1(body, usedforsecurity=False).digest()


def with_extension(index: bytes, signature: bytes, data: bytes = b"") -> bytes:
    """`index` with one extension appended before a recomputed checksum."""
    body = index[:-20] + signature + struct.pack(">I", len(data)) + data
    return rechecksummed(body)


# --- an epoch at S1 --------------------------------------------------------------------------


@dataclass(frozen=True)
class Epoch:
    store: CoordinationStore
    scope: w.Scope
    root: OwnerAuthorizationId
    s1: M2PositionEntry


def referents(
    s: w.Scope, repo: Repository, branch: str = "main", commit: str | None = None
) -> list[IngestRecord]:
    """The outside party's `RC-10`/`RC-11` rows, bound to the fixture repository."""
    return [
        Project(identity=s.project),
        GovernedStage(identity=s.stage, project=s.project),
        RepositoryBoundary(identity=s.repository, repository_location=repo.location, branch=branch),
        BaselineIdentity(
            identity=s.baseline, committed_history_identity=commit if commit else repo.commit
        ),
        s.contract,
    ]


def epoch_at_s1(
    store: CoordinationStore,
    repo: Repository,
    tag: str = "",
    branch: str = "main",
    commit: str | None = None,
    extra: tuple[IngestRecord, ...] = (),
    *,
    opened: bool = True,
) -> Epoch:
    """Ingest a valid authorization bound to `repo`, resolve it (ST-06) and open its epoch —
    `B1`, a fixture of ST-16's act — unless `opened` is false."""
    s = w.scope(tag)
    root = OwnerAuthorizationId(value=f"root{tag}")
    ingest(store.path, [*referents(s, repo, branch, commit), *extra])
    ingest(store.path, [w.record(s, f"record{tag}", root.value)])
    done = w.resolve(store, s)
    assert isinstance(done, authority.Resolved), done
    s1 = w.m2(root, M2Position.S1_EPOCH_OPENED, M2Edge.B1, None)
    if opened:
        store.create(s1)
    return Epoch(store, s, root, s1)


def other_baseline(tag: str, commit: str) -> BaselineIdentity:
    """A recorded `RC-10` no root here is bound to."""
    return BaselineIdentity(
        identity=BaselineIdentityId(value=f"unbound-baseline{tag}"),
        committed_history_identity=commit,
    )


def snapshot(path: Path) -> dict[str, tuple[int, int, bytes | str]]:
    """Every item under `path`, `.git` included: mode, modification time, and content or
    link target — the before-and-after evidence that nothing was written or refreshed."""
    found: dict[str, tuple[int, int, bytes | str]] = {}
    for directory, directories, files in os.walk(path):
        for name in [*directories, *files]:
            item = Path(directory) / name
            info = item.lstat()
            if item.is_symlink():
                content: bytes | str = os.readlink(item)
            elif item.is_file():
                content = item.read_bytes()
            else:
                content = ""
            found[str(item.relative_to(path))] = (info.st_mode, info.st_mtime_ns, content)
    return found


def stored[R](store: CoordinationStore, kind: type[R]) -> list[R]:
    """The readable records of `kind` in `store`."""
    return [r for r in store.enumerate(kind) if isinstance(r, kind)]  # type: ignore[arg-type]


def store_state(store: CoordinationStore) -> dict[str, tuple[Any, ...]]:
    """Every record of every stored class — the evidence that an act wrote nothing."""
    from gpauto.store_schema import build_catalogue

    return {kind.__name__: store.enumerate(kind) for kind in build_catalogue().by_record}


def main(argv: list[str]) -> int:
    """`st07_world.py <store> <root>`: a fresh process asks for the root's boundary and
    prints what it got and how many repository reads that took — the Class A evidence that
    a restart finds the boundary and never re-observes it (`AV11-14`)."""
    from gpauto.store import open_store

    store = open_store(Path(argv[0]))
    try:
        reader = CountingReader()
        found = observation.fix_entry_boundary(store, OwnerAuthorizationId(value=argv[1]), reader)
    finally:
        store.close()
    identity = found.boundary.boundary.identity.value if hasattr(found, "boundary") else "-"
    print(type(found).__name__, identity, len(reader.calls))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
