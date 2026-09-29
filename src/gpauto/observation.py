"""The GP-AUTO observation module: the one entry observation per resolved root, and `B2`.

Design basis: AP-11 §16 GP-AUTO-ST-07; AP-09 §6.3 (`GR9-1`…`GR9-8`), §7 (`OB9-1`…`OB9-18`);
AP-07 §9.1 (`RS7-1`…`RS7-5`); AP-10 IX-1, IX-1a, IX-2; AP-04 `B2`, `K-5`, `V-14`, `RP-4`;
AP-07 `WP-11`, `WP-12`, `MC-3`, `MC-19`, `CW-2`; `AP03-I08`. OWNER decisions
`ST07-OWNER-DECISION-01 = A_WITH_CONSTRAINT` and `ST07-OWNER-DECISION-02 = A`.

**The observation reads and never writes, and executes nothing** (`GR9-4`, `GR9-5`,
`OB9-8`). Every repository byte arrives through one read-only reader: `os.lstat` to classify
an item without following it, one no-follow, non-blocking, read-only `os.open` of a regular
file, `os.readlink` for a link, `os.scandir` to list a directory. **No component of any path
is followed** — not only the last: each path is reached from `/` one directory at a time,
each directory classified and opened no-follow relative to the one before, and every
operation is made relative to the directory so reached. A link, `.` or `..` at any
intermediate component makes the item unreadable, and so the observation indeterminate: no
item outside the directories actually reached can influence it. There is no `git` process
and no subprocess of any kind: a Git process reads repository configuration, and nothing
could show that every hook, filter, `textconv`, diff driver, pager, alias and `fsmonitor`
it might run was excluded. A reader that runs nothing excludes them by construction. The
reader writes no index, ref, object, configuration, hook or working-tree file, and refreshes
no stat cache.

**Five subjects, kept apart** (AP-09 §7.1): the commit `HEAD` resolves to (the baseline); the
branch `HEAD` names; the commit that branch's ref names (the committed-history identity); the
index's content entries — path, blob identity, mode, stage and the intent-to-add and
skip-worktree flags, never a stat field, size or timestamp (`OB9-1`); and every item of the
working tree by content identity and mode, never by timestamp (`OB9-2`). Tracked and
untracked items alike are observed, ignored ones included, and legacy `.coord` content with
them: there is no exemption, allowlist or exclude rule (`OB9-4`, `IX-1a`, `IX-2`). The one
directory not walked as working-tree content is the repository's own `.git` directory, whose
contents are subjects 1…4. A working-tree item's content identity is ST-02's one derivation
(`identify_artifact_content`), and no second digest exists for content.

**Coherence is three conditions, all required** (`OB9-9a`). (i) Each subject comes from a
representation verifiable as one state: the index by its trailing checksum and its own
structure, the committed history by the content-addressed commit identity, each working-tree
item by its own content identity. (ii) No authorized writer exists: the epoch is at `S1` and
no M3 subject of the root is live (`K-5`), read from records before any repository byte is
read. (iii) No defeat test fires (`OB9-9b`): an integrity failure, a torn read, a subject
differing between the two reads of one determination, a witness differing across the window,
an item appearing, disappearing or changing mid-walk, an unreadable subject, or a mode the
reader cannot take. **Matching witnesses establish nothing** (`OB9-9`, `AV11-2`): a witness
round is a defeat test only, and equality of the two rounds never overrides another defeat.

**The honest limit is retained, not closed** (`OB9-9c`). A change made and restored inside the
window that leaves no indication in any determined subject is not detected. Nothing here
claims an atomic snapshot, a coherence guarantee, the absence of an external writer, or
anything about who wrote what.

**Indeterminate means nothing is kept** (`OB9-9d`, `OB9-11`). No partial result, no per-subject
salvage, no value spliced from two reads, no "latest", and no retry. Recording the
indeterminacy and halting are `GP-AUTO-ST-16`'s; this module returns it and writes nothing.

**Fixable only against the bound referents** (`ST07-OWNER-DECISION-01`). A determinate
observation becomes the boundary only when the observed branch is exactly the root's `RA-04`
branch and the observed commit is exactly its `RA-05` committed-history identity — string
equality, no normalization, no abbreviation. Otherwise the result is
`Indeterminate(NOT_FIXABLE_AGAINST_BOUND_REFERENTS)`: no guard, refusal class or re-binding
is added, and nothing is written.

**One boundary per resolved root, never re-observed** (`RS7-1`, `OB9-14`, `AV11-14`). The key
— the resolved root — is read first. A recorded boundary is returned as it is, and the
repository is not read at all. Otherwise the boundary and its `S2` position entry are
created as one unit (`WP-12`) or not at all. No function here takes a boundary and yields
another.

**SHA-1 verifies the index checksum and does nothing else** (`ST07-OWNER-DECISION-02`). It is
called once, in `_index_checksum_holds`, which answers only whether the checksum holds. The
digest is never returned, stored, encoded or used as any identity.

Guard identifiers are fixed where each guard is written (`MU11-3`): `ga_observation_read_only`,
`ga_observation_coherence`, `ga_observation_defeat` and `ga_entry_once_per_root`.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from gpauto import authority
from gpauto import derivations as dv
from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.absence import KnownAbsent, Present
from gpauto.content_identity import identify_artifact_content
from gpauto.coordination_identity import M2PositionEntryId
from gpauto.coordination_records import (
    AuthorityEnvelopeRecord,
    EntryStateBoundaryRecord,
    M2PositionEntry,
)
from gpauto.coordination_vocabulary import M2Edge, M2Position, M3Position
from gpauto.identity import BaselineIdentityId, EntryStateBoundaryId, OwnerAuthorizationId
from gpauto.minting import mint_value
from gpauto.repository import EntryStateBoundary
from gpauto.scope_frame import BaselineIdentity, RepositoryBoundary
from gpauto.store import CoordinationStore, WriteRefused

# --- the reader seam ----------------------------------------------------------------------


class Kind(StrEnum):
    """What one `lstat` found. `OTHER` is a FIFO, socket or device: never opened."""

    DIRECTORY = "DIRECTORY"
    FILE = "FILE"
    LINK = "LINK"
    OTHER = "OTHER"
    ABSENT = "ABSENT"


@dataclass(frozen=True)
class Stat:
    """One item's kind and mode, with the fields that witness it did not change while read.

    `witness` is device, inode, mode, size and the modification and change times. It is a
    defeat witness only — never a subject (`OB9-2`): no element records any of it.
    """

    kind: Kind
    mode: int
    size: int
    witness: tuple[int, ...]


ABSENT_ITEM: Final = Stat(Kind.ABSENT, 0, 0, ())


@dataclass(frozen=True)
class Read:
    """A regular file's bytes, with its `fstat` when opened and after the last read."""

    data: bytes
    opened: Stat
    closed: Stat


class Reader(Protocol):
    """The one seam every repository byte crosses. `None` means unreadable; an `OSError`
    never crosses it, and nothing else is caught (§10 rule 9)."""

    def lstat(self, path: bytes) -> Stat | None: ...

    def read_regular(self, path: bytes) -> Read | None: ...

    def read_link(self, path: bytes) -> bytes | None: ...

    def list_dir(self, path: bytes) -> tuple[bytes, ...] | None: ...


def _kind(mode: int) -> Kind:
    if stat.S_ISDIR(mode):
        return Kind.DIRECTORY
    if stat.S_ISLNK(mode):
        return Kind.LINK
    if stat.S_ISREG(mode):
        return Kind.FILE
    return Kind.OTHER  # guard:ga_observation_read_only


def _stat(info: os.stat_result) -> Stat:
    witness = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    return Stat(_kind(info.st_mode), info.st_mode, info.st_size, witness)


def _open(name: bytes, directory: int | None, kind: int) -> int:
    """The one open: read-only, no-follow, close-on-exec, relative to `directory`. `kind` is
    `O_NONBLOCK` for a regular file and `O_DIRECTORY` for a directory."""
    flags = (
        os.O_RDONLY  # guard:ga_observation_read_only
        | os.O_NOFOLLOW  # guard:ga_observation_read_only
        | os.O_CLOEXEC
        | kind
    )
    return os.open(name, flags, dir_fd=directory)


def _step(directory: int, component: bytes) -> int | Stat | None:
    """One intermediate component below `directory`: the directory it names, opened
    no-follow; absent; or unreadable — a link, `.`, `..`, or anything that cannot be opened.
    A link is refused here, not followed, whatever it points at."""
    if component in (b".", b".."):  # guard:ga_observation_read_only
        return None
    try:
        info = os.lstat(component, dir_fd=directory)
    except FileNotFoundError:
        return ABSENT_ITEM
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode):  # guard:ga_observation_read_only
        return None
    if not stat.S_ISDIR(info.st_mode):
        return ABSENT_ITEM
    try:
        return _open(component, directory, os.O_DIRECTORY)
    except OSError:
        return None


def _parent(path: bytes) -> tuple[int, bytes] | Stat | None:
    """The open directory holding `path`'s last component, with that component.

    Reached from `/` one component at a time by `_step` — never by the kernel resolving the
    whole path, which would follow a link at any intermediate component. An unreadable
    intermediate makes the item unreadable (`None`), so no item outside the directories
    actually reached can influence a read; a missing or non-directory intermediate makes it
    absent, as `lstat` of the whole path would say."""
    *ancestors, name = path.split(b"/")
    if name in (b"", b".", b".."):
        return None
    try:
        directory = _open(b"/" if path.startswith(b"/") else b".", None, os.O_DIRECTORY)
    except OSError:
        return None
    for component in ancestors:
        if not component:
            continue
        child = _step(directory, component)
        os.close(directory)
        if not isinstance(child, int):
            return child
        directory = child
    return directory, name


def _lstat(path: bytes) -> Stat | None:
    """Classify without following: a link is a link (`GR9-4`), at every component."""
    reached = _parent(path)
    if not isinstance(reached, tuple):
        return reached
    directory, name = reached
    try:
        info = os.lstat(name, dir_fd=directory)  # guard:ga_observation_read_only
    except (FileNotFoundError, NotADirectoryError):
        return ABSENT_ITEM
    except OSError:
        return None
    finally:
        os.close(directory)
    return _stat(info)


def _read_regular(path: bytes) -> Read | None:
    """One read-only, no-follow, non-blocking open; the descriptor is never written to."""
    reached = _parent(path)
    if not isinstance(reached, tuple):
        return None
    directory, name = reached
    try:
        descriptor = _open(name, directory, os.O_NONBLOCK)
    except OSError:
        return None
    finally:
        os.close(directory)
    try:
        opened = _stat(os.fstat(descriptor))
        chunks: list[bytes] = []
        chunk = os.read(descriptor, 1 << 16)
        while chunk:
            chunks.append(chunk)
            chunk = os.read(descriptor, 1 << 16)
        closed = _stat(os.fstat(descriptor))
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return Read(b"".join(chunks), opened, closed)


def _read_link(path: bytes) -> bytes | None:
    reached = _parent(path)
    if not isinstance(reached, tuple):
        return None
    directory, name = reached
    try:
        return os.readlink(name, dir_fd=directory)
    except OSError:
        return None
    finally:
        os.close(directory)


def _list_dir(path: bytes) -> tuple[bytes, ...] | None:
    """A directory's names, the directory itself opened no-follow: a link is never listed."""
    reached = _parent(path)
    if not isinstance(reached, tuple):
        return None
    directory, name = reached
    try:
        listed = _open(name, directory, os.O_DIRECTORY)
    except OSError:
        return None
    finally:
        os.close(directory)
    try:
        with os.scandir(listed) as entries:
            return tuple(sorted(os.fsencode(entry.name) for entry in entries))
    except OSError:
        return None
    finally:
        os.close(listed)


class FilesystemReader:
    """The production reader. Each method looks its function up when called, so the reader
    is nothing but the four module functions above."""

    def lstat(self, path: bytes) -> Stat | None:
        return _lstat(path)

    def read_regular(self, path: bytes) -> Read | None:
        return _read_regular(path)

    def read_link(self, path: bytes) -> bytes | None:
        return _read_link(path)

    def list_dir(self, path: bytes) -> tuple[bytes, ...] | None:
        return _list_dir(path)


FILESYSTEM: Final = FilesystemReader()


# --- results -------------------------------------------------------------------------------


class ObservationCause(StrEnum):
    """Why an observation is indeterminate — enumerated, never an exception (`OB9-9b`)."""

    FORBIDDEN_OR_UNSUPPORTED_MODE = "FORBIDDEN_OR_UNSUPPORTED_MODE"
    INTEGRITY_CHECK_FAILED = "INTEGRITY_CHECK_FAILED"
    TORN_READ = "TORN_READ"
    SUBJECT_DIFFERED_BETWEEN_READS = "SUBJECT_DIFFERED_BETWEEN_READS"
    WITNESS_DIFFERED = "WITNESS_DIFFERED"
    ITEM_APPEARED = "ITEM_APPEARED"
    ITEM_DISAPPEARED = "ITEM_DISAPPEARED"
    ITEM_CHANGED = "ITEM_CHANGED"
    UNREADABLE_SUBJECT = "UNREADABLE_SUBJECT"
    NOT_FIXABLE_AGAINST_BOUND_REFERENTS = "NOT_FIXABLE_AGAINST_BOUND_REFERENTS"


@dataclass(frozen=True)
class Observation:
    """The five subjects of one coherent determination (AP-09 §7.1), each its own field.

    `baseline` is the commit `HEAD` resolves to; `branch` the branch `HEAD` names, as raw
    ref-name bytes, `None` when `HEAD` is detached; `committed_history` the commit that
    branch's ref names, `None` when detached or unborn. `index` and `working_tree` are the
    `RC-17` elements, in ascending raw-path order — an inert order nothing reads.
    """

    baseline: str | None
    branch: bytes | None
    committed_history: str | None
    index: tuple[str, ...]
    working_tree: tuple[str, ...]


@dataclass(frozen=True)
class Determinate:
    observation: Observation


@dataclass(frozen=True)
class Indeterminate:
    """No observation: only why, in the enumeration's order. Nothing of it is kept."""

    causes: tuple[ObservationCause, ...]


class NotFixedReason(StrEnum):
    UNREADABLE_RECORDS = "UNREADABLE_RECORDS"
    INCONSISTENT_RECORDS = "INCONSISTENT_RECORDS"
    EPOCH_NOT_AT_S1 = "EPOCH_NOT_AT_S1"
    WRITE_DOMAIN_NOT_EXCLUSIVE = "WRITE_DOMAIN_NOT_EXCLUSIVE"
    PREFLIGHT_NOT_PERMITTED = "PREFLIGHT_NOT_PERMITTED"
    REFERENTS_UNAVAILABLE = "REFERENTS_UNAVAILABLE"
    OBSERVATION_INDETERMINATE = "OBSERVATION_INDETERMINATE"
    B2_REFUSED = "B2_REFUSED"
    WRITE_REFUSED = "WRITE_REFUSED"


@dataclass(frozen=True)
class NotFixed:
    """No boundary was fixed, and nothing was written. `observation` says why an observation
    could not be fixed; `refused` is ST-05's refusal of `B2`, where it was evaluated."""

    reason: NotFixedReason
    observation: Indeterminate | None = None
    refused: sm.Refused | None = None


@dataclass(frozen=True)
class Fixed:
    """`B2` holds: the boundary and its `S2` entry were created now, as one unit."""

    boundary: EntryStateBoundaryRecord
    entry: M2PositionEntry


@dataclass(frozen=True)
class Replayed:
    """The root's boundary was already fixed. It is returned as recorded, and the repository
    was not read (`AV11-14`, `OB9-14`)."""

    boundary: EntryStateBoundaryRecord
    entry: M2PositionEntry


# --- index checksum: the one SHA-1 use (ST07-OWNER-DECISION-02) -----------------------------


def _index_checksum_holds(body: bytes, trailer: bytes) -> bool:
    """Whether the index's trailing checksum is the SHA-1 of its body (`OB9-9a`(i)): a yes
    or a no, and nothing else. The digest is compared here and goes nowhere."""
    return hashlib.sha1(body, usedforsecurity=False).digest() == trailer


# --- parsing the repository's own representations -------------------------------------------


class _Malformed(Exception):
    """Internal: a representation failing its own integrity or structure."""


class _Unsupported(Exception):
    """Internal: a representation only a mode this reader does not take could interpret."""


GIT_DIRECTORY: Final = b".git"
BRANCH_PREFIX: Final = b"refs/heads/"
OBJECT_ID_LENGTH: Final = 40
HEX_DIGITS: Final = frozenset(b"0123456789abcdef")
FORBIDDEN_REF_BYTES: Final = frozenset(b" ~^:?*[") | {0x5C, 0x7F}
INDEX_ENTRY_MODES: Final = frozenset({0o100644, 0o100755, 0o120000})
SUPPORTED_EXTENSIONS: Final = frozenset({(b"objectformat", b"sha1"), (b"refstorage", b"files")})
FIXED_ENTRY_SIZE: Final = 62
TRAILER_SIZE: Final = 20
EXTENDED_FLAG: Final = 0x4000
SKIP_WORKTREE_FLAG: Final = 0x4000
INTENT_TO_ADD_FLAG: Final = 0x2000
LIVE_M3: Final = frozenset({M3Position.ENVELOPE_DERIVED, M3Position.ACTIVATION_RUNNING})
FIRST_CYCLE_ABSENT: Final = KnownAbsent(basis="S2 is not a cyclic step")


def _take(body: bytes, start: int, size: int) -> bytes:
    """`size` bytes at `start`, or a structural failure — never a short slice."""
    if start + size > len(body):
        raise _Malformed
    return body[start : start + size]


def _line(raw: bytes) -> bytes:
    """A one-line representation's content: exactly one line, newline-terminated."""
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise _Malformed
    return raw[:-1]


def _object_id(text: bytes) -> str:
    """A full lowercase SHA-1 object id — never abbreviated, never normalized."""
    full = len(text) == OBJECT_ID_LENGTH
    hexadecimal = set(text) <= HEX_DIGITS
    if not (full and hexadecimal):  # guard:ga_observation_coherence
        raise _Malformed
    return text.decode("ascii")


def _ref_name_valid(name: bytes) -> bool:
    """A branch name that names a path under `refs/heads/` and nothing outside it."""
    parts = name.split(b"/")
    return (
        bool(name)
        and b".." not in name
        and all(part and not part.startswith(b".") for part in parts)
        and not name.endswith(b".lock")
        and all(byte > 0x20 and byte not in FORBIDDEN_REF_BYTES for byte in name)
    )


def _symbolic_branch(head: bytes | None) -> bytes | None:
    """The branch a symbolic `HEAD` names, if its name is a valid branch name."""
    if head is None or not head.startswith(b"ref: " + BRANCH_PREFIX):
        return None
    name = head[len(b"ref: " + BRANCH_PREFIX) :].removesuffix(b"\n")
    return name if _ref_name_valid(name) else None


def _packed(raw: bytes | None) -> tuple[tuple[str, bytes], ...]:
    """`(commit, ref name)` for each line of `packed-refs`; peeled lines are checked only."""
    if raw is None:
        return ()
    if not raw.endswith(b"\n"):
        raise _Malformed
    found: list[tuple[str, bytes]] = []
    for line in raw[:-1].split(b"\n"):
        if line.startswith(b"#"):
            continue
        if line.startswith(b"^"):
            _object_id(line[1:])
            continue
        commit, separator, name = line.partition(b" ")
        if not separator or not name:
            raise _Malformed
        found.append((_object_id(commit), name))
    return tuple(found)


@dataclass(frozen=True)
class _Refs:
    baseline: str | None
    branch: bytes | None
    committed_history: str | None


def _refs(head: bytes | None, loose: bytes | None, packed: bytes | None) -> _Refs:
    """Subjects 1…3 from `HEAD`, the branch's loose ref and `packed-refs`. A loose ref
    takes precedence over a packed one, as Git reads them; the reflog is never read."""
    if head is None:
        raise _Malformed
    if not head.startswith(b"ref: "):
        return _Refs(_object_id(_line(head)), None, None)
    branch = _symbolic_branch(head)
    if branch is None or _line(head) != b"ref: " + BRANCH_PREFIX + branch:
        raise _Unsupported
    if loose is not None:  # guard:ga_observation_coherence
        commit = _object_id(_line(loose))
        return _Refs(commit, branch, commit)
    named = [
        commit
        for commit, name in _packed(packed)
        if name == BRANCH_PREFIX + branch  # guard:ga_observation_coherence
    ]
    if len(named) > 1:
        raise _Malformed
    unborn = not named
    commit_or_none = None if unborn else named[0]
    return _Refs(commit_or_none, branch, commit_or_none)


def _value(raw: bytes) -> bytes:
    """A configuration value: unquoted text before any comment, or the raw text."""
    text = raw.strip()
    if b'"' in text:
        return text
    return text.split(b"#", 1)[0].split(b";", 1)[0].strip()


def _settings(raw: bytes) -> dict[tuple[bytes, bytes], tuple[bytes, ...]]:
    """`.git/config`, read as data and never executed: `(section, key) -> values`. An
    include of another file, a continuation line or text outside a section is a mode this
    reader does not take."""
    section: bytes | None = None
    found: dict[tuple[bytes, bytes], tuple[bytes, ...]] = {}
    for line in raw.split(b"\n"):
        text = line.strip()
        if not text or text.startswith((b"#", b";")):
            continue
        if text.endswith(b"\\") or (text.startswith(b"[") and not text.endswith(b"]")):
            raise _Unsupported
        if text.startswith(b"["):
            section = text[1:-1].strip().split(b" ", 1)[0].split(b".", 1)[0].lower()
            if section in (b"include", b"includeif"):  # guard:ga_observation_read_only
                raise _Unsupported
            continue
        if section is None:
            raise _Unsupported
        key, separator, value = text.partition(b"=")
        setting = (section, key.strip().lower())
        found[setting] = (*found.get(setting, ()), _value(value) if separator else b"true")
    return found


def _mode_supported(config: bytes | None) -> bool:
    """A non-bare repository of format 0 or 1, SHA-1 objects, files refs, no separate work
    tree, no include. Anything else is a mode this reader does not take (`OB9-9b`)."""
    if config is None:
        return False
    settings = _settings(config)
    version = settings.get((b"core", b"repositoryformatversion"), ())
    extensions = [
        (key, value)
        for (section, key), values in settings.items()
        if section == b"extensions"
        for value in values
    ]
    bare = settings.get((b"core", b"bare"), (b"false",))
    separate = (b"core", b"worktree") in settings
    known = [pair in SUPPORTED_EXTENSIONS for pair in extensions]
    return (
        version in ((b"0",), (b"1",))  # guard:ga_observation_read_only
        and bare == (b"false",)  # guard:ga_observation_read_only
        and not separate  # guard:ga_observation_read_only
        and all(known)  # guard:ga_observation_read_only
    )


def _offset(body: bytes, cursor: int) -> tuple[int, int]:
    """Index v4's prefix-strip length: Git's offset varint."""
    byte = _take(body, cursor, 1)[0]
    cursor += 1
    value = byte & 0x7F
    while byte & 0x80:
        byte = _take(body, cursor, 1)[0]
        cursor += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, cursor


def _flags(extended: int) -> str:
    intent = "i" if extended & INTENT_TO_ADD_FLAG else ""
    skip = "s" if extended & SKIP_WORKTREE_FLAG else ""
    return intent + skip or "-"


def _entry(body: bytes, start: int, version: int, previous: bytes) -> tuple[bytes, str, int]:
    """One index entry: `(path, element, next position)`. Stat fields are skipped unread."""
    fixed = _take(body, start, FIXED_ENTRY_SIZE)
    (mode,) = struct.unpack_from(">I", fixed, 24)
    blob = fixed[40:60]
    (flags,) = struct.unpack_from(">H", fixed, 60)
    cursor = start + FIXED_ENTRY_SIZE
    extended = 0
    if flags & EXTENDED_FLAG:
        if version < 3:
            raise _Malformed
        (extended,) = struct.unpack(">H", _take(body, cursor, 2))
        cursor += 2
    if extended & ~(INTENT_TO_ADD_FLAG | SKIP_WORKTREE_FLAG):
        raise _Malformed
    if version == 4:
        strip, cursor = _offset(body, cursor)
        end = body.find(b"\0", cursor)
        if strip > len(previous) or end < 0:
            raise _Malformed
        path = previous[: len(previous) - strip] + body[cursor:end]
        following = end + 1
    else:
        end = body.find(b"\0", cursor)
        if end < 0:
            raise _Malformed
        path = body[cursor:end]
        following = start + (end - start + 8) // 8 * 8
        if _take(body, end, following - end).strip(b"\0"):
            raise _Malformed
    if (flags & 0xFFF) != min(len(path), 0xFFF) or not path:
        raise _Malformed
    if mode not in INDEX_ENTRY_MODES:  # guard:ga_observation_read_only
        raise _Unsupported
    stage = (flags >> 12) & 0x3
    element = f"{mode:06o} {blob.hex()} {stage} {_flags(extended)} {path.hex()}"
    return path, element, following


def _index_elements(body: bytes) -> tuple[str, ...]:
    """Subject 4: the index's content entries, from a body whose checksum already held."""
    header = _take(body, 0, 12)
    version, count = struct.unpack(">II", header[4:])
    if header[:4] != b"DIRC":
        raise _Malformed
    if version not in (2, 3, 4):
        raise _Unsupported
    position, previous = 12, b""
    found: list[tuple[bytes, str]] = []
    for _ in range(count):
        previous, element, position = _entry(body, position, version, previous)
        found.append((previous, element))
    while len(body) - position >= 8:
        signature = body[position : position + 4]
        (size,) = struct.unpack(">I", body[position + 4 : position + 8])
        _take(body, position + 8, size)
        if not b"A" <= signature[:1] <= b"Z":  # guard:ga_observation_read_only
            raise _Unsupported
        position += 8 + size
    structured = position == len(body)  # guard:ga_observation_coherence
    if not structured:
        raise _Malformed
    return tuple(element for _, element in sorted(found))


def _index(raw: bytes | None) -> tuple[str, ...]:
    """The index, verified whole before a single entry is read (`OB9-9a`(i))."""
    if raw is None or len(raw) < TRAILER_SIZE:
        raise _Malformed
    body, trailer = raw[:-TRAILER_SIZE], raw[-TRAILER_SIZE:]
    if not _index_checksum_holds(body, trailer):  # guard:ga_observation_coherence
        raise _Malformed
    return _index_elements(body)


# --- the observation -------------------------------------------------------------------------


@dataclass(frozen=True)
class _Round:
    """One read of every repository-internal representation: `HEAD`, the configuration, the
    branch's loose ref, `packed-refs` and the index. `None` where a file is absent."""

    head: bytes | None
    config: bytes | None
    loose: bytes | None
    packed: bytes | None
    index: bytes | None


def _readable[T](found: T | None, fallback: T, causes: set[ObservationCause]) -> T:
    """The reader's answer, or — where it was unreadable — the defeat, and a placeholder
    that can reach no result, since any defeat makes the whole observation indeterminate."""
    unreadable = found is None
    if unreadable:  # guard:ga_observation_defeat
        causes.add(ObservationCause.UNREADABLE_SUBJECT)
    return fallback if found is None else found


def _stable(before: Stat, after: Stat, causes: set[ObservationCause]) -> None:
    """An item whose witness changed while it was read changed mid-determination."""
    if before.witness != after.witness:  # guard:ga_observation_defeat
        causes.add(ObservationCause.ITEM_CHANGED)


def _content(reader: Reader, path: bytes, before: Stat, causes: set[ObservationCause]) -> bytes:
    """A regular file's bytes, read once, with the torn-read and changed-item tests."""
    hollow = Stat(before.kind, before.mode, 0, before.witness)
    got = _readable(reader.read_regular(path), Read(b"", hollow, hollow), causes)
    after = _readable(reader.lstat(path), before, causes)
    whole = len(got.data) == got.opened.size == got.closed.size
    if not whole:  # guard:ga_observation_defeat
        causes.add(ObservationCause.TORN_READ)
    _stable(before, got.opened, causes)
    _stable(got.opened, got.closed, causes)
    _stable(before, after, causes)
    return got.data


def _internal(reader: Reader, path: bytes, causes: set[ObservationCause]) -> bytes | None:
    """One repository-internal file, or `None` where it is absent."""
    before = _readable(reader.lstat(path), ABSENT_ITEM, causes)
    if before.kind == Kind.ABSENT:
        return None
    if before.kind != Kind.FILE:
        causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
        return None
    return _content(reader, path, before, causes)


def _round(reader: Reader, git: bytes, causes: set[ObservationCause]) -> _Round:
    head = _internal(reader, git + b"/HEAD", causes)
    branch = _symbolic_branch(head)
    loose = None
    if branch is not None:
        loose = _internal(reader, git + b"/" + BRANCH_PREFIX + branch, causes)
    return _Round(
        head,
        _internal(reader, git + b"/config", causes),
        loose,
        _internal(reader, git + b"/packed-refs", causes),
        _internal(reader, git + b"/index", causes),
    )


def _item(
    reader: Reader,
    path: bytes,
    relative: bytes,
    before: Stat,
    causes: set[ObservationCause],
) -> tuple[bytes, str]:
    """One regular file or link: `(relative path, element)`."""
    if before.kind == Kind.LINK:
        target = _readable(reader.read_link(path), b"", causes)
        after = _readable(reader.lstat(path), before, causes)
        _stable(before, after, causes)
        identity = identify_artifact_content(target).identity.value
        return relative, f"link 120000 {identity} {relative.hex()}"
    data = _content(reader, path, before, causes)
    mode = 0o100755 if before.mode & stat.S_IXUSR else 0o100644
    identity = identify_artifact_content(data).identity.value
    return relative, f"file {mode:06o} {identity} {relative.hex()}"


def _walk(
    reader: Reader,
    root: bytes,
    relative: bytes,
    causes: set[ObservationCause],
    found: list[tuple[bytes, str]],
) -> None:
    """Subject 5: every non-directory item under the root, tracked, untracked and ignored
    alike. The listing is taken twice; an item's witness is taken before and after it is
    read. Empty directories are not items."""
    directory = root + b"/" + relative if relative else root
    names = _readable(reader.list_dir(directory), (), causes)
    for name in names:
        child = relative + b"/" + name if relative else name
        path = root + b"/" + child
        if name == GIT_DIRECTORY:  # guard:ga_observation_coherence
            if relative:  # guard:ga_observation_read_only
                causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
            continue
        before = _readable(reader.lstat(path), ABSENT_ITEM, causes)
        if before.kind == Kind.ABSENT:  # guard:ga_observation_defeat
            causes.add(ObservationCause.ITEM_DISAPPEARED)
        elif before.kind == Kind.DIRECTORY:  # guard:ga_observation_coherence
            _walk(reader, root, child, causes, found)
        elif before.kind in (Kind.FILE, Kind.LINK):  # guard:ga_observation_coherence
            found.append(_item(reader, path, child, before, causes))
        elif before.kind == Kind.OTHER:  # guard:ga_observation_defeat
            causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
    again = _readable(reader.list_dir(directory), (), causes)
    if set(again) - set(names):  # guard:ga_observation_defeat
        causes.add(ObservationCause.ITEM_APPEARED)
    if set(names) - set(again):  # guard:ga_observation_defeat
        causes.add(ObservationCause.ITEM_DISAPPEARED)


def _parsed(determination: _Round, causes: set[ObservationCause]) -> tuple[_Refs, tuple[str, ...]]:
    """Subjects 1…4 from one determination's representations, or the defeat they show."""
    refs = _Refs(None, None, None)
    index: tuple[str, ...] = ()
    try:
        if not _mode_supported(determination.config):  # guard:ga_observation_read_only
            causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
        refs = _refs(determination.head, determination.loose, determination.packed)
        index = _index(determination.index)
    except _Unsupported:
        causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
    except _Malformed:
        causes.add(ObservationCause.INTEGRITY_CHECK_FAILED)
    return refs, index


def observe(location: str, reader: Reader = FILESYSTEM) -> Determinate | Indeterminate:
    """The entry observation of the repository at `location`: read-only, execution-free.

    The pre-window witness round, the determination read twice, the working-tree walk, the
    post-window witness round. Every defeat test is evaluated; any one makes the whole
    observation indeterminate, and witness equality overrides none of them (`AV11-2`).
    """
    root = os.fsencode(location)
    git = root + b"/" + GIT_DIRECTORY
    causes: set[ObservationCause] = set()
    top = _readable(reader.lstat(git), ABSENT_ITEM, causes)
    if top.kind != Kind.DIRECTORY:
        causes.add(ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE)
        return Indeterminate(tuple(c for c in ObservationCause if c in causes))
    opening = _round(reader, git, causes)
    first, second = _round(reader, git, causes), _round(reader, git, causes)
    if first != second:  # guard:ga_observation_defeat
        causes.add(ObservationCause.SUBJECT_DIFFERED_BETWEEN_READS)
    refs, index = _parsed(first, causes)
    found: list[tuple[bytes, str]] = []
    _walk(reader, root, b"", causes, found)
    closing = _round(reader, git, causes)
    witnessed = opening == closing
    if not witnessed:  # guard:ga_observation_defeat
        causes.add(ObservationCause.WITNESS_DIFFERED)
    defeated = bool(causes)  # guard:ga_observation_defeat
    if defeated:  # guard:ga_observation_coherence
        return Indeterminate(tuple(c for c in ObservationCause if c in causes))
    working_tree = tuple(element for _, element in sorted(found))
    return Determinate(
        Observation(refs.baseline, refs.branch, refs.committed_history, index, working_tree)
    )


# --- the bound referents (ST07-OWNER-DECISION-01) --------------------------------------------


@dataclass(frozen=True)
class Referents:
    """What the resolved root is bound to, read from its `RC-12` content: the `RA-04`
    repository and branch, the `RA-05` baseline and its committed-history identity."""

    location: str
    branch: str
    baseline: BaselineIdentityId
    commits: tuple[str, ...]


def bound_referents(
    records: authority.AuthorityRecords, root: OwnerAuthorizationId
) -> Referents | None:
    """The root's own bound referents, and no other record's (`DC-3`); `None` when they
    cannot be read as exactly one repository boundary."""
    resolved = authority.resolved_root(records, root)
    if isinstance(resolved, dv.Indeterminate):
        return None
    bound_repository = resolved.content.repository_boundary
    bound_baseline = resolved.content.baseline
    repositories = [
        r
        for r in records.records
        if isinstance(r, RepositoryBoundary) and r.identity == bound_repository
    ]
    commits = tuple(
        b.committed_history_identity
        for b in records.records
        if isinstance(b, BaselineIdentity)
        and b.identity == bound_baseline  # guard:ga_observation_coherence
    )
    if len(repositories) != 1:
        return None
    (repository,) = repositories
    return Referents(repository.repository_location, repository.branch, bound_baseline, commits)


def _decoded(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def fixable(observed: Determinate | Indeterminate, bound: Referents) -> Determinate | Indeterminate:
    """A determinate observation is fixable only if its branch and its commit are exactly
    the bound ones — byte-for-byte strings, never normalized or abbreviated. A detached
    `HEAD` names no branch and is never fixable. Otherwise: the observation result
    `Indeterminate(NOT_FIXABLE_AGAINST_BOUND_REFERENTS)`, and nothing is re-bound."""
    if isinstance(observed, Indeterminate):
        return observed
    seen = observed.observation
    named = None if seen.branch is None else _decoded(seen.branch)
    commits = (seen.baseline, seen.committed_history)
    branch = named == bound.branch  # guard:ga_observation_coherence
    commit = all(c in bound.commits for c in commits)  # guard:ga_observation_coherence
    if branch and commit:  # guard:ga_observation_coherence
        return observed
    return Indeterminate((ObservationCause.NOT_FIXABLE_AGAINST_BOUND_REFERENTS,))


# --- the facts ST-05 names ST-07 as supplier of ------------------------------------------------


def _truth(value: bool) -> str:
    return model.TRUE if value else model.FALSE


def entry_facts(no_boundary: bool, observed: Determinate | Indeterminate) -> sm.Facts:
    """`B2-1`…`B2-4`. The observation is read-only when the reader could take the mode; it
    is never a worker activation, since it derives no envelope and starts nothing (`GR9-7`)."""
    fixed, read_only = True, True
    if isinstance(observed, Indeterminate):
        forbidden = ObservationCause.FORBIDDEN_OR_UNSUPPORTED_MODE
        fixed, read_only = False, forbidden not in observed.causes
    return {
        model.NO_BOUNDARY_FOR_ROOT.name: _truth(no_boundary),
        model.OBSERVATION_FIXED.name: _truth(fixed),
        model.OBSERVATION_READ_ONLY.name: _truth(read_only),
        model.NOT_A_WORKER_ACTIVATION.name: model.TRUE,
    }


def _recorded(
    records: dv.AuthoritativeRecords, root: OwnerAuthorizationId
) -> Replayed | NotFixed | None:
    """The root's recorded boundary and its `B2` entry, read before anything else; `None`
    when neither exists. One without the other is a torn unit (`CW-2`)."""
    withheld = records.unreadable | records.unstable
    if EntryStateBoundaryRecord in withheld:  # guard:ga_entry_once_per_root
        return NotFixed(NotFixedReason.UNREADABLE_RECORDS)
    boundaries = [
        b
        for b in records.records
        if isinstance(b, EntryStateBoundaryRecord)
        and b.resolved_root == root  # guard:ga_entry_once_per_root
    ]
    position = dv.derive_m2_position(records, root)
    if isinstance(position, dv.Indeterminate):
        return NotFixed(NotFixedReason.UNREADABLE_RECORDS)
    chain = position.chain if isinstance(position, dv.Occupancy) else ()
    entries = [e for e in chain if e.edge == M2Edge.B2]
    if not boundaries and not entries:
        return None
    if len(boundaries) == 1 and len(entries) == 1:
        return Replayed(boundaries[0], entries[0])
    return NotFixed(NotFixedReason.INCONSISTENT_RECORDS)


def boundary_facts(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> sm.Facts:
    """`BOUNDARY_FIXED` (`V-14`) and `RP-4`: exactly one readable `RC-17` for the root, with
    its `B2` entry. Read over records alone — the repository is never observed for it
    (`AV11-13`). Unreadable or inconsistent records supply neither fact."""
    found = _recorded(records, root)
    if isinstance(found, NotFixed):
        return {}
    fixed = isinstance(found, Replayed)
    return {model.BOUNDARY_FIXED.name: _truth(fixed), model.RP_4.name: _truth(fixed)}


def write_domain_exclusive(records: dv.AuthoritativeRecords, root: OwnerAuthorizationId) -> bool:
    """`OB9-9a`(ii) from records, not sampled: no M3 subject of the root is live (`K-5`)."""
    envelopes = [
        r.envelope.identity
        for r in records.records
        if isinstance(r, AuthorityEnvelopeRecord) and r.envelope.resolved_root == root
    ]
    positions = [dv.derive_m3_position(records, envelope) for envelope in envelopes]
    unknown = [p for p in positions if isinstance(p, dv.Indeterminate)]
    states = [p.reached.state for p in positions if isinstance(p, dv.Occupancy)]
    live = [state for state in states if state in LIVE_M3]  # guard:ga_observation_coherence
    return not live and not unknown  # guard:ga_observation_coherence


# --- the B2 act --------------------------------------------------------------------------------


def fix_entry_boundary(
    store: CoordinationStore, root: OwnerAuthorizationId, reader: Reader = FILESYSTEM
) -> Fixed | Replayed | NotFixed:
    """`B2`: observe the resolved root's repository once and fix the boundary with its `S2`
    entry as one unit — or return the boundary already fixed, reading nothing.

    Records first: the key, then `S1`, `RA-09`, the write domain's exclusivity and the bound
    referents, all before a single repository byte is read. Then the observation, the bound-
    referent match, ST-05's evaluation of `B2`, and the one unit. Nothing is written unless
    the unit is (`WP-12`); a refused unit is re-read by its key (`WP-11`).
    """
    records = authority.read_authority_records(store)
    if records.unstable:
        return NotFixed(NotFixedReason.UNREADABLE_RECORDS)
    recorded = _recorded(records.derivable, root)
    if recorded is not None:  # guard:ga_entry_once_per_root
        return recorded
    position = dv.derive_m2_position(records.derivable, root)
    if not isinstance(position, dv.Occupancy):
        return NotFixed(NotFixedReason.EPOCH_NOT_AT_S1)
    source = position.reached
    at_s1 = source.state == M2Position.S1_EPOCH_OPENED
    if not at_s1:  # guard:ga_entry_once_per_root
        return NotFixed(NotFixedReason.EPOCH_NOT_AT_S1)
    if not write_domain_exclusive(records.derivable, root):
        return NotFixed(NotFixedReason.WRITE_DOMAIN_NOT_EXCLUSIVE)
    permitted = authority.root_facts(records, root)
    if permitted.get(model.PREFLIGHT_PERMITTED.name) != model.TRUE:
        return NotFixed(NotFixedReason.PREFLIGHT_NOT_PERMITTED)
    bound = bound_referents(records, root)
    if bound is None:
        return NotFixed(NotFixedReason.REFERENTS_UNAVAILABLE)
    observed = fixable(observe(bound.location, reader), bound)
    facts = {
        **entry_facts(True, observed),
        **permitted,
        model.TRIGGER.name: model.COORDINATOR,
    }
    admitted = sm.evaluate(M2Edge.B2, source.state, facts)
    if isinstance(observed, Indeterminate):
        refused = admitted if isinstance(admitted, sm.Refused) else None
        return NotFixed(NotFixedReason.OBSERVATION_INDETERMINATE, observed, refused)
    if isinstance(admitted, sm.Refused):
        return NotFixed(NotFixedReason.B2_REFUSED, None, admitted)
    seen = observed.observation
    boundary = EntryStateBoundaryRecord(
        boundary=EntryStateBoundary(
            identity=EntryStateBoundaryId(value=mint_value()),
            baseline=bound.baseline,
            pre_existing_working_tree_state=seen.working_tree,
            pre_existing_index_state=seen.index,
        ),
        resolved_root=root,
    )
    entry = M2PositionEntry(
        identity=M2PositionEntryId(epoch_root=root, discriminator=mint_value()),
        state=M2Position(str(admitted.target)),
        edge=M2Edge.B2,
        predecessor=Present[M2PositionEntryId](value=source.identity),
        cycle_occurrence=FIRST_CYCLE_ABSENT,
    )
    try:
        store.create_unit((boundary, entry))  # guard:ga_entry_once_per_root
    except WriteRefused:
        again = _recorded(authority.read_authority_records(store).derivable, root)
        if isinstance(again, Replayed):
            return again
        return NotFixed(NotFixedReason.WRITE_REFUSED)
    return Fixed(boundary, entry)
