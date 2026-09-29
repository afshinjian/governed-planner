"""`GP-AUTO-ST-07`: the five observed subjects, each over what it denotes and nothing else.

Design basis: AP-09 §7.1 (`OB9-1`…`OB9-5`), `OB9-12`; AP-10 `IX-1`, `IX-1a`, `IX-2`; AP-11
§16 `GP-AUTO-ST-07` (Deliverables; Tests: *"legacy `.coord` content recorded as
pre-existing entry state"* `CV11-13`), `AV11-5`; plan §6.2, §6.3.

The subjects are kept apart: the commit `HEAD` resolves to, the branch it names, the commit
that branch's ref names, the index's content entries, and every working-tree item by content
and mode. Each test changes one thing in a real repository and shows which subject moved —
and that nothing a subject does not denote (a stat refresh, a timestamp, a label) moved it.
"""

from __future__ import annotations

import ast
import os
import shutil
from pathlib import Path

import pytest

import st07_world as x
from gpauto import observation
from gpauto.content_identity import identify_artifact_content
from gpauto.observation import Determinate, Indeterminate, Observation, ObservationCause

GPAUTO_STAGE = "GP-AUTO-ST-07"


def _seen(repo: x.Repository) -> Observation:
    found = observation.observe(repo.location)
    assert isinstance(found, Determinate), found
    return found.observation


def _element(kind: str, mode: str, content: bytes, path: bytes) -> str:
    identity = identify_artifact_content(content).identity.value
    return f"{kind} {mode} {identity} {path.hex()}"


@pytest.mark.traces("ST07-D1", "OB9-4")
def test_the_working_tree_is_every_item_by_content_and_mode() -> None:
    """Subject 5, exactly: each regular file and link, tracked or untracked, by kind, mode,
    content identity and raw path — and not one item of the `.git` directory, whose
    contents are subjects 1…4. Empty directories are not items."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.write("untracked.txt", b"new\n")
        (repo.path / "bin").mkdir()
        tool = repo.write("bin/tool", b"#!/bin/sh\n")
        tool.chmod(0o755)
        (repo.path / "empty").mkdir()
        os.symlink("a.txt", repo.path / "link")
        seen = _seen(repo)
    assert seen.working_tree == (
        _element("file", "100644", b"alpha\n", b"a.txt"),
        _element("file", "100755", b"#!/bin/sh\n", b"bin/tool"),
        _element("link", "120000", b"a.txt", b"link"),
        _element("file", "100644", b"print('b')\n", b"src/b.py"),
        _element("file", "100644", b"gamma\n", b"src/deep/c.txt"),
        _element("file", "100644", b"new\n", b"untracked.txt"),
    )


@pytest.mark.traces("OB9-4", "ST07-T2", "RS7-3")
def test_untracked_and_ignored_items_are_observed_with_no_exemption() -> None:
    """`OB9-4`: untracked state is in scope, and an ignore rule exempts nothing — neither a
    `.gitignore` pattern nor `info/exclude`. Dirty tracked content is recorded as it is."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.write(".gitignore", b"*.log\n")
        repo.write("build.log", b"ignored\n")
        repo.write(".git/info/exclude", b"secret.txt\n")
        repo.write("secret.txt", b"excluded\n")
        repo.write("a.txt", b"dirty\n")
        seen = _seen(repo)
    paths = {element.split()[-1] for element in seen.working_tree}
    for name in (b".gitignore", b"build.log", b"secret.txt", b"a.txt"):
        assert name.hex() in paths, name
    assert _element("file", "100644", b"dirty\n", b"a.txt") in seen.working_tree


@pytest.mark.supports("OB9-6", "IX-1", "IX-1a", "OB9-5")
@pytest.mark.traces("IX-2", "ST07-T3", "OB9-12")
def test_legacy_coord_content_is_ordinary_pre_existing_entry_state() -> None:
    """`IX-1a`, `IX-2`, `CV11-13`: `.coord` inside the repository — here excluded through
    `info/exclude`, as this checkout excludes it — is observed as working-tree content like
    any other, by content identity, with no exemption, allowlist or exclude rule."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.write(".git/info/exclude", b".coord/\n")
        repo.write(".coord/STATUS", b"AWAITING_CODEX_REVIEW\n")
        repo.write(".coord/PROTOCOL.md", b"# protocol\n")
        seen = _seen(repo)
    assert _element("file", "100644", b"AWAITING_CODEX_REVIEW\n", b".coord/STATUS") in (
        seen.working_tree
    )
    assert _element("file", "100644", b"# protocol\n", b".coord/PROTOCOL.md") in (seen.working_tree)
    tree = ast.parse(Path(observation.__file__).read_text(encoding="utf-8"))
    identifiers = [
        n.id if isinstance(n, ast.Name) else n.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Name | ast.Attribute)
    ]
    constants = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)]
    for word in ("exclude", "ignore", "allowlist", "exempt", "coord_"):
        assert not [i for i in identifiers if word in i.lower()], word
    for value in constants:
        if isinstance(value, bytes):
            assert b"coord" not in value and b"exclude" not in value and b"ignore" not in value


@pytest.mark.traces("ST07-D1", "OB9-1")
def test_the_index_is_its_content_entries_never_its_file_bytes() -> None:
    """`OB9-1`: a stat refresh rewrites the index file and changes no entry, so the subject
    is unchanged; staging a change alters an entry, so it changes. The entries carry path,
    blob identity, mode, stage and flags, and no stat field."""
    with x.workspace() as base:
        repo = x.repository(base)
        index = repo.path / ".git" / "index"
        before = _seen(repo)
        raw = index.read_bytes()
        stamp = (repo.path / "a.txt").stat()
        os.utime(repo.path / "a.txt", ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 10**11))
        repo.git("update-index", "--refresh")
        refreshed = index.read_bytes()
        assert refreshed != raw
        assert _seen(repo).index == before.index
        repo.git("update-index", "--index-version", "4")
        assert index.read_bytes() != refreshed
        assert _seen(repo).index == before.index
        repo.write("a.txt", b"staged\n")
        repo.git("add", "a.txt")
        after = _seen(repo)
    assert after.index != before.index
    (entry,) = [e for e in after.index if e.endswith(b"a.txt".hex())]
    mode, blob_id, stage, flags, path = entry.split()
    assert (mode, stage, flags, path) == ("100644", "0", "-", b"a.txt".hex())
    assert len(blob_id) == 40


@pytest.mark.traces("OB9-1", "ST07-D1")
def test_index_versions_two_three_and_four_give_the_same_entries() -> None:
    """One set of content entries, whatever representation the index uses: version 4's
    prefix-compressed paths decode to the same paths as versions 2 and 3."""
    with x.workspace() as base:
        repo = x.repository(base)
        found = []
        for version in ("2", "3", "4"):
            repo.git("update-index", "--index-version", version)
            found.append(_seen(repo).index)
    assert found[0] == found[1] == found[2]
    assert len(found[0]) == 3


@pytest.mark.traces("OB9-1", "OB9-12", "ST07-T2")
def test_staged_intent_to_add_and_skip_worktree_entries_are_recorded() -> None:
    """Staged-at-entry state is valid entry evidence (`OB9-12`): an intent-to-add entry and a
    skip-worktree entry are recorded with their flags."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.write("later.txt", b"later\n")
        repo.git("add", "-N", "later.txt")
        repo.git("update-index", "--skip-worktree", "src/b.py")
        seen = _seen(repo)
    flags = {e.split()[4]: e.split()[3] for e in seen.index}
    assert flags[b"later.txt".hex()] == "i"
    assert flags[b"src/b.py".hex()] == "s"
    assert flags[b"a.txt".hex()] == "-"


@pytest.mark.traces("OB9-2", "ST07-D1")
def test_the_working_tree_is_content_and_mode_never_timestamps() -> None:
    """`OB9-2`: rewriting identical content with a new timestamp changes nothing; changing
    content under a preserved timestamp changes the subject; so does changing the mode."""
    with x.workspace() as base:
        repo = x.repository(base)
        target = repo.path / "a.txt"
        first = _seen(repo).working_tree
        stamp = target.stat()
        target.write_bytes(b"alpha\n")
        os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns + 10**9))
        assert _seen(repo).working_tree == first
        target.write_bytes(b"ALPHA\n")
        os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        second = _seen(repo).working_tree
        assert second != first
        target.chmod(0o755)
        third = _seen(repo).working_tree
    assert third != second


@pytest.mark.traces("ST07-D1", "OB9-1", "OB9-2")
def test_the_five_subjects_are_distinct() -> None:
    """`AV11-5`: moving one subject moves only it. A branch switch at the same commit moves
    the branch alone; a detached `HEAD` keeps the baseline and names no branch or branch
    history; staging moves the index alone; an untracked write moves the working tree alone."""
    with x.workspace() as base:
        repo = x.repository(base)
        start = _seen(repo)
        assert start.branch == b"main"
        assert start.baseline == start.committed_history == repo.commit
        repo.git("checkout", "-q", "-b", "other")
        switched = _seen(repo)
        assert switched.branch == b"other"
        assert (switched.baseline, switched.committed_history) == (repo.commit, repo.commit)
        assert (switched.index, switched.working_tree) == (start.index, start.working_tree)
        repo.git("checkout", "-q", "--detach")
        detached = _seen(repo)
        assert (detached.branch, detached.baseline, detached.committed_history) == (
            None,
            repo.commit,
            None,
        )
        repo.git("checkout", "-q", "main")
        repo.write("u.txt", b"u\n")
        untracked = _seen(repo)
        assert untracked.index == start.index and untracked.working_tree != start.working_tree
        repo.git("add", "u.txt")
        staged = _seen(repo)
    assert staged.index != start.index and staged.working_tree == untracked.working_tree
    assert staged.baseline == start.baseline and staged.branch == start.branch


@pytest.mark.supports("OB9-3")
@pytest.mark.traces("ST07-D1")
def test_committed_history_is_the_ref_identity_not_the_label() -> None:
    """`OB9-3`'s entry clause: `HEAD` naming the same branch is not the branch naming the same
    commit. A new commit on the branch keeps the label and changes the identity."""
    with x.workspace() as base:
        repo = x.repository(base)
        before = _seen(repo)
        repo.write("a.txt", b"next\n")
        repo.git("commit", "-q", "-am", "next")
        after = _seen(repo)
    assert after.branch == before.branch == b"main"
    assert after.committed_history != before.committed_history
    assert after.committed_history == after.baseline


@pytest.mark.traces("ST07-D1")
def test_a_packed_ref_is_read_as_its_own_branch_and_no_other() -> None:
    """With every ref packed, the branch's commit is the `packed-refs` line naming exactly
    that branch — never another branch's line — and a loose ref, when present, is read
    before the packed one. The reflog is never read."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.git("checkout", "-q", "-b", "other")
        repo.write("a.txt", b"other\n")
        repo.git("commit", "-q", "-am", "other")
        other = x.head(repo)
        repo.git("checkout", "-q", "main")
        repo.git("pack-refs", "--all")
        assert not (repo.path / ".git/refs/heads/main").exists()
        packed = _seen(repo)
        assert (packed.branch, packed.committed_history) == (b"main", repo.commit)
        repo.git("checkout", "-q", "other")
        assert _seen(repo).committed_history == other
        (repo.path / ".git" / "logs").rename(repo.path / ".git" / "moved-logs")
        assert _seen(repo).committed_history == other
        repo.git("checkout", "-q", "main")
        repo.write("a.txt", b"after packing\n")
        repo.git("commit", "-q", "-am", "after packing")
        assert (repo.path / ".git/refs/heads/main").exists()
        loose = _seen(repo)
        assert loose.committed_history == x.head(repo) != repo.commit


@pytest.mark.traces("GR9-4", "ST07-N1")
def test_symlink_is_recorded_as_a_link_never_followed() -> None:
    """`GR9-4`: a link is observed as a link — its target bytes are its content — and never
    followed, whether it names a file, a directory or nothing."""
    with x.workspace() as base:
        repo = x.repository(base)
        os.symlink("a.txt", repo.path / "to-file")
        os.symlink("src", repo.path / "to-directory")
        os.symlink("missing", repo.path / "dangling")
        seen = _seen(repo)
    for name, target in (
        (b"to-file", b"a.txt"),
        (b"to-directory", b"src"),
        (b"dangling", b"missing"),
    ):
        assert _element("link", "120000", target, name) in seen.working_tree, name
    assert not [e for e in seen.working_tree if e.split()[-1].startswith(b"to-directory/".hex())]


def _branch_behind_a_link(repo: x.Repository, outside: Path, planted: str) -> None:
    """`HEAD` names `feature/x`, whose only ref is packed; `.git/refs/heads/feature` is then a
    link to `outside`, where a loose `x` names `planted`. A reader following the link would
    take `planted` as the branch's commit; one taking the link as absent would take the
    packed commit instead — and either is a determinate misread."""
    repo.git("checkout", "-q", "-b", "feature/x")
    repo.git("pack-refs", "--all")
    heads = repo.path / ".git/refs/heads"
    assert not (heads / "feature").exists()
    outside.mkdir()
    (outside / "x").write_bytes(planted.encode("ascii") + b"\n")
    os.symlink(outside, heads / "feature")


@pytest.mark.traces("GR9-4", "ST07-N1", "OB9-9b")
def test_an_intermediate_link_in_a_ref_path_is_never_followed() -> None:
    """`GR9-4` at every component, not only the last: the branch's loose ref is reached
    through a linked intermediate directory, and the observation is indeterminate — whatever
    the file outside names, a different commit or the packed one itself — so no file outside
    the repository influences a determinate observation, and the link is not read as
    absence either."""
    for planted in ("f" * 40, None):
        with x.workspace() as base:
            repo = x.repository(base)
            _branch_behind_a_link(repo, base / "outside", planted or repo.commit)
            found = observation.observe(repo.location)
        assert found == Indeterminate((ObservationCause.UNREADABLE_SUBJECT,)), planted


@pytest.mark.traces("GR9-4", "ST07-N1", "OB9-9b")
def test_a_linked_git_subdirectory_is_never_followed() -> None:
    """`.git/refs` replaced by a link to an identical copy outside the repository: every ref
    read crosses the link, and the observation is indeterminate rather than the copy's."""
    with x.workspace() as base:
        repo = x.repository(base)
        refs = repo.path / ".git/refs"
        shutil.copytree(refs, base / "outside-refs", symlinks=True)
        shutil.rmtree(refs)
        os.symlink(base / "outside-refs", refs)
        found = observation.observe(repo.location)
    assert isinstance(found, Indeterminate)
    assert ObservationCause.UNREADABLE_SUBJECT in found.causes


@pytest.mark.traces("GR9-4", "ST07-N1", "OB9-9b")
def test_a_working_tree_directory_swapped_for_a_link_mid_walk_is_never_followed() -> None:
    """A directory classified as a directory and then replaced by a link to an identical
    copy outside, before it is listed: the listing is a no-follow open of the directory
    itself, so the copy is never read and the observation is indeterminate."""
    with x.workspace() as base:
        repo = x.repository(base)

        def swap(found: observation.Stat) -> observation.Stat:
            (repo.path / "src").rename(base / "outside-src")
            os.symlink(base / "outside-src", repo.path / "src")
            return found

        reader = x.FaultReader({("lstat", b"/src", 1): swap})
        found = observation.observe(repo.location, reader)
    assert reader.fired
    assert isinstance(found, Indeterminate)
    assert ObservationCause.UNREADABLE_SUBJECT in found.causes


@pytest.mark.traces("GR9-4", "ST07-N1")
def test_a_location_with_a_dot_dot_or_linked_component_is_indeterminate() -> None:
    """The bound location is resolved like every other path: a `..` component, or an
    ancestor that is a link, is refused rather than followed — even where it would reach
    the very same repository."""
    with x.workspace() as base:
        repo = x.repository(base)
        os.symlink(base, base / "alias")
        assert isinstance(observation.observe(repo.location), Determinate)
        for location in (f"{repo.location}/../repo", str(base / "alias" / "repo")):
            found = observation.observe(location)
            assert isinstance(found, Indeterminate), location
            assert ObservationCause.UNREADABLE_SUBJECT in found.causes, location


@pytest.mark.traces("RS7-2", "ST07-D1")
def test_the_encoding_is_injective_over_raw_path_bytes() -> None:
    """Paths are carried as raw bytes in base 16: a space, a newline, a non-UTF-8 byte and a
    name that looks like an element separator each stay distinct and recoverable."""
    names = [b"with space", b"new\nline", b"\xff\xfe", b"a b c", b"file 100644"]
    with x.workspace() as base:
        repo = x.repository(base)
        for name in names:
            descriptor = os.open(os.fsencode(repo.path) + b"/" + name, os.O_WRONLY | os.O_CREAT)
            os.close(descriptor)
        seen = _seen(repo)
    recovered = {bytes.fromhex(e.split()[-1]) for e in seen.working_tree}
    assert set(names) <= recovered
    assert len({e.split()[-1] for e in seen.working_tree}) == len(seen.working_tree)


@pytest.mark.traces("ST07-N9", "OB9-12")
def test_no_clean_tree_is_required_anywhere() -> None:
    """`OB9-12`: a repository dirty in every way — modified, deleted, untracked, staged — is
    observed determinately. No cause names cleanliness, and nothing prepares the tree."""
    with x.workspace() as base:
        repo = x.repository(base)
        repo.write("a.txt", b"modified\n")
        (repo.path / "src/deep/c.txt").unlink()
        repo.write("new.txt", b"new\n")
        repo.write("src/b.py", b"staged\n")
        repo.git("add", "src/b.py")
        found = observation.observe(repo.location)
    assert isinstance(found, Determinate)
    for cause in ObservationCause:
        assert "CLEAN" not in cause.name and "DIRTY" not in cause.name
    assert not isinstance(found, Indeterminate)
