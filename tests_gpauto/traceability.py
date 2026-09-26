"""The GP-AUTO traceability matrix: frozen inventory, executed evidence.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-1`, `EV11-5`, `EV11-6`,
`EV11-7`), §15 (`SG11-9`), §16 (`GP-AUTO-ST-01` and `GP-AUTO-ST-02` acceptance);
AP-07 §5 (`ID-*`, `EQ-*`), §23 (`VM-11`), §23.1 (`DC-*`).

Three things are read; nothing normative is transcribed.

* **The inventory** is parsed out of the **frozen AP-03 artifact** — its §17 invariant
  table — after verifying the artifact's SHA-256 against the digest recorded in
  `pyproject.toml`. `TR11-4` requires the mapping to be generated from the artifacts;
  a transcribed list would be a second normative inventory that can drift from the
  first, and `TR11-8` is explicit that the matrix adapts to the artifacts rather than
  the artifacts to the matrix. If the artifact is missing or its digest does not
  match, this module **fails**: there is no fallback list to fall back to.
* **The declarations** are read back out of the test corpus by scanning for
  `@pytest.mark.traces(...)` and `@pytest.mark.supports(...)`.
* **The results** are read from an executed `pytest` run's JUnit XML. `EV11-1`(a)
  makes test output an evidence class in its own right, and `TR11-9` allows
  `discharged` only where *"the identified evidence exists, was actually run, and
  passed"*. A marker is a declaration, not a result, so a declared element whose
  designated tests were not run — or were run and failed — is `undischarged`.

`TR11-5` makes the matrix a derivation stored nowhere as authority: it is regenerated
on demand, a stale copy is not evidence, and a copy disagreeing with the corpus is
evidence about the copy. Nothing here writes it to a file.

**Disposition vocabulary** — `TR11-9`'s three, closed: `discharged`, `N/A` with its
reason, `undischarged`. `undischarged` is a **failing disposition**: required, honest,
and never rounded into a pass. No element is dispositioned `N/A` here, because every
AP-03 invariant carries an implementation obligation somewhere in GP-AUTO and `N/A`
for *"its behaviour belongs to a later stage"* is the re-disposition `TR11-9` names as
a defect in the plan's execution.

**When an element is `discharged` at this stage, exactly.** Per `SG11-9` a stage's
scope is its own delta and its frozen obligations. An AP-03 invariant is `discharged`
here only when **every clause of it** is enforced by structure present in this stage's
delta and confirmed by an executed passing test. A clause requiring an operation this
stage does not implement — resolution, derivation, persistence, observation,
lifecycle, comparison — leaves the element `undischarged`, owed by the first stage
that implements that operation, with the clauses that *are* enforced recorded as
support. An impossibility clause is not such an operation: `VP11-4` and §3.2 make
structural absence the primary evidence for those, and the absence exists now.

**From `GP-AUTO-ST-02` on, the matrix covers more than one stage.** ST-02's frozen
inputs are AP-07 §5 (`ID-*`, `EQ-*`), §23.1 (`DC-1`…`DC-5`) and AP-11's `SD11-1`,
`SD11-2`, `SD11-4`, with `VM-11` named by its negative tests (AP-11 §16). Those rows
are parsed out of the **frozen AP-07 and AP-11 artifacts**, digest-verified exactly
as AP-03 is. AP-07's path and digest are recorded here in the test tree rather than in
`pyproject.toml`, because ST-02's authorized scope is its modules and tests and does
not carry ST-01's tool-configuration clause.

**Which stage implemented an element is derived, not declared.** Each test module
that belongs to a stage after ST-01 states its stage as a module constant,
`GPAUTO_STAGE`; ST-01's modules predate the constant and are ST-01's. A discharged
element's implementing and local-verifying stage (`TR11-4a`) is the **earliest**
stage whose modules carry its passing evidence — where the enforcement first exists.

Run it:

    pytest tests_gpauto --junitxml=<results.xml>
    python tests_gpauto/traceability.py --results <results.xml>
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import tomllib
from pathlib import Path
from xml.etree import ElementTree

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_scope import REPOSITORY_ROOT

TEST_TREE = Path(__file__).resolve().parent

AP03_INVARIANT_ROW = re.compile(r"^\|\s*\*\*(AP03-I\d{2})\*\*\s*\|\s*(.+?)\s*\|\s*[^|]*\|\s*$")

DISCHARGED = "discharged"
UNDISCHARGED = "undischarged"
NOT_APPLICABLE = "N/A"

IMPLEMENTING_STAGE = "GP-AUTO-ST-01"
"""The stage of every test module that declares no `GPAUTO_STAGE` — ST-01's, which
predate the declaration. Later stages' modules always declare theirs."""

STAGES_RUN = ("GP-AUTO-ST-01", "GP-AUTO-ST-02", "GP-AUTO-ST-03")
"""The stages whose code and tests this matrix is generated over. A stage outside this
tuple has not run, so a row naming it as implementing stage must be an owed row."""

AP07_PATH = Path("/root/.claude/plans/you-are-now-authorized-vectorized-karp.md")
AP07_SHA256 = "64b6c3ec3c296c8ea1eee008eb81a50c354ea23b70dfe1d2c56fe175fb374f8d"
"""Frozen AP-07 (Persistence & Message Architecture), 1127 lines / 245910 bytes.

Recorded here rather than in `pyproject.toml`: `GP-AUTO-ST-02`'s authorized scope is
its modules and tests, so its frozen source is expressed inside the test tree."""

AP11_ST03_PATH = Path("/root/.claude/plans/AP-11-AMENDMENT-ST03-store-realization-boundary.md")
AP11_ST03_SHA256 = "8b8b785b73bcf41c09633912514ef722fd993074558d9dda8c637e2db6c91658"
"""The accepted AP-11 ST-03 store-realization amendment, 451 lines / 61690 bytes."""

AP11_ST03_FOLLOWON_PATH = Path(
    "/root/.claude/plans/AP-11-AMENDMENT-ST03-FOLLOW-ON-root-resolution-outcome-carrier.md"
)
AP11_ST03_FOLLOWON_SHA256 = "d084db02d31a68e7e8885cfda146f5452b70041007ef195c08ae020db26b405e"
"""The accepted ST-03 follow-on amendment, 153 lines / 18457 bytes."""

AP10_PATH = Path("/root/.claude/plans/AP-10-GP-AUTO-001-coord-compatibility-and-migration.md")
AP10_SHA256 = "d28a828b59064a10d45c32a28478c2f762567aa34034caff14397bcb2ddb4a3b"
"""Frozen AP-10, 741 lines / 139777 bytes — the `PB-2` placement row.

Like AP-07's, these three are recorded in the test tree: `GP-AUTO-ST-03`'s authorized
scope is its store modules and tests, with no tool-configuration clause."""

AP07_ROW = re.compile(r"^\|\s*((?:ID|EQ|DC)-\d+|VM-11)\s*\|\s*(.+?)\s*\|\s*$")
AP07_RECORD_ROW = re.compile(r"^\|\s*(RC-\d+)\s*\|(.+)\|\s*$")
AP07_EQ0 = re.compile(r"^> \*\*`(EQ-0)`\.\*\*\s*(.+?)\s*$")
AP11_SD_ROW = re.compile(r"^\|\s*(SD11-\d+[a-z]?)\s*\|\s*(.+?)\s*\|\s*$")

ST02_AP07_RECORD_ELEMENTS = ("RC-21",)
"""The AP-07 §14 record rows `GP-AUTO-ST-02` implements.

Exactly the rows this stage's frozen basis names — `RC-21` `ArtifactContent`, whose
content column is *"the bytes as produced"*. The record table's other ~60 rows are the
store's classes and belong to `GP-AUTO-ST-03`; parsing them here would put rows in the
matrix that no stage that has run could dispose, which `TR11-3` and `EV11-6` are not a
licence to do. Selected the same way `ST02_AP11_ELEMENTS` is, and checked against the
frozen text rather than transcribed.
"""

ST03_AP07_RECORD_ELEMENTS = tuple(f"RC-{number}" for number in range(10, 42))
"""The AP-07 §3.2 record classes `GP-AUTO-ST-03` realizes — every one, `RC-10` … `RC-41`
(`SRB11-1`, `SRB11-31`). `RC-21` is among them: owed by ST-03 since ST-02's acceptance."""

AMENDMENT_ROW = re.compile(r"^\|\s*((?:IV11|AP11-I)-?\d+)\s*\|(.+)\|\s*$")
ST03_AMENDMENT_ELEMENTS = (
    *(f"IV11-{number}" for number in range(1, 16)),
    *(f"AP11-I{number}" for number in range(64, 72)),
)
"""From the store-realization amendment: `IV11-1` … `IV11-15` (`SRB11-33`) and the new
invariants `AP11-I64` … `AP11-I71`. **`AP11-I72` is not a matrix row**: it is the `SG11-10`
bound, whose evidence is the stage-size evaluation reported to the OWNER at the stage
outcome (`SZ11-5`). No executed test can discharge it and no later stage owes it, so
recording it here would force either a false discharge or an invented owner."""

ST03_FOLLOWON_ELEMENTS = ("AP11-I73",)

PLACEMENT_ELEMENTS = ("PB-2(i)", "PB-2(ii)", "PB-2(iii)", "PB-2(iv)", "PB-2(v)")
"""AP-10 `PB-2`'s five boundaries, each its own row (`SRB11-35`)."""

ST02_AP11_ELEMENTS = ("SD11-1", "SD11-2", "SD11-4", "SD11-15", "SD11-16")
"""AP-11 §16's `GP-AUTO-ST-02` row names `SD11-1`, `SD11-2`, `SD11-4` as frozen inputs
and `SD11-15` as discovery-review scope; `SD11-16` is the import boundary the two
authorized primitives are imported under. `test_ga15` checks the row names them."""
INTEGRATIVE_STAGE = "GP-AUTO-ST-18"
"""`TR11-4a`(iii)'s integrative re-verification stage.

Taken from frozen AP-11 §16, whose `GP-AUTO-ST-18` row is *"End-to-end governed stage,
adversarial and mutation verification"* with a discovery-review scope of *"cross-cutting
conformance and claim discipline"*. It is not invented here, and `TR11-4b` is respected:
no element is mapped to `ST-18` alone.
"""


class FrozenSourceError(RuntimeError):
    """The frozen artifact is missing, unreadable, or is not the frozen artifact."""


def _traceability_configuration() -> dict[str, str]:
    manifest = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    configured = manifest["tool"]["gpauto"]["traceability"]
    assert isinstance(configured, dict)
    return {key: str(value) for key, value in configured.items()}


def frozen_artifact_text(path_key: str, digest_key: str) -> str:
    """Read a frozen artifact after verifying its digest, or raise.

    There is deliberately no fallback. `TR11-5` says a copy that disagrees with the
    corpus is evidence about the copy; an artifact whose digest does not match is not
    the frozen artifact, and generating an inventory from it would be generating one
    from something else while claiming the frozen source.
    """
    configured = _traceability_configuration()
    return verified_text(Path(configured[path_key]), configured[digest_key])


def verified_text(path: Path, expected: str) -> str:
    """A frozen artifact's text, only if its SHA-256 is the recorded one."""
    if not path.is_file():
        raise FrozenSourceError(f"frozen artifact not found: {path}")
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise FrozenSourceError(
            f"frozen artifact digest mismatch for {path}: expected {expected}, read {actual}"
        )
    return raw.decode("utf-8")


def ap03_invariants() -> dict[str, str]:
    """`AP03-I01`…`AP03-I36`, parsed from frozen AP-03 §17 (`TR11-4`, `TR11-8`)."""
    inventory: dict[str, str] = {}
    for line in frozen_artifact_text("ap03_path", "ap03_sha256").splitlines():
        matched = AP03_INVARIANT_ROW.match(line)
        if matched is None:
            continue
        element, statement = matched.group(1), matched.group(2)
        if element in inventory:
            raise FrozenSourceError(f"duplicate invariant row in the frozen artifact: {element}")
        inventory[element] = statement
    if not inventory:
        raise FrozenSourceError("no AP-03 invariant rows parsed from the frozen artifact")
    return inventory


def ap07_elements() -> dict[str, str]:
    """`ID-1`…`ID-14`, `EQ-0`…`EQ-10`, `DC-1`…`DC-5` and `VM-11`, from frozen AP-07."""
    inventory: dict[str, str] = {}
    for line in verified_text(AP07_PATH, AP07_SHA256).splitlines():
        matched = AP07_ROW.match(line) or AP07_EQ0.match(line)
        if matched is None:
            continue
        element, statement = matched.group(1), matched.group(2)
        if element in inventory:
            raise FrozenSourceError(f"duplicate row in the frozen AP-07 artifact: {element}")
        inventory[element] = statement
    if not inventory:
        raise FrozenSourceError("no AP-07 rows parsed from the frozen artifact")
    return inventory


def ap07_record_elements() -> dict[str, str]:
    """The `RC-*` rows implemented so far, from frozen AP-07 §3.2's record table."""
    wanted = (*ST02_AP07_RECORD_ELEMENTS, *ST03_AP07_RECORD_ELEMENTS)
    found: dict[str, str] = {}
    for line in verified_text(AP07_PATH, AP07_SHA256).splitlines():
        matched = AP07_RECORD_ROW.match(line)
        if matched is not None and matched.group(1) in wanted:
            if matched.group(1) in found:
                raise FrozenSourceError(f"duplicate record row in frozen AP-07: {matched.group(1)}")
            columns = [column.strip() for column in matched.group(2).split("|")]
            found[matched.group(1)] = " / ".join(column for column in columns if column)
    missing = set(wanted) - set(found)
    if missing:
        raise FrozenSourceError(f"AP-07 record rows not found: {sorted(missing)}")
    return {element: found[element] for element in sorted(set(wanted), key=_rc_number)}


def _rc_number(element: str) -> int:
    return int(element.split("-")[1])


def _amendment_rows(path: Path, digest: str, wanted: tuple[str, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in verified_text(path, digest).splitlines():
        matched = AMENDMENT_ROW.match(line)
        if matched is not None and matched.group(1) in wanted:
            if matched.group(1) in found:
                raise FrozenSourceError(f"duplicate row in {path.name}: {matched.group(1)}")
            columns = [column.strip() for column in matched.group(2).split("|")]
            found[matched.group(1)] = " / ".join(column for column in columns if column)
    missing = set(wanted) - set(found)
    if missing:
        raise FrozenSourceError(f"rows not found in {path.name}: {sorted(missing)}")
    return {element: found[element] for element in wanted}


def st03_amendment_elements() -> dict[str, str]:
    """`IV11-*` and `AP11-I64`…`AP11-I71`, from the accepted ST-03 amendment."""
    return _amendment_rows(AP11_ST03_PATH, AP11_ST03_SHA256, ST03_AMENDMENT_ELEMENTS)


def st03_followon_elements() -> dict[str, str]:
    """`AP11-I73`, from the accepted ST-03 follow-on amendment."""
    return _amendment_rows(
        AP11_ST03_FOLLOWON_PATH, AP11_ST03_FOLLOWON_SHA256, ST03_FOLLOWON_ELEMENTS
    )


def placement_elements() -> dict[str, str]:
    """`PB-2`(i) … (v), each clause split out of frozen AP-10's `PB-2` row verbatim."""
    row = next(
        (
            line
            for line in verified_text(AP10_PATH, AP10_SHA256).splitlines()
            if line.startswith("| PB-2 |")
        ),
        None,
    )
    if row is None:
        raise FrozenSourceError("AP-10 PB-2 row not found")
    clauses = re.split(r"\*\((i|ii|iii|iv|v)\)\*", row)
    labels, texts = clauses[1::2], clauses[2::2]
    if labels != ["i", "ii", "iii", "iv", "v"]:
        raise FrozenSourceError(f"AP-10 PB-2 clauses not as frozen: {labels}")
    return {f"PB-2({label})": text.strip(" ;|") for label, text in zip(labels, texts, strict=True)}


def ap11_elements() -> dict[str, str]:
    """The `SD11-*` rows `GP-AUTO-ST-02` implements, from frozen AP-11 §14."""
    found: dict[str, str] = {}
    for line in frozen_artifact_text("ap11_path", "ap11_sha256").splitlines():
        matched = AP11_SD_ROW.match(line)
        if matched is not None and matched.group(1) in ST02_AP11_ELEMENTS:
            if matched.group(1) in found:
                raise FrozenSourceError(f"duplicate row in frozen AP-11: {matched.group(1)}")
            found[matched.group(1)] = matched.group(2)
    missing = set(ST02_AP11_ELEMENTS) - set(found)
    if missing:
        raise FrozenSourceError(f"AP-11 rows not found in the frozen artifact: {sorted(missing)}")
    return {element: found[element] for element in ST02_AP11_ELEMENTS}


def headline(statement: str) -> str:
    """The invariant's leading bold clause — its name, as AP-03 writes it."""
    bold = re.match(r"^\*\*(.+?)\*\*", statement)
    text = bold.group(1) if bold else statement
    return re.sub(r"\s+", " ", text).strip()


ST01_CONTRACT_OBLIGATIONS: dict[str, str] = {
    "ST01-D1": "Deliverable: typed domain structures.",
    "ST01-D2": "Deliverable: identity-kind representations.",
    "ST01-D3": "Deliverable: closed vocabularies.",
    "ST01-D4": "Deliverable: three-valued absence types.",
    "ST01-T1": "Test: construction and round-trip of every entity.",
    "ST01-T2": "Test: closed-vocabulary acceptance.",
    "ST01-T3": "Test: three-valued absence expressible.",
    "ST01-T4": "Test: gate-scope proof — paths enumerated, fixture fails (SD11-12b).",
    "ST01-N1": "Negative: undeclared field refused (extra=forbid).",
    "ST01-N2": "Negative: a list where a tuple is required is refused.",
    "ST01-N3": "Negative: identity kinds are not interchangeable.",
    "ST01-N4": "Negative: provider absent from every bounds structure (NV11-6).",
    "ST01-N5": "Negative: objective-production admissibility is tied to the referent's "
    "provenance, not asserted beside it (EA-1, AP-03 §18.4).",
    "ST01-N6": "Negative: each governed fact kind admits only its permitted referent "
    "identity type (AP-03 §8.2).",
    "ST01-N7": "Negative: a stage-outcome acceptance cannot produce an authorization "
    "(SO-1, AP-03 §11.2).",
    "ST01-N8": "Negative: the frozen Git grantability classification cannot be mutated "
    "(AP-03 §4.8.1).",
    "ST01-G1": "Static gate: ruff over the GP-AUTO package (SD11-12a(ii)).",
    "ST01-G2": "Static gate: mypy --strict actually type-checking GP-AUTO code.",
    "ST01-G3": "Static gate: GP-AUTO decode/import gate over GP-AUTO code (DC-1, DC-2).",
    "ST01-A1": "Acceptance: every AP-03 entity and identity kind representable.",
    "ST01-A2": "Acceptance: no entity outside AP-03 introduced.",
    "ST01-A3": "Acceptance: separate package; the spike is untouched and inert (SD11-10, SD11-16).",
    "ST01-A4": "Acceptance: no provider surface on any entry surface (SG11-11, SG11-11a).",
    "ST01-A5": "Acceptance: delta is uncommitted project-file change only (SG11-8).",
    "ST01-A6": "Acceptance: traceability rows with closed dispositions (TR11-4, TR11-9).",
}
"""Labels for this stage's own contract rows — **not** a second normative inventory.

The normative inventory is AP-03's, parsed from the frozen artifact above. These ids
name the `GP-AUTO-ST-01` contract's own deliverables, tests, negative tests, static
gates and acceptance criteria — `TR11-1`(c), (d) and (e) units — and exist so that
`TR11-7`'s reverse direction is answerable: *"why does this test exist?"* must have an
answer for a test that verifies this stage's contract rather than an AP-03 invariant.
They restate no AP-03 content and no element is disposed by them.
"""

ST02_CONTRACT_OBLIGATIONS: dict[str, str] = {
    "ST02-D1": "Deliverable: content-identity derivation over the canonical preimage.",
    "ST02-D2": "Deliverable: equivalence comparison for authority-bearing content.",
    "ST02-D3": "Deliverable: GP-AUTO codec with model_validate_json only.",
    "ST02-T1": "Test: canonical preimage stored and used as the authoritative representation.",
    "ST02-T2": "Test: identical content => identical identity.",
    "ST02-T3": "Test: equivalence over RA-01...RA-09 plus liveness.",
    "ST02-N1": "Negative: json.loads + model_validate absent package-wide.",
    "ST02-N2": "Negative: re-serialization round trip not treated as identity (DC-4).",
    "ST02-N3": "Negative: differing authority-bearing content => not equivalent.",
    "ST02-N4": "Negative: format version never read as recency or precedence (VM-11).",
    "ST02-M1": "Mutation: equivalence comparison guard, per mutant, killing test named.",
    "ST02-M2": "Mutation: decode-path guard by schema mutation (MU11-5), per mutant.",
    "ST02-G1": "Static gate: ruff scope extended to ST-02's modules (SD11-12b).",
    "ST02-G2": "Static gate: mypy --strict scope extended to ST-02's modules (SD11-12b).",
    "ST02-G3": "Static gate: GP-AUTO decode/import gate, load-bearing on the codec (DC-2).",
    "ST02-A1": "Acceptance: one canonicalization and one SHA-256 site in the repository.",
    "ST02-A2": "Acceptance: equivalence conformant (AP-03 §4.4's four properties).",
    "ST02-A3": "Acceptance: codec boundary enforced by the existing gate.",
    "ST02-A5": "Acceptance: only the two authorized primitives imported; the spike, "
    "its tests, documents and gates unchanged (SD11-10, SD11-16).",
}
"""Labels for `GP-AUTO-ST-02`'s own contract rows — as `ST01_CONTRACT_OBLIGATIONS`,
**not** a second normative inventory. The normative rows are AP-07's and AP-11's,
parsed from the frozen artifacts. (`ST02-A4` is not a label: the contract's fourth
acceptance-side obligation, reused primitives verified rather than assumed, is the
frozen row `SD11-15` itself.)"""

ST03_CONTRACT_OBLIGATIONS: dict[str, str] = {
    "ST03-D1": "Deliverable: create-only write surface for every record class RC-10...RC-41.",
    "ST03-D2": "Deliverable: the SRB11-8 uniqueness constraints — envelope reuse and a "
    "second boundary per root inexpressible.",
    "ST03-D3": "Deliverable: native referential integrity, and the instance-identity "
    "existence rule (SRB11-10).",
    "ST03-D4": "Deliverable: atomic coupled-create capability (SRB11-11).",
    "ST03-D5": "Deliverable: the frozen store pattern — WAL, synchronous=FULL, foreign keys, "
    "bounded busy_timeout, STRICT tables (EB-13).",
    "ST03-D6": "Deliverable: the IV11-* vocabularies and the section 5.3 identity types.",
    "ST03-T1": "Test: each record class created once.",
    "ST03-T2": "Test: coupled unit visible whole or not at all.",
    "ST03-T3": "Test: every reference resolves.",
    "ST03-T4": "Test: write-once classes reject a second write.",
    "ST03-T5": "Test: append-only classes accept only new rows naming a predecessor.",
    "ST03-T6": "Test: every IV11-* value set accepts exactly its frozen members and refuses "
    "any other value.",
    "ST03-T7": "Test: every visible record under one identity surfaced individually (NP-13).",
    "ST03-N1": "Negative: no UPDATE or DELETE reachable for any class (PV11-1).",
    "ST03-N2": "Negative: no GP-AUTO write path into any ingest-only class (SRB11-20).",
    "ST03-N3": "Negative: a dangling or mismatched reference is refused.",
    "ST03-N4": "Negative: every SRB11-8 forbidden duplicate is inexpressible.",
    "ST03-N5": "Negative: an older, newer or altered schema is refused, never migrated or "
    "partially read (section 8).",
    "ST03-N6": "Negative: forbidden fields (RC-50...RC-61) and the ST-01 derived fields "
    "absent; an unreadable record surfaced, never dropped (VM-6).",
    "ST03-N7": "Negative: no guard or transition logic over any IV11-* value, structurally; "
    "no second encoding of any section 5.2 concept.",
    "ST03-R1": "Restart/persistence: crash consistency at the coupled-create window, "
    "Class A (CW-2); records and identities survive reopen.",
    "ST03-P1": "Placement: verified by location, relying on no exclude, ignore rule, "
    "untrackedness or permission (PB-8).",
    "ST03-P2": "Placement: no default location; the store writes only where it is placed "
    "(SRB11-26).",
    "ST03-G1": "Static gate: decision layer imports no engine (EB-6); GP-AUTO gates extended "
    "to every new module (SD11-12b).",
    "ST03-A1": "Acceptance: no record class invented and none omitted.",
    "ST03-A2": "Acceptance: stale-schema refusal is ST-03's deliverable (SRB11-17).",
    "ST03-RR1": "Root resolution: RC-14 is the A1 occurrence; an open resolution is a "
    "complete stored state (RO7A-1, RO7A-9, SRF11-1).",
    "ST03-RR2": "Root resolution: the A2 entry carries the resolved-root instance (RO7A-3).",
    "ST03-RR3": "Root resolution: MC-17(ii) on the instance identity alone.",
    "ST03-RR4": "Root resolution: A3 and A4 bind their Refusal / AuthorityAmbiguity by "
    "reference, created in the same unit (RO7A-4).",
    "ST03-RR5": "Root resolution: bindings structurally absent where they do not belong (RO7A-5).",
    "ST03-RR6": "Root resolution: reconstruction from the chain alone after restart (RB-1).",
    "ST03-M1": "Mutation: write-class enforcement, per mutant, killing test named.",
    "ST03-M2": "Mutation: referential-integrity enforcement, per mutant.",
    "ST03-M3": "Mutation: stale-schema refusal, per mutant.",
    "ST03-M4": "Mutation: the frozen keys and the root-resolution bindings, per mutant.",
}
"""Labels for `GP-AUTO-ST-03`'s own contract rows (AP-11 §16 as replaced by the ST-03
amendment §11.1 and the follow-on §3) — as the ST-01 and ST-02 labels, **not** a second
normative inventory: the normative rows are parsed from the frozen artifacts above."""

OWED_AT_ST02_ACCEPTANCE: dict[str, str] = {
    "ID-3": "GP-AUTO-ST-03",
    "ID-4": "GP-AUTO-ST-03",
    "ID-5": "GP-AUTO-ST-03",
    "ID-7": "GP-AUTO-ST-03",
    "ID-8": "GP-AUTO-ST-03",
    "ID-14": "GP-AUTO-ST-03",
    "EQ-6": "GP-AUTO-ST-06",
    "EQ-7": "GP-AUTO-ST-03",
    "EQ-9": "GP-AUTO-ST-03",
    "RC-21": "GP-AUTO-ST-03",
}
"""The ST-02 rows owed to a later stage when ST-02 was accepted — a historical record, so
a row owed then and discharged since can be checked against the stage that owed it."""

OWED_BY: dict[str, tuple[str, str]] = {
    "AP03-I01": (
        "GP-AUTO-ST-06",
        "The derivation chain first exists where envelopes are derived from a resolved root.",
    ),
    "AP03-I02": (
        "GP-AUTO-ST-06",
        "The structural halves hold now — RA-02 is singular and multiplicity is "
        "representable — but 'at most one may be resolved as root and govern' is a "
        "resolution outcome, which this stage does not implement.",
    ),
    "AP03-I06": (
        "GP-AUTO-ST-06",
        "Eligibility, exclusion and the outcome rule are resolution behaviour.",
    ),
    "AP03-I07": (
        "GP-AUTO-ST-06",
        "The ordering constraint binds the act of deriving; ST-07 supplies the boundary "
        "observation the chain consumes.",
    ),
    "AP03-I08": (
        "GP-AUTO-ST-07",
        "'Never moves' is a property of the observation and its store, not of a type.",
    ),
    "AP03-I11": (
        "GP-AUTO-ST-08",
        "Non-convertibility is enforced where state is classified, not where it is typed.",
    ),
    "AP03-I12": (
        "GP-AUTO-ST-05",
        "'One envelope identity, one activation' is a cardinality the state machine "
        "enforces. Minted-not-content identity and the absence of any revive operation "
        "already hold and are tested here.",
    ),
    "AP03-I13": ("GP-AUTO-ST-06", "Envelope <= ceiling is a comparison this stage does not make."),
    "AP03-I14": ("GP-AUTO-ST-06", "Re-derivation is an act, and AP-08 governs whether one occurs."),
    "AP03-I15": (
        "GP-AUTO-ST-06",
        "The role-conditional dimensions are typed so applicability is expressible, but "
        "which role makes which dimension applicable is AP-02 §3.1.2's table — not among "
        "this stage's frozen inputs, and not invented from AP-03's partial text.",
    ),
    "AP03-I18": (
        "GP-AUTO-ST-06",
        "A statement about what a derived envelope may grant a reviewing role.",
    ),
    "AP03-I24": (
        "GP-AUTO-ST-09",
        "Closure being per finding and bound to one closure activation is structural and "
        "holds now, in the dependent identity pair. The remaining clause — that closure "
        "scope is a subset of the frozen set's membership — is freeze-and-closure "
        "behaviour, which ST-09 owns.",
    ),
    "AP03-I28": (
        "GP-AUTO-ST-08",
        "The five facts are five distinct non-convertible types, the case markers are "
        "pinned and required, and no record recommends a disposition — all structural and "
        "tested here. The remaining clause is GE-4's coexistence: that one occurrence may "
        "require several records, and that a known-producer unaccounted mutation is "
        "recorded as **both** an UnaccountedMutation and an EnvelopeViolation. That is a "
        "recording behaviour, which ST-08 owns.",
    ),
    "AP03-I30": (
        "GP-AUTO-ST-06",
        "That no envelope is produced for a non-activated role is a derivation outcome. "
        "Recording the absence as correct is already expressible and is tested here.",
    ),
    "AP03-I36": (
        "GP-AUTO-ST-09",
        "'Zero or one set per discovery activation' is freeze behaviour. The three-valued "
        "distinction between no set, an empty set and not-yet-observed is already "
        "expressible and is tested here.",
    ),
    # --- GP-AUTO-ST-02's AP-07 rows whose remaining clause needs a later operation ---
    # (ID-3/4/5/7/8/14, EQ-7, EQ-9 and RC-21 were owed to ST-03 and are discharged there.)
    # --- GP-AUTO-ST-03: placement boundaries no stage has yet instantiated (SRB11-29) ---
    "PB-2(ii)": (
        "GP-AUTO-ST-17",
        "The workspace boundary E-10 and every worker's mutation reach are extents the "
        "implemented runtime has not instantiated; ST-17's Tests cell owes the check by "
        "location against them (SRB11-29, AP11-I71). Never N/A.",
    ),
    "PB-2(iii)": (
        "GP-AUTO-ST-17",
        "Every reviewing role's read boundary is not instantiated before ST-17 (SRB11-29, "
        "AP11-I71). Never N/A.",
    ),
    "PB-2(v)": (
        "GP-AUTO-ST-17",
        "The bounded non-project execution side-effect area (XA-1) is not instantiated "
        "before ST-17 (SRB11-29, AP11-I71). AP-10's PB-2(v)-redundancy follow-up is carried "
        "unfixed (SRB11-30). Never N/A.",
    ),
    "EQ-6": (
        "GP-AUTO-ST-06",
        "Indeterminate is never equivalence, and is shown here in every form. The rest "
        "of the rule — record an AuthorityAmbiguity naming the identity and disagreeing "
        "classes, constitute no instance, do not begin the stage — is root resolution.",
    ),
}
"""For every element not yet discharged: its first executable stage.

`EV11-6`: an owed-but-not-yet-executable obligation is recorded as **owed by its first
executable stage** rather than as absent or waived. The stages are AP-11 §16's and §17's;
none is invented here.
"""


CORRECTION_SOURCES = (
    (
        "ST-01-CORRECTION-OwnerDecision-obligation-referent.md",
        130,
        27959,
        "bde313b2fa55f1f718bce72abe563a813e02b73275df862f86fcb72dcb7a954f",
    ),
    (
        "ST-03-CORRECTION-RC13-obligation-referent-schema-v3.md",
        148,
        30524,
        "4225a488627f08b4dacd4250fb7e70cd45561add2525f467077c086e6d562590",
    ),
)


def correction_elements() -> dict[str, str]:
    """Accepted corrective verification rows, read from their frozen identities.

    SC01_V14_IMPLEMENTATION_CLARIFICATION_ONLY locates V14 enforcement at RC-13.
    OBS_ST03_1_IMPLEMENTATION_DETAIL retains both member foreign keys.
    OBS_ST03_2_IMPLEMENTATION_DETAIL requires referential fixture insertion order.
    """
    rows: dict[str, str] = {}
    for name, lines, size, digest in CORRECTION_SOURCES:
        raw = (Path("/root/.claude/plans") / name).read_bytes()
        assert (raw.count(b"\n"), len(raw), hashlib.sha256(raw).hexdigest()) == (
            lines,
            size,
            digest,
        )
        for line in raw.decode().splitlines():
            match = re.match(r"^\| (SC0[13]-V\d+) \| (.*) \|$", line)
            if match:
                rows[match[1]] = match[2]
    assert len(rows) == 31
    rows["SC01-V14"] += " SC01_V14_IMPLEMENTATION_CLARIFICATION_ONLY: enforced at RC-13."
    return rows


def inventory() -> dict[str, str]:
    """The full in-scope element set, over every stage that has run.

    Frozen AP-03 invariants and ST-01's contract rows; frozen AP-07 and AP-11 rows and
    ST-02's contract rows.
    """
    return {
        **ap03_invariants(),
        **ST01_CONTRACT_OBLIGATIONS,
        **ap07_elements(),
        **ap07_record_elements(),
        **ap11_elements(),
        **ST02_CONTRACT_OBLIGATIONS,
        **st03_amendment_elements(),
        **st03_followon_elements(),
        **placement_elements(),
        **ST03_CONTRACT_OBLIGATIONS,
        **correction_elements(),
    }


def module_stage(path: Path) -> str:
    """The stage a test module declares by `GPAUTO_STAGE`, else ST-01's (see above)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and [getattr(target, "id", None) for target in node.targets] == ["GPAUTO_STAGE"]
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    return IMPLEMENTING_STAGE


def evidence_stage(node_ids: list[str]) -> str:
    """The earliest stage among the modules carrying these tests (`TR11-4a`(i))."""
    return min(module_stage(REPOSITORY_ROOT / node_id.split("::")[0]) for node_id in node_ids)


def _declared(marker: str) -> dict[str, list[str]]:
    """Element id -> test node ids, read back out of the corpus (`TR11-4`)."""
    declarations: dict[str, list[str]] = {}
    for path in sorted(TEST_TREE.glob("test_*.py")):
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                target = decorator.func
                if not (isinstance(target, ast.Attribute) and target.attr == marker):
                    continue
                for argument in decorator.args:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        declarations.setdefault(argument.value, []).append(
                            f"{relative}::{node.name}"
                        )
    return {key: sorted(set(value)) for key, value in declarations.items()}


def declared_evidence() -> dict[str, list[str]]:
    """Discharging declarations, by element. A declaration is not yet a discharge."""
    return _declared("traces")


def declared_support() -> dict[str, list[str]]:
    """Non-discharging declarations, by element — reported, never counted (`TR11-9`)."""
    return _declared("supports")


def executed_results(report: Path) -> dict[str, bool]:
    """`node id -> passed`, from an executed `pytest --junitxml` run (`EV11-1`(a)).

    Parametrized cases are folded onto their function's node id and must **all** pass:
    a suite where one parametrization failed has not shown the element enforced.
    """
    outcomes: dict[str, bool] = {}
    for case in ElementTree.parse(report).iter("testcase"):
        classname = case.get("classname", "")
        name = re.sub(r"\[.*\]$", "", case.get("name", ""))
        if not classname or not name:
            continue
        node_id = f"{classname.replace('.', '/')}.py::{name}"
        passed = all(case.find(tag) is None for tag in ("failure", "error", "skipped"))
        outcomes[node_id] = outcomes.get(node_id, True) and passed
    return outcomes


class Row:
    """One matrix row. `TR11-4a` keeps the three stage roles separate, recorded."""

    def __init__(
        self,
        element: str,
        statement: str,
        disposition: str,
        detail: str,
        implementing: str,
        local_verifying: str,
        integrative: str,
        note: str,
    ) -> None:
        self.element = element
        self.statement = statement
        self.disposition = disposition
        self.detail = detail
        self.implementing = implementing
        self.local_verifying = local_verifying
        self.integrative = integrative
        self.note = note


def matrix(results: dict[str, bool] | None) -> list[Row]:
    """The matrix, over the frozen inventory and the executed results supplied.

    `results is None` means no executed evidence was supplied, and every element is
    then `undischarged` — *"evidence-missing"* is one of `TR11-9`'s own cases, and a
    marker without a result is a declaration, not a discharge.
    """
    evidence = declared_evidence()
    support = declared_support()
    rows: list[Row] = []

    for element, statement in inventory().items():
        designated = evidence.get(element, [])
        executed = [
            node_id for node_id in designated if results is not None and results.get(node_id)
        ]
        unrun = [node_id for node_id in designated if results is None or node_id not in results]
        failed = [
            node_id
            for node_id in designated
            if results is not None and results.get(node_id) is False
        ]

        if designated and not unrun and not failed:
            stage = evidence_stage(designated)
            rows.append(
                Row(
                    element,
                    statement,
                    DISCHARGED,
                    "; ".join(executed),
                    stage,
                    stage,
                    INTEGRATIVE_STAGE,
                    headline(statement),
                )
            )
            continue

        if designated:
            stage = evidence_stage(designated)
            reason = "declared evidence did not pass: " + "; ".join(sorted(failed + unrun))
            rows.append(
                Row(
                    element,
                    statement,
                    UNDISCHARGED,
                    reason,
                    stage,
                    stage,
                    INTEGRATIVE_STAGE,
                    headline(statement),
                )
            )
            continue

        owed_stage, reason = OWED_BY.get(element, ("<UNRECORDED>", "no owed-by recorded"))
        detail = f"owed by {owed_stage}"
        if element in support:
            detail += " | structure verified here: " + "; ".join(support[element])
        rows.append(
            Row(
                element,
                statement,
                UNDISCHARGED,
                detail,
                owed_stage,
                owed_stage,
                INTEGRATIVE_STAGE,
                reason,
            )
        )
    return rows


def unknown_elements() -> list[str]:
    """Element ids declared by a test but absent from the inventory (`TR11-4`)."""
    declared = set(declared_evidence()) | set(declared_support())
    return sorted(declared - set(inventory()))


def untraced_tests() -> list[str]:
    """Test node ids carrying neither marker (`TR11-7`, evidence -> element)."""
    traced: set[str] = set()
    for mapping in (declared_evidence(), declared_support()):
        for node_ids in mapping.values():
            traced.update(node_ids)

    untraced: list[str] = []
    for path in sorted(TEST_TREE.glob("test_*.py")):
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
                "test_"
            ):
                node_id = f"{relative}::{node.name}"
                if node_id not in traced:
                    untraced.append(node_id)
    return untraced


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    results: dict[str, bool] | None = None
    source = "none supplied — every element is undischarged for missing evidence"
    if "--results" in arguments:
        report = Path(arguments[arguments.index("--results") + 1])
        results = executed_results(report)
        source = f"{report} ({len(results)} executed test node ids)"

    rows = matrix(results)
    discharged = [row for row in rows if row.disposition == DISCHARGED]
    undischarged = [row for row in rows if row.disposition == UNDISCHARGED]
    not_applicable = [row for row in rows if row.disposition == NOT_APPLICABLE]

    print("GP-AUTO traceability matrix (TR11-4) — regenerated, stored nowhere (TR11-5).")
    print(f"Stages run: {', '.join(STAGES_RUN)}.")
    print(
        "Inventory: AP-03 invariants, AP-07 ID-*/EQ-*/DC-*/VM-11 and AP-11 SD11-* rows,"
        " parsed from the frozen artifacts, digests verified; plus each stage's contract rows."
    )
    print(f"Executed evidence: {source}")
    print("Disposition is relative to this stage's delta and its frozen obligations (SG11-9).\n")
    print(f"{'element':<11} {'disposition':<13} {'impl':<15} {'local':<15} {'integrative':<15}")
    by_stage: dict[str, list[Row]] = {}
    print("-" * 100)
    for row in rows:
        print(
            f"{row.element:<11} {row.disposition:<13} {row.implementing:<15} "
            f"{row.local_verifying:<15} {row.integrative:<15}"
        )
        print(f"{'':<12}{row.note}")
        print(f"{'':<12}{row.detail}")
    print("-" * 100)
    for row in rows:
        by_stage.setdefault(row.implementing, []).append(row)
    for stage in sorted(by_stage):
        counted = by_stage[stage]
        print(
            f"implementing {stage}: {len(counted)} element(s) — "
            f"{sum(r.disposition == DISCHARGED for r in counted)} discharged, "
            f"{sum(r.disposition == UNDISCHARGED for r in counted)} undischarged"
        )
    print(f"in-scope elements : {len(rows)}")
    print(f"discharged        : {len(discharged)}")
    print(f"undischarged      : {len(undischarged)}   (a FAILING disposition — TR11-9, EV11-6)")
    print(f"N/A               : {len(not_applicable)}")

    if undischarged:
        print("\nUNDISCHARGED ELEMENTS (reported, never a completion — TR11-9):")
        for row in undischarged:
            print(f"  {row.element}  -> {row.implementing}")
            print(f"      {row.note}")
            if "structure verified here:" in row.detail:
                print(f"      {row.detail.split('| ', 1)[1]}")

    status = 0
    unknown = unknown_elements()
    if unknown:
        print(f"\nDEFECT — evidence names elements not in the inventory: {unknown}")
        status = 1
    untraced = untraced_tests()
    if untraced:
        print(f"\nDEFECT — tests tracing to no element (TR11-7): {untraced}")
        status = 1
    missing_owed = [row.element for row in undischarged if row.implementing == "<UNRECORDED>"]
    if missing_owed:
        print(f"\nDEFECT — undischarged elements with no first executable stage: {missing_owed}")
        status = 1
    corrections = [row for row in rows if row.element in correction_elements()]
    if all(row.disposition == DISCHARGED for row in corrections):
        print("DV-5 / DV-3: enabled for ST-04, not discharged.")
    print("ST04_REMAINS_HALTED_PENDING_IMPLEMENTATION_REVIEW_AND_ACCEPTANCE")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
