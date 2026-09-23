"""The `GP-AUTO-ST-01` traceability matrix: frozen inventory, executed evidence.

Design basis: AP-11 §3 (`TR11-1`…`TR11-9`), §13 (`EV11-1`, `EV11-5`, `EV11-6`,
`EV11-7`), §15 (`SG11-9`), §16 (`GP-AUTO-ST-01` acceptance).

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
    path = Path(configured[path_key])
    expected = configured[digest_key]
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
    "AP03-I04": (
        "GP-AUTO-ST-02",
        "Content equivalence needs canonicalization and comparison, which AP-03 §4.4 "
        "expressly does not design and which ST-02 owns under AP-07.",
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
    "AP03-I10": (
        "GP-AUTO-ST-03",
        "Attribution surviving consumption is a persistence property. The dependent "
        "identity already makes attribution structural.",
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
    "AP03-I19": (
        "GP-AUTO-ST-03",
        "The two-level model, the immutability of provenance and the admissibility "
        "relation's exclusion of worker-authored productions all hold and are tested "
        "here. The clause that does not is persistence: storing, indexing, surfacing, "
        "mirroring and **deduplicating by content** must confer no standing and must "
        "never merge two productions, and there is no store yet for that to be true of.",
    ),
    "AP03-I24": (
        "GP-AUTO-ST-09",
        "Closure being per finding and bound to one closure activation is structural and "
        "holds now, in the dependent identity pair. The remaining clause — that closure "
        "scope is a subset of the frozen set's membership — is freeze-and-closure "
        "behaviour, which ST-09 owns.",
    ),
    "AP03-I27": ("GP-AUTO-ST-03", "A statement about a store; this stage has none."),
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
    "AP03-I35": (
        "GP-AUTO-ST-03",
        "Instances surviving every disposition is a persistence and retrieval property.",
    ),
    "AP03-I36": (
        "GP-AUTO-ST-09",
        "'Zero or one set per discovery activation' is freeze behaviour. The three-valued "
        "distinction between no set, an empty set and not-yet-observed is already "
        "expressible and is tested here.",
    ),
}
"""For every AP-03 element this stage does not discharge: its first executable stage.

`EV11-6`: an owed-but-not-yet-executable obligation is recorded as **owed by its first
executable stage** rather than as absent or waived. The stages are AP-11 §16's and §17's;
none is invented here.
"""


def inventory() -> dict[str, str]:
    """The full in-scope element set: frozen AP-03 invariants plus this stage's rows."""
    return {**ap03_invariants(), **ST01_CONTRACT_OBLIGATIONS}


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
            rows.append(
                Row(
                    element,
                    statement,
                    DISCHARGED,
                    "; ".join(executed),
                    IMPLEMENTING_STAGE,
                    IMPLEMENTING_STAGE,
                    INTEGRATIVE_STAGE,
                    headline(statement),
                )
            )
            continue

        if designated:
            reason = "declared evidence did not pass: " + "; ".join(sorted(failed + unrun))
            rows.append(
                Row(
                    element,
                    statement,
                    UNDISCHARGED,
                    reason,
                    IMPLEMENTING_STAGE,
                    IMPLEMENTING_STAGE,
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

    print("GP-AUTO-ST-01 traceability matrix (TR11-4) — regenerated, stored nowhere (TR11-5).")
    print("AP-03 invariant inventory: parsed from the frozen AP-03 artifact, digest verified.")
    print(f"Executed evidence: {source}")
    print("Disposition is relative to this stage's delta and its frozen obligations (SG11-9).\n")
    print(f"{'element':<11} {'disposition':<13} {'impl':<15} {'local':<15} {'integrative':<15}")
    print("-" * 100)
    for row in rows:
        print(
            f"{row.element:<11} {row.disposition:<13} {row.implementing:<15} "
            f"{row.local_verifying:<15} {row.integrative:<15}"
        )
        print(f"{'':<12}{row.note}")
        print(f"{'':<12}{row.detail}")
    print("-" * 100)
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
    return status


if __name__ == "__main__":
    raise SystemExit(main())
