"""The coordination store's schema: one table family per record class, generated from the models.

Design basis: AP-11 ST-03 store-realization amendment §6 (`RS11-10`…`RS11-41`), §7
(`SRB11-8`…`SRB11-11`), §8 (`SRB11-12`, `SRB11-13`), §9 (`SRB11-18`…`SRB11-23`), as
modified by the ST-03 follow-on §3 (`RS11-14`, `RS11-34`, `SRF11-1`); AP-07 §3.2, §6
(`WP-1`…`WP-4`, `WP-17`, `WP-19`), §7 (`IM-1`…`IM-5`), §15.3 (`MC-15`…`MC-17`), §22.1
(`EB-2`, `EB-2a`, `EB-5`), §23 (`VM-1`, `VM-3`, `VM-5`); root-resolution clarification
`RO7A-1`…`RO7A-5`, `RO7A-9`.

**The schema is derived from the one encoding, never restated.** Every column, every
closed value set, every key and every reference below is generated from the record
models' own type annotations — ST-01's entities and vocabularies, ST-02's identified
content, and ST-03's `coordination_*` modules. A `CHECK (… IN (…))` list is the enum it
was generated from, not a transcription of it, so no vocabulary has a second encoding in
the schema (`SRB11-4`, `AP11-I65`). What *is* stated here, per table, is only what the
frozen text fixes and a type cannot say: which field is the record's key, the uniqueness
constraints `SRB11-8` names, and the handful of structural rules the amendments fix.

**How a model becomes columns.** A field's type decides its representation, uniformly:

* an opaque identity — one `TEXT` column; a **minted** identity also carries `ID-4`'s
  shape check;
* a closed vocabulary or a `Literal` — one column, `CHECK`ed to exactly its members;
* `str` / `bool` / `bytes` — `TEXT` / `INTEGER` (0 or 1) / `BLOB`;
* a value model or dependent identity — its fields, as `<field>__<sub-field>` columns;
* a union — a `<field>__kind` column naming the variant, and each variant's columns,
  present **iff** that variant is the one named, so a variant not taken is structurally
  absent, never an implicit null;
* `tuple[X, ...]` — a child table, one row per member, keyed by the parent's key and the
  member's slot;
* an embedded objective or worker-authored production — a **reference** to the `RC-22`
  record, keyed by identity **and** provenance and reconstructed from it on read, never a
  copy (`AT-9`).

**Every reference is enforced, never assumed** (`EB-2a`, `SRB11-10`, `SRB11-22`). Each
identity-typed column references the table where that identity is a record's key, by a
native foreign key within the one database file. A reference to an **`OwnerAuthorization`
instance** cannot be one: that identity is borne by one or more `RC-12` records and is the
key of none (`NP-13`, `AP03-I33`), so it is enforced by a trigger inside the same insert
that requires at least one `RC-12` record bearing it — no instance table is invented, and
whether the instance is *constituted* stays ST-06's. `RC-12` rows cannot be deleted, so a
reference that resolved once resolves forever (`IM-4`).

**Create-only is structural** (`WP-4`, `EB-5`, `IM-1`). Every table, child tables included,
carries triggers refusing `UPDATE` and `DELETE`. The store's own write path issues `INSERT`
only, never `REPLACE`. A conflict-resolving `INSERT OR REPLACE` fires the delete trigger only
on a connection with `recursive_triggers` on: every GP-AUTO connection sets and verifies it
(`store.PRAGMAS`), and another connection is covered only if it adopts the same
configuration. The file is not an access-control boundary — nothing here is claimed against
an actor who opens it with other pragmas, or drops or alters its triggers.

**The ingest domain shares the file and gets no write path** (`SRB11-18`…`SRB11-23`,
`AP11-I70`). `RC-10`, `RC-11` contents, `RC-12` and `RC-13` are `INGEST` tables: their DDL
and their read decoding are here, and `writable_layouts` excludes them, so the store's
insert machinery is never handed one. That is an absence of an operation, not access
control: nothing is claimed against an actor holding the file.

**Nothing here decides anything** (`SRB11-3`, `AP11-I66`, `AP11-I67`). No transition
graph, guard, evaluator, from→to mapping or derivation exists in this module. The only
cross-field rules are structural facts the frozen text states of the *record*: the `A2`,
`A3`, `A4` result bindings fixed by an M1 entry's edge (`RO7A-5`), a predecessor naming
its own subject's chain (`PA-04`), and a determination naming its own activation's effects
(`RS7-10`).

Guard identifiers are fixed where each guard is written (`MU11-3`):
`ga_store_write_class`, `ga_store_referential_integrity`, `ga_store_keys`.
"""

from __future__ import annotations

import functools
import operator
import types
import typing
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any, Final, Literal, get_args, get_origin

from pydantic import BaseModel

from gpauto.authorization import AuthorityAmbiguity, AuthorizationRecord
from gpauto.content_identity import IdentifiedArtifactContent, IdentifiedStageContract
from gpauto.coordination_records import (
    ActivationEffectRecord,
    ArtifactProductionRecord,
    AuditEntry,
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    ClosureAssessmentRecord,
    ConformanceDetermination,
    CycleOccurrence,
    DispatchRecord,
    DispositionEstablishingRecord,
    EntryStateBoundaryRecord,
    EnvelopeViolationRecord,
    ExecutionObservation,
    FindingRecord,
    GovernanceEventResolution,
    HaltOccurrence,
    InputPackageRecord,
    M1PositionEntry,
    M2PositionEntry,
    M3PositionEntry,
    M4PositionEntry,
    OutcomeIngestionRecord,
    PostFreezeCandidateRecord,
    RefusalRecord,
    RootResolutionRecord,
    SessionRecord,
    WorkerActivationRecord,
)
from gpauto.evidence import ArtifactProduction
from gpauto.governance import DecisionAct, OwnerDecision, StageOutcome
from gpauto.identity import DependentIdentity, MintedIdentity, OpaqueIdentity, OwnerAuthorizationId
from gpauto.minting import MINTED_VALUE_LENGTH
from gpauto.repository import ClassificationContext, UnaccountedMutation
from gpauto.review import FrozenFindingSet, RemediationObligation
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)

SCHEMA_VERSION: Final[str] = "gpauto.coordination-store/4"
"""The schema's identity (`SRB11-12`). A different table or constraint set is a different
version (`SRB11-13`); nothing migrates between versions (`VM-8`). Version 4 realizes
`ST06PC-1`: the role-indexed `RA-07` ceiling and the RC-18 `E-16` member
`BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA`, on top of version 3's ST01C-2 decision referents
and ST03C-1 bindings. v1, v2 and v3 are stale and refused."""


STORAGE_VERSION: Final[int] = 4
"""The physical marker persisted in `PRAGMA user_version`, following the frozen
`governance.sqlite` pattern (`EB-13`). It is paired with an exact structural comparison,
because `user_version` defaults to 0 and alone cannot tell *new* from *old*."""

RECORD_FORMAT: Final[str] = "gpauto.coordination-record/1"
"""The record-format version every stored record carries (`VM-1`). Non-authority-bearing
(`EQ-8`), never read as recency or precedence (`VM-11`)."""

COVERED_RECORD_FORMATS: Final[frozenset[str]] = frozenset({RECORD_FORMAT})
"""The record formats this definition interprets. A record under any other is surfaced as
unreadable and never dropped (`VM-6`, `VM-12`)."""

FORMAT_COLUMN: Final[str] = "record_format"
SLOT_COLUMN: Final[str] = "tuple_slot"
"""A child row's position inside its parent's tuple — part of the value's own structure
(`EQ-3`), never an ordering of records and never read by anything but reconstruction."""
ELEMENT: Final[str] = "element"
KIND: Final[str] = "kind"


class SchemaDefinitionError(RuntimeError):
    """A record model uses a shape this mapping does not represent. Raised at build time."""


class Domain(StrEnum):
    """`WP-1` / `WP-2`+`WP-3`: the ingest domain, or the coordination facts."""

    INGEST = "INGEST"
    COORDINATION = "COORDINATION"


class WriteClass(StrEnum):
    """AP-07 §3.2's legend: ingest-only, write-once, append-only."""

    I = "I"  # noqa: E741 - the frozen legend's own name
    W1 = "W1"
    A = "A"


# --- layout: what a model becomes ---------------------------------------------------

Condition = tuple[tuple[str, str], ...]
"""The union choices under which a column is present: `((kind column, variant), ...)`."""


@dataclass(frozen=True)
class Column:
    name: str
    sql_type: str
    condition: Condition
    allowed: tuple[str | int, ...] | None = None
    minted: bool = False


@dataclass(frozen=True)
class Scalar:
    column: str
    annotation: Any


@dataclass(frozen=True)
class Composite:
    prefix: str
    cls: type[BaseModel]
    fields: tuple[tuple[str, Node], ...]


@dataclass(frozen=True)
class Choice:
    column: str
    variants: tuple[tuple[str, Any, Node], ...]


@dataclass(frozen=True)
class Repeated:
    table: str
    condition: Condition
    element: Node


@dataclass(frozen=True)
class ProductionReference:
    cls: type[BaseModel]
    identity_column: str
    provenance_column: str


Node = Scalar | Composite | Choice | Repeated | ProductionReference


@dataclass
class Layout:
    """One table: its columns, its node tree, and — for a parent — its child tables."""

    name: str
    spec: TableSpec
    columns: list[Column] = field(default_factory=list)
    children: list[Layout] = field(default_factory=list)
    node: Node | None = None
    parent: Layout | None = None
    parent_condition: Condition = ()

    @property
    def is_child(self) -> bool:
        return self.parent is not None

    def column(self, name: str) -> Column:
        for column in self.columns:
            if column.name == name:
                return column
        raise SchemaDefinitionError(f"{self.name} has no column {name!r}")


@dataclass(frozen=True)
class Unique:
    columns: tuple[str, ...]
    where: str | None = None


@dataclass(frozen=True)
class Reference:
    """A foreign key this table declares, beyond the ones its identity types imply."""

    columns: tuple[str, ...]
    table: str
    target: tuple[str, ...]
    deferred: bool = False


@dataclass(frozen=True)
class TableSpec:
    """What the frozen text fixes about one table and a type cannot say."""

    rc: str
    name: str
    record: type[BaseModel]
    domain: Domain
    write_class: WriteClass
    key: str
    home: bool = True
    key_is_reference: bool = False
    json_payload: bool = False
    unique: tuple[Unique, ...] = ()
    checks: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    child_unique: tuple[tuple[str, Unique], ...] = ()
    child_checks: tuple[tuple[str, str], ...] = ()
    deferred: tuple[tuple[str, str], ...] = ()


def _join(prefix: str, name: str) -> str:
    return name if not prefix else f"{prefix}__{name}"


def _substitute(annotation: Any, mapping: Mapping[Any, Any]) -> Any:
    if isinstance(annotation, typing.TypeVar):
        return mapping.get(annotation, annotation)
    if get_origin(annotation) in (typing.Union, types.UnionType):
        members = [_substitute(member, mapping) for member in get_args(annotation)]
        return functools.reduce(operator.or_, members)
    metadata = getattr(annotation, "__pydantic_generic_metadata__", None)
    if isinstance(metadata, dict) and metadata.get("origin") is not None:
        arguments = tuple(_substitute(argument, mapping) for argument in metadata["args"])
        return metadata["origin"][arguments if len(arguments) > 1 else arguments[0]]
    return annotation


def _unwrap(annotation: Any) -> Any:
    """Strip `Annotated`, and expand PEP 695 aliases — `Determined[X]` included."""
    while True:
        origin = get_origin(annotation)
        if origin is typing.Annotated:
            annotation = get_args(annotation)[0]
        elif isinstance(annotation, typing.TypeAliasType):
            annotation = annotation.__value__
        elif isinstance(origin, typing.TypeAliasType):
            mapping = dict(zip(origin.__type_params__, get_args(annotation), strict=True))
            annotation = _substitute(origin.__value__, mapping)
        else:
            return annotation


def _union_members(annotation: Any) -> Iterator[Any]:
    """A union's members, with a nested union alias expanded into its own members."""
    for member in get_args(annotation):
        expanded = _unwrap(member)
        if get_origin(expanded) in (typing.Union, types.UnionType):
            yield from _union_members(expanded)
        else:
            yield expanded


def variant_tag(annotation: Any) -> str:
    """The name a union variant is stored under: its class, or its generic origin."""
    metadata = getattr(annotation, "__pydantic_generic_metadata__", None)
    if isinstance(metadata, dict) and metadata.get("origin") is not None:
        return str(metadata["origin"].__name__)
    if isinstance(annotation, type):
        return annotation.__name__
    raise SchemaDefinitionError(f"no variant tag for {annotation!r}")


def sql_value(value: Any) -> str | int:
    """A `Literal` member or enum value, as stored."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, str):
        return value
    raise SchemaDefinitionError(f"unsupported literal {value!r}")


def _production_origin(annotation: Any) -> bool:
    metadata = getattr(annotation, "__pydantic_generic_metadata__", None)
    origin = metadata.get("origin") if isinstance(metadata, dict) else None
    return annotation is ArtifactProduction or origin is ArtifactProduction


def _node(annotation: Any, prefix: str, condition: Condition, layout: Layout) -> Node:
    annotation = _unwrap(annotation)
    origin = get_origin(annotation)
    if origin in (typing.Union, types.UnionType):
        kind = _join(prefix, KIND)
        variants: list[tuple[str, Any, Node]] = []
        for member in _union_members(annotation):
            tag = variant_tag(member)
            variants.append(
                (tag, member, _node(member, _join(prefix, tag), (*condition, (kind, tag)), layout))
            )
        layout.columns.append(Column(kind, "TEXT", condition, tuple(t for t, _, _ in variants)))
        return Choice(kind, tuple(variants))
    if origin is Literal:
        values = tuple(sql_value(value) for value in get_args(annotation))
        sql_type = "INTEGER" if all(isinstance(v, int) for v in values) else "TEXT"
        layout.columns.append(Column(prefix, sql_type, condition, values))
        return Scalar(prefix, annotation)
    if origin is tuple:
        element, ellipsis = get_args(annotation)
        if ellipsis is not Ellipsis or layout.is_child:
            raise SchemaDefinitionError(f"{layout.name}.{prefix}: only a flat tuple[X, ...]")
        child = Layout(f"{layout.name}__{prefix}", layout.spec, parent=layout)
        child.parent_condition = condition
        child.node = _node(element, ELEMENT, (), child)
        layout.children.append(child)
        return Repeated(child.name, condition, child.node)
    if not isinstance(annotation, type):
        raise SchemaDefinitionError(f"{layout.name}.{prefix}: unsupported {annotation!r}")
    if issubclass(annotation, OpaqueIdentity):
        minted = issubclass(annotation, MintedIdentity)
        layout.columns.append(Column(prefix, "TEXT", condition, None, minted))
        return Scalar(prefix, annotation)
    if issubclass(annotation, Enum):
        members = tuple(str(member.value) for member in annotation)
        layout.columns.append(Column(prefix, "TEXT", condition, members))
        return Scalar(prefix, annotation)
    if annotation is bool:
        layout.columns.append(Column(prefix, "INTEGER", condition, (0, 1)))
        return Scalar(prefix, annotation)
    if annotation is str:
        layout.columns.append(Column(prefix, "TEXT", condition))
        return Scalar(prefix, annotation)
    if annotation is bytes:
        layout.columns.append(Column(prefix, "BLOB", condition))
        return Scalar(prefix, annotation)
    if (
        _production_origin(annotation)
        and issubclass(annotation, BaseModel)
        and layout.spec.record is not ArtifactProductionRecord
    ):
        provenance = _unwrap(annotation.model_fields["provenance"].annotation)
        if get_origin(provenance) is not Literal:
            raise SchemaDefinitionError(f"{layout.name}.{prefix}: provenance must be pinned")
        identity, pinned = _join(prefix, "identity"), _join(prefix, "provenance")
        layout.columns.append(Column(identity, "TEXT", condition, None, True))
        pinned_values = tuple(sql_value(v) for v in get_args(provenance))
        layout.columns.append(Column(pinned, "TEXT", condition, pinned_values))
        return ProductionReference(annotation, identity, pinned)
    if issubclass(annotation, BaseModel):
        fields = tuple(
            (name, _node(info.annotation, _join(prefix, name), condition, layout))
            for name, info in annotation.model_fields.items()
        )
        return Composite(prefix, annotation, fields)
    raise SchemaDefinitionError(f"{layout.name}.{prefix}: unsupported {annotation!r}")


def _json_layout(spec: TableSpec) -> Layout:
    """`RC-12` is stored as the record's JSON, decoded through ST-02's codec (`DC-1`)."""
    layout = Layout(spec.name, spec)
    layout.columns = [
        Column("identity", "TEXT", ()),
        Column("authorization_identity", "TEXT", ()),
        Column("payload", "TEXT", ()),
    ]
    return layout


def build_layout(spec: TableSpec) -> Layout:
    if spec.json_payload:
        return _json_layout(spec)
    layout = Layout(spec.name, spec)
    layout.node = _node(spec.record, "", (), layout)
    return layout


# --- the catalogue: RC-10 … RC-41 -----------------------------------------------------


def _m1_checks() -> tuple[str, ...]:
    return (
        "predecessor__kind <> 'Present' "
        "OR predecessor__Present__value__resolution = identity__resolution",
        "(edge = 'A2') = (result__kind = 'ResolvedRootResult')",  # guard:ga_store_keys
        "(edge = 'A3') = (result__kind = 'RefusalResult')",  # guard:ga_store_keys
        "(edge = 'A4') = (result__kind = 'AmbiguityResult')",  # guard:ga_store_keys
    )


def _chain(subject: str) -> tuple[Unique, ...]:
    """`MC-2`: (subject, predecessor entry) is unique — the chain cannot fork — with the
    affirmative absence of a predecessor keyed on the subject alone."""
    return (
        Unique((subject, "predecessor__Present__value__discriminator")),  # guard:ga_store_keys
        Unique((subject,), "predecessor__kind = 'KnownAbsent'"),  # guard:ga_store_keys
    )


def _same_subject(subject: str) -> str:
    return (
        f"predecessor__kind <> 'Present' OR predecessor__Present__value__{subject} "
        f"= identity__{subject}"
    )


CYCLE_OCCURRENCE_KEY: Final[tuple[str, ...]] = (
    "predecessor_entry__epoch_root",
    "predecessor_entry__discriminator",
    "target_state",
)
"""`MC-16`: (predecessor position entry, target step `S6`)."""


def catalogue_specs() -> tuple[TableSpec, ...]:
    """Every record class `RC-10` … `RC-41`, and nothing else (`SRB11-1`, `AP11-I64`)."""
    ingest, coordination = Domain.INGEST, Domain.COORDINATION
    w1, a = WriteClass.W1, WriteClass.A
    members = "rc26_frozen_finding_set__members"
    return (
        TableSpec("RC-10", "rc10_project", Project, ingest, WriteClass.I, "identity"),
        TableSpec("RC-10", "rc10_governed_stage", GovernedStage, ingest, WriteClass.I, "identity"),
        TableSpec(
            "RC-10",
            "rc10_repository_boundary",
            RepositoryBoundary,
            ingest,
            WriteClass.I,
            "identity",
        ),
        TableSpec(
            "RC-10", "rc10_baseline_identity", BaselineIdentity, ingest, WriteClass.I, "identity"
        ),
        TableSpec("RC-11", "rc11_stage_contract", StageContract, ingest, WriteClass.I, "identity"),
        TableSpec(
            "RC-11",
            "rc11_stage_contract_preimage",
            IdentifiedStageContract,
            coordination,
            w1,
            "identity",
            home=False,
            references=(Reference(("identity",), "rc11_stage_contract", ("identity",)),),
        ),
        TableSpec(
            "RC-12",
            "rc12_authorization_record",
            AuthorizationRecord,
            ingest,
            WriteClass.I,
            "identity",
            json_payload=True,
        ),
        TableSpec(
            "RC-13",
            "rc13_owner_decision",
            OwnerDecision,
            ingest,
            WriteClass.I,
            "identity",
            # OBS_ST03_1_IMPLEMENTATION_DETAIL: retain the generated RC-25 FK as well.
            references=(
                Reference(("act__DisputeResolutionDecision__member",), members, ("element",)),
            ),
            checks=(
                "act__ObligationChangeDecision__replacement_requirement IS NULL OR "
                "length(CAST(act__ObligationChangeDecision__replacement_requirement AS BLOB)) > 0",
                *(
                    f"act__{form.__name__}__corrects__Present__value IS NULL OR "
                    f"act__{form.__name__}__corrects__Present__value <> identity"
                    for form in get_args(DecisionAct.__value__)
                    if "corrects" in form.model_fields
                ),
            ),
        ),
        TableSpec(
            "RC-14",
            "rc14_root_resolution",
            RootResolutionRecord,
            coordination,
            w1,
            "identity",
            unique=(
                Unique(
                    (
                        "project",
                        "stage",
                        "predecessor_terminal_entry__Present__value__resolution",
                        "predecessor_terminal_entry__Present__value__discriminator",
                    )
                ),
                Unique(
                    ("project", "stage"),
                    "predecessor_terminal_entry__kind = 'KnownAbsent'",  # guard:ga_store_keys
                ),
            ),
        ),
        TableSpec(
            "RC-15",
            "rc15_candidate_exclusion",
            CandidateExclusionRecord,
            coordination,
            a,
            "exclusion__identity",
            checks=(
                "predecessor__kind <> 'Present' OR predecessor__Present__value__parent_resolution"
                " = exclusion__identity__parent_resolution",
            ),
        ),
        TableSpec(
            "RC-16", "rc16_authority_ambiguity", AuthorityAmbiguity, coordination, w1, "identity"
        ),
        TableSpec(
            "RC-17",
            "rc17_entry_state_boundary",
            EntryStateBoundaryRecord,
            coordination,
            w1,
            "boundary__identity",
            unique=(Unique(("resolved_root",)),),  # guard:ga_store_keys (RS7-1)
        ),
        TableSpec(
            "RC-18",
            "rc18_authority_envelope",
            AuthorityEnvelopeRecord,
            coordination,
            w1,
            "envelope__identity",
            unique=(
                Unique(
                    (
                        "envelope__resolved_root",
                        "predecessor_entry__epoch_root",
                        "predecessor_entry__discriminator",
                        "target_state",
                        "envelope__role",  # guard:ga_store_keys
                    )
                ),
            ),
            checks=("predecessor_entry__epoch_root = envelope__resolved_root",),
        ),
        TableSpec(
            "RC-19",
            "rc19_worker_activation",
            WorkerActivationRecord,
            coordination,
            w1,
            "identity",
            unique=(Unique(("envelope",)),),  # guard:ga_store_keys (CO-7)
        ),
        TableSpec(
            "RC-20",
            "rc20_input_package",
            InputPackageRecord,
            coordination,
            w1,
            "package__identity",
        ),
        TableSpec(
            "RC-21",
            "rc21_artifact_content",
            IdentifiedArtifactContent,
            coordination,
            w1,
            "identity",
        ),
        TableSpec(
            "RC-22",
            "rc22_artifact_production",
            ArtifactProductionRecord,
            coordination,
            w1,
            "production__identity",
        ),
        TableSpec(
            "RC-23", "rc23_activation_effect", ActivationEffectRecord, coordination, w1, "identity"
        ),
        TableSpec(
            "RC-24",
            "rc24_unaccounted_mutation",
            UnaccountedMutation,
            coordination,
            w1,
            "identity",
        ),
        TableSpec(
            "RC-25",
            "rc25_finding",
            FindingRecord,
            coordination,
            w1,
            "finding__identity",
            references=(  # WP-19: a finding exists only as a member of a set
                Reference(("finding__identity",), members, ("element",), deferred=True),
            ),
        ),
        TableSpec(
            "RC-26",
            "rc26_frozen_finding_set",
            FrozenFindingSet,
            coordination,
            w1,
            "identity",
            unique=(Unique(("resolved_root",)),),  # guard:ga_store_keys (FP-17)
            child_unique=(("members", Unique(("element",))),),
            deferred=(("members", "element"),),
        ),
        TableSpec(
            "RC-27",
            "rc27_remediation_obligation",
            RemediationObligation,
            coordination,
            w1,
            "identity",
            references=(
                Reference(
                    ("identity__parent_frozen_set", "identity__member_finding"),
                    members,
                    ("identity", "element"),
                ),
            ),
        ),
        TableSpec(
            "RC-28",
            "rc28_closure_assessment",
            ClosureAssessmentRecord,
            coordination,
            w1,
            "assessment__identity",
        ),
        TableSpec(
            "RC-29",
            "rc29_post_freeze_candidate",
            PostFreezeCandidateRecord,
            coordination,
            w1,
            "candidate__identity",
        ),
        TableSpec("RC-30", "rc30_refusal", RefusalRecord, coordination, w1, "refusal__identity"),
        TableSpec(
            "RC-30",
            "rc30_envelope_violation",
            EnvelopeViolationRecord,
            coordination,
            w1,
            "violation__identity",
        ),
        TableSpec("RC-31", "rc31_halt_occurrence", HaltOccurrence, coordination, w1, "identity"),
        TableSpec(
            "RC-32",
            "rc32_governance_event_resolution",
            GovernanceEventResolution,
            coordination,
            w1,
            "identity",
            references=(
                Reference(
                    ("decision", "halt_occurrence"),
                    "rc13_owner_decision",
                    ("identity", "act__RefusalResolutionDecision__halt_occurrence"),
                ),
            ),
        ),
        TableSpec(
            "RC-33",
            "rc33_cycle_occurrence",
            CycleOccurrence,
            coordination,
            w1,
            "identity",
            unique=(Unique(CYCLE_OCCURRENCE_KEY),),  # guard:ga_store_keys (MC-16)
        ),
        TableSpec(
            "RC-34",
            "rc34_m1_position_entry",
            M1PositionEntry,
            coordination,
            a,
            "identity",
            unique=(
                *_chain("identity__resolution"),
                Unique(("result__ResolvedRootResult__resolved_root",)),  # guard:ga_store_keys
            ),
            checks=_m1_checks(),
        ),
        TableSpec(
            "RC-34",
            "rc34_m2_position_entry",
            M2PositionEntry,
            coordination,
            a,
            "identity",
            unique=_chain("identity__epoch_root"),
            checks=(_same_subject("epoch_root"),),
        ),
        TableSpec(
            "RC-34",
            "rc34_m3_position_entry",
            M3PositionEntry,
            coordination,
            a,
            "identity",
            unique=_chain("identity__envelope"),
            checks=(_same_subject("envelope"),),
        ),
        TableSpec(
            "RC-34",
            "rc34_m4_position_entry",
            M4PositionEntry,
            coordination,
            a,
            "identity",
            unique=_chain("identity__authorization"),
            checks=(_same_subject("authorization"),),
        ),
        TableSpec(
            "RC-35",
            "rc35_disposition_establishing_record",
            DispositionEstablishingRecord,
            coordination,
            w1,
            "identity",
            references=(
                Reference(
                    (
                        "disposition__RevokedDisposition__established_by_decision",
                        "identity__authorization",
                    ),
                    "rc13_owner_decision",
                    ("identity", "act__RevocationDecision__revoked"),
                ),
            ),
        ),
        TableSpec(
            "RC-36",
            "rc36_stage_outcome",
            StageOutcome,
            coordination,
            w1,
            "identity",  # guard:ga_store_keys (ID-8)
            references=(
                Reference(
                    ("established_by", "identity__parent_stage", "disposition"),
                    "rc13_owner_decision",
                    ("identity", "stage", "act__StageOutcomeDecision__outcome"),
                ),
            ),
        ),
        TableSpec(
            "RC-37",
            "rc37_dispatch_record",
            DispatchRecord,
            coordination,
            w1,
            "identity",
            unique=(Unique(("correlation__envelope",)),),  # guard:ga_store_keys (MH-7)
        ),
        TableSpec(
            "RC-37",
            "rc37_outcome_ingestion_record",
            OutcomeIngestionRecord,
            coordination,
            w1,
            "identity",
            unique=(Unique(("activation",)),),  # guard:ga_store_keys (MH-13)
        ),
        TableSpec(
            "RC-38",
            "rc38_execution_observation",
            ExecutionObservation,
            coordination,
            w1,
            "identity",
        ),
        TableSpec(
            "RC-39",
            "rc39_conformance_determination",
            ConformanceDetermination,
            coordination,
            w1,
            "identity",
            unique=(
                Unique(
                    ("identity__activation",),
                    "determination__kind = 'AdoptionDetermination'",  # guard:ga_store_keys
                ),
            ),
            child_checks=(
                (
                    "determination__EnvelopeConformanceDetermination__effects",
                    "element__effect__parent_activation = identity__activation",
                ),
            ),
        ),
        TableSpec("RC-40", "rc40_audit_entry", AuditEntry, coordination, a, "identity"),
        TableSpec(
            "RC-41",
            "rc41_session_record",
            SessionRecord,
            coordination,
            w1,
            "activation",
            key_is_reference=True,
        ),
    )


# --- the catalogue, laid out ------------------------------------------------------------


@dataclass(frozen=True)
class Home:
    """Where an identity type is a record's key: table and key-column groups."""

    table: str
    groups: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]


@dataclass
class Catalogue:
    specs: tuple[TableSpec, ...]
    layouts: dict[str, Layout]
    by_record: dict[type[BaseModel], Layout]
    homes: dict[type[BaseModel], Home]


INSTANCE_HOME: Final[tuple[str, str]] = ("rc12_authorization_record", "authorization_identity")
"""Where an `OwnerAuthorization` instance identity is borne — by one or more records."""


def _find(node: Node | None, prefix: str) -> Node:
    if node is None:
        raise SchemaDefinitionError(f"no node at {prefix!r}")
    if isinstance(node, Scalar) and node.column == prefix:
        return node
    if isinstance(node, Composite):
        if node.prefix == prefix:
            return node
        for _, child in node.fields:
            try:
                return _find(child, prefix)
            except SchemaDefinitionError:
                continue
    raise SchemaDefinitionError(f"no node at {prefix!r}")


def groups(node: Node) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    """An identity node's columns, grouped by the union choices they are present under."""
    if isinstance(node, Scalar):
        return (((), (node.column,)),)
    if isinstance(node, Composite):
        combined: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (((), ()),)
        for _, child in node.fields:
            combined = tuple(
                (tags + more_tags, columns + more_columns)
                for tags, columns in combined
                for more_tags, more_columns in groups(child)
            )
        return combined
    if isinstance(node, Choice):
        return tuple(
            ((tag, *tags), columns)
            for tag, _, child in node.variants
            for tags, columns in groups(child)
        )
    raise SchemaDefinitionError(f"an identity cannot contain {type(node).__name__}")


def key_node(layout: Layout) -> Node:
    return _find(layout.node, layout.spec.key)


def key_groups(layout: Layout) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    if layout.spec.json_payload:
        return (((), ("identity",)),)
    return groups(key_node(layout))


def build_catalogue() -> Catalogue:
    specs = catalogue_specs()
    layouts: dict[str, Layout] = {}
    by_record: dict[type[BaseModel], Layout] = {}
    homes: dict[type[BaseModel], Home] = {}
    for spec in specs:
        layout = build_layout(spec)
        layouts[spec.name] = layout
        by_record[spec.record] = layout
        for child in layout.children:
            layouts[child.name] = child
        if not spec.home or spec.key_is_reference:
            continue
        if spec.json_payload:
            identity: Any = spec.record.model_fields["identity"].annotation
        else:
            node = key_node(layout)
            identity = node.annotation if isinstance(node, Scalar) else node.cls  # type: ignore[union-attr]
        homes[identity] = Home(spec.name, key_groups(layout))
    return Catalogue(specs, layouts, by_record, homes)


def writable_layouts(catalogue: Catalogue) -> dict[type[BaseModel], Layout]:
    """The record classes the store may create — the coordination domain, and only it."""
    return {
        record: layout
        for record, layout in catalogue.by_record.items()
        if layout.spec.domain is Domain.COORDINATION  # guard:ga_store_write_class
    }


# --- references: foreign keys and instance-existence rules ------------------------------


@dataclass(frozen=True)
class ForeignKey:
    columns: tuple[str, ...]
    table: str
    target: tuple[str, ...]
    deferred: bool


def _align(reference: Node, home: Home, *, deferred: bool) -> Iterator[ForeignKey]:
    targets = dict(home.groups)
    for tags, columns in groups(reference):
        if tags not in targets:
            raise SchemaDefinitionError(f"no key group {tags} in {home.table}")
        yield ForeignKey(columns, home.table, targets[tags], deferred)


def _references(
    node: Node, layout: Layout, catalogue: Catalogue, own_key: str | None
) -> Iterator[ForeignKey | str]:
    """Every foreign key a node implies, and every instance-reference column (as `str`)."""
    deferred_columns = {
        column
        for suffix, column in layout.spec.deferred
        if layout.name == f"{layout.spec.name}__{suffix}"
    }
    if isinstance(node, Scalar):
        annotation = node.annotation
        if not (isinstance(annotation, type) and issubclass(annotation, OpaqueIdentity)):
            return
        if node.column == own_key:
            return
        if annotation is OwnerAuthorizationId:
            yield node.column
            return
        home = catalogue.homes[annotation]
        yield from _align(node, home, deferred=node.column in deferred_columns)
    elif isinstance(node, Composite):
        if node.cls is ClassificationContext:  # guard:ga_store_referential_integrity
            yield ForeignKey(
                (_join(node.prefix, "authorization"), _join(node.prefix, "entry_boundary")),
                "rc17_entry_state_boundary",
                ("resolved_root", "boundary__identity"),
                False,
            )
            return
        if issubclass(node.cls, DependentIdentity) and node.prefix != own_key:
            yield from _align(node, catalogue.homes[node.cls], deferred=False)
            return
        for _, child in node.fields:
            yield from _references(child, layout, catalogue, own_key)
    elif isinstance(node, Choice):
        for _, _, child in node.variants:
            yield from _references(child, layout, catalogue, own_key)
    elif isinstance(node, ProductionReference):
        yield ForeignKey(
            (node.identity_column, node.provenance_column),
            "rc22_artifact_production",
            ("production__identity", "production__provenance"),
            False,
        )


def table_references(layout: Layout, catalogue: Catalogue) -> tuple[list[ForeignKey], list[str]]:
    """The foreign keys this table declares and its instance-reference columns."""
    foreign: list[ForeignKey] = []
    instances: list[str] = []
    if layout.spec.json_payload:
        return foreign, instances
    own_key = None if (layout.is_child or layout.spec.key_is_reference) else layout.spec.key
    assert layout.node is not None
    for found in _references(layout.node, layout, catalogue, own_key):
        if isinstance(found, str):
            instances.append(found)
        else:
            foreign.append(found)
    if layout.is_child:
        assert layout.parent is not None
        parent_key = key_groups(layout.parent)
        if len(parent_key) != 1:
            raise SchemaDefinitionError(f"{layout.name}: a tuple under a union-keyed record")
        ((_, columns),) = parent_key
        foreign.append(ForeignKey(columns, layout.parent.name, columns, False))
    else:
        for reference in layout.spec.references:  # guard:ga_store_referential_integrity
            foreign.append(
                ForeignKey(reference.columns, reference.table, reference.target, reference.deferred)
            )
    return foreign, instances


# --- DDL -----------------------------------------------------------------------------------


def _presence(column: Column) -> str:
    return " AND ".join(f"{kind} = '{tag}'" for kind, tag in column.condition)


def _literal(value: str | int) -> str:
    return str(value) if isinstance(value, int) else "'" + value.replace("'", "''") + "'"


def _column_ddl(column: Column) -> tuple[str, list[str]]:
    checks: list[str] = []
    definition = f"{column.name} {column.sql_type}"
    if not column.condition:
        definition += " NOT NULL"
    else:
        checks.append(f"COALESCE({_presence(column)}, 0) = ({column.name} IS NOT NULL)")
    if column.allowed is not None:
        checks.append(f"{column.name} IN ({', '.join(_literal(v) for v in column.allowed)})")
    if column.minted:
        checks.append(
            f"length({column.name}) = {MINTED_VALUE_LENGTH} "
            f"AND NOT {column.name} GLOB '*[^0-9a-f]*'"
        )
    return definition, checks


def child_key(layout: Layout) -> tuple[str, ...]:
    assert layout.parent is not None
    ((_, columns),) = key_groups(layout.parent)
    return (*columns, SLOT_COLUMN)


def table_columns(layout: Layout) -> list[Column]:
    """A table's stored columns: a child's carries its parent's key and the member slot."""
    if layout.is_child:
        assert layout.parent is not None
        ((_, key_columns),) = key_groups(layout.parent)
        prefix = [layout.parent.column(name) for name in key_columns]
        carried = [Column(c.name, c.sql_type, (), c.allowed, c.minted) for c in prefix]
        return [*carried, Column(SLOT_COLUMN, "INTEGER", ()), *layout.columns]
    return [*layout.columns, Column(FORMAT_COLUMN, "TEXT", ())]


def _superkeys(catalogue: Catalogue) -> dict[str, set[tuple[str, ...]]]:
    """Composite reference targets that are not a table's own key need a unique index."""
    needed: dict[str, set[tuple[str, ...]]] = {}
    for layout in catalogue.layouts.values():
        for key in table_references(layout, catalogue)[0]:
            target = catalogue.layouts[key.table]
            own = {columns for _, columns in _own_keys(target)}
            if key.target not in own:
                needed.setdefault(key.table, set()).add(key.target)
    return needed


def _own_keys(layout: Layout) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    if layout.is_child:
        return (((), child_key(layout)),)
    return key_groups(layout)


def table_ddl(layout: Layout, catalogue: Catalogue, superkeys: set[tuple[str, ...]]) -> str:
    lines: list[str] = []
    checks: list[str] = []
    for column in table_columns(layout):
        definition, column_checks = _column_ddl(column)
        lines.append(definition)
        checks.extend(column_checks)
    keys = _own_keys(layout)
    uniques: list[tuple[str, ...]] = []
    if len(keys) == 1:
        lines.append(f"PRIMARY KEY ({', '.join(keys[0][1])})")
    else:
        uniques.extend(columns for _, columns in keys)
    if not layout.is_child:
        declared = [u for u in layout.spec.unique if u.where is None]
        checks.extend(layout.spec.checks)
    else:
        suffix = layout.name.removeprefix(f"{layout.spec.name}__")
        declared = [u for name, u in layout.spec.child_unique if name == suffix]
        checks.extend(check for name, check in layout.spec.child_checks if name == suffix)
    uniques.extend(u.columns for u in declared)
    for columns in sorted(superkeys):
        if columns not in uniques:
            uniques.append(columns)
    lines.extend(f"UNIQUE ({', '.join(columns)})" for columns in uniques)
    lines.extend(f"CHECK ({check})" for check in checks)
    for foreign in table_references(layout, catalogue)[0]:  # guard:ga_store_referential_integrity
        clause = (
            f"FOREIGN KEY ({', '.join(foreign.columns)}) "
            f"REFERENCES {foreign.table} ({', '.join(foreign.target)})"
        )
        if foreign.deferred:
            clause += " DEFERRABLE INITIALLY DEFERRED"
        lines.append(clause)
    body = ",\n    ".join(lines)
    return f"CREATE TABLE {layout.name} (\n    {body}\n) STRICT"


def _partial_unique_ddl(layout: Layout) -> Iterator[str]:
    for number, unique in enumerate(layout.spec.unique if not layout.is_child else ()):
        if unique.where is not None:
            yield (
                f"CREATE UNIQUE INDEX {layout.name}__unique_{number} ON {layout.name} "
                f"({', '.join(unique.columns)}) WHERE {unique.where}"
            )


def _trigger_ddl(layout: Layout, instances: list[str]) -> Iterator[str]:
    name = layout.name
    yield (
        f"CREATE TRIGGER {name}__no_update BEFORE UPDATE ON {name} "
        f"BEGIN SELECT RAISE(ABORT, 'GPAUTO_NO_UPDATE: {name}'); END"  # guard:ga_store_write_class
    )
    yield (
        f"CREATE TRIGGER {name}__no_delete BEFORE DELETE ON {name} "
        f"BEGIN SELECT RAISE(ABORT, 'GPAUTO_NO_DELETE: {name}'); END"  # guard:ga_store_write_class
    )
    table, column = INSTANCE_HOME
    for reference in instances:  # guard:ga_store_referential_integrity
        yield (
            f"CREATE TRIGGER {name}__instance__{reference} BEFORE INSERT ON {name} "
            f"WHEN NEW.{reference} IS NOT NULL AND NOT EXISTS "
            f"(SELECT 1 FROM {table} WHERE {column} = NEW.{reference}) "
            f"BEGIN SELECT RAISE(ABORT, 'GPAUTO_DANGLING_INSTANCE: {name}.{reference}'); END"
        )

    if name == "rc13_owner_decision":
        # SC03-7b: native FKs alone allow a forward target in a multi-row INSERT.
        for form in get_args(DecisionAct.__value__):
            if "corrects" not in form.model_fields:
                continue
            value = f"act__{form.__name__}__corrects__Present__value"
            yield (
                f"CREATE TRIGGER {name}__prior__{form.__name__} BEFORE INSERT ON {name} "
                f"WHEN NEW.{value} IS NOT NULL AND NOT EXISTS "
                f"(SELECT 1 FROM {name} WHERE identity = NEW.{value}) "
                "BEGIN SELECT RAISE(ABORT, 'GPAUTO_CORRECTION_TARGET_NOT_PRIOR'); END"
            )
        # SC03-7a / SA9-2: exactly this structural pairing, in both directions.
        yield (
            f"CREATE TRIGGER {name}__no_outcome_succession BEFORE INSERT ON {name} "
            "WHEN (NEW.act__AuthorizingDecision__kind = 'NEXT_STAGE_AUTHORIZATION' AND EXISTS "
            f"(SELECT 1 FROM {name} WHERE identity = "
            "NEW.act__AuthorizingDecision__corrects__Present__value "
            "AND act__StageOutcomeDecision__kind = 'STAGE_OUTCOME')) OR "
            "(NEW.act__StageOutcomeDecision__kind = 'STAGE_OUTCOME' AND EXISTS "
            f"(SELECT 1 FROM {name} WHERE identity = "
            "NEW.act__StageOutcomeDecision__corrects__Present__value "
            "AND act__AuthorizingDecision__kind = 'NEXT_STAGE_AUTHORIZATION')) "
            "BEGIN SELECT RAISE(ABORT, 'GPAUTO_OUTCOME_SUCCESSION'); END"
        )
    if name == "rc35_disposition_establishing_record":
        # SC03-10a: consumption names the instance of the establishing F-9 context.
        yield (
            f"CREATE TRIGGER {name}__consumed_context BEFORE INSERT ON {name} "
            "WHEN NEW.disposition__kind = 'ConsumedDisposition' AND NOT EXISTS "
            "(SELECT 1 FROM rc36_stage_outcome AS outcome JOIN rc13_owner_decision AS decision "
            "ON decision.identity = outcome.established_by "
            "WHERE outcome.identity__parent_stage = "
            "NEW.disposition__ConsumedDisposition__established_by_outcome__parent_stage "
            "AND outcome.identity__local_discriminator = "
            "NEW.disposition__ConsumedDisposition__established_by_outcome__local_discriminator "
            "AND decision.act__StageOutcomeDecision__context__authorization = "
            "NEW.identity__authorization) "
            "BEGIN SELECT RAISE(ABORT, 'GPAUTO_CONSUMED_CONTEXT'); END"
        )


def schema_statements(catalogue: Catalogue) -> tuple[str, ...]:
    """The complete DDL of `SCHEMA_VERSION`, in a fixed order."""
    superkeys = _superkeys(catalogue)
    tables: list[str] = []
    rest: list[str] = []
    for layout in catalogue.layouts.values():
        tables.append(table_ddl(layout, catalogue, superkeys.get(layout.name, set())))
        rest.extend(_partial_unique_ddl(layout))
        rest.extend(_trigger_ddl(layout, table_references(layout, catalogue)[1]))
    table, column = INSTANCE_HOME
    rest.append(f"CREATE INDEX {table}__{column} ON {table} ({column})")
    return (*tables, *rest)


# --- mapping a record to rows and back ---------------------------------------------------

Row = dict[str, Any]


class Unreadable(Exception):
    """A stored record this definition cannot interpret; carries the enumerated reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _scalar_value(annotation: Any, value: Any) -> Any:
    if get_origin(annotation) is Literal:
        return sql_value(value)
    if isinstance(annotation, type) and issubclass(annotation, OpaqueIdentity):
        return value.value
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return value.value
    if annotation is bool:
        return int(value)
    return value


def _flatten(node: Node, value: Any, row: Row, children: dict[str, list[Row]]) -> None:
    if isinstance(node, Scalar):
        row[node.column] = _scalar_value(node.annotation, value)
    elif isinstance(node, Composite):
        for name, child in node.fields:
            _flatten(child, getattr(value, name), row, children)
    elif isinstance(node, Choice):
        tag = variant_tag(type(value)) if not isinstance(value, Enum) else type(value).__name__
        for variant, _, child in node.variants:
            if variant == tag:
                row[node.column] = tag
                _flatten(child, value, row, children)
                return
        raise SchemaDefinitionError(f"{node.column}: {type(value).__name__} is not a variant")
    elif isinstance(node, Repeated):
        rows = children.setdefault(node.table, [])
        for slot, member in enumerate(value):
            element: Row = {SLOT_COLUMN: slot}
            _flatten(node.element, member, element, children)
            rows.append(element)
    else:
        row[node.identity_column] = value.identity.value
        row[node.provenance_column] = value.provenance.value


def flatten(layout: Layout, record: BaseModel) -> tuple[Row, dict[str, list[Row]]]:
    """A record as its parent row and child rows — child rows without the parent key."""
    row: Row = {column.name: None for column in layout.columns}
    children: dict[str, list[Row]] = {}
    assert layout.node is not None
    _flatten(layout.node, record, row, children)
    row[FORMAT_COLUMN] = RECORD_FORMAT
    return row, children


def key_values(layout: Layout, key: BaseModel) -> Row:
    """The key columns' values for an identity value (or, for `RC-41`, an activation)."""
    row: Row = {}
    if layout.spec.json_payload:
        assert isinstance(key, OpaqueIdentity)
        return {"identity": key.value}
    _flatten(key_node(layout), key, row, {})
    return row


ProductionResolver = Callable[[str], BaseModel | None]


def _decode_scalar(annotation: Any, raw: Any) -> Any:
    if get_origin(annotation) is Literal:
        for value in get_args(annotation):
            if sql_value(value) == raw:
                return value
        raise Unreadable(f"value {raw!r} is not the pinned literal")
    if isinstance(annotation, type) and issubclass(annotation, OpaqueIdentity):
        return annotation(value=raw)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        if raw not in {member.value for member in annotation}:
            raise Unreadable(f"value {raw!r} is not a member of {annotation.__name__}")
        return annotation(raw)
    if annotation is bool:
        return bool(raw)
    if annotation is bytes:
        return bytes(raw)
    return raw


def _unflatten(
    node: Node,
    row: Row,
    children: Mapping[str, list[Row]],
    resolve: ProductionResolver,
) -> Any:
    if isinstance(node, Scalar):
        return _decode_scalar(node.annotation, row[node.column])
    if isinstance(node, Composite):
        values = {name: _unflatten(child, row, children, resolve) for name, child in node.fields}
        return node.cls(**values)
    if isinstance(node, Choice):
        tag = row[node.column]
        for variant, _, child in node.variants:
            if variant == tag:
                return _unflatten(child, row, children, resolve)
        raise Unreadable(f"{node.column}: no variant {tag!r}")
    if isinstance(node, Repeated):
        return tuple(
            _unflatten(node.element, member, children, resolve)
            for member in children.get(node.table, [])
        )
    production = resolve(row[node.identity_column])
    if production is None:
        raise Unreadable(f"{node.identity_column}: referenced production not held")
    fields = {name: getattr(production, name) for name in node.cls.model_fields}
    return node.cls(**fields)


def _stray_children(node: Node, row: Row, children: Mapping[str, list[Row]]) -> Iterator[str]:
    """Child tables whose parent choice was not taken but which hold rows."""
    if isinstance(node, Composite):
        for _, child in node.fields:
            yield from _stray_children(child, row, children)
    elif isinstance(node, Choice):
        for variant, _, child in node.variants:
            if row[node.column] == variant:
                yield from _stray_children(child, row, children)
            else:
                yield from _tables_under(child, children)


def _tables_under(node: Node, children: Mapping[str, list[Row]]) -> Iterator[str]:
    if isinstance(node, Repeated) and children.get(node.table):
        yield node.table
    elif isinstance(node, Composite):
        for _, child in node.fields:
            yield from _tables_under(child, children)
    elif isinstance(node, Choice):
        for _, _, child in node.variants:
            yield from _tables_under(child, children)


def unflatten(
    layout: Layout, row: Row, children: Mapping[str, list[Row]], resolve: ProductionResolver
) -> BaseModel:
    """A stored row and its child rows as the record, or `Unreadable` with the reason."""
    if row[FORMAT_COLUMN] not in COVERED_RECORD_FORMATS:
        raise Unreadable(f"record format {row[FORMAT_COLUMN]!r} is not covered")
    assert layout.node is not None
    stray = sorted(_stray_children(layout.node, row, children))
    if stray:
        raise Unreadable(f"member rows under a variant not taken: {stray}")
    record = _unflatten(layout.node, row, children, resolve)
    assert isinstance(record, BaseModel)
    return record
