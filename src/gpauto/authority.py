"""The GP-AUTO authority module: `M1` root resolution and mechanical envelope derivation.

Design basis: AP-11 §16 `GP-AUTO-ST-06`; AP-02 §3 (`E-*`, §3.1.2 applicability, §3.2),
§4.2.1…§4.2.3, §5, §8, §11, §13.6; AP-03 §4.1…§4.8, §5 (`EV-1`…`EV-7`); AP-04 §3 (`M1`,
`A1`…`A4`, `M1-1`…`M1-9`), §5 (`C1`), §11 (`V-01`…`V-18`); AP-07 `EQ-6`, `MC-15`, `MC-17`,
`RO7A-1`…`RO7A-9`; the AP-04 amendment `AP04-I49`; the AP-11 ST-04 amendment (`DO11-2`,
`DO11-3`, `DO11-6`); the frozen ST-06 clarification (`S6G2-1`…`S6G2-11`, `S6G3-1`…`S6G3-7`,
`ST06C-I01`…`ST06C-I07`, `G1 = INGEST_REFERENT_MATCH`); correction `ST06PC-1` and its
amendment A1.

**Three layers, and only the last one writes.**

* *Evaluation* — `RA-00`…`RA-09` validity, `G1` binding, `DV-4` liveness (ST-04's),
  same-identity consistency (ST-02's one comparator) and eligible multiplicity. Writes
  nothing.
* *Derivation* — the envelope as a total function of exactly five inputs (`EV-4`), and
  the two relations `≤ ceiling` (`S6G2-6`) and equivalent-or-narrower (`S6G2-7`). Writes
  nothing.
* *Acts* — `A1`; a resolution's `RC-15` exclusions; `A2`, `A3` or `A4`; `C1`. Each writes
  one unit through `create_unit`, and nothing else is written anywhere.

**No selection operation exists** (AP-03 §4.5, `AP04-I06`, `M1-4`). Nothing here ranks,
prefers, orders, merges or reconciles candidates. The resolved root is produced only when
the eligible set holds exactly one identity, by unpacking it. Two orderings exist, and
neither is over candidates: the lowest failing `RA` index among **one record's**
attributes (`S6G3-3`), and canonical JCS byte order — of a resolution's candidates and
exclusions (`S6G3-6`), of an ambiguity's competing identities, and of the tokens of a
set-valued bounds dimension (the `EQ-3` member order). Every one is inert: no guard, key
or derivation reads a position in it.

**Validity is a function of one decoded record's content** (`S6G3-1`, `S6G3-3`).
`RA-00`…`RA-05` are typed identities whose shape the decode enforces, so a decoded record
can express no value-level invalidity for them; their referents are `G1` binding, never
validity. `RA-06` is invalid only when empty: frozen text states no other `RA-06` rule, and
none is invented. `RA-07` is `S6G2-2`(a)…(h), clause by clause, over exact tokens only.
`RA-08` and `RA-09` are the value-expressed incompleteness `S6G3-1`(ii) names.

**An unreadable or unstable candidate leaves the resolution open** (`S6G3-7`). No `RC-15`
names it, no completing entry is written, and the result reports why. Nothing is read
around the store's own decode path.

**Envelope derivation copies and never computes** (`S6G2-4`, `S6G2-10`). The envelope is
the requested role's valid ceiling member, field for field, plus `E-14` from the frozen-set
input. The root input is the constituted **instance**, never one chosen record: each
set-valued dimension is carried in the canonical `EQ-3` member order, so every
content-equivalent constituting record yields the same bounds. `CYCLE_BOUND`,
obligations, closure history and the envelope identity are never inputs (`S6G2-8`,
`AP04-I49`); the identity is minted by the act, after derivation.

**Liveness is ST-04's, and transitions are ST-05's.** `DV-4` liveness and the recorded M1
position come from `derivations.py`; whether `A1`…`A4` or `C1` is admissible is decided
by `state_machine.py` over the facts this module supplies. Nothing derived here is stored
(`DV-14`).

Guard identifiers are fixed where each guard is written (`MU11-3`): `ga_root_uniqueness`,
`ga_eligibility_completeness`, `ga_bounds_within_ceiling`, `ga_equivalent_or_narrower`,
`ga_role_write_mode` and `ga_envelope_validity`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel

from gpauto import derivations as dv
from gpauto import state_machine as sm
from gpauto import state_machine_model as model
from gpauto.absence import Carried, Determined, KnownAbsent, NotApplicable, Present
from gpauto.authorization import (
    AuthorityAmbiguity,
    AuthorityBearingContent,
    AuthorizationRecord,
    CandidateExclusion,
    DistinctMultiplicityForm,
    SameIdentityConflictForm,
)
from gpauto.bounds import (
    ActionClass,
    AuthoritativeInputDesignation,
    AuthorityBounds,
    AuthorityCeilingMember,
    ReadBoundary,
    ScopeFrameBounds,
    WriteBoundary,
)
from gpauto.coordination_identity import (
    CycleOccurrenceId,
    M1PositionEntryId,
    M2PositionEntryId,
    M3PositionEntryId,
)
from gpauto.coordination_records import (
    AmbiguityResult,
    AuthorityEnvelopeRecord,
    CandidateExclusionRecord,
    EntryStateBoundaryRecord,
    M1PositionEntry,
    M3PositionEntry,
    NoResolutionResult,
    RefusalRecord,
    RefusalResult,
    ResolvedRootResult,
    RootResolutionRecord,
)
from gpauto.coordination_vocabulary import (
    M1Edge,
    M1Position,
    M2Position,
    M3Edge,
    M3Position,
    Machine,
)
from gpauto.envelope import AuthorityEnvelope
from gpauto.equivalence import PROJECTION, EquivalenceOutcome, compare_records
from gpauto.governance import Refusal
from gpauto.identity import (
    AuthorityAmbiguityId,
    AuthorityEnvelopeId,
    AuthorizationRecordId,
    CandidateExclusionId,
    EntryStateBoundaryId,
    FrozenFindingSetId,
    GovernedStageId,
    OwnerAuthorizationId,
    ProjectId,
    RefusalId,
    RootResolutionId,
)
from gpauto.minting import mint_value
from gpauto.review import FrozenFindingSet
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.store import CoordinationStore, UnreadableRecord
from gpauto.vocabulary import (
    AuthorityBearingContentClass,
    BoundedPreflightPermission,
    ExternalActionClass,
    GitCapabilityClass,
    GovernanceCase,
    RaAttribute,
    Role,
    WriteMode,
)
from gplanner.canonical import canonical_bytes

# --- the frozen role tables --------------------------------------------------------------

WORKER_ROLES: Final[frozenset[Role]] = frozenset(
    {Role.IMPLEMENTER, Role.DISCOVERY_REVIEWER, Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER}
)
"""The roles an envelope is ever derived for (AP-02 §3, §3.3.4; `S6G2-2`(b)). No OWNER or
COORDINATOR member exists, because no envelope is derived for either."""

WRITING_ROLES: Final[frozenset[Role]] = frozenset({Role.IMPLEMENTER, Role.REMEDIATOR})
"""`E-12` applicable, `WRITING`, Git `NONE` (`S6G2-2`(c); AP-02 §3.1.2, Panel A)."""

REVIEWING_ROLES: Final[frozenset[Role]] = frozenset(
    {Role.DISCOVERY_REVIEWER, Role.BOUNDED_CLOSURE_VERIFIER}
)
"""`E-20` applicable, `READ_ONLY`, Git `BOUNDED_READ` (`S6G2-2`(d); Panel A note 8)."""

FROZEN_SET_ROLES: Final[frozenset[Role]] = frozenset(
    {Role.REMEDIATOR, Role.BOUNDED_CLOSURE_VERIFIER}
)
"""`E-14` applicable (`S6G2-3`; AP-02 §3.1.2)."""

DECLARABLE_SIDE_EFFECTS: Final[frozenset[ExternalActionClass]] = frozenset(
    {ExternalActionClass.BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA}
)
"""The whole of `E-16` a valid member may carry (`S6G2-2`(g), `S6G2-11`)."""

DERIVABLE_ROLE_STEPS: Final[frozenset[tuple[Role, M2Position]]] = frozenset(
    {
        (Role.IMPLEMENTER, M2Position.S3_IMPLEMENTATION_ACTIVE),
        (Role.DISCOVERY_REVIEWER, M2Position.S4_DISCOVERY_ACTIVE),
        (Role.REMEDIATOR, M2Position.S6_REMEDIATION_ACTIVE),
        (Role.BOUNDED_CLOSURE_VERIFIER, M2Position.S7_CLOSURE_ACTIVE),
    }
)
"""The branch input's derivability (`EV-6`, `AP03-I30`, `AP04-I12`). Each role is activated
at exactly one step, and `S6`/`S7` exist only on the findings branch (AP-02 §4.3; AP-04
`B3`, `B4`, `B6a`, `B7`). The branch is realized as the target step: the branch-bearing
element of `RC-18`'s frozen `MC-15` key."""

RA_ORDER: Final[tuple[RaAttribute, ...]] = tuple(RaAttribute)
"""The frozen `RA-00`…`RA-09` enumeration: the one total order frozen text fixes over the
attributes of **one record** (`S6G3-3`). Never an order over candidates."""

ZERO, ONE, MANY = model.ELIGIBLE_MULTIPLICITY.values
"""ST-05's own values for `ELIGIBLE_MULTIPLICITY`, imported and never restated."""

EXCLUSION_CHAIN_START: Final = KnownAbsent(basis="the first exclusion of its resolution")
FIRST_ENTRY: Final = KnownAbsent(basis="the first entry of its subject")
BEFORE_ANY_CYCLE: Final = KnownAbsent(basis="refused at stage entry, before any cycle")
NO_FROZEN_SET: Final = KnownAbsent(basis="no set is frozen for this root")
NO_PRIOR_ATTEMPT: Final = KnownAbsent(basis="the first attempt for this project and stage")

MISSING_AUTHORITY_CONDITION: Final = "V-16"
"""`A3`'s refusal content (AP-02 §13.6, concept level; AP-04 §11 `V-16`). Non-authority-
bearing: no guard, key or derivation reads it. The condition is the frozen condition
identifier; observed and bound are ST-05's multiplicity values for `A3-1` and `A2-1`; the
attempted act is the stage-entry attempt, ST-05's encoding of `A1`'s trigger. No routing
branch exists before `ROOT_RESOLVED` (`V-16`: *stage not begun*)."""

SUPPLIED_FACTS: Final[frozenset[str]] = frozenset(
    {model.BOUNDARY_FIXED.name, model.UNACCOUNTED_MUTATION.name}
)
"""The two `C1` facts ST-06 cannot compute — `V-14` is ST-07's and `V-06` is ST-08's — and
the only facts a caller may supply to `record_envelope`."""

AUTHORITY_INPUTS: Final[tuple[type[BaseModel], ...]] = (
    AuthorizationRecord,
    Project,
    GovernedStage,
    StageContract,
    RepositoryBoundary,
    BaselineIdentity,
    CandidateExclusionRecord,
)
"""The classes only root resolution reads (`DO11-2`): `RC-12`, the `RC-10`/`RC-11`
referents `G1` matches against, and `RC-15`. Read in the same passes as ST-04's inputs."""

INGEST_REFERENTS: Final[tuple[type[BaseModel], ...]] = (
    Project,
    GovernedStage,
    StageContract,
    RepositoryBoundary,
    BaselineIdentity,
)

ROOT_INSTANCE_READS: Final[tuple[type[BaseModel], ...]] = (M1PositionEntry, RootResolutionRecord)
"""What the resolved root is read from: the `A2` entry naming it and its `RC-14` occurrence."""

ENVELOPE_INPUT_READS: Final[tuple[type[BaseModel], ...]] = (
    EntryStateBoundaryRecord,
    FrozenFindingSet,
)
"""The `EV-4` inputs read from records besides the root: `RC-17` and `RC-26`."""

PRIOR_ENVELOPE_READS: Final[tuple[type[BaseModel], ...]] = (
    AuthorityEnvelopeRecord,
    M3PositionEntry,
)
"""What replay detection and the `AP03-I14` prior check read: `RC-18` and its `C1` entries."""


# --- reading ------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRecords:
    """Every record root resolution and derivation read, from **one** two-pass read.

    `derivable` is ST-04's `AuthoritativeRecords` over its own input classes, so liveness
    and the recorded M1 position are computed over the very records the candidates were
    read with. `records` holds the decoded `AUTHORITY_INPUTS`; `unreadable` names every
    record of those classes the store could not interpret, with its class — surfaced,
    never dropped (`VM-6`). `unstable` is true when the two passes disagreed, and nothing
    is kept then.
    """

    derivable: dv.AuthoritativeRecords
    records: tuple[BaseModel, ...]
    unreadable: tuple[tuple[type[BaseModel], UnreadableRecord], ...]
    unstable: bool


def read_authority_records(store: CoordinationStore) -> AuthorityRecords:
    """Read every input class twice, through `store.enumerate` only, and keep the read
    only if both passes agree — `read_authoritative_records`' discipline (`S6G3-7`)."""
    passes = [_read_pass(store), _read_pass(store)]
    if passes[0] != passes[1]:  # guard:ga_eligibility_completeness
        unstable = dv.AuthoritativeRecords((), unstable=frozenset(dv.DERIVATION_INPUTS))
        return AuthorityRecords(unstable, (), (), True)
    return passes[0]


def _read_pass(store: CoordinationStore) -> AuthorityRecords:
    derivable: list[BaseModel] = []
    unreadable_kinds: set[type[BaseModel]] = set()
    own: list[BaseModel] = []
    unreadable: list[tuple[type[BaseModel], UnreadableRecord]] = []
    for kind in dv.DERIVATION_INPUTS:
        for item in store.enumerate(kind):
            if isinstance(item, UnreadableRecord):
                unreadable_kinds.add(kind)
            else:
                derivable.append(item)
    for kind in AUTHORITY_INPUTS:
        for item in store.enumerate(kind):
            if isinstance(item, UnreadableRecord):
                unreadable.append((kind, item))
            else:
                own.append(item)
    return AuthorityRecords(
        dv.AuthoritativeRecords(tuple(derivable), frozenset(unreadable_kinds)),
        tuple(own),
        tuple(unreadable),
        False,
    )


def _own[R: BaseModel](records: AuthorityRecords, kind: type[R]) -> tuple[R, ...]:
    return tuple(r for r in records.records if isinstance(r, kind))


def _derivable[R: BaseModel](records: AuthorityRecords, kind: type[R]) -> tuple[R, ...]:
    return tuple(r for r in records.derivable.records if isinstance(r, kind))


def _unreadable_of(records: AuthorityRecords, kinds: tuple[type[BaseModel], ...]) -> bool:
    """Whether a record of `kinds` could not be interpreted — named in `unreadable`, or of a
    class ST-04's read found unreadable. A derivation that needs such a class is
    indeterminate, never computed over the readable remainder (`VM-6`, `RC-4`)."""
    own = any(kind in kinds for kind, _ in records.unreadable)
    shared = any(k in records.derivable.unreadable for k in kinds)  # guard:ga_envelope_validity
    return own or shared


def _unreadable_record_ids(records: AuthorityRecords) -> frozenset[AuthorizationRecordId]:
    """The record identities of the unreadable `RC-12` records: `RC-12` is keyed on its
    record identity alone, so that is all an unreadable one can be named by (`S6G3-7`)."""
    return frozenset(
        AuthorizationRecordId(value=str(value))
        for kind, u in records.unreadable
        if kind is AuthorizationRecord
        for column, value in u.key
        if column == "identity"
    )


def _indeterminate(cause: dv.IndeterminacyCause, detail: str) -> dv.Indeterminate:
    return dv.Indeterminate(cause, detail)


def _canonical_key(value: BaseModel | str) -> bytes:
    """A value's canonical JCS bytes: the `EQ-3` member order, and `S6G3-6`'s."""
    return canonical_bytes(value.model_dump(mode="json") if isinstance(value, BaseModel) else value)


# --- RA-07: the role-indexed ceiling, clause by clause (S6G2-2) ---------------------------


def _carried_scopes(value: Carried[Any] | NotApplicable) -> frozenset[str] | None:
    """The scopes a carried `E-12` or `E-20` names, or `None` where it is inapplicable."""
    if isinstance(value, NotApplicable):
        return None
    inner = value.value
    scopes = inner.scopes if isinstance(inner, WriteBoundary) else inner.designated_scopes
    return frozenset(scopes)


def members_distinct(content: AuthorityBearingContent) -> bool:
    """`S6G2-2`(a): member roles are pairwise distinct."""
    roles = [m.role_applicability for m in content.authority_ceiling]
    return len(roles) == len(set(roles))  # guard:ga_role_write_mode


def members_cover_worker_roles(content: AuthorityBearingContent) -> bool:
    """`S6G2-2`(b): the member roles are exactly `RA-06` ∩ the four worker roles."""
    members = {m.role_applicability for m in content.authority_ceiling}
    authorized = set(content.authorized_roles)
    return members == authorized & WORKER_ROLES  # guard:ga_role_write_mode


def writer_shape(w: AuthorityCeilingMember) -> bool:
    """`S6G2-2`(c): IMPLEMENTER / REMEDIATOR — `WRITING`, `E-12` carried, `E-20`
    inapplicable, Git `NONE`."""
    return (
        w.write_mode == WriteMode.WRITING  # guard:ga_role_write_mode
        and isinstance(w.write_boundary, Carried)  # guard:ga_role_write_mode
        and isinstance(w.authoritative_input_designation, NotApplicable)  # guard:ga_role_write_mode
        and w.git_capability_class == GitCapabilityClass.NONE  # guard:ga_role_write_mode
    )


def reviewer_shape(r: AuthorityCeilingMember) -> bool:
    """`S6G2-2`(d): DISCOVERY REVIEWER / BCV — `READ_ONLY`, `E-12` inapplicable, `E-20`
    carried, Git `BOUNDED_READ`. `NONE` is invalid: both roles' Git read is required."""
    git = r.git_capability_class
    return (
        r.write_mode == WriteMode.READ_ONLY  # guard:ga_role_write_mode
        and isinstance(r.write_boundary, NotApplicable)  # guard:ga_role_write_mode
        and isinstance(r.authoritative_input_designation, Carried)  # guard:ga_role_write_mode
        and git == GitCapabilityClass.BOUNDED_READ  # guard:ga_role_write_mode
    )


def member_shape(member: AuthorityCeilingMember) -> bool:
    """`S6G2-2`(c)/(d) for the member's own role. A member of any other role has no shape,
    and fails (b) as well."""
    role = member.role_applicability
    if role in WRITING_ROLES:  # guard:ga_role_write_mode
        return writer_shape(member)
    if role in REVIEWING_ROLES:  # guard:ga_role_write_mode
        return reviewer_shape(member)
    return False


def designation_within_read(member: AuthorityCeilingMember) -> bool:
    """`S6G2-2`(e): for DR and BCV, every `E-20` token is an `E-11` token — exact tokens.
    Writers carry no `E-20` (c), so the clause does not bind them."""
    if member.role_applicability not in REVIEWING_ROLES:
        return True
    designated = _carried_scopes(member.authoritative_input_designation)
    readable = set(member.read_boundary.scopes)
    return designated is not None and designated <= readable  # guard:ga_bounds_within_ceiling


def remediator_within_implementer(content: AuthorityBearingContent) -> bool:
    """`S6G2-2`(f): a REMEDIATOR member implies an IMPLEMENTER member, and is within it on
    write scopes, read scopes, tool categories and action classes — exact tokens only."""
    pairs = [(m.role_applicability, m) for m in content.authority_ceiling]
    rem = [m for r, m in pairs if r == Role.REMEDIATOR]  # guard:ga_bounds_within_ceiling
    imp = [m for r, m in pairs if r == Role.IMPLEMENTER]  # guard:ga_bounds_within_ceiling
    if not rem:
        return True
    if len(rem) != 1 or len(imp) != 1:
        return False
    (r,), (i,) = rem, imp
    r_writes, i_writes = _carried_scopes(r.write_boundary), _carried_scopes(i.write_boundary)
    if r_writes is None or i_writes is None:
        return False
    r_reads, i_reads = set(r.read_boundary.scopes), set(i.read_boundary.scopes)
    return (
        r_writes <= i_writes  # guard:ga_bounds_within_ceiling
        and r_reads <= i_reads  # guard:ga_bounds_within_ceiling
        and set(r.tool_categories) <= set(i.tool_categories)  # guard:ga_bounds_within_ceiling
        and set(r.action_classes) <= set(i.action_classes)  # guard:ga_bounds_within_ceiling
    )


def side_effects_declarable(member: AuthorityCeilingMember) -> bool:
    """`S6G2-2`(g): `E-16` is at most the declarable side-effect class. Egress, install and
    external mutation are invalid in a member of any role (`S6G2-11`)."""
    external = set(member.external_action_classes)
    return external <= DECLARABLE_SIDE_EFFECTS  # guard:ga_bounds_within_ceiling


def scope_frame_matches(member: AuthorityCeilingMember, content: AuthorityBearingContent) -> bool:
    """`S6G2-2`(h): the member's scope frame is `(RA-01, RA-02, RA-04, RA-05)`."""
    expected = ScopeFrameBounds(
        project=content.project,
        stage=content.stage,
        repository_boundary=content.repository_boundary,
        baseline=content.baseline,
    )
    return member.scope_frame == expected  # guard:ga_role_write_mode


@dataclass(frozen=True)
class CeilingClauses:
    """`S6G2-2`(a)…(h), each evaluated on its own. (i) holds by type: a member has no
    `E-14` field at all."""

    a_distinct: bool
    b_covers_worker_roles: bool
    c_d_role_shapes: bool
    e_designation_within_read: bool
    f_remediator_within_implementer: bool
    g_side_effects_declarable: bool
    h_scope_frame: bool

    def holds(self) -> bool:
        return all(vars(self).values())


def ceiling_clauses(content: AuthorityBearingContent) -> CeilingClauses:
    """`S6G2-2`(a)…(h) over one record's role-indexed `RA-07`."""
    members = content.authority_ceiling
    return CeilingClauses(
        a_distinct=members_distinct(content),
        b_covers_worker_roles=members_cover_worker_roles(content),
        c_d_role_shapes=all(member_shape(m) for m in members),
        e_designation_within_read=all(designation_within_read(m) for m in members),
        f_remediator_within_implementer=remediator_within_implementer(content),
        g_side_effects_declarable=all(side_effects_declarable(m) for m in members),
        h_scope_frame=all(scope_frame_matches(m, content) for m in members),
    )


# --- RA-00 … RA-09 (S6G3-1 … S6G3-3) -------------------------------------------------------


def _ra_checks(record: AuthorizationRecord) -> tuple[tuple[RaAttribute, bool], ...]:
    """Each attribute that can fail on a decoded record, with whether it holds.

    Evaluated in an order deliberately unrelated to the `RA` index, so the attribute a
    record is excluded for is visibly the minimum and never an artefact of evaluation
    order (`S6G3-3`). `RA-00`…`RA-05` do not appear: a decoded record carries each as a
    typed identity, and their referents are `G1` binding, never validity.
    """
    c = record.content
    permitted = c.preflight_permission == BoundedPreflightPermission.PERMITTED
    labelled = c.owner_human_label_present
    bounded = ceiling_clauses(c).holds()
    roles = len(c.authorized_roles) > 0
    return (
        (RaAttribute.RA_09_PREFLIGHT_PERMISSION, permitted),  # guard:ga_eligibility_completeness
        (RaAttribute.RA_08_OWNER_HUMAN_LABEL, labelled),  # guard:ga_eligibility_completeness
        (RaAttribute.RA_07_AUTHORITY_CEILING, bounded),  # guard:ga_eligibility_completeness
        (RaAttribute.RA_06_AUTHORIZED_ROLES, roles),  # guard:ga_eligibility_completeness
    )


def ra_failures(record: AuthorizationRecord) -> frozenset[RaAttribute]:
    """Every `RA` attribute the decoded record fails — a function of its content alone."""
    return frozenset(a for a, holds in _ra_checks(record) if not holds)


def failing_attribute(record: AuthorizationRecord) -> RaAttribute | None:
    """The failing attribute with the **lowest** `RA` index, or `None` for a valid record
    (`S6G3-3`). It orders one record's attributes, never records."""
    failed = [a for a, holds in _ra_checks(record) if not holds]
    if not failed:
        return None
    return min(failed, key=RA_ORDER.index)  # guard:ga_eligibility_completeness


# --- G1: binding match against the attempt and its ingest referents -----------------------


def binding_match(
    record: AuthorizationRecord, occurrence: RootResolutionRecord, records: AuthorityRecords
) -> bool | dv.Indeterminate:
    """`G1 = INGEST_REFERENT_MATCH` (clarification §4): `RA-01`/`RA-02` against the attempt
    (`RC-14`), and `RA-02`…`RA-05` against the recorded `RC-10`/`RC-11` referents — the
    stage recorded under `RA-01`'s project, which the store's reference makes a recorded
    project too. A mismatch makes a valid candidate not eligible, with no `RC-15`
    (`S6G3-4`)."""
    if _unreadable_of(records, INGEST_REFERENTS):
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an ingest referent")
    c = record.content
    stages = {(s.identity, s.project) for s in _own(records, GovernedStage)}
    contracts = {k.identity for k in _own(records, StageContract)}
    repositories = {b.identity for b in _own(records, RepositoryBoundary)}
    baselines = {b.identity for b in _own(records, BaselineIdentity)}
    return (
        c.project == occurrence.project  # guard:ga_eligibility_completeness
        and c.stage == occurrence.stage  # guard:ga_eligibility_completeness
        and (c.stage, c.project) in stages  # guard:ga_eligibility_completeness
        and c.contract in contracts  # guard:ga_eligibility_completeness
        and c.repository_boundary in repositories  # guard:ga_eligibility_completeness
        and c.baseline in baselines  # guard:ga_eligibility_completeness
    )


# --- same-identity consistency, through ST-02's one comparator ----------------------------


def _disagreeing_classes(
    first: AuthorizationRecord, second: AuthorizationRecord
) -> frozenset[AuthorityBearingContentClass]:
    """The projection classes on which two same-identity records disagree.

    Class `c` disagrees iff `first`, and `first` with `c` taken from `second`, are not
    `EQUIVALENT` under `compare_records` — ST-02's one comparator, and no other (`DO11-6`,
    `AP11-I74`). An indeterminate class counts as disagreeing (`EQ-6`).
    """
    fields: dict[str, Any] = {name: getattr(first.content, name) for name in PROJECTION.values()}
    found: set[AuthorityBearingContentClass] = set()
    for projection_class, name in PROJECTION.items():
        probe = AuthorizationRecord(
            identity=first.identity,
            authorization_identity=first.authorization_identity,
            content=AuthorityBearingContent(**{**fields, name: getattr(second.content, name)}),
        )
        outcome = compare_records(first, probe)
        if outcome != EquivalenceOutcome.EQUIVALENT:  # guard:ga_root_uniqueness
            found.add(projection_class)
    return frozenset(found)


@dataclass(frozen=True)
class Consistency:
    """`V-17b` over one identity's valid records: consistent, or the classes that disagree."""

    consistent: bool
    disagreeing: tuple[AuthorityBearingContentClass, ...]


def identity_consistency(valid: tuple[AuthorizationRecord, ...]) -> Consistency:
    """Every pair of one identity's **valid** records compared — binding-matched or not,
    since constitution turns on validity and equivalence alone (AP-03 §4.1, `S6G3-5`).
    `NOT_EQUIVALENT` and `INDETERMINATE` are both conflict (`EQ-6`)."""
    pairs = [(a, b) for index, a in enumerate(valid) for b in valid[index + 1 :]]
    found = [compare_records(a, b) for a, b in pairs]
    consistent = all(o == EquivalenceOutcome.EQUIVALENT for o in found)  # guard:ga_root_uniqueness
    classes = {c for a, b in pairs for c in _disagreeing_classes(a, b)}
    return Consistency(consistent, tuple(c for c in AuthorityBearingContentClass if c in classes))


# --- eligible multiplicity (S6G3-5, S6G3-7) -------------------------------------------------


@dataclass(frozen=True)
class ResolutionEvaluation:
    """What evaluating one open resolution found. A derived view: never stored, and an input
    to nothing but this resolution's own completing act (`RO7A-6`(a), `RO7A-9`).

    `multiplicity` is `ZERO`, `ONE` or `MANY` — or `INDETERMINATE`, with its cause in
    `indeterminacy`. `consistency` exists only for `ONE`. `exclusions` are in canonical
    order, and are computed — and written — whatever the multiplicity (`S6G3-7`).
    """

    occurrence: RootResolutionRecord
    exclusions: tuple[CandidateExclusion, ...]
    eligible: frozenset[OwnerAuthorizationId]
    multiplicity: str
    consistency: Consistency | None
    indeterminacy: dv.Indeterminate | None


def _exclusions(
    resolution: RootResolutionId, decoded: tuple[AuthorizationRecord, ...]
) -> tuple[CandidateExclusion, ...]:
    """One exclusion per decoded invalid candidate, naming its lowest failing attribute, in
    ascending canonical byte order of the excluded record (`S6G3-1`, `S6G3-3`, `S6G3-6`)."""
    failing = [(r.identity, failing_attribute(r)) for r in decoded]
    made = [
        CandidateExclusion(
            identity=CandidateExclusionId(parent_resolution=resolution, excluded_record=record),
            failing_attribute=attribute,
        )
        for record, attribute in failing
        if attribute is not None  # guard:ga_eligibility_completeness
    ]
    by_record = {_canonical_key(e.identity.excluded_record): e for e in made}
    return tuple(by_record[k] for k in sorted(by_record))  # guard:ga_eligibility_completeness


def evaluate_resolution(
    records: AuthorityRecords, resolution: RootResolutionId
) -> ResolutionEvaluation | dv.Indeterminate:
    """`A2`/`A3`/`A4`'s inputs for one open resolution, from records that already exist
    (`RO7A-9`): its `RC-14` candidates, their validity, `G1` binding and `DV-4` liveness."""
    if records.unstable:
        return _indeterminate(dv.IndeterminacyCause.UNSTABLE_READ, "the two read passes differ")
    occurrences = [
        r
        for r in _derivable(records, RootResolutionRecord)
        if r.identity == resolution  # guard:ga_eligibility_completeness
    ]
    if len(occurrences) != 1:
        return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the RC-14 occurrence")
    (occurrence,) = occurrences
    named = set(occurrence.candidates)
    decoded = tuple(
        r
        for r in _own(records, AuthorizationRecord)
        if r.identity in named  # guard:ga_eligibility_completeness
    )
    exclusions = _exclusions(resolution, decoded)
    unreadable = _unreadable_record_ids(records) & named
    blocked = bool(unreadable) or len(decoded) != len(named)  # guard:ga_eligibility_completeness
    if blocked:
        why = "a candidate is unreadable or absent: its RA-00 identity is not attributable"
        return ResolutionEvaluation(
            occurrence,
            exclusions,
            frozenset(),
            model.INDETERMINATE,
            None,
            _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, why),
        )
    return _multiplicity_of(records, occurrence, exclusions, decoded)


def _multiplicity_of(
    records: AuthorityRecords,
    occurrence: RootResolutionRecord,
    exclusions: tuple[CandidateExclusion, ...],
    decoded: tuple[AuthorizationRecord, ...],
) -> ResolutionEvaluation:
    """Eligible = valid ∧ binding ∧ live, counted over distinct identities (`S6G3-5`)."""
    valid = tuple(r for r in decoded if not ra_failures(r))  # guard:ga_eligibility_completeness
    bindings = [(r, binding_match(r, occurrence, records)) for r in valid]
    matched = {
        r.authorization_identity
        for r, bound in bindings
        if bound is True  # guard:ga_eligibility_completeness
    }
    liveness = {i: dv.derive_liveness(records.derivable, i) for i in matched}
    unknown = [
        found
        for found in (*(b for _, b in bindings), *liveness.values())
        if isinstance(found, dv.Indeterminate)  # guard:ga_eligibility_completeness
    ]
    if unknown:
        return ResolutionEvaluation(
            occurrence, exclusions, frozenset(), model.INDETERMINATE, None, unknown[0]
        )
    eligible = frozenset(
        i
        for i, live in liveness.items()
        if isinstance(live, dv.Liveness) and live.live  # guard:ga_eligibility_completeness
    )
    multiplicity = _multiplicity(len(eligible))
    if multiplicity != ONE:
        return ResolutionEvaluation(occurrence, exclusions, eligible, multiplicity, None, None)
    (only,) = eligible
    same = [r for r in decoded if r.authorization_identity == only]
    group = tuple(r for r in same if not ra_failures(r))  # guard:ga_root_uniqueness
    consistency = identity_consistency(group)
    if not consistency.consistent and not consistency.disagreeing:
        return ResolutionEvaluation(
            occurrence,
            exclusions,
            eligible,
            model.INDETERMINATE,
            None,
            _indeterminate(
                dv.IndeterminacyCause.INCONSISTENT_RECORDS,
                "records conflict, yet no disagreeing class could be named",
            ),
        )
    return ResolutionEvaluation(occurrence, exclusions, eligible, ONE, consistency, None)


def _multiplicity(count: int) -> str:
    """Distinct eligible identities: none, exactly one, or more (`V-16`, `V-17a`)."""
    if count == 0:  # guard:ga_root_uniqueness
        return ZERO
    if count == 1:
        return ONE
    return MANY


def resolution_facts(evaluation: ResolutionEvaluation) -> sm.Facts:
    """The facts ST-05's `A2`/`A3`/`A4` guards read, and only those. An indeterminate
    multiplicity supplies neither ST-06 fact, so every completing edge is refused."""
    facts: sm.Facts = {model.TRIGGER.name: model.COORDINATOR}
    if evaluation.indeterminacy is None:
        facts[model.ELIGIBLE_MULTIPLICITY.name] = evaluation.multiplicity
    if evaluation.consistency is not None:
        consistent = evaluation.consistency.consistent
        key = model.IDENTITY_RECORDS_CONSISTENT.name
        facts[key] = _truth(consistent)  # guard:ga_root_uniqueness
    return facts


def _truth(value: bool) -> str:
    return model.TRUE if value else model.FALSE


# --- the M1 acts: A1, the exclusions, A2 / A3 / A4 ----------------------------------------


@dataclass(frozen=True)
class Opened:
    """`A1` holds: the occurrence exists — minted now, or found by its anchor (`MC-17`(i))."""

    resolution: RootResolutionId
    replayed: bool


@dataclass(frozen=True)
class Resolved:
    """The resolution is complete: its completing entry, written now or already recorded."""

    resolution: RootResolutionId
    entry: M1PositionEntry
    replayed: bool


@dataclass(frozen=True)
class StillOpen:
    """No completing edge is admissible: the resolution stays `RESOLUTION_OPEN`, with
    nothing false recorded (`S6G3-7`). The evaluation says why, and is not stored."""

    resolution: RootResolutionId
    evaluation: ResolutionEvaluation
    refused: tuple[sm.Refused, ...]


def _attempt_anchor(
    records: AuthorityRecords, project: ProjectId, stage: GovernedStageId
) -> Determined[M1PositionEntryId] | dv.Indeterminate:
    """`MC-17`(i): the terminal M1 entry of the latest attempt for `(project, stage)`, or its
    affirmative absence. The latest attempt is the one whose terminal entry no other
    attempt names — found by reference, never by order. An open attempt is its own head, so
    a repeated `A1` finds it. Two heads is a fork, and indeterminate."""
    attempts = [
        a
        for a in _derivable(records, RootResolutionRecord)
        if a.project == project and a.stage == stage
    ]
    named = {
        a.predecessor_terminal_entry.value
        for a in attempts
        if isinstance(a.predecessor_terminal_entry, Present)
    }
    heads: list[Determined[M1PositionEntryId]] = []
    for attempt in attempts:
        position = dv.derive_m1_position(records.derivable, attempt.identity)
        if not isinstance(position, dv.Occupancy):
            return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "an attempt's A1 entry")
        reached = position.reached
        if reached.edge not in dv.COMPLETING_EDGES:
            heads.append(attempt.predecessor_terminal_entry)
        elif reached.identity not in named:
            heads.append(Present[M1PositionEntryId](value=reached.identity))
    if len(heads) > 1:
        return _indeterminate(dv.IndeterminacyCause.BROKEN_CHAIN, "attempts fork")
    return heads[0] if heads else NO_PRIOR_ATTEMPT


def open_resolution(
    store: CoordinationStore, project: ProjectId, stage: GovernedStageId
) -> Opened | sm.Refused | dv.Indeterminate:
    """`A1`: a stage-entry attempt naming `(project, stage)` mints its `RootResolution`
    occurrence (`RC-14`) and the `A1` entry as one unit (`MC-19`, `RO7A-1`) — or finds the
    occurrence already holding the attempt anchor, and mints nothing (`MC-17`(i)).

    The candidates are **every** `RC-12` record visible, readable or not: an unreadable one
    is named by its record identity and never dropped (`VM-6`, `S6G3-7`)."""
    records = read_authority_records(store)
    if records.unstable:
        return _indeterminate(dv.IndeterminacyCause.UNSTABLE_READ, "the two read passes differ")
    anchor = _attempt_anchor(records, project, stage)
    if isinstance(anchor, dv.Indeterminate):
        return anchor
    existing = [
        a
        for a in _derivable(records, RootResolutionRecord)
        if a.project == project and a.stage == stage and a.predecessor_terminal_entry == anchor
    ]
    if existing:
        return Opened(existing[0].identity, replayed=True)
    trigger = {model.TRIGGER.name: model.STAGE_ENTRY_ATTEMPT}
    admitted = sm.evaluate(M1Edge.A1, model.M1_ENTRY, trigger)
    if isinstance(admitted, sm.Refused):
        return admitted
    candidates = {r.identity for r in _own(records, AuthorizationRecord)}
    candidates |= _unreadable_record_ids(records)
    occurrence = RootResolutionRecord(
        identity=RootResolutionId(value=mint_value()),
        project=project,
        stage=stage,
        predecessor_terminal_entry=anchor,
        candidates=tuple(sorted(candidates, key=_canonical_key)),
    )
    entry = M1PositionEntry(
        identity=M1PositionEntryId(resolution=occurrence.identity, discriminator=mint_value()),
        state=M1Position(str(admitted.target)),
        edge=M1Edge.A1,
        predecessor=FIRST_ENTRY,
        result=NoResolutionResult(),
    )
    store.create_unit((occurrence, entry))
    return Opened(occurrence.identity, replayed=False)


def _exclusion_chain(
    exclusions: tuple[CandidateExclusion, ...],
) -> tuple[CandidateExclusionRecord, ...]:
    """The `RC-15` chain in canonical order, each naming the previous (`S6G3-6`, `PA-04`)."""
    predecessors: list[Determined[CandidateExclusionId]] = [EXCLUSION_CHAIN_START]
    predecessors += [Present[CandidateExclusionId](value=e.identity) for e in exclusions]
    return tuple(
        CandidateExclusionRecord(exclusion=exclusion, predecessor=predecessor)
        for exclusion, predecessor in zip(exclusions, predecessors, strict=False)
    )


def _missing_exclusions(
    records: AuthorityRecords,
    resolution: RootResolutionId,
    chain: tuple[CandidateExclusionRecord, ...],
) -> tuple[CandidateExclusionRecord, ...] | dv.Indeterminate:
    """The exclusions still to append. Those already recorded must be exactly the chain's
    canonical prefix (`MC-3` replay equality); anything else is inconsistent."""
    if _unreadable_of(records, (CandidateExclusionRecord,)):
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an RC-15 exclusion")
    recorded = {
        r
        for r in _own(records, CandidateExclusionRecord)
        if r.exclusion.identity.parent_resolution == resolution  # guard:ga_eligibility_completeness
    }
    prefix = set(chain[: len(recorded)])
    if recorded != prefix:  # guard:ga_eligibility_completeness
        return _indeterminate(
            dv.IndeterminacyCause.INCONSISTENT_RECORDS,
            "recorded exclusions are not the canonical prefix of the recomputed ones",
        )
    return chain[len(recorded) :]


def complete_resolution(
    store: CoordinationStore, resolution: RootResolutionId
) -> Resolved | StillOpen | dv.Indeterminate:
    """Record the exclusions an open resolution is missing, then complete it by the one
    admissible edge of `A2`, `A3` and `A4` — or leave it open when none is admissible.

    A completed resolution is never re-evaluated: its recorded result is returned and
    nothing is written (`M1-7`, `RO7A-6`(b)). Exclusions are written only while it is open
    (`RO7A-9`), and even when its multiplicity is indeterminate (`S6G3-7`)."""
    records = read_authority_records(store)
    recorded = dv.derive_recorded_eligibility(records.derivable, resolution)
    if isinstance(recorded, dv.CompletedResolution):
        (entry,) = [
            e
            for e in _derivable(records, M1PositionEntry)
            if e.identity == recorded.completing_entry
        ]
        return Resolved(resolution, entry, replayed=True)
    if isinstance(recorded, dv.Indeterminate):
        return recorded
    position = dv.derive_m1_position(records.derivable, resolution)
    if not isinstance(position, dv.Occupancy):
        return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the resolution's A1 entry")
    evaluation = evaluate_resolution(records, resolution)
    if isinstance(evaluation, dv.Indeterminate):
        return evaluation
    chain = _exclusion_chain(evaluation.exclusions)
    missing = _missing_exclusions(records, resolution, chain)
    if isinstance(missing, dv.Indeterminate):
        return missing
    if missing:
        store.create_unit(missing)
    facts = resolution_facts(evaluation)
    admitted = sm.admissible_edges(Machine.M1, M1Position.RESOLUTION_OPEN, facts)
    if len(admitted) != 1:
        refused = tuple(
            found
            for edge in (M1Edge.A2, M1Edge.A3, M1Edge.A4)
            for found in (sm.evaluate(edge, M1Position.RESOLUTION_OPEN, facts),)
            if isinstance(found, sm.Refused)
        )
        return StillOpen(resolution, evaluation, refused)
    (edge,) = admitted
    outcome, entry = _completing_unit(evaluation, edge, position.reached)
    store.create_unit((*outcome, entry))
    return Resolved(resolution, entry, replayed=False)


def _completing_unit(
    evaluation: ResolutionEvaluation, edge: sm.Admitted, a1: M1PositionEntry
) -> tuple[tuple[RefusalRecord | AuthorityAmbiguity, ...], M1PositionEntry]:
    """The completing transition's own unit: its outcome record, if any, then its entry,
    whose result binds that record by reference (`RO7A-2`…`RO7A-5`)."""
    occurrence = evaluation.occurrence
    result: ResolvedRootResult | RefusalResult | AmbiguityResult
    outcome: tuple[RefusalRecord | AuthorityAmbiguity, ...]
    if edge.edge == M1Edge.A2:
        (only,) = evaluation.eligible
        result, outcome = ResolvedRootResult(resolved_root=only), ()
    elif edge.edge == M1Edge.A3:
        refusal = missing_authority_refusal(occurrence)
        result, outcome = RefusalResult(refusal=refusal.refusal.identity), (refusal,)
    else:
        ambiguity = authority_ambiguity(evaluation)
        result, outcome = AmbiguityResult(ambiguity=ambiguity.identity), (ambiguity,)
    entry = M1PositionEntry(
        identity=M1PositionEntryId(resolution=occurrence.identity, discriminator=mint_value()),
        state=M1Position(str(edge.target)),
        edge=M1Edge(edge.edge),
        predecessor=Present[M1PositionEntryId](value=a1.identity),
        result=result,
    )
    return outcome, entry


def missing_authority_refusal(occurrence: RootResolutionRecord) -> RefusalRecord:
    """`A3`'s `RC-30` Case A, *missing authority* (`V-16`, AP-02 §13.6)."""
    return RefusalRecord(
        refusal=Refusal(
            identity=RefusalId(value=mint_value()),
            case=GovernanceCase.CASE_A,
            stage=occurrence.stage,
            branch=model.STAGE_ENTRY_ATTEMPT,
            role=KnownAbsent(basis="no role: the stage has not begun"),
            resolved_root=KnownAbsent(basis="zero eligible live authorizations remain"),
            envelope=KnownAbsent(basis="no envelope precedes resolution"),
            condition=MISSING_AUTHORITY_CONDITION,
            observed_value=ZERO,
            bound_value=ONE,
            refused_action_class=ActionClass(name=model.STAGE_ENTRY_ATTEMPT),
        ),
        cycle_occurrence=BEFORE_ANY_CYCLE,
    )


def authority_ambiguity(evaluation: ResolutionEvaluation) -> AuthorityAmbiguity:
    """`A4`'s `RC-16`: every eligible identity — never a non-live one, never a winner — or
    the one identity and the classes that disagree (`V-17a`, `V-17b`, `EQ-6`, `GE-1`)."""
    form: DistinctMultiplicityForm | SameIdentityConflictForm
    consistency = evaluation.consistency
    if consistency is None:
        competing = tuple(sorted(evaluation.eligible, key=_canonical_key))
        form = DistinctMultiplicityForm(competing_identities=competing)
    else:
        (only,) = evaluation.eligible
        form = SameIdentityConflictForm(
            conflicting_identity=only, disagreeing_content_classes=consistency.disagreeing
        )
    return AuthorityAmbiguity(
        identity=AuthorityAmbiguityId(value=mint_value()),
        stage=evaluation.occurrence.stage,
        form=form,
    )


# --- the root instance, in canonical representation ---------------------------------------


def _canonical[T: BaseModel | str](values: tuple[T, ...]) -> tuple[T, ...]:
    """A set-valued dimension in the canonical `EQ-3` member order, duplicates collapsed:
    the same tokens, whichever content-equivalent record carried them."""
    keyed = {_canonical_key(v): v for v in values}
    return tuple(keyed[k] for k in sorted(keyed))


def canonical_member(member: AuthorityCeilingMember) -> AuthorityCeilingMember:
    """One member, each set-valued dimension canonical and every other dimension as is."""
    write: Carried[WriteBoundary] | NotApplicable = member.write_boundary
    if isinstance(write, Carried):
        write = Carried[WriteBoundary](value=WriteBoundary(scopes=_canonical(write.value.scopes)))
    designation: Carried[AuthoritativeInputDesignation] | NotApplicable = (
        member.authoritative_input_designation
    )
    if isinstance(designation, Carried):
        designated = _canonical(designation.value.designated_scopes)
        designation = Carried[AuthoritativeInputDesignation](
            value=AuthoritativeInputDesignation(designated_scopes=designated)
        )
    return AuthorityCeilingMember(
        role_applicability=member.role_applicability,
        action_classes=_canonical(member.action_classes),
        read_boundary=ReadBoundary(scopes=_canonical(member.read_boundary.scopes)),
        write_mode=member.write_mode,
        write_boundary=write,
        tool_categories=_canonical(member.tool_categories),
        external_action_classes=_canonical(member.external_action_classes),
        git_capability_class=member.git_capability_class,
        scope_frame=member.scope_frame,
        authoritative_input_designation=designation,
    )


def canonical_content(content: AuthorityBearingContent) -> AuthorityBearingContent:
    """The instance's content: every content-equivalent record yields this same value."""
    fields: dict[str, Any] = {name: getattr(content, name) for name in PROJECTION.values()}
    fields.update(
        authorized_roles=_canonical(content.authorized_roles),
        authority_ceiling=_canonical(tuple(canonical_member(m) for m in content.authority_ceiling)),
    )
    return AuthorityBearingContent(**fields)


@dataclass(frozen=True)
class ResolvedRoot:
    """`EV-4` input 1: the resolved **instance** and its content — never a record. It also
    carries the resolution that resolved it and its constituting records, which the
    derivation-time guards re-read (`S6G2-2`(k), `V-02`…`V-04`)."""

    authorization: OwnerAuthorizationId
    content: AuthorityBearingContent
    resolution: RootResolutionRecord
    records: tuple[AuthorizationRecord, ...]


def resolved_root(
    records: AuthorityRecords, root: OwnerAuthorizationId
) -> ResolvedRoot | dv.Indeterminate:
    """The root the `A2` entry names, read after the resolution completed (`RO7A-6`(b)),
    and its constituting records re-read and re-validated (`S6G2-2`(k))."""
    if records.unstable:
        return _indeterminate(dv.IndeterminacyCause.UNSTABLE_READ, "the two read passes differ")
    if _unreadable_of(records, ROOT_INSTANCE_READS):  # guard:ga_envelope_validity
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an A2 entry or RC-14")
    naming = [
        e
        for e in _derivable(records, M1PositionEntry)
        if isinstance(e.result, ResolvedRootResult)
        and e.result.resolved_root == root  # guard:ga_envelope_validity
    ]
    if len(naming) != 1:
        return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the A2 entry naming root")
    (a2,) = naming
    occurrences = [
        r for r in _derivable(records, RootResolutionRecord) if r.identity == a2.identity.resolution
    ]
    if len(occurrences) != 1:
        return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the RC-14 occurrence")
    (occurrence,) = occurrences
    if _unreadable_record_ids(records) & set(occurrence.candidates):
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an RC-12 candidate")
    candidates = set(occurrence.candidates)
    group = tuple(
        r
        for r in _own(records, AuthorizationRecord)
        if r.identity in candidates
        and r.authorization_identity == root  # guard:ga_envelope_validity
        and not ra_failures(r)  # guard:ga_envelope_validity
    )
    one_identity = {r.authorization_identity for r in group} == {root}
    if not one_identity or not identity_consistency(group).consistent:
        why = "the root's valid records do not constitute one instance"
        return _indeterminate(dv.IndeterminacyCause.INCONSISTENT_RECORDS, why)
    content = canonical_content(group[0].content)
    return ResolvedRoot(root, content, occurrence, group)


# --- envelope derivation: exactly five inputs (EV-4, S6G2-4, S6G2-8) ----------------------


@dataclass(frozen=True)
class DerivedEnvelope:
    """What derivation yields: everything an `AuthorityEnvelope` carries but its identity,
    which the act mints afterwards and which is never an input (`S6G2-9`, `EV-5`)."""

    resolved_root: OwnerAuthorizationId
    stage: GovernedStageId
    entry_boundary: EntryStateBoundaryId
    role: Role
    bounds: AuthorityBounds
    declared_closed: bool


class NotDerivableReason(StrEnum):
    """Why no envelope exists — an absence that is correct, never a stripped authority
    (`EV-6`, `AP03-I30`, `AP04-I12`, `N-07`)."""

    ROLE_NOT_AUTHORIZED = "ROLE_NOT_AUTHORIZED"
    NOT_ACTIVATED_ON_BRANCH = "NOT_ACTIVATED_ON_BRANCH"
    NO_UNIQUE_MEMBER = "NO_UNIQUE_MEMBER"
    NO_FROZEN_SET = "NO_FROZEN_SET"


@dataclass(frozen=True)
class NotDerivable:
    reason: NotDerivableReason


def _frozen_set_reference(
    role: Role, frozen_set: Determined[FrozenFindingSetId]
) -> Carried[FrozenFindingSetId] | NotApplicable | None:
    """`E-14` (`S6G2-3`): the frozen-set input, carried iff the role is REMEDIATOR or BCV,
    and inapplicable to IMPLEMENTER and DR. `None`: applicable, but no set exists."""
    if role not in FROZEN_SET_ROLES:  # guard:ga_role_write_mode
        return NotApplicable()
    if isinstance(frozen_set, Present):
        return Carried[FrozenFindingSetId](value=frozen_set.value)
    return None


def derive_envelope(
    root: ResolvedRoot,
    role: Role,
    branch: M2Position,
    frozen_set: Determined[FrozenFindingSetId],
    boundary: EntryStateBoundaryId,
) -> DerivedEnvelope | NotDerivable:
    """`EV-4`: a total function of exactly five inputs, with no free parameter.

    The root gives the role's member (`RA-07`) and the scope frame; the role selects the
    member and fixes `E-14`'s applicability; the branch gates derivability only; the
    frozen set gives `E-14`'s value; the boundary gives `E-07`. The member is copied field
    for field, and nothing is intersected, unioned or computed (`S6G2-4`, `S6G2-10`).
    """
    content = root.content
    if role not in content.authorized_roles:  # guard:ga_envelope_validity
        return NotDerivable(NotDerivableReason.ROLE_NOT_AUTHORIZED)
    if (role, branch) not in DERIVABLE_ROLE_STEPS:  # guard:ga_role_write_mode
        return NotDerivable(NotDerivableReason.NOT_ACTIVATED_ON_BRANCH)
    ceiling = content.authority_ceiling
    members = [m for m in ceiling if m.role_applicability == role]  # guard:ga_role_write_mode
    if len(members) != 1:
        return NotDerivable(NotDerivableReason.NO_UNIQUE_MEMBER)
    (member,) = members
    e14 = _frozen_set_reference(role, frozen_set)
    if e14 is None:
        return NotDerivable(NotDerivableReason.NO_FROZEN_SET)
    copied: dict[str, Any] = {
        name: getattr(member, name) for name in AuthorityCeilingMember.model_fields
    }
    return DerivedEnvelope(
        resolved_root=root.authorization,
        stage=content.stage,
        entry_boundary=boundary,
        role=role,
        bounds=AuthorityBounds(**copied, frozen_set_reference=e14),
        declared_closed=True,
    )


@dataclass(frozen=True)
class EnvelopeInputs:
    """The five inputs, read from records: the `A2`-named root, the role, the branch (the
    target step), the root's `RC-26` set or its absence, and its `RC-17` boundary."""

    root: ResolvedRoot
    role: Role
    branch: M2Position
    frozen_set: Determined[FrozenFindingSetId]
    boundary: EntryStateBoundaryId


def envelope_inputs(
    records: AuthorityRecords, root: OwnerAuthorizationId, role: Role, step: M2Position
) -> EnvelopeInputs | dv.Indeterminate:
    """Read the five inputs. No `CYCLE_BOUND`, obligation, closure record or envelope
    identity is read (`S6G2-8`, `AP04-I49`). No boundary means no envelope (`AP03-I07`)."""
    resolved = resolved_root(records, root)
    if isinstance(resolved, dv.Indeterminate):
        return resolved
    if _unreadable_of(records, ENVELOPE_INPUT_READS):  # guard:ga_envelope_validity
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an RC-17 or RC-26")
    boundaries = [
        b.boundary.identity
        for b in _derivable(records, EntryStateBoundaryRecord)
        if b.resolved_root == root  # guard:ga_envelope_validity
    ]
    if len(boundaries) != 1:
        return _indeterminate(dv.IndeterminacyCause.MISSING_RECORD, "the root's entry boundary")
    sets = [
        s.identity
        for s in _derivable(records, FrozenFindingSet)
        if s.resolved_root == root  # guard:ga_envelope_validity
    ]
    if len(sets) > 1:
        return _indeterminate(dv.IndeterminacyCause.INCONSISTENT_RECORDS, "two frozen sets")
    frozen: Determined[FrozenFindingSetId] = NO_FROZEN_SET
    if sets:
        frozen = Present[FrozenFindingSetId](value=sets[0])
    return EnvelopeInputs(resolved, role, step, frozen, boundaries[0])


# --- the two relations: ≤ ceiling (S6G2-6) and equivalent-or-narrower (S6G2-7) ------------


class Order(StrEnum):
    """A bounds comparison's result. `MALFORMED` is a mixed role-conditional pair — an
    inapplicable dimension present, or an applicable one absent — and is never read as
    wider (`AP03-I15`)."""

    WITHIN = "WITHIN"
    WIDER = "WIDER"
    MALFORMED = "MALFORMED"


def _conditional_order(
    lower: Carried[Any] | NotApplicable, upper: Carried[Any] | NotApplicable
) -> Order:
    """`NotApplicable ≤ NotApplicable`; `Carried(a) ≤ Carried(b)` iff `a`'s scopes ⊆ `b`'s;
    a mixed pair is malformed."""
    lower_scopes, upper_scopes = _carried_scopes(lower), _carried_scopes(upper)
    if lower_scopes is None and upper_scopes is None:
        return Order.WITHIN
    if lower_scopes is None or upper_scopes is None:
        return Order.MALFORMED
    within = lower_scopes <= upper_scopes  # guard:ga_bounds_within_ceiling
    return Order.WITHIN if within else Order.WIDER


def _ten_dimension_order(
    lower: AuthorityBounds, upper: AuthorityBounds | AuthorityCeilingMember
) -> Order:
    """`≤_d` over the ten dimensions a ceiling conveys: exact-token inclusion for sets and
    scopes, `READ_ONLY < WRITING`, `NONE < BOUNDED_READ`, equality for role and scope
    frame, and the role-conditional order for `E-12` and `E-20`."""
    lo, up = lower, upper
    conditional = (
        _conditional_order(lo.write_boundary, up.write_boundary),
        _conditional_order(lo.authoritative_input_designation, up.authoritative_input_designation),
    )
    if Order.MALFORMED in conditional:
        return Order.MALFORMED
    mode_within = lo.write_mode in (up.write_mode, WriteMode.READ_ONLY)
    git_within = lo.git_capability_class in (up.git_capability_class, GitCapabilityClass.NONE)
    external = set(lo.external_action_classes) <= set(up.external_action_classes)
    reads = set(lo.read_boundary.scopes) <= set(up.read_boundary.scopes)
    within = (
        lo.role_applicability == up.role_applicability  # guard:ga_bounds_within_ceiling
        and lo.scope_frame == up.scope_frame  # guard:ga_bounds_within_ceiling
        and set(lo.action_classes) <= set(up.action_classes)  # guard:ga_bounds_within_ceiling
        and set(lo.tool_categories) <= set(up.tool_categories)  # guard:ga_bounds_within_ceiling
        and external  # guard:ga_bounds_within_ceiling
        and reads  # guard:ga_bounds_within_ceiling
        and mode_within  # guard:ga_bounds_within_ceiling
        and git_within  # guard:ga_bounds_within_ceiling
        and all(o == Order.WITHIN for o in conditional)  # guard:ga_bounds_within_ceiling
    )
    return Order.WITHIN if within else Order.WIDER


def within_ceiling(bounds: AuthorityBounds, ceiling: tuple[AuthorityCeilingMember, ...]) -> Order:
    """`bounds ≤ ceiling` (`EV-3`, `AP03-I13`, `S6G2-6`): exactly one member has the bounds'
    role, and every one of the ten conveyed dimensions is `≤` it. There is no `E-14` term:
    a member has no `E-14` at all."""
    role = bounds.role_applicability
    members = [m for m in ceiling if m.role_applicability == role]  # guard:ga_bounds_within_ceiling
    if len(members) != 1:
        return Order.WIDER
    (member,) = members
    return _ten_dimension_order(bounds, member)


def equivalent_or_narrower(later: AuthorityBounds, prior: AuthorityBounds) -> Order:
    """`AP03-I14`, `S6G2-7`: `later ≤ prior` over all eleven dimensions, `E-14` included —
    equal when both carry the same frozen set or both are inapplicable. Identity is not a
    term: the comparison is over non-identity bounds."""
    order = _ten_dimension_order(later, prior)
    later_set, prior_set = later.frozen_set_reference, prior.frozen_set_reference
    mixed = isinstance(later_set, NotApplicable) != isinstance(prior_set, NotApplicable)
    if mixed:  # guard:ga_equivalent_or_narrower
        return Order.MALFORMED
    if order != Order.WITHIN:  # guard:ga_equivalent_or_narrower
        return order
    same_set = later_set == prior_set  # guard:ga_equivalent_or_narrower
    return Order.WITHIN if same_set else Order.WIDER


def envelope_applicability(bounds: AuthorityBounds) -> bool:
    """§3.2 validity and `AP03-I15`: each role-conditional dimension is carried iff it is
    applicable to the envelope's role — `E-12` for writers, `E-20` for reviewers, `E-14`
    for REMEDIATOR and BCV. An inapplicable dimension present is **malformed**."""
    role = bounds.role_applicability
    e12 = isinstance(bounds.write_boundary, Carried)
    e20 = isinstance(bounds.authoritative_input_designation, Carried)
    e14 = isinstance(bounds.frozen_set_reference, Carried)
    return (
        role in WORKER_ROLES  # guard:ga_envelope_validity
        and e12 == (role in WRITING_ROLES)  # guard:ga_envelope_validity
        and e20 == (role in REVIEWING_ROLES)  # guard:ga_envelope_validity
        and e14 == (role in FROZEN_SET_ROLES)  # guard:ga_envelope_validity
    )


def envelope_role_shape(bounds: AuthorityBounds) -> bool:
    """Role and write mode (AP-11 §16 ST-06 Mutation cell): writers are `WRITING` with Git
    `NONE`, reviewers `READ_ONLY` with Git `BOUNDED_READ`, and `E-16` is at most the
    declarable side-effect class. No envelope carries Git outside `{NONE, BOUNDED_READ}`:
    the type admits nothing else."""
    mode, git = bounds.write_mode, bounds.git_capability_class
    writer_git = git == GitCapabilityClass.NONE  # guard:ga_role_write_mode
    reviewer_git = git == GitCapabilityClass.BOUNDED_READ  # guard:ga_role_write_mode
    writer = mode == WriteMode.WRITING and writer_git  # guard:ga_role_write_mode
    reviewer = mode == WriteMode.READ_ONLY and reviewer_git  # guard:ga_role_write_mode
    shaped = writer if bounds.role_applicability in WRITING_ROLES else reviewer
    external = set(bounds.external_action_classes)
    return shaped and external <= DECLARABLE_SIDE_EFFECTS  # guard:ga_role_write_mode


def envelope_facts(
    records: AuthorityRecords,
    envelope: AuthorityEnvelope,
    root: OwnerAuthorizationId,
    step: M2Position,
) -> sm.Facts:
    """The ST-06 facts `C1` reads — and the derivation facts `B3`, `B4`, `B6a` and `B7`
    share with it — for one envelope, derived now or recorded, against the epoch's `root`.
    A fact whose input is indeterminate is absent, and every guard reading it refuses.

    `C1`'s `S6G2-2`(k) recheck is here: the root's ceiling is re-validated clause by clause,
    and a failing ceiling makes the envelope out of bounds, invalid and not derivable.
    """
    bounds, role = envelope.bounds, envelope.role
    inputs = envelope_inputs(records, root, role, step)
    if isinstance(inputs, dv.Indeterminate):
        return {}
    resolved = inputs.root
    content = resolved.content
    ceiling = content.authority_ceiling
    ceiling_valid = ceiling_clauses(content).holds()
    derived = derive_envelope(resolved, role, inputs.branch, inputs.frozen_set, inputs.boundary)
    same_derivation = (
        isinstance(derived, DerivedEnvelope)
        and derived.bounds == bounds  # guard:ga_envelope_validity
        and derived.entry_boundary == envelope.entry_boundary  # guard:ga_envelope_validity
        and derived.stage == envelope.stage  # guard:ga_envelope_validity
    )
    within = within_ceiling(bounds, ceiling) == Order.WITHIN
    frozen = inputs.frozen_set
    e14 = bounds.frozen_set_reference
    references_set = isinstance(frozen, Present) and e14 == Carried[FrozenFindingSetId](
        value=frozen.value
    )
    remediator = role == Role.REMEDIATOR and isinstance(e14, Carried)  # guard:ga_role_write_mode
    read_only = bounds.write_mode == WriteMode.READ_ONLY
    no_writes = isinstance(bounds.write_boundary, NotApplicable)
    designates = isinstance(bounds.authoritative_input_designation, Carried)
    valid = (
        envelope_applicability(bounds)  # guard:ga_envelope_validity
        and envelope_role_shape(bounds)  # guard:ga_envelope_validity
        and envelope.declared_closed  # guard:ga_envelope_validity
        and bounds.role_applicability == role  # guard:ga_envelope_validity
        and envelope.stage == content.stage  # guard:ga_envelope_validity
    )
    bounded = ceiling_valid and within  # guard:ga_bounds_within_ceiling
    names_root = envelope.resolved_root == root  # guard:ga_envelope_validity
    facts: sm.Facts = {
        model.ROLE_AUTHORIZED.name: _truth(role in content.authorized_roles),
        model.BOUNDS_WITHIN_CEILING.name: _truth(bounded),
        model.DERIVATION_TOTAL.name: _truth(ceiling_valid and same_derivation),
        model.ENVELOPE_VALID.name: _truth(valid and ceiling_valid),
        model.NAMES_ROOT_INSTANCE.name: _truth(names_root),
        model.E14_REFERENCES_FROZEN_SET.name: _truth(references_set),
        model.REMEDIATOR_BOUNDS.name: _truth(
            remediator and remediator_within_implementer(content) and within
        ),
        model.READ_ONLY_WITHOUT_WRITE_BOUNDARY.name: _truth(read_only and no_writes),
        model.E20_DESIGNATES_INPUTS.name: _truth(designates),
    }
    bindings = [binding_match(r, resolved.resolution, records) for r in resolved.records]
    if not any(isinstance(b, dv.Indeterminate) for b in bindings):
        matches = all(b is True for b in bindings)
        facts[model.BINDINGS_MATCH.name] = _truth(matches)
    return facts


def root_facts(records: AuthorityRecords, root: OwnerAuthorizationId) -> sm.Facts:
    """`PREFLIGHT_PERMITTED` (`B2-0`): the resolved root's `RA-09`."""
    resolved = resolved_root(records, root)
    if isinstance(resolved, dv.Indeterminate):
        return {}
    permitted = resolved.content.preflight_permission == BoundedPreflightPermission.PERMITTED
    return {model.PREFLIGHT_PERMITTED.name: _truth(permitted)}


# --- the C1 act ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvelopeRecorded:
    """`C1` holds: the envelope and its `ENVELOPE_DERIVED` entry exist — written now, or
    found by the `MC-15` key (`EV-5`: a replay mints no second identity)."""

    record: AuthorityEnvelopeRecord
    entry: M3PositionEntry
    replayed: bool


@dataclass(frozen=True)
class NarrowingRefused:
    """A prior envelope for the same root, stage, role and boundary is narrower than this
    one, or a prior envelope of the root is not within its own member (`AP03-I14`,
    `EV-3`'s *union ≤ ceiling*). Nothing is written."""

    prior: AuthorityEnvelopeId
    order: Order


def _priors_hold(
    records: AuthorityRecords,
    envelope: AuthorityEnvelope,
    ceiling: tuple[AuthorityCeilingMember, ...],
) -> NarrowingRefused | None:
    """`AP03-I14` against every prior envelope of the same `(root, stage, role, boundary)`,
    and *union ≤ ceiling* as every envelope of the root within its own member."""
    root = envelope.resolved_root
    priors = [
        p.envelope
        for p in _derivable(records, AuthorityEnvelopeRecord)
        if p.envelope.resolved_root == root  # guard:ga_equivalent_or_narrower
    ]
    for prior in priors:
        own = within_ceiling(prior.bounds, ceiling)
        if own != Order.WITHIN:  # guard:ga_bounds_within_ceiling
            return NarrowingRefused(prior.identity, own)
        same = (prior.stage, prior.role, prior.entry_boundary) == (
            envelope.stage,
            envelope.role,  # guard:ga_equivalent_or_narrower
            envelope.entry_boundary,
        )
        order = equivalent_or_narrower(envelope.bounds, prior.bounds)
        if same and order != Order.WITHIN:  # guard:ga_equivalent_or_narrower
            return NarrowingRefused(prior.identity, order)
    return None


def record_envelope(
    store: CoordinationStore,
    root: OwnerAuthorizationId,
    role: Role,
    step: M2Position,
    predecessor_entry: M2PositionEntryId,
    cycle_occurrence: Determined[CycleOccurrenceId],
    supplied: sm.Facts,
) -> EnvelopeRecorded | NotDerivable | NarrowingRefused | sm.Refused | dv.Indeterminate:
    """`C1`: derive the envelope and record it with its `ENVELOPE_DERIVED` entry as one unit —
    only if ST-05 admits `C1` over this module's facts and the two supplied ones.

    `supplied` is exactly `BOUNDARY_FIXED` and `UNACCOUNTED_MUTATION`, ST-07's and ST-08's
    facts. `predecessor_entry` and `cycle_occurrence` are the caller's `MC-15` / `CO-5`
    bindings, checked by the store's references. A replay finds the envelope by the
    `MC-15` key before anything is minted.
    """
    if set(supplied) != SUPPLIED_FACTS:
        raise ValueError(f"only {sorted(SUPPLIED_FACTS)} may be supplied, got {sorted(supplied)}")
    records = read_authority_records(store)
    if records.unstable:
        return _indeterminate(dv.IndeterminacyCause.UNSTABLE_READ, "the two read passes differ")
    if _unreadable_of(records, PRIOR_ENVELOPE_READS):  # guard:ga_equivalent_or_narrower
        return _indeterminate(dv.IndeterminacyCause.UNREADABLE_INPUT, "an RC-18 or C1 entry")
    keyed = [
        r
        for r in _derivable(records, AuthorityEnvelopeRecord)
        if r.envelope.resolved_root == root
        and r.predecessor_entry == predecessor_entry
        and r.target_state == step
        and r.envelope.role == role
    ]
    if keyed:
        return _replayed(records, keyed)
    inputs = envelope_inputs(records, root, role, step)
    if isinstance(inputs, dv.Indeterminate):
        return inputs
    derived = derive_envelope(
        inputs.root, inputs.role, inputs.branch, inputs.frozen_set, inputs.boundary
    )
    if isinstance(derived, NotDerivable):
        return derived
    envelope = AuthorityEnvelope(
        identity=AuthorityEnvelopeId(value=mint_value()),
        resolved_root=derived.resolved_root,
        stage=derived.stage,
        entry_boundary=derived.entry_boundary,
        role=derived.role,
        bounds=derived.bounds,
        declared_closed=derived.declared_closed,
    )
    facts = {
        **supplied,
        **envelope_facts(records, envelope, root, step),
        model.TRIGGER.name: model.COORDINATOR,
    }
    admitted = sm.evaluate(M3Edge.C1, model.M3_ENTRY, facts)
    if isinstance(admitted, sm.Refused):
        return admitted
    narrowing = _priors_hold(records, envelope, inputs.root.content.authority_ceiling)
    if narrowing is not None:
        return narrowing
    record = AuthorityEnvelopeRecord(
        envelope=envelope,
        cycle_occurrence=cycle_occurrence,
        predecessor_entry=predecessor_entry,
        target_state=step,
    )
    entry = M3PositionEntry(
        identity=M3PositionEntryId(envelope=envelope.identity, discriminator=mint_value()),
        state=M3Position(str(admitted.target)),
        edge=M3Edge.C1,
        predecessor=FIRST_ENTRY,
    )
    store.create_unit((record, entry))
    return EnvelopeRecorded(record, entry, replayed=False)


def _replayed(
    records: AuthorityRecords, keyed: list[AuthorityEnvelopeRecord]
) -> EnvelopeRecorded | dv.Indeterminate:
    """A replayed `C1` finds its envelope by the `MC-15` key and mints nothing (`MC-3`). The
    `RC-18` record and its `C1` entry share one unit, so one without the other is
    inconsistent."""
    found = keyed[0]
    identity = found.envelope.identity
    entries = [
        e
        for e in _derivable(records, M3PositionEntry)
        if e.identity.envelope == identity and e.edge == M3Edge.C1
    ]
    if len(keyed) != 1 or len(entries) != 1:
        return _indeterminate(dv.IndeterminacyCause.INCONSISTENT_RECORDS, "RC-18 without C1")
    return EnvelopeRecorded(found, entries[0], replayed=True)
