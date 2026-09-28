"""The closed vocabularies AP-03 fixes — data only, no evaluator.

Design basis: AP-03 §2 (entity inventory), §3 (identity kinds), §4.1 (dispositions,
RA attributes), §4.5 (resolution outcomes), §4.8/§4.8.1 (bounds dimensions, Git
tiers), §8.1 (provenance), §8.2 (governed-fact kinds), §11.2 (OWNER acts), §12
(governance-event cases), §13 (stage outcome), §14 (role/provider separation).

Every enumeration here is **closed**: AP-03 states its members, and a member this
module adds would be an entity or a capability AP-03 does not have. Where AP-03
names a dimension but assigns its value space to another frozen phase — action
classes (`E-09`), tool categories (`E-15`) — no enumeration appears here at all and
the dimension is carried as an opaque token in `bounds.py`. Silence in AP-03 is not
permission to enumerate (`AP-00 §4.3`, `TR11-7`).

Every member's value is its own name, following the spike's `states.py` convention:
a term written into a record, quoted in evidence, or read back from storage is the
same token in all three places, so there is no translation table that could drift.

**These are terms, not permissions.** No vocabulary here confers anything. `Role` in
particular confers no authority — authority comes only from the envelope derived for
a role under the resolved root (`AP03-I01`, `AP03-I17`, AP-03 §14) — and
`GitActionClass` is an **observable** vocabulary, deliberately complete so that an
act which could never have been authorized is still recordable (AP-03 §4.8.1).
"""

from __future__ import annotations

from enum import StrEnum


class IdentityKind(StrEnum):
    """The four identity kinds of AP-03 §3.

    `SUPPLIED` and `MINTED` are both *non-content-derived*. AP-03 §3's non-implication
    block is part of the definition and is not weakened by naming them here: neither
    kind implies authentication, cryptographic assignment, trusted-infrastructure
    origin, global uniqueness, provable ordering, freshness, tamper-evidence or
    non-repudiation. The property claimed is narrow — stable, opaque, per-instance,
    and independent of the authority-bearing content it names.
    """

    SUPPLIED = "SUPPLIED"
    MINTED = "MINTED"
    CONTENT = "CONTENT"
    DEPENDENT = "DEPENDENT"


class Role(StrEnum):
    """The six closed role values (AP-03 §2.3, §14; `E-08`).

    A role is *what a participant does*, never *what it may do*. Two activations
    holding the same role are related by nothing but the name.
    """

    OWNER = "OWNER"
    COORDINATOR = "COORDINATOR"
    IMPLEMENTER = "IMPLEMENTER"
    DISCOVERY_REVIEWER = "DISCOVERY_REVIEWER"
    REMEDIATOR = "REMEDIATOR"
    BOUNDED_CLOSURE_VERIFIER = "BOUNDED_CLOSURE_VERIFIER"


class RaAttribute(StrEnum):
    """The `RA-00`…`RA-09` bindings an OwnerAuthorization carries (AP-03 §4.1).

    Named as a vocabulary because two records must be able to say *which* attribute
    they are about: a `CandidateExclusion` names the failing applicable attribute
    (AP-03 §4.5, `AP03-I06`), and a same-identity conflict names the disagreeing
    content classes (AP-03 §4.6).
    """

    RA_00_AUTHORIZATION_IDENTITY = "RA_00_AUTHORIZATION_IDENTITY"
    RA_01_PROJECT = "RA_01_PROJECT"
    RA_02_STAGE = "RA_02_STAGE"
    RA_03_CONTRACT = "RA_03_CONTRACT"
    RA_04_REPOSITORY_BOUNDARY = "RA_04_REPOSITORY_BOUNDARY"
    RA_05_BASELINE = "RA_05_BASELINE"
    RA_06_AUTHORIZED_ROLES = "RA_06_AUTHORIZED_ROLES"
    RA_07_AUTHORITY_CEILING = "RA_07_AUTHORITY_CEILING"
    RA_08_OWNER_HUMAN_LABEL = "RA_08_OWNER_HUMAN_LABEL"
    RA_09_PREFLIGHT_PERMISSION = "RA_09_PREFLIGHT_PERMISSION"


class AuthorityBearingContentClass(StrEnum):
    """The classes of the closed authority-bearing projection (AP-03 §4.3).

    `RA-01`…`RA-09` plus the liveness-relevant facts. `RA-00` is the identity the
    projection is compared *within* and is therefore not one of its classes, and the
    record's own instance identity is explicitly out of the projection.
    """

    PROJECT = "PROJECT"
    STAGE = "STAGE"
    CONTRACT = "CONTRACT"
    REPOSITORY_BOUNDARY = "REPOSITORY_BOUNDARY"
    BASELINE = "BASELINE"
    AUTHORIZED_ROLES = "AUTHORIZED_ROLES"
    AUTHORITY_CEILING = "AUTHORITY_CEILING"
    OWNER_HUMAN_LABEL_PRESENCE = "OWNER_HUMAN_LABEL_PRESENCE"
    PREFLIGHT_PERMISSION = "PREFLIGHT_PERMISSION"
    LIVENESS_FACTS = "LIVENESS_FACTS"


class AuthorizationDisposition(StrEnum):
    """Liveness-relevant facts about an authorization instance (AP-03 §4.1).

    A disposition is a statement about **governing capacity, not existence**: the
    instance persists under every one of these, and every historical reference to it
    stays valid (`AP03-I35`). There is deliberately **no `SUPERSEDED`** member —
    supersession is expressed only by explicit revocation or binding change, never
    inferred from recency or arrival order (`AP03-I05`).

    The transition graph, ordering and terminality over these values are AP-04's and
    are not modelled here.
    """

    LIVE = "LIVE"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"
    SUSPENDED = "SUSPENDED"


class BoundedPreflightPermission(StrEnum):
    """`RA-09`: whether root resolution and the one read-only entry observation are
    permitted (AP-03 §4.1). A permission value, nothing finer — AP-03 gives it no
    internal structure and none is invented."""

    PERMITTED = "PERMITTED"
    NOT_PERMITTED = "NOT_PERMITTED"


class RootResolutionOutcome(StrEnum):
    """The only outcomes AP-03 §4.5 admits.

    Determined **solely by the eligible candidates remaining after exclusion**. The
    existence of an excluded invalid candidate is neither an outcome nor a halt, and
    exclusion never manufactures a resolution (`AP03-I06`). The resolution *procedure*
    is not implemented at this stage; only its recordable outcome is named.
    """

    AUTHORIZATION_MISSING = "AUTHORIZATION_MISSING"
    RESOLVED_ROOT = "RESOLVED_ROOT"
    AMBIGUITY_DISTINCT_MULTIPLICITY = "AMBIGUITY_DISTINCT_MULTIPLICITY"
    AMBIGUITY_SAME_IDENTITY_CONFLICT = "AMBIGUITY_SAME_IDENTITY_CONFLICT"


class AmbiguityForm(StrEnum):
    """The two forms of one entity (AP-03 §2.2, §4.5, §12).

    Kept as forms of a single `AuthorityAmbiguity` rather than two entities because
    AP-02 gives them one V-number; kept distinct from a Refusal for *missing*
    authority because zero eligible is a different fact from competing authority.
    """

    DISTINCT_MULTIPLICITY = "DISTINCT_MULTIPLICITY"
    SAME_IDENTITY_CONFLICT = "SAME_IDENTITY_CONFLICT"


class GovernanceCase(StrEnum):
    """Case A and Case B never collapse (AP-03 §12, `AP03-I28`).

    `CASE_A` — the effect **did not occur**; refusal and prevention coincide.
    `CASE_B` — the effect **already exists** and was **not** prevented.

    Describing a refusal as a detection understates, and the reverse overstates.
    """

    CASE_A = "CASE_A"
    CASE_B = "CASE_B"


class WriteMode(StrEnum):
    """Bounds dimension: read-only vs writing (AP-03 §4.8; `E-13`)."""

    READ_ONLY = "READ_ONLY"
    WRITING = "WRITING"


class ExternalActionClass(StrEnum):
    """Bounds dimension: the external / network classes AP-03 §4.8 names (`E-16`).

    Exactly four members: the three AP-03 §4.8 names — egress, install, external
    mutation — and `BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA` (AP-06 `XA-1`…`XA-9`,
    correction `ST06PC-1`). A bounds value naming one asserts that the class is
    **authorized**, never that anything is prevented (AP-03 §12, `P-14`).

    The fourth names `XA-1`'s per-activation area, inside `E-10` and strictly outside
    the governed repository boundary, toward which verification-execution side effects
    may be directed. It is declarable, never ambient (`XA-2`): present in a ceiling
    member only if the OWNER placed it in `RA-07` (`XA-3`, `AP06-I18`), and copied
    into an envelope, never added. **It grants nothing by existing.** It is not
    repository write authority (`XA-9`; `E-12` is unchanged), not network, install or
    external mutation, and not uncontrolled external mutation — one bounded,
    per-activation, never-shared area (`XA-4`). It is not a sandbox, confinement or
    exemption (`XA-1`, `XA-6`, `XA-7`), so residual in-repository by-products stay
    violations, and it widens none of `E-10`…`E-13`.

    **Where the prohibition of the other three lives.** A ceiling member and
    `AuthorityBounds` both admit all four values structurally; no validator refuses
    one. A ceiling member carrying `EGRESS`, `INSTALL` or `EXTERNAL_MUTATION` is
    `RA-07`-invalid, evaluated by `GP-AUTO-ST-06` (S6G2-2(g)); an envelope cannot carry
    one, because derivation copies only a valid member and `C1` re-validates it.
    """

    EGRESS = "EGRESS"
    INSTALL = "INSTALL"
    EXTERNAL_MUTATION = "EXTERNAL_MUTATION"
    BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA = "BOUNDED_NON_PROJECT_SIDE_EFFECT_AREA"


class GitActionClass(StrEnum):
    """The **observable** Git action vocabulary (AP-03 §4.8.1).

    Complete by design, so that any observed act is recordable regardless of whether
    it could ever have been authorized. Used by `EnvelopeViolation`,
    `UnaccountedMutation` and `Refusal`. **It is not a grantable value space** —
    conflating the two in either direction changes a frozen boundary (`DM-07`,
    `AP03-I16`).

    `HISTORY_MUTATION` is one class covering reset, rebase, branch manipulation,
    force-update and checkout, exactly as AP-03 §4.8.1 groups them.
    """

    READ_STATUS = "READ_STATUS"
    READ_DIFF = "READ_DIFF"
    READ_LOG = "READ_LOG"
    READ_SHOW = "READ_SHOW"
    READ_REV_PARSE = "READ_REV_PARSE"
    STAGING = "STAGING"
    COMMIT = "COMMIT"
    TAG = "TAG"
    PUSH = "PUSH"
    HISTORY_MUTATION = "HISTORY_MUTATION"


class GitGrantabilityTier(StrEnum):
    """Grantability is a property of an action class, **not** a value any bounds may
    carry (AP-03 §4.8.1, `AP03-I16`).

    The middle tier is retained deliberately. Collapsing `CURRENTLY_NON_GRANTABLE_
    RESERVED` into `PERMANENTLY_NON_GRANTABLE` would decide, against AP-01 and AP-02,
    that a scope change the OWNER reserved could never be expressed. Retaining it
    grants nothing: staging and commit remain outside today's grantable space, and
    the representation of any future change is AP-09's.
    """

    CURRENTLY_GRANTABLE = "CURRENTLY_GRANTABLE"
    CURRENTLY_NON_GRANTABLE_RESERVED = "CURRENTLY_NON_GRANTABLE_RESERVED"
    PERMANENTLY_NON_GRANTABLE = "PERMANENTLY_NON_GRANTABLE"


class GitCapabilityClass(StrEnum):
    """Today's **grantable** Git value space, and all of it (AP-03 §4.8.1).

    *"Today's grantable Git value space is therefore: none, or bounded read."* This
    enumeration is the whole of the Git dimension's admissible values, so a bounds
    value carrying staging, commit, tag, push or history mutation is not expressible
    at all rather than merely refused.
    """

    NONE = "NONE"
    BOUNDED_READ = "BOUNDED_READ"


class Provenance(StrEnum):
    """The provenance of one `ArtifactProduction` occurrence (AP-03 §8.1).

    Exactly two values, and there is deliberately **no third** for forbidden-transfer
    material: AP-03 §8.3 gives hidden reasoning and copied conclusions no entity, no
    container, no provenance value and no referent kind, because a domain container
    for material the architecture depends on never holding would build the vessel
    whose absence is the control (`AP03-I20`).

    Provenance does not mix: a production containing any worker-authored material is
    `WORKER_AUTHORED`, whatever else it quotes.
    """

    OBJECTIVE = "OBJECTIVE"
    WORKER_AUTHORED = "WORKER_AUTHORED"


class StageContractPart(StrEnum):
    """The named parts a `StageContract` carries under one identity (AP-03 §2.1).

    Enumerated because a reference to *"a named part of the contract"* (AP-03 §8.2)
    has to name **which** part, and an arbitrary string there would leave the referent
    unbound to anything — which is the shape a typed reference exists to remove. The
    six are AP-03's own list and are not extended here.

    They are parts, not entities: AP-03 §18.1 merged acceptance criteria,
    implementation instructions and review instructions into `StageContract` under one
    content identity, because `RA-03` is a single binding and a change to any part is a
    scope change invalidating identically.
    """

    OBJECTIVE = "OBJECTIVE"
    DELIVERABLE_BOUNDARY = "DELIVERABLE_BOUNDARY"
    EXPLICIT_OUT_OF_STAGE = "EXPLICIT_OUT_OF_STAGE"
    IMPLEMENTATION_INSTRUCTIONS = "IMPLEMENTATION_INSTRUCTIONS"
    REVIEW_INSTRUCTIONS = "REVIEW_INSTRUCTIONS"
    ACCEPTANCE_CRITERIA = "ACCEPTANCE_CRITERIA"


class GovernedFactKind(StrEnum):
    """The governed domain facts admissible as authoritative basis (AP-03 §8.2).

    Closed at the referents AP-03 enumerates. AP-03's trailing *"or another
    structurally authoritative domain record"* is **not** rendered as an open escape
    member: an open vocabulary here would let a later reader admit a basis AP-03 never
    named, which is the widening `TR11-7` and `AP-00 §4.3` forbid.

    **This enumeration names kinds; it does not carry referents.** Each kind's
    permitted referent identity type is fixed by its own reference variant in
    `activation.py`, so a kind cannot be paired with an identity belonging to another
    kind. The vocabulary and the referent are two facts, and neither stands in for the
    other.
    """

    STAGE_CONTRACT = "STAGE_CONTRACT"
    STAGE_CONTRACT_PART = "STAGE_CONTRACT_PART"
    ACCEPTANCE_CRITERIA = "ACCEPTANCE_CRITERIA"
    BASELINE_IDENTITY = "BASELINE_IDENTITY"
    ENTRY_STATE_BOUNDARY = "ENTRY_STATE_BOUNDARY"
    FROZEN_FINDING_SET = "FROZEN_FINDING_SET"
    REMEDIATION_OBLIGATION = "REMEDIATION_OBLIGATION"
    ACTIVATION_EFFECT = "ACTIVATION_EFFECT"


class OwnerDecisionKind(StrEnum):
    """The OWNER acts AP-03 §11.2 classifies.

    Kinds of one `OwnerDecision` type. `STAGE_OUTCOME` is a kind here and
    **not** a separate entity, because the distinction that must be structural is
    acceptance vs *authorization* — and that is carried by `OwnerDecision` and
    `OwnerAuthorization` being two types, never joined by subtyping (`AP03-I25`).
    """

    STAGE_ENTRY_AUTHORIZATION = "STAGE_ENTRY_AUTHORIZATION"
    NEXT_STAGE_AUTHORIZATION = "NEXT_STAGE_AUTHORIZATION"
    SCOPE_CHANGE = "SCOPE_CHANGE"
    AUTHORITY_EXPANSION = "AUTHORITY_EXPANSION"
    FINDING_DISPUTE = "FINDING_DISPUTE"
    WAIVER = "WAIVER"
    DEFERRAL = "DEFERRAL"
    OBLIGATION_CHANGE = "OBLIGATION_CHANGE"
    EXCEPTIONAL_RECOVERY = "EXCEPTIONAL_RECOVERY"
    STAGE_OUTCOME = "STAGE_OUTCOME"
    REFUSAL_RESOLUTION = "REFUSAL_RESOLUTION"
    REVOCATION = "REVOCATION"


class StageOutcomeDisposition(StrEnum):
    """The recorded terminal disposition of a GovernedStage (AP-03 §13).

    Gate arrival is **not** one of these, and none of them is authored by a worker,
    a coordinator or a persistence mechanism (`AP03-I34`).
    """

    ACCEPTED = "ACCEPTED"
    REFUSED = "REFUSED"
    ABANDONED = "ABANDONED"
    ACCEPT_PARTIAL = "ACCEPT_PARTIAL"
