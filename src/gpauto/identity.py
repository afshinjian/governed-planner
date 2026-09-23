"""AP-03's identity kinds, one type per identified thing, none interchangeable.

Design basis: AP-03 §3 (identity model), §3.1 (the seven identity confusions),
§2.1–§2.7 (which things are identified); `AP03-I03`, `AP03-I12`, `AP03-I33`,
`AP03-I35`, `AP03-I36`.

**Why one type per identity and not one `str`.** AP-03 §3.1 resolves seven
confusions, and each is a claim that two identities must not be substitutable for
one another. A shared string type would make every one of them a naming convention
enforced by care, and care is not a structure. Here each identity is its own frozen
model: a `GovernedStageId` where a `StageContractId` is annotated is refused by
strict validation with `model_type`, not accepted and misread.

**The kind is data, not a superclass relation.** `IDENTITY_KINDS` records which of
AP-03 §3's four kinds an identity may be, while the *sibling* relation between
concrete identities is what carries non-interchangeability. That split matters:
pydantic's strict mode accepts any subclass where a base is annotated, so if
`ProjectId` were a subtype of something a field could be annotated with, the
substitution would re-open. The intermediate bases here exist only to attach a kind,
are never annotated on any field, and `tests_gpauto` asserts that structurally.

**No identity is derived here, content identities included.** `StageContractId` and
`ArtifactContentId` are content-identified — *different content is necessarily a
different identity* — but the mechanism that determines the value from content is
canonicalization and digest, which `GP-AUTO-ST-02` owns under AP-07. This module
represents the identity; it computes none, and a generator, parser, uniqueness check
or comparison algorithm would be a capability AP-03 §4.2 and §4.4 expressly do not
design.

**What "supplied" and "non-content-derived" do not mean** (AP-03 §3, `T-13`…`T-17`):
no authentication, no cryptographic assignment or attestation, no trusted-infrastructure
origin, no global uniqueness, no provable ordering, no freshness, no tamper-evidence,
no non-repudiation. The property is narrow and structural — stable, opaque,
per-instance, and independent of the authority-bearing content it names.
"""

from __future__ import annotations

from typing import ClassVar

from gpauto.schema import DomainValue
from gpauto.vocabulary import IdentityKind


class DomainIdentity(DomainValue):
    """Root of every identity type. Never annotate a field with it, or with any of the
    four kind bases below — doing so restores the substitutability this module closes."""

    IDENTITY_KINDS: ClassVar[tuple[IdentityKind, ...]]


class OpaqueIdentity(DomainIdentity):
    """An identity whose whole content is one opaque, stable token.

    `value` is referenced and never interpreted: AP-03 §4.2 designs no syntax, no
    grammar, no generator and no uniqueness mechanism, and asserts none of the
    properties §3's non-implication block excludes.
    """

    value: str


class SuppliedIdentity(OpaqueIdentity):
    """Supplied *with* the thing by whoever authored or asserted it (AP-03 §3)."""

    IDENTITY_KINDS = (IdentityKind.SUPPLIED,)


class MintedIdentity(OpaqueIdentity):
    """Created by GP-AUTO once per occurrence and never recomputed (AP-03 §3)."""

    IDENTITY_KINDS = (IdentityKind.MINTED,)


class ContentIdentity(OpaqueIdentity):
    """Determined by the content it denotes (AP-03 §3).

    The determination is `GP-AUTO-ST-02`'s under AP-07; nothing here computes it.
    """

    IDENTITY_KINDS = (IdentityKind.CONTENT,)


class DependentIdentity(DomainIdentity):
    """Identified only relative to a named parent (AP-03 §3).

    Subclasses declare the parent references *as typed fields*, so the dependency is
    structural: a dependent identity cannot be built without naming its parent, and
    it cannot name a parent of the wrong kind.
    """

    IDENTITY_KINDS = (IdentityKind.DEPENDENT,)


# --- Supplied ------------------------------------------------------------------


class ProjectId(SuppliedIdentity):
    """Never the RepositoryBoundary and never the checkout directory (AP-03 §3.1 row 5)."""


class GovernedStageId(SuppliedIdentity):
    """Never the StageContract, never the OwnerAuthorization, and never a GP-SPK-001
    `SCOPE_*` state (`F9`, `AP03-I32`)."""


class RepositoryBoundaryId(SuppliedIdentity):
    """Never the Project, never the BaselineIdentity, never the working tree."""


class BaselineIdentityId(SuppliedIdentity):
    """VCS-asserted and resting on a trusted assumption (`T-05`), not on verification
    performed here. Never the EntryStateBoundary and never *"HEAD now"*."""


class OwnerAuthorizationId(SuppliedIdentity):
    """`RA-00`. **Deliberately not content-derived** (AP-03 §3.1 row 1, `AP03-I03`).

    A content-derived identity would make *"same identity, conflicting content"*
    impossible by construction — and AP-02 requires that case to be representable and
    halting. A model that cannot express the conflict has silently resolved it.
    """


class OwnerDecisionId(SuppliedIdentity):
    """OWNER-asserted. Never the OwnerAuthorization it may produce (`AP03-I25`)."""


# --- Supplied or minted --------------------------------------------------------


class AuthorizationRecordId(OpaqueIdentity):
    """One visible assertion of an authorization; minted or supplied per assertion.

    Never the OwnerAuthorization identity it purports to express, and **never an
    authority source**: authority is borne by the constituted instance, and no
    envelope, refusal, evidence or effect record names a record identity as its root
    (`AP03-I33`).
    """

    IDENTITY_KINDS = (IdentityKind.MINTED, IdentityKind.SUPPLIED)


# --- Content -------------------------------------------------------------------


class StageContractId(ContentIdentity):
    """Changed content **is** a different identity (AP-03 §3.1 row 4).

    Not the GovernedStage: one contract identity may serve several stages, and one
    stage may reference different contract identities across authorization epochs.
    """


class ArtifactContentId(ContentIdentity):
    """The bytes, and nothing else (AP-03 §8.1).

    Any alteration is different content, so a verdict cannot cite content that later
    changed under it. It carries **no provenance and no standing** — those attach to
    an `ArtifactProduction` occurrence, never here (`AP03-I19`).
    """


# --- Minted --------------------------------------------------------------------


class EntryStateBoundaryId(MintedIdentity):
    """One observation occurrence, fixed at observation and never moved (`AP03-I08`)."""


class RootResolutionId(MintedIdentity):
    """An eligibility verdict occurrence. Never an OwnerAuthorization and never a Refusal."""


class AuthorityEnvelopeId(MintedIdentity):
    """**Minted, never content** (AP-03 §3.1 row 2, `AP03-I12`).

    Content identity over bounds would collapse a later derivation with *equivalent*
    bounds onto the consumed identity — it would **be** the revival the frozen set
    forbids. Two envelopes with identical bounds are two envelopes.
    """


class WorkerActivationId(MintedIdentity):
    """One bounded run. Distinct from the envelope's identity (AP-03 §3.1 row 3), so
    that *"envelope derived, never activated"* and an attempted second activation on a
    consumed identity are both expressible."""


class InputPackageId(MintedIdentity):
    """Never the read boundary, never the artifacts it references."""


class ArtifactProductionId(MintedIdentity):
    """One production or capture occurrence. Never the content it binds, and never
    another production of identical content (`AP03-I19`)."""


class FindingId(MintedIdentity):
    """Not content-derived: textually identical defects are two findings, and identity
    does not change when annotations do (AP-03 §9)."""


class FrozenFindingSetId(MintedIdentity):
    """Minted and **not derived from its members** (AP-03 §3.1 row 6).

    A membership-derived identity would make every zero-finding set in the system one
    identity, collapsing *"stage A froze empty"* into *"stage B froze empty"*.
    Membership is a property of the set, not its name.
    """


class PostFreezeCandidateId(MintedIdentity):
    """Never a Finding and never a frozen-set member (`AP03-I21`)."""


class RefusalId(MintedIdentity):
    """Case A. Never an EnvelopeViolation (`AP03-I28`)."""


class EnvelopeViolationId(MintedIdentity):
    """Case B. Never a Refusal and never a Finding (`AP03-I28`, `GE-3`)."""


class AuthorityAmbiguityId(MintedIdentity):
    """Arises **before any envelope exists**, which is the structural reason it cannot
    be a kind of EnvelopeViolation (AP-03 §4.7)."""


class UnaccountedMutationId(MintedIdentity):
    """Never the expected stage delta and never pre-existing entry state (`AP03-I11`)."""


# --- Dependent -----------------------------------------------------------------


class CandidateExclusionId(DependentIdentity):
    """`RootResolution` × record (AP-03 §3).

    Exclusions from different resolution attempts must stay attributable, which is
    why the parent resolution is part of the identity rather than a mere field.
    """

    parent_resolution: RootResolutionId
    excluded_record: AuthorizationRecordId


class ActivationEffectId(DependentIdentity):
    """`WorkerActivation` × a local discriminator (AP-03 §3).

    `local_discriminator` is opaque and carries **no ordering**: AP-03 designs no
    ordering anywhere, and an effect index that read as a sequence would be one.
    """

    parent_activation: WorkerActivationId
    local_discriminator: str


class RemediationObligationId(DependentIdentity):
    """`FrozenFindingSet` × `Finding` (AP-03 §3).

    The pair is the whole identity, which is what keeps obligation addressable
    *separately from* membership — so a waiver can extinguish an obligation while the
    frozen set stays byte-for-byte what it was (`AP03-I23`).
    """

    parent_frozen_set: FrozenFindingSetId
    member_finding: FindingId


class ClosureAssessmentId(DependentIdentity):
    """`Finding` × closure `WorkerActivation` (AP-03 §3).

    Closure is per finding, so *"three of five verified"* is statable (`AP03-I24`).
    """

    assessed_finding: FindingId
    closure_activation: WorkerActivationId


class StageOutcomeId(DependentIdentity):
    """Dependent on `GovernedStage` (AP-03 §3).

    Never the OwnerDecision that establishes it, and never gate arrival (`AP03-I31`).
    """

    parent_stage: GovernedStageId
