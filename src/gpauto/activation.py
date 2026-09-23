"""The activation domain: one bounded run, its basis, and its audit annotation.

Design basis: AP-03 §2.3 (`WorkerActivation`, `ProviderAssignment`, `InputPackage`),
§3.1 row 3, §6 (activation domain), §8.2 (authoritative review input), §8.4 (`EA-1`),
§14 (role/provider), §16.3; `AP03-I17`, `AP03-I19`, `AP03-I20`; AP-11 §7 (`NV11-6`).

A `WorkerActivation` is an **occurrence, not an authority**: it holds none and confers
none on its outputs. Its identity is distinct from its envelope's, which is what makes
three facts expressible — an envelope derived but never activated (correct on a
refusal), an attempted second activation on a consumed identity, and effect
attribution, which is per activation.

**Provider is an annotation and nothing more.** *DISCOVERY REVIEWER → some vendor* is
an assignment, not a grant. It appears here, on the activation, and nowhere else — not
in an envelope, not in a bounds value, not in an authorization, and nowhere on the
path from root to authority (`AP03-I17`, `NV11-6`). **The domain provides no relation
between activations sharing a provider and none between activations sharing a
session**, so role inheritance, standing transfer and *"the same agent already checked
this"* are inexpressible rather than merely discouraged. That two activations of one
provider are independent judges is an explicit non-guarantee (`T-12`) and is not
claimed here.

**Admissibility is closed at its domain, not checked at a flag** (`EA-1`). An
`AuthoritativeInputReference` is either a reference to an **objective**
`ArtifactProduction` or a reference to a governed domain fact.

For the first: the reference names the production **occurrence**, whose provenance is
fixed at that occurrence and immutable. Naming an opaque production identity and
writing `OBJECTIVE` beside it would exclude nothing — the annotation would be an
independent assertion about a referent that does not carry it, and a worker-authored
production could be named with the annotation simply written next to it. AP-03 §18.4
is explicit that what excludes worker-authored provenance is **passing the
admissibility relation**, so the relation's domain is typed
`ObjectiveArtifactProduction`: a worker-authored production is refused on construction
and on the JSON path alike, as an unconstructible value rather than a rejected one
(`VP11-4`, `EA-1`).

That keeps §8.2's three guarantees exactly: the referent keeps its own identity
(`production.identity`), it keeps its own standing (its provenance travels with it and
no operation here can change it), and **nothing is re-provenanced** — which the earlier
shape did, by asserting a provenance the reference had no way to establish.

For the second: each governed fact kind has its own reference variant carrying its own
**typed** referent identity, so a fact kind cannot be paired with an identity belonging
to another kind. AP-03 §8.2 enumerates which domain facts are admissible as basis; an
arbitrary string referent would have admitted any of them under any kind's name, which
is not a reference to a governed fact but a label beside an unbound value.

**Why the governed-fact form is necessary.** AP-01 §8.1's reviewer bases include the
`EntryStateBoundary`, which is coordinator-observed *before the first worker activation
exists*, and the `FrozenFindingSet`, which is a governance fact rather than an
objective-test output. Requiring every authoritative input to originate from a worker
activation would make both inadmissible, and the reviewer bases the frozen set fixes
could not be stated.

**A reference copies nothing and re-provenances nothing.** The referent keeps its own
identity and standing; the reference records only that this package offers it to this
role as basis (AP-03 §8.2). That is why it is modelled as a reference relation rather
than a container — and why no container exists anywhere here for forbidden-transfer
material, whose containment rests on not supplying and on placement rather than on
detection (`AP03-I20`).

Process start, session construction, isolation enforcement, adapters, capture,
parsing, timeouts and exit codes are AP-06's; failure classification and recovery are
AP-08's. None is here.
"""

from __future__ import annotations

from typing import Final, Literal

from gpauto.absence import Perhaps
from gpauto.evidence import ObjectiveArtifactProduction
from gpauto.identity import (
    ActivationEffectId,
    AuthorityEnvelopeId,
    BaselineIdentityId,
    EntryStateBoundaryId,
    FrozenFindingSetId,
    InputPackageId,
    RemediationObligationId,
    StageContractId,
    WorkerActivationId,
)
from gpauto.schema import DomainEntity, DomainValue
from gpauto.vocabulary import GovernedFactKind, Role, StageContractPart


class ProviderAssignment(DomainValue):
    """An audit fact: which vendor session ran one activation (AP-03 §2.3, §14).

    **Zero authority.** Provider identity confers nothing and vouches for nothing
    (`T-08`). The reference is referenced and never interpreted.
    """

    provider_reference: str


class ObjectiveProductionReference(DomainValue):
    """A reference to an `ArtifactProduction` of **objective** provenance (AP-03 §8.3).

    The referent is the production occurrence itself, because that is the only thing
    that carries the provenance. It carries no provenance field of its own: there is
    nothing here to assert, and therefore nothing to assert wrongly.
    """

    production: ObjectiveArtifactProduction


class StageContractReference(DomainValue):
    """The stage contract as a whole (AP-03 §8.2)."""

    fact_kind: Literal[GovernedFactKind.STAGE_CONTRACT] = GovernedFactKind.STAGE_CONTRACT
    contract: StageContractId


class StageContractPartReference(DomainValue):
    """A **named part** of the stage contract (AP-03 §8.2, §2.1).

    Carries the contract identity and which part, because the parts live under one
    content identity and a part is not separately identified (AP-03 §18.1).
    """

    fact_kind: Literal[GovernedFactKind.STAGE_CONTRACT_PART] = (
        GovernedFactKind.STAGE_CONTRACT_PART
    )
    contract: StageContractId
    part: StageContractPart


class AcceptanceCriteriaReference(DomainValue):
    """The acceptance criteria, which AP-03 §8.2 names in its own right.

    Kept as its own kind rather than folded into the part reference because AP-01 §8.1
    names it separately among the reviewer's bases; the referent is still the contract
    identity, since the criteria are a part under it and have no identity of their own.
    """

    fact_kind: Literal[GovernedFactKind.ACCEPTANCE_CRITERIA] = (
        GovernedFactKind.ACCEPTANCE_CRITERIA
    )
    contract: StageContractId


class BaselineIdentityReference(DomainValue):
    """The committed baseline the authorization is bound to (AP-03 §8.2)."""

    fact_kind: Literal[GovernedFactKind.BASELINE_IDENTITY] = GovernedFactKind.BASELINE_IDENTITY
    baseline: BaselineIdentityId


class EntryStateBoundaryReference(DomainValue):
    """The fixed entry observation (AP-03 §8.2).

    One of the two referents that make the governed-fact form necessary at all: it is
    coordinator-observed *before the first worker activation exists*, so it is the
    production of no activation.
    """

    fact_kind: Literal[GovernedFactKind.ENTRY_STATE_BOUNDARY] = (
        GovernedFactKind.ENTRY_STATE_BOUNDARY
    )
    entry_boundary: EntryStateBoundaryId


class FrozenFindingSetReference(DomainValue):
    """The frozen finding set (AP-03 §8.2).

    The other such referent: a governance fact rather than an objective-test output,
    and the basis `E-14` requires the closure verifier to have.
    """

    fact_kind: Literal[GovernedFactKind.FROZEN_FINDING_SET] = GovernedFactKind.FROZEN_FINDING_SET
    frozen_set: FrozenFindingSetId


class RemediationObligationReference(DomainValue):
    """One remediation obligation (AP-03 §8.2)."""

    fact_kind: Literal[GovernedFactKind.REMEDIATION_OBLIGATION] = (
        GovernedFactKind.REMEDIATION_OBLIGATION
    )
    obligation: RemediationObligationId


class ActivationEffectReference(DomainValue):
    """One recorded activation effect (AP-03 §8.2)."""

    fact_kind: Literal[GovernedFactKind.ACTIVATION_EFFECT] = GovernedFactKind.ACTIVATION_EFFECT
    effect: ActivationEffectId


type GovernedFactReference = (
    StageContractReference
    | StageContractPartReference
    | AcceptanceCriteriaReference
    | BaselineIdentityReference
    | EntryStateBoundaryReference
    | FrozenFindingSetReference
    | RemediationObligationReference
    | ActivationEffectReference
)
"""A reference to a governed domain fact admissible as basis (AP-03 §8.2).

One variant per `GovernedFactKind`, each binding its kind to the one referent identity
type AP-03 permits for it. The kind is pinned by a `Literal`, so a variant cannot be
relabelled, and the referent is typed, so a kind cannot be paired with another kind's
identity. Neither fact stands in for the other.
"""


GOVERNED_FACT_VARIANTS: Final[tuple[type[DomainValue], ...]] = (
    StageContractReference,
    StageContractPartReference,
    AcceptanceCriteriaReference,
    BaselineIdentityReference,
    EntryStateBoundaryReference,
    FrozenFindingSetReference,
    RemediationObligationReference,
    ActivationEffectReference,
)
"""The variants of `GovernedFactReference`, enumerated so the union is checkable.

A union is not introspectable as a list of its members without unwrapping the alias,
and the property that matters — one variant per `GovernedFactKind`, each with its own
typed referent — is one a test should be able to state directly.
"""


type AuthoritativeInputReference = ObjectiveProductionReference | GovernedFactReference
"""Admissible **as basis** for the receiving role (AP-03 §8.2, `E-20`)."""


class InputPackage(DomainEntity):
    """The bounded context for one activation (AP-03 §2.3, §6).

    `authoritative_inputs` is what this package offers the receiving role as basis;
    `non_basis_context` is other material the envelope's read boundary permits, which
    is supplied context and never basis. The worker never fetches its own basis.
    """

    identity: InputPackageId
    authoritative_inputs: tuple[AuthoritativeInputReference, ...]
    non_basis_context: tuple[str, ...]


class WorkerActivation(DomainEntity):
    """One bounded run of one role under one envelope (AP-03 §6).

    `role` must equal the envelope's role; a mismatch is a Refusal, never a
    substitution (`V-05`). Checking that equality is `GP-AUTO-ST-06`'s — the field
    exists here so the fact is recorded, not so it is evaluated.

    `completed` exists because AP-03 §6 requires *completed* to be distinguishable
    from *not completed*: only a completed **authorized** activation's effects enter
    the expected current authorized state. The activation **state set, the transitions,
    and what makes an activation complete are AP-04's** and are not modelled here; this
    is the distinguishability §6 asks for and nothing more.

    Produced artifacts and observed effects are attributed *from* the production and
    effect side, so the relation is recorded once rather than in two places that could
    disagree.
    """

    identity: WorkerActivationId
    envelope: AuthorityEnvelopeId
    role: Role
    input_package: InputPackageId
    provider: Perhaps[ProviderAssignment]
    completed: bool
