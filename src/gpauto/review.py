"""Findings, the frozen set, obligations and closure — concepts only, no lifecycle.

Design basis: AP-03 §2.6 (review / finding entities), §3.1 row 6, §9 (finding
domain), §10.1 (identity and membership), §10.2, §10.3 (`FS-1`…`FS-6`), §16.5;
`AP03-I21`…`AP03-I24`, `AP03-I36`.

AP-03 §9 is explicit that only the concepts AP-05 will need belong here: **no
lifecycle, no transitions, no freeze mechanics, no closure rules.** Obligation states,
discharge criteria, verdict vocabulary, dispute/waiver/deferral routing and the
only-shrink rule are all AP-05's, and none of them is modelled.

**Sole discovery origination, made structural.** A `Finding` originates only from a
pre-freeze DISCOVERY REVIEWER activation (`MA-08`). `originating_role` is a
`Literal[Role.DISCOVERY_REVIEWER]`, so a finding originating from any other role is
not a refused value but an unconstructible one (`VP11-4`, `AP03-I21`). Everything else
in this module follows from that one constraint: because a post-freeze observation
cannot be a `Finding` whatever it is labelled, `PostFreezeCandidate` needs its own
identity so an OWNER disposition has a referent — and because membership's domain is
`Finding`, a candidate can never enter a frozen set.

**Set identity is not derived from membership** (AP-03 §3.1 row 6). A
membership-derived identity would make every zero-finding set in the system share one
identity, collapsing *"stage A froze empty"* into *"stage B froze empty"*. Membership
is a property of the set, not its name.

**`no set exists` ≠ `an empty set exists`.** A zero-finding PASS produces a **real,
empty** set — a first-class, fully-identified object. A discovery activation that is
still running, fails structurally, returns malformed output or halts on a refusal
produces **no set at all** (`AP03-I36`). The asymmetry is load-bearing: a model
requiring one set per discovery activation would have to manufacture a set for a
crashed reviewer, and since an empty set is the zero-finding PASS, that manufactured
set would read as *"discovery passed with no findings"*. The three-valued absence in
`absence.py` is what keeps *not yet observed*, *established absent* and *present and
empty* three different facts here.

**Immutability after freeze is the absence of an operation.** The domain provides no
add, remove or reclassify for a frozen set's membership, and `frozen=True` means the
structure offers none either. A change to a frozen set is not a modelled act: AP-02
makes it OWNER-reserved and makes it invalidate derived remediation envelopes rather
than edit the set. The freeze act, its point and its structural irreversibility are
AP-05's.

**Obligation is distinct from membership** (`AP03-I23`). An OWNER waiver or deferral
can extinguish an obligation while membership — the historical record of what
discovery froze — stays intact. If obligation were membership, a waiver could only be
recorded by mutating the frozen set. Obligation state is never evidence that
membership changed, and no operation here could make it so.
"""

from __future__ import annotations

from typing import Literal

from gpauto.identity import (
    ClosureAssessmentId,
    FindingId,
    FrozenFindingSetId,
    GovernedStageId,
    OwnerAuthorizationId,
    PostFreezeCandidateId,
    RemediationObligationId,
    WorkerActivationId,
)
from gpauto.schema import DomainEntity
from gpauto.vocabulary import Role


class Finding(DomainEntity):
    """A governed pre-freeze stage finding (AP-03 §2.6, §9).

    Binds to one `GovernedStage` **and** to the resolved root authorization under
    which it was originated, which is what keeps findings from different authorization
    epochs of one stage separable without a separate stage-occurrence entity.

    Identity is minted and not content-derived: textually identical defects are two
    findings, and identity does not change when annotations do.
    """

    identity: FindingId
    stage: GovernedStageId
    originating_authorization: OwnerAuthorizationId
    originating_activation: WorkerActivationId
    originating_role: Literal[Role.DISCOVERY_REVIEWER] = Role.DISCOVERY_REVIEWER


class FrozenFindingSet(DomainEntity):
    """What one discovery review froze (AP-03 §10.1).

    `members` may be empty, and an empty set is a first-class object — the zero-finding
    PASS. It is not the same fact as no set existing, which is represented by there
    being no `FrozenFindingSet` at all.

    `members` is typed `tuple[FindingId, ...]`, which is the whole of `AP03-I21`'s
    membership guarantee: a `PostFreezeCandidateId` or an `OwnerDecisionId` is not a
    refused member, it is an unexpressible one. A governance event is not a defect in
    the work, and none may enter a set (`GE-3`).
    """

    identity: FrozenFindingSetId
    stage: GovernedStageId
    resolved_root: OwnerAuthorizationId
    originating_activation: WorkerActivationId
    members: tuple[FindingId, ...]


class RemediationObligation(DomainEntity):
    """The obligation the freeze creates, per member (AP-03 §10.3).

    Addressable in its own right, because an OWNER waiver or deferral must be able to
    extinguish it while the frozen set stays byte-for-byte what it was (`FS-2`,
    `FS-5`). Empty membership yields no obligations, with nothing invented.

    Obligation states and discharge criteria are AP-05's; this asserts only that the
    obligation exists, is addressable, and is separable from membership.
    """

    identity: RemediationObligationId


class ClosureAssessment(DomainEntity):
    """One finding × one closure activation (AP-03 §2.6, §10.2).

    Closure is assessed **per member**, so *"three of five verified"* is statable and
    closure scope has membership. The **verdict vocabulary is AP-05's** and is
    deliberately not invented here: a verdict field with a made-up value space would be
    a vocabulary AP-03 does not have, and a later phase would inherit it as though it
    were frozen.
    """

    identity: ClosureAssessmentId


class PostFreezeCandidate(DomainEntity):
    """A post-freeze observation, given identity so an OWNER disposition has a referent.

    Not an independent stipulation: it **follows** from the `Finding` origination
    constraint. Because a finding originates only from a pre-freeze DISCOVERY REVIEWER
    activation, a post-freeze observation cannot be one whatever it is called. Without
    this entity, *"a defect was raised for OWNER disposition"* would be
    indistinguishable from *"a worker wrote commentary"*.

    A classification flag on `Finding` would be strictly weaker — membership exclusion
    would become an attribute check at insertion rather than a domain fact.
    """

    identity: PostFreezeCandidateId
    stage: GovernedStageId
    observing_activation: WorkerActivationId
