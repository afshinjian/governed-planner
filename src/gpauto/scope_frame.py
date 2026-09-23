"""The scope-frame entities: what a stage is *about* (AP-03 §2.1, §16.1).

Design basis: AP-03 §2.1 (scope-frame entities), §3 (identity kinds), §3.1 rows 4
and 5, §16.1 (scope-frame relationships); `AP03-I02`, `AP03-I32`.

Five entities, and each exists because a specific question loses its referent
without it: *which project*, *which stage*, *what was in scope*, *which repository
and branch*, *which committed baseline*. AP-01 requires expressly that baseline
identity and stage delta be distinct modelled concepts rather than one
*"repository state"* blob, which is why `BaselineIdentity` is here and the entry
observation is not (that is `repository.py`'s).

**A stage does not own its repository, baseline or contract.** AP-03 §16.1 is
explicit: those are *named by the authorization*, so `GovernedStage` carries only
its project. The stage's "current" contract is a **reading of its governing
authorization's `RA-03`**, never a stage-level mutable pointer — which is what keeps
a scope change from looking like a stage change, and keeps historical bindings
intact when a later scope change gives the same stage a different contract identity.

**`StageContract` is content-identified, and its parts live under one identity.**
AP-03 §2.1 names them: objective, deliverable boundary, explicit out-of-stage,
implementation instructions, review instructions, acceptance criteria. They are
named parts of one contract, not six separately identified things — so *"was this in
scope"* has a single referent, and a change to any part is a different contract.

GP-AUTO never authors or reinterprets contract content (`NG-19`, AP-03 §15); it is
read, referenced, and nothing else.
"""

from __future__ import annotations

from gpauto.identity import (
    BaselineIdentityId,
    GovernedStageId,
    ProjectId,
    RepositoryBoundaryId,
    StageContractId,
)
from gpauto.schema import DomainEntity


class Project(DomainEntity):
    """`RA-01`'s referent (AP-03 §2.1).

    Without it, two projects sharing one checkout or one coordination store become
    one, and cross-project use of an authorization is undetectable.
    """

    identity: ProjectId


class GovernedStage(DomainEntity):
    """The unit an authorization covers and at whose outcome it is consumed.

    A stage may be associated with more than one authorization over its lifetime,
    including across OWNER-resolved recovery epochs, and more than one may be
    eligible and live at once — representable, and halting as ambiguity (`AP03-I02`).
    Nothing here caps that, because a cap would render the ambiguity condition
    unrepresentable and therefore silently resolved.
    """

    identity: GovernedStageId
    project: ProjectId


class StageContract(DomainEntity):
    """`RA-03`: the named parts of one scope, under one **content** identity.

    Identity is content, so identical contract content across two stages is one
    contract identity, and one stage may reference different contract identities over
    time (AP-03 §3.1 row 4). The identity value is not computed here — that is
    `GP-AUTO-ST-02`'s under AP-07.
    """

    identity: StageContractId
    objective: str
    deliverable_boundary: tuple[str, ...]
    explicit_out_of_stage: tuple[str, ...]
    implementation_instructions: tuple[str, ...]
    review_instructions: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]


class RepositoryBoundary(DomainEntity):
    """`RA-04`: repository location **and** branch (AP-03 §2.1).

    Both, because an action outside the authorized branch is as much outside the
    boundary as one outside the authorized repository, and a model carrying only the
    location cannot say so.
    """

    identity: RepositoryBoundaryId
    repository_location: str
    branch: str


class BaselineIdentity(DomainEntity):
    """`RA-05`: the committed-history identity the authorization is bound to.

    VCS-asserted, resting on a trusted assumption (`T-05`) rather than on verification
    performed here. It is not the working tree and not *"HEAD now"*: authority applied
    to a different baseline than authorized is the failure this entity exists to make
    visible.
    """

    identity: BaselineIdentityId
    committed_history_identity: str
