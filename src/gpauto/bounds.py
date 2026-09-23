"""`AuthorityBounds` — one value-type, eleven dimensions, used in exactly two places.

Design basis: AP-03 §4.8 (ceiling vs envelope, the dimension set), §4.8.1 (Git
observable vocabulary and three-tier grantability), §4.8.2 (role-conditional
applicability), §14 (role/provider separation); `AP03-I13`, `AP03-I15`, `AP03-I16`,
`AP03-I17`; AP-11 §7 (`NV11-6`).

AP-03 merges `AuthorityCeiling` into this one value-type rather than giving it an
entity of its own. The reason is structural: a separately identified ceiling could
outlive an authorization or be shared between two, which would make it a **second
authority source**. Here the ceiling is `RA-07`'s value inside the authorization, an
envelope carries a granted value of the same type, and `envelope ≤ ceiling` is
expressible at all only because both are the same type.

**No ordering is implemented here.** AP-03 §4.8 defines a dimension-wise partial
order, and `AP03-I13` makes envelope derivation a total function with no free
parameters — but the comparison and the derivation are `GP-AUTO-ST-06`'s. This module
declares the dimensions; it evaluates nothing, compares nothing and derives nothing.

**Provider appears in no dimension, and that absence is the point** (`NV11-6`,
`AP03-I17`, AP-03 §14). If provider identity appeared in a bounds value, a change of
vendor would change authority — making authority derivable from a configuration
choice rather than from the OWNER. `ProviderAssignment` is an annotation on
`WorkerActivation` alone, and `tests_gpauto` asserts its absence from every bounds
structure structurally rather than by inspection.

**Two dimensions carry opaque tokens rather than enumerations.** AP-03 names *action
classes* (`E-09`) and *tool categories* (`E-15`) as dimensions but assigns their
value spaces to AP-02. Enumerating them here would invent a capability vocabulary
AP-03 does not have, so each is carried as a named token type — present as a
dimension, undecided as a value space. `ToolCategory` is a **class, never a tool
name**, which AP-03 states and no structure can enforce; it is recorded here so the
constraint is at least stated where the type is read.

**Git: the vocabulary and the grantable space are two different things.**
`GitActionClass` (in `vocabulary.py`) is the complete *observable* vocabulary, so any
observed act is recordable. `GitCapabilityClass` is the whole of today's *grantable*
value space — `NONE` or `BOUNDED_READ` — so staging, commit, tag, push and history
mutation are not expressible in a bounds value at all rather than merely refused.
`GIT_GRANTABILITY` records the three tiers exactly as AP-03 §4.8.1 fixes them,
including the reserved middle tier, which is retained rather than collapsed: erasing
it would decide, against AP-01 and AP-02, that a scope change the OWNER reserved
could never be expressed. Retaining it grants nothing.

**Which roles make which dimension applicable is deliberately not here.** AP-03
§4.8.2 fixes that applicability is role-determined and assigns the per-role table to
AP-02 §3.1.2, which is not among this stage's frozen inputs. AP-03's own Git
role list is likewise partial. Encoding a table from partial text would be inventing
the missing rows, so the role-conditional dimensions are typed `RoleConditional[...]`
— the distinction is expressible, and the table belongs to the stage that derives
envelopes under AP-02 §3.1.2.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from gpauto.absence import RoleConditional
from gpauto.identity import (
    BaselineIdentityId,
    FrozenFindingSetId,
    GovernedStageId,
    ProjectId,
    RepositoryBoundaryId,
)
from gpauto.schema import DomainValue
from gpauto.vocabulary import (
    ExternalActionClass,
    GitActionClass,
    GitCapabilityClass,
    GitGrantabilityTier,
    Role,
    WriteMode,
)

GIT_GRANTABILITY: Final[Mapping[GitActionClass, GitGrantabilityTier]] = MappingProxyType(
    {
        GitActionClass.READ_STATUS: GitGrantabilityTier.CURRENTLY_GRANTABLE,
        GitActionClass.READ_DIFF: GitGrantabilityTier.CURRENTLY_GRANTABLE,
        GitActionClass.READ_LOG: GitGrantabilityTier.CURRENTLY_GRANTABLE,
        GitActionClass.READ_SHOW: GitGrantabilityTier.CURRENTLY_GRANTABLE,
        GitActionClass.READ_REV_PARSE: GitGrantabilityTier.CURRENTLY_GRANTABLE,
        GitActionClass.STAGING: GitGrantabilityTier.CURRENTLY_NON_GRANTABLE_RESERVED,
        GitActionClass.COMMIT: GitGrantabilityTier.CURRENTLY_NON_GRANTABLE_RESERVED,
        GitActionClass.TAG: GitGrantabilityTier.PERMANENTLY_NON_GRANTABLE,
        GitActionClass.PUSH: GitGrantabilityTier.PERMANENTLY_NON_GRANTABLE,
        GitActionClass.HISTORY_MUTATION: GitGrantabilityTier.PERMANENTLY_NON_GRANTABLE,
    }
)
"""Grantability per action class, exactly as AP-03 §4.8.1 fixes it (`AP03-I16`).

A property of the action class, **not** a value any bounds may carry. It is recorded
as data so that the three tiers are readable and checkable; it grants nothing, and
this stage neither consults it nor derives anything from it.

**It is a read-only mapping, and that is load-bearing.** `Final` stops the *name* from
being rebound; it does nothing about the object behind it, so a plain `dict` here
would leave AP-03 §4.8.1's frozen three-tier classification editable at run time — one
assignment could move staging into the grantable tier, or move the reserved tier into
the permanent one, which `AP03-I16` forbids in both directions. A `MappingProxyType`
refuses assignment, deletion, `update`, `clear`, `pop` and `setdefault`, and the dict
it reads is built inline and bound to no other name, so there is no mutable backing
object reachable from this module. There is deliberately no API to change a tier: a
scope change reaching the reserved tier is an OWNER act whose representation AP-02 §18
assigns to AP-09, not a mutation of this table.
"""


class ActionClass(DomainValue):
    """A class of act at all (`E-09`), carried as an opaque token.

    AP-03 names the dimension and assigns its value space to AP-02. The token is
    referenced and never interpreted here.
    """

    name: str


class ToolCategory(DomainValue):
    """A tool **category**, never a tool name (`E-15`, AP-03 §4.8).

    AP-03 states the constraint and assigns the category vocabulary to AP-02. That a
    given token is a category rather than a name is not structurally checkable; it is
    recorded here so the constraint is stated where the type is read.
    """

    name: str


class ReadBoundary(DomainValue):
    """Where reading may reach (`E-11`)."""

    scopes: tuple[str, ...]


class WriteBoundary(DomainValue):
    """Where writing may reach (`E-12`). Role-conditional: writing roles only."""

    scopes: tuple[str, ...]


class AuthoritativeInputDesignation(DomainValue):
    """Which subset of the read boundary is admissible as **basis** (`E-20`).

    Role-conditional: reviewing roles only. Admissibility is role-relative, which is
    why it is a bounds dimension and not a property of any artifact (`AP03-I19`).
    """

    designated_scopes: tuple[str, ...]


class ScopeFrameBounds(DomainValue):
    """Project, stage, repository/branch, baseline (`E-03`, `E-04`, `E-06`, `E-10`)."""

    project: ProjectId
    stage: GovernedStageId
    repository_boundary: RepositoryBoundaryId
    baseline: BaselineIdentityId


class AuthorityBounds(DomainValue):
    """The eleven dimensions of AP-03 §4.8, and nothing else.

    Carried by an `OwnerAuthorization` as its ceiling (`RA-07`) and by an
    `AuthorityEnvelope` as its granted bounds. Whether one is at or below another is
    a comparison this stage does not implement.

    A bounds value naming an external class asserts that the class is **authorized**,
    never that anything is prevented: authorization decision and technical prevention
    are separate facts, and AP-03 provides no structure that conflates them
    (AP-03 §12, `P-14`).
    """

    role_applicability: Role
    action_classes: tuple[ActionClass, ...]
    read_boundary: ReadBoundary
    write_mode: WriteMode
    write_boundary: RoleConditional[WriteBoundary]
    tool_categories: tuple[ToolCategory, ...]
    external_action_classes: tuple[ExternalActionClass, ...]
    git_capability_class: GitCapabilityClass
    scope_frame: ScopeFrameBounds
    authoritative_input_designation: RoleConditional[AuthoritativeInputDesignation]
    frozen_set_reference: RoleConditional[FrozenFindingSetId]
