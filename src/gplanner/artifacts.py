"""Content-addressable artifacts.

Design basis: design/GP-SPK-001-governance-kernel.md §4, §6.

This module holds **content only**. It imports neither `states` nor `approvals`, which
is what makes artifact identity a pure function of content: a `ScopeSpec` cannot
depend on where a case has got to, and a digest computed today means the same thing
when recomputed by anyone else.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SCOPE_SCHEMA_VERSION: Final[Literal["gplanner.scope/v1"]] = "gplanner.scope/v1"


class ScopeSpec(BaseModel):
    """A scope specification: what a piece of work is, and is not.

    The load-bearing property is what this model **lacks**. There is no digest, no
    workflow id, no state, no timestamp and no approval data, so the model contains
    nothing derived from or about itself. When it is later hashed (§6), the whole
    model is the preimage payload -- there is no field to exclude, and so no way for
    a "compute the hash" path and a "verify the hash" path to disagree about which
    fields count. That divergence is a real defect in the sibling `governed-runtime`
    (`authority.py:154` vs `:168`); the shape here rules it out rather than guarding
    against it.

    Field types are restricted to `str`, `tuple[str, ...]` and `Literal` on purpose.
    No float, no datetime, no Decimal, no Optional: identity must not depend on how a
    given Pydantic version renders those in JSON mode. `gplanner.payload-profile/1`
    enforces the same restriction independently, as a check on any future field.

    Sequence order is significant and is **never sorted**. Two specs listing the same
    items in different orders are different specs, and normalizing them would
    silently merge them under one identity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: Literal["gplanner.scope/v1"] = SCOPE_SCHEMA_VERSION
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    problem_statement: Annotated[str, StringConstraints(min_length=1)]
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    acceptance_criteria: Annotated[tuple[str, ...], Field(min_length=1)]
    assumptions: tuple[str, ...] = ()


class ArtifactRef(BaseModel):
    """A reference to a stored artifact: what it is, which bytes it is, how many.

    Three fields and no more. A reference does not know a case's state, its workflow, or
    when it was written -- those are the store's and the kernel's business, and a state
    field here would make a *reference* carry case semantics that could disagree with
    the case itself.

    `digest` is constrained to the `sha256:<64 lowercase hex>` wire format by pattern
    rather than by calling `digest.is_digest`, because this module must not import
    `digest.py`: identity depends on content, so the dependency runs the other way (§4).
    The pattern is therefore stated in two places, and GP-03 asserts the two agree.
    Lowercase only -- hex is case-insensitive as an encoding, so accepting both cases
    would give one artifact two spellings of its identity.

    `byte_len` is the length of `canonical_preimage`, the authoritative bytes (§6). It
    is bounded below because a stored artifact has content; it is a size, not an
    authority-bearing field, and nothing is decided from it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    media_type: Annotated[str, StringConstraints(min_length=1)]
    digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    byte_len: Annotated[int, Field(ge=1)]
