"""Entry state, effects, and state the derivation does not explain.

Design basis: AP-03 §2.4, §7.1 (the four concepts), §7.2 (`ES-1`…`ES-6`), §7.2.1
(classification is boundary-relative), §7.3 (effect / delta model), §12
(`UnaccountedMutation`), §16.4; `AP03-I08`…`AP03-I11`, `AP03-I28`.

Four concepts, kept apart because collapsing any two loses a fact the OWNER needs.
`BaselineIdentity` is the committed history an authorization is bound to and lives in
`scope_frame.py`; the three here are the fixed observation, the recorded effect, and
the state nothing explains.

**`ExpectedCurrentAuthorizedState` has no class here, deliberately.** AP-03 makes it a
**derivation** — `EntryStateBoundary + Σ effects of completed authorized activations`
— and `AP03-I09` forbids storing it as an independently writable record, because a
stored copy is a second baseline and therefore the silent re-binding `MB-24` forbids.
The structural absence is the enforcement, and `tests_gpauto` asserts it: a
derivation with no type cannot be written to.

**Why `ActivationEffect` must exist at all.** Without it the second term of the
derivation does not exist, the expected current authorized state degenerates to the
bare entry state, and **every lawful IMPLEMENTER or REMEDIATOR write reads as
divergence** (`MB-16`). In the other direction, unaccounted mutation has nothing to
fail to match and cannot be defined.

**Authorized effect ≠ any effect of an authorized activation.** An effect enters the
derivation only when *the effect itself* falls within the producing activation's valid
envelope. An authorized activation writing outside its write boundary produces an
effect that is *attributable* but not authorized, and therefore explains nothing —
which is why `within_producing_envelope` is a field of the effect rather than a
property inferred from the activation.

**Attribution is permanent** (`ES-4`, `AP03-I10`). The producing activation is part of
the effect's dependent identity, so consumption of an envelope or an authorization
cannot delete, detach or re-attribute it. Authority ends; attribution does not.

**Classification is boundary-relative** (`AP03-I11`). Every classification is made
relative to one `ClassificationContext` — a resolved root authorization and its fixed
entry boundary. Inside a context, pre-existing entry state, expected stage delta and
unaccounted mutation are mutually exclusive and non-convertible. Across contexts the
same state may be classified differently, and that records a new boundary-relative
fact rather than revising an old one. No inheritance relation exists between
boundaries (`ES-5`), and none may be added: only an OWNER-resolved act creates a new
context, and GP-AUTO never manufactures one — least of all to dispose of an
inconvenient classification.

Snapshotting, hashing, diffing, index inspection, attribution mechanics and every
observation algorithm are AP-09's; storage is AP-07's. None is here.
"""

from __future__ import annotations

from gpauto.absence import Observable
from gpauto.identity import (
    ActivationEffectId,
    AuthorityEnvelopeId,
    BaselineIdentityId,
    EntryStateBoundaryId,
    OwnerAuthorizationId,
    UnaccountedMutationId,
    WorkerActivationId,
)
from gpauto.schema import DomainEntity, DomainValue


class EntryStateBoundary(DomainEntity):
    """The one fixed read-only observation at stage entry (`E-07`, AP-03 §7.1).

    Governed committed baseline, pre-existing working-tree state and pre-existing
    index/staged state, recorded once per resolved root and **never moved** — the
    domain provides no operation that moves, replaces, re-observes, semantically edits
    or transfers it (`ES-1`, `AP03-I08`).

    Pre-existing dirty working-tree and index state are **valid entry evidence**: they
    are recorded here, are not stage delta, and are not divergence merely by existing
    (`ES-2`, `E13`, `E14`, `F8`). This boundary is not a prediction and not evidence of
    cleanliness.
    """

    identity: EntryStateBoundaryId
    baseline: BaselineIdentityId
    pre_existing_working_tree_state: tuple[str, ...]
    pre_existing_index_state: tuple[str, ...]


class ClassificationContext(DomainValue):
    """`(resolved root authorization, its fixed EntryStateBoundary)` (AP-03 §7.2.1).

    A classification is only ever a statement *within* one context. Naming the context
    on every classified fact is what keeps `AP03-I11`'s non-convertibility a statement
    inside a context rather than an impossible claim across contexts.
    """

    authorization: OwnerAuthorizationId
    entry_boundary: EntryStateBoundaryId


class ActivationEffect(DomainEntity):
    """The recorded effect of one activation (AP-03 §7.1, §7.3).

    Not a worker's account of what it did — that is a worker-authored
    `ArtifactProduction`, and the two must not be confused (`EA-2`).
    """

    identity: ActivationEffectId
    observed_state: tuple[str, ...]
    within_producing_envelope: bool


class UnaccountedMutation(DomainEntity):
    """State the derivation does not explain, producer known or unknown (AP-03 §7.3).

    It asserts something different from an `EnvelopeViolation`: *the expected
    authorized state does not explain this state*, as opposed to *this activation
    exceeded its envelope*. The two **coexist rather than compete** — where a producer
    is known, both are recorded, because recording only one loses either which
    activation exceeded its authority or that the expected state no longer explains the
    repository (`GE-4`, `AP03-I28`).

    `producing_activation` is `Observable`, which is the whole point: it is *present*
    or *not observed*, and there is deliberately no value meaning *no producer exists*.
    The domain never claims none exists merely because none is named (AP-03 §12,
    `VP11-5`).

    The expected current authorized state is **not a field**. It is a derivation
    (`AP03-I09`), so what is carried is the observed state and the portion of it the
    derivation leaves unexplained.
    """

    identity: UnaccountedMutationId
    context: ClassificationContext
    observed_state: tuple[str, ...]
    unexplained_portion: tuple[str, ...]
    affected_envelopes: tuple[AuthorityEnvelopeId, ...]
    producing_activation: Observable[WorkerActivationId]
