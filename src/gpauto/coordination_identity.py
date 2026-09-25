"""Identity types for the record classes ST-01 did not type — frozen kinds only.

Design basis: AP-11 ST-03 store-realization amendment §5.3, §3 (R-4, OWNER resolved);
AP-07 §3.2 (identity-kind column), §5.1 (`ID-3`…`ID-8`); AP-03 §3 (the four kinds).

**No new identity kind.** Every type here is a subtype of one of ST-01's kind bases in
`identity.py`, which is imported and not modified (`RC-5`, `AP07-I04`):

* **minted** — `RC-31` halt occurrence, `RC-32` governance-event resolution, `RC-33` cycle
  occurrence, `RC-37` dispatch record and outcome-ingestion record;
* **dependent**, stored as the pair *(parent identity, discriminator)* and never flattened
  (`ID-8`) — `RC-34` position entries on their subject; `RC-35` on the authorization
  instance whose disposition it establishes; `RC-38` and `RC-39` on their activation;
  `RC-40` on the record the entry reports or audits.

**`RC-34` has one identity type per machine.** AP-04 §2 gives each machine a different
subject — M1 a `RootResolution`, M2 a classification context, M3 an envelope, M4 an
authorization instance — so a position entry's parent is typed by its machine and an M3
entry cannot name a resolution as its subject. The M2 subject is the classification
context *(resolved root, **its** fixed `EntryStateBoundary`)*: `RS7-1` makes that boundary
unique per root, so the context is named by its root, and the first M2 entry (`B1`,
`S1 EPOCH_OPENED`) is expressible before `B2` fixes the boundary (AP-04 §4.1).

**`RC-35` and `RC-40` parents are the OWNER's R-4 resolution**: the authorization instance
whose disposition is established, and the record the audit entry reports or audits. The
establishing record and the predecessor audit entry are separate references on the record
and are never the parent.

**`RC-41` has no identity type of its own.** AP-07 gives it the identity *"annotation on
`RC-19`"*: a session record is identified by the `WorkerActivation` it annotates, so no
identifier — and no kind — is introduced for it.

A **discriminator** is an opaque token, carrying no time, sequence, counter or ordering
(`ID-3`); it distinguishes siblings under one parent and says nothing else. Nothing here
mints, parses or compares an identity: minting is `minting.py`'s, and uniqueness is the
store's constraint over the pair.
"""

from __future__ import annotations

from gpauto.identity import (
    AuthorityAmbiguityId,
    AuthorityEnvelopeId,
    CandidateExclusionId,
    DependentIdentity,
    EnvelopeViolationId,
    InputPackageId,
    MintedIdentity,
    OwnerAuthorizationId,
    RefusalId,
    RootResolutionId,
    UnaccountedMutationId,
    WorkerActivationId,
)

# --- Minted ----------------------------------------------------------------------


class HaltOccurrenceId(MintedIdentity):
    """`RC-31`: one halt, individually identified, never merged with another (`GH-4`)."""


class GovernanceEventResolutionId(MintedIdentity):
    """`RC-32`: one resolution record, naming the halt occurrence it resolves (`GH-5`)."""


class CycleOccurrenceId(MintedIdentity):
    """`RC-33`: one cycle occurrence. Never a counter and never an index (`CO-12`)."""


class DispatchRecordId(MintedIdentity):
    """`RC-37` dispatch record (`MH-7`…`MH-10`)."""


class OutcomeIngestionRecordId(MintedIdentity):
    """`RC-37` outcome-ingestion record (`MH-13`…`MH-18`)."""


# --- Dependent: RC-34 position entries, one type per machine ----------------------


class M1PositionEntryId(DependentIdentity):
    """An M1 entry, dependent on its `RootResolution` occurrence (AP-04 §2)."""

    resolution: RootResolutionId
    discriminator: str


class M2PositionEntryId(DependentIdentity):
    """An M2 entry, dependent on its classification context, named by its root."""

    epoch_root: OwnerAuthorizationId
    discriminator: str


class M3PositionEntryId(DependentIdentity):
    """An M3 entry, dependent on its `AuthorityEnvelope` (AP-04 §2)."""

    envelope: AuthorityEnvelopeId
    discriminator: str


class M4PositionEntryId(DependentIdentity):
    """An M4 entry, dependent on its `OwnerAuthorization` instance (AP-04 §2)."""

    authorization: OwnerAuthorizationId
    discriminator: str


# --- Dependent: RC-35, RC-38, RC-39 -----------------------------------------------


class DispositionRecordId(DependentIdentity):
    """`RC-35`, dependent on the authorization instance whose disposition it establishes
    (R-4). The `StageOutcome`, `OwnerDecision` or event that establishes it is carried
    by the disposition value, not by the identity."""

    authorization: OwnerAuthorizationId
    discriminator: str


class ExecutionObservationId(DependentIdentity):
    """`RC-38`, dependent on one activation (AP-07 §3.2)."""

    activation: WorkerActivationId
    discriminator: str


class ConformanceDeterminationId(DependentIdentity):
    """`RC-39`, dependent on one activation (AP-07 §3.2)."""

    activation: WorkerActivationId
    discriminator: str


# --- Dependent: RC-40 -------------------------------------------------------------

type AuditedRecordReference = (
    WorkerActivationId
    | InputPackageId
    | OutcomeIngestionRecordId
    | DispatchRecordId
    | RefusalId
    | EnvelopeViolationId
    | AuthorityAmbiguityId
    | CandidateExclusionId
    | UnaccountedMutationId
    | HaltOccurrenceId
    | GovernanceEventResolutionId
    | CycleOccurrenceId
    | M1PositionEntryId
    | M2PositionEntryId
    | M3PositionEntryId
    | M4PositionEntryId
)
"""What an audit entry may report or audit: exactly one record of an `AR-1` class, or a
replayed or delivered occurrence (`AR-1`, `AR-2`, `MC-6`, `MC-13`). Typed, so an entry
references a record rather than copying it or naming it by an untyped string."""


class AuditEntryId(DependentIdentity):
    """`RC-40`, dependent on the record it reports or audits (R-4).

    The predecessor audit entry is **not** the parent: it is the separate succession
    reference `AR-3` requires, so the first entry has a parent and no predecessor.
    """

    audited: AuditedRecordReference
    discriminator: str
