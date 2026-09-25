"""The inert value vocabularies `GP-AUTO-ST-03` owns — `IV11-1` … `IV11-15`, and nothing else.

Design basis: AP-11 ST-03 store-realization amendment §5.1 (`IV11-1`…`IV11-15`), §4
(`SRB11-2`, `SRB11-3`, `SRB11-4`), §15 (`AP11-I65`, `AP11-I66`); AP-04 §2, §3.1, §4.1,
§5.1, §3.2/§4.2/§5.2/§6 and AP-04 amendment §3.1 (machines, states, edges); AP-05 `CL-7`,
`CL-8`, `DO-1`, `RM-5`; AP-06 `WL-13`, `WL-14`, `QO-5`, `CA-7`…`CA-15`, `CA-17`; AP-07
`RC-39`, `MH-15`, `MH-18`, `CO-16`, §19; AP-08 `FC-2a`, `FC-3`.

**These are value sets, and only value sets** (`SRB11-3`, `AP11-I66`). Each enumeration
below is closed at exactly its frozen source's members, and carries no guard, predicate,
transition function, from→to mapping, admissibility table, evaluator, ordering,
derivation, lifecycle act or default. The store checks that a stored value is a member
of its set — **type and closure** — and never whether a value is *governance-valid*: that
an `A2` edge reaches `ROOT_RESOLVED`, that `B15` leaves `S7`, or that a quiescence value
permits a dispatch, is each the behaviour of a later stage (ST-05, ST-09, ST-10, ST-12)
and appears nowhere here.

**Each concept is encoded once** (`SRB11-4`, `AP11-I65`). The M4 disposition is ST-01's
`AuthorizationDisposition` and is imported, not repeated; the ST-01 root-resolution
*outcome* (AP-03 §4.5) and `IV11-1`'s M1 *positions* (AP-04 §3.1) are two frozen concepts
from two frozen sources, as the amendment's §5.2 note records. Later stages import these
encodings and add no second one.

**Member naming.** Following ST-01's `vocabulary.py`, every member's value is its own
name. AP-04 numbers the M2 states (`S1` … `S11`) and the amendment names them with their
numbers, so the numbers are part of the frozen name here. `B14` does not exist in AP-04
and is therefore not a member — it is not encodable, not merely refused.

The few small value models here exist because a frozen value set is not flat: `IV11-5`'s
`NOT_CLOSED` carries the `CL-8` indeterminacy reason, and `IV11-9`'s *terminated* carries
its disposition class while *termination indeterminate* carries none. They are values,
with no behaviour.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from gpauto.absence import Determined
from gpauto.schema import DomainValue


class Machine(StrEnum):
    """`IV11-14` — the four machines of AP-04 §2."""

    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"


class M1Position(StrEnum):
    """`IV11-1` — M1 stage-entry authority resolution states (AP-04 §3.1)."""

    RESOLUTION_OPEN = "RESOLUTION_OPEN"
    ROOT_RESOLVED = "ROOT_RESOLVED"
    ROOT_ABSENT = "ROOT_ABSENT"
    ROOT_CONTESTED = "ROOT_CONTESTED"


class M2Position(StrEnum):
    """`IV11-2` — M2 coordination-epoch states (AP-04 §4.1), numbered as frozen."""

    S1_EPOCH_OPENED = "S1_EPOCH_OPENED"
    S2_ENTRY_BOUNDARY_FIXED = "S2_ENTRY_BOUNDARY_FIXED"
    S3_IMPLEMENTATION_ACTIVE = "S3_IMPLEMENTATION_ACTIVE"
    S4_DISCOVERY_ACTIVE = "S4_DISCOVERY_ACTIVE"
    S5_FINDING_SET_FROZEN = "S5_FINDING_SET_FROZEN"
    S6_REMEDIATION_ACTIVE = "S6_REMEDIATION_ACTIVE"
    S7_CLOSURE_ACTIVE = "S7_CLOSURE_ACTIVE"
    S8_GATE_REACHED = "S8_GATE_REACHED"
    S9_EPOCH_HALTED = "S9_EPOCH_HALTED"
    S10_EPOCH_SETTLED = "S10_EPOCH_SETTLED"
    S11_EPOCH_AUTHORITY_ENDED = "S11_EPOCH_AUTHORITY_ENDED"


class M3Position(StrEnum):
    """`IV11-3` — M3 derived-authority and activation states (AP-04 §5.1)."""

    ENVELOPE_DERIVED = "ENVELOPE_DERIVED"
    ENVELOPE_VOIDED = "ENVELOPE_VOIDED"
    ACTIVATION_RUNNING = "ACTIVATION_RUNNING"
    ACTIVATION_COMPLETED = "ACTIVATION_COMPLETED"
    ACTIVATION_CLOSED_UNADOPTED = "ACTIVATION_CLOSED_UNADOPTED"


class M1Edge(StrEnum):
    """`IV11-4`, M1 partition — edge identifiers only (AP-04 §3.2)."""

    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"


class M2Edge(StrEnum):
    """`IV11-4`, M2 partition (AP-04 §4.2; AP-04 amendment §3.1). There is no `B14`."""

    B1 = "B1"
    B2 = "B2"
    B3 = "B3"
    B4 = "B4"
    B5 = "B5"
    B6a = "B6a"
    B6b = "B6b"
    B7 = "B7"
    B8 = "B8"
    B9 = "B9"
    B10 = "B10"
    B11 = "B11"
    B12 = "B12"
    B13 = "B13"
    B15 = "B15"


class M3Edge(StrEnum):
    """`IV11-4`, M3 partition (AP-04 §5.2)."""

    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"
    C5 = "C5"
    C6 = "C6"


class M4Edge(StrEnum):
    """`IV11-4`, M4 partition (AP-04 §6)."""

    G1 = "G1"
    G2 = "G2"
    G3 = "G3"
    G4 = "G4"
    G5 = "G5"
    G6 = "G6"


class ClosureVerdict(StrEnum):
    """`IV11-5` — the closed two-valued closure verdict (AP-05 `CL-7`)."""

    CLOSED = "CLOSED"
    NOT_CLOSED = "NOT_CLOSED"


class ClosedVerdict(DomainValue):
    """`IV11-5` `CLOSED`."""

    verdict: Literal[ClosureVerdict.CLOSED] = ClosureVerdict.CLOSED


class NotClosedVerdict(DomainValue):
    """`IV11-5` `NOT_CLOSED`, with the `CL-8` reason where it arises from indeterminacy.

    `KnownAbsent` records that the verdict did **not** arise from indeterminacy; a
    present reason records that it did. Neither is a third verdict.
    """

    verdict: Literal[ClosureVerdict.NOT_CLOSED] = ClosureVerdict.NOT_CLOSED
    indeterminacy_reason: Determined[str]


type ClosureVerdictValue = ClosedVerdict | NotClosedVerdict
"""`IV11-5` as carried by `RC-28` and by a `CA-12` per-member closure-result item."""


class DiscoveryVerdict(StrEnum):
    """`IV11-6` — *findings reported* / *no findings* (AP-05 `DO-1`, AP-06 `CA-7`)."""

    FINDINGS_REPORTED = "FINDINGS_REPORTED"
    NO_FINDINGS = "NO_FINDINGS"


class ObligationDisposition(StrEnum):
    """`IV11-7` — *addressed* / *not addressed* (AP-05 `RM-5`, AP-06 `CA-10`)."""

    ADDRESSED = "ADDRESSED"
    NOT_ADDRESSED = "NOT_ADDRESSED"


class DeclaredItemClass(StrEnum):
    """`IV11-8` — the declared outcome item classes (AP-06 §12.2, AP-07 `MH-15`)."""

    DISCOVERY_VERDICT = "DISCOVERY_VERDICT"
    FINDING_ITEM = "FINDING_ITEM"
    OBLIGATION_DISPOSITION_ITEM = "OBLIGATION_DISPOSITION_ITEM"
    MEMBER_CLOSURE_RESULT = "MEMBER_CLOSURE_RESULT"
    DISPUTE_ITEM = "DISPUTE_ITEM"
    POST_FREEZE_CANDIDATE_ITEM = "POST_FREEZE_CANDIDATE_ITEM"
    WORKER_REFUSAL_OR_EXPANSION_REQUEST = "WORKER_REFUSAL_OR_EXPANSION_REQUEST"


class TerminatedDisposition(StrEnum):
    """`IV11-9` — the four `WL-13` terminated disposition classes."""

    ORDINARY_EXIT = "ORDINARY_EXIT"
    NON_ZERO_EXIT = "NON_ZERO_EXIT"
    SIGNALLED_OR_KILLED = "SIGNALLED_OR_KILLED"
    EXTERNALLY_LOST = "EXTERNALLY_LOST"


class Terminated(DomainValue):
    """`IV11-9` *terminated*, with its disposition class (`WL-13`)."""

    disposition: TerminatedDisposition


class TerminationIndeterminate(DomainValue):
    """`IV11-9` *termination indeterminate* (`WL-14`) — never stored as terminated.

    It carries no disposition field, so a terminated class is not expressible on it.
    """


type TerminationValue = Terminated | TerminationIndeterminate
"""`IV11-9`."""


class TimeoutDisposition(StrEnum):
    """`IV11-10` — the timeout termination-disposition class (`WL-20`, `FC-2a`, `FC-3`).

    Not one of `WL-13`'s four terminated classes, and never by itself a termination.
    """

    TIMEOUT = "TIMEOUT"


class Quiescence(StrEnum):
    """`IV11-11` — three values; indeterminate is never quiescent (`QO-5`, `CO-16`)."""

    QUIESCENT = "QUIESCENT"
    NOT_QUIESCENT = "NOT_QUIESCENT"
    INDETERMINATE = "INDETERMINATE"


class ConformanceDeterminationClass(StrEnum):
    """`IV11-12` — the four separate `RC-39` determinations (`MH-16`)."""

    STRUCTURAL_CONFORMANCE = "STRUCTURAL_CONFORMANCE"
    ENVELOPE_CONFORMANCE = "ENVELOPE_CONFORMANCE"
    RESIDUE = "RESIDUE"
    ADOPTION = "ADOPTION"


class StructuralConformanceResult(StrEnum):
    """`IV11-13` — indeterminate is a nonconformance, never conformant (`CA-20`)."""

    CONFORMANT = "CONFORMANT"
    NONCONFORMANT = "NONCONFORMANT"
    INDETERMINATE = "INDETERMINATE"


class AuditEntryClass(StrEnum):
    """`IV11-15` — a record reported (`AR-1`), a replay (`AR-6`), a delivery (`MC-13`)."""

    REPORTED = "REPORTED"
    REPLAY = "REPLAY"
    DELIVERY = "DELIVERY"
