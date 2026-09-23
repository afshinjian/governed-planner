"""Three-valued absence, and the two-valued applicability AP-03 keeps separate from it.

Design basis: AP-03 §4.8.2 (role-conditional applicability), §5.3 `EV-6`, §7.3
(producer known or unknown), §10.1 (no set exists vs an empty set exists), §12
(what a governance record carries), `AP03-I15`, `AP03-I30`, `AP03-I36`; AP-11 §4
(`VL11-2`), §2 (`VP11-5`).

**Why absence needs three values and not two.** A plain optional says only *present*
or *not present*, and AP-03 forbids exactly the inference that collapse invites.
`UnaccountedMutation` carries its producing activation *where one is known*, and the
domain may never make *"a claim that no producer exists merely because none is
named"* (AP-03 §12). `VP11-5` says the same thing for every record: absence of a
record is never evidence of compliance. So *known to be absent* and *not observed*
must be different values, and neither may be read as the other.

* `Present[T]` — the thing exists and is named. A zero-finding PASS's real, empty
  frozen set is this value, not an absence.
* `KnownAbsent` — absence is an established fact, with its basis. No envelope exists
  for a role not activated on the branch taken, and that absence is correct
  (`AP03-I30`); a Refusal for missing authority names no root.
* `NotObserved` — the domain does not know. A discovery activation still running has
  produced no frozen set *yet*; an unaccounted mutation may have no producer named.

`KnownAbsent` carries its `basis` because an unexplained absence is exactly what
`NotObserved` is for; recording `KnownAbsent` without saying what established it
would be the silent claim AP-03 §12 forbids.

**Applicability is a different question and gets a different type.** AP-03 §4.8.2
states it two-valued — for each Role each dimension is *applicable* or
*inapplicable* — and `AP03-I15` makes a bounds value carrying an inapplicable
dimension **malformed, not wider**. That is a statement about a value's shape, not
about observation, so `NotObserved` must not be expressible for it: bounds are
authored and derived, never observed. `Carried[T]` / `NotApplicable` keeps the two
questions apart, which is what stops an unobserved dimension from reading as an
inapplicable one.

**Which roles make which dimension applicable is not decided here.** AP-03 §4.8.2
fixes that applicability is role-determined and assigns the per-role table to
AP-02 §3.1.2, which is not among this stage's frozen inputs. This module therefore
makes the distinction *expressible* and decides none of it; the table belongs to the
stage that derives envelopes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from gpauto.schema import DomainValue


class AbsenceState(StrEnum):
    """The three values. Closed, and each is a different fact (AP-03 §12, `VP11-5`)."""

    PRESENT = "PRESENT"
    KNOWN_ABSENT = "KNOWN_ABSENT"
    NOT_OBSERVED = "NOT_OBSERVED"


class DimensionApplicability(StrEnum):
    """Two values, per AP-03 §4.8.2 — *applicable* or *inapplicable*, and nothing else."""

    APPLICABLE = "APPLICABLE"
    INAPPLICABLE = "INAPPLICABLE"


class Present[T](DomainValue):
    """The thing exists and is named."""

    state: Literal[AbsenceState.PRESENT] = AbsenceState.PRESENT
    value: T


class KnownAbsent(DomainValue):
    """Absence is an established fact. `basis` records what established it."""

    state: Literal[AbsenceState.KNOWN_ABSENT] = AbsenceState.KNOWN_ABSENT
    basis: str


class NotObserved(DomainValue):
    """The domain does not know. Never read as `KnownAbsent` (AP-03 §12, `VP11-5`)."""

    state: Literal[AbsenceState.NOT_OBSERVED] = AbsenceState.NOT_OBSERVED


class Carried[T](DomainValue):
    """A bounds dimension applicable to this role, carrying its value (AP-03 §4.8.2)."""

    applicability: Literal[DimensionApplicability.APPLICABLE] = DimensionApplicability.APPLICABLE
    value: T


class NotApplicable(DomainValue):
    """A bounds dimension inapplicable to this role. Carrying a value here would be
    **malformed, not wider** (`AP03-I15`), so no value field exists to carry."""

    applicability: Literal[DimensionApplicability.INAPPLICABLE] = (
        DimensionApplicability.INAPPLICABLE
    )


type Perhaps[T] = Present[T] | KnownAbsent | NotObserved
"""Three-valued absence over `T`: present, known-absent, or not observed."""

type Determined[T] = Present[T] | KnownAbsent
"""Two of the three, where AP-03 makes *not observed* structurally inadmissible —
a Refusal's root is either resolved or established absent, never unobserved, because
GP-AUTO controlled the point of action (AP-03 §12, Case A)."""

type Observable[T] = Present[T] | NotObserved
"""Two of the three, where AP-03 forbids the *known-absent* value — an
`UnaccountedMutation`'s producing activation is named or unknown, and the domain
never claims no producer exists merely because none is named (AP-03 §7.3, §12)."""

type RoleConditional[T] = Carried[T] | NotApplicable
"""A role-conditional bounds dimension (AP-03 §4.8.2, `AP03-I15`)."""
