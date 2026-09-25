"""Minting: the one place a GP-AUTO minted identifier value is generated.

Design basis: AP-07 §5.1 (`ID-3`, `ID-4`, `ID-5`), §4 (*"minted (opaque, no time, no
sequence, no content derivation)"*); AP-03 §3 (non-implication block), `AP03-I27`; AP-11
ST-03 store-realization amendment §5.3.

**Generation relies on unpredictability, and validation is syntactic only** (`ID-4`),
following the frozen `approval_id` precedent: a minted value is 32 lowercase hexadecimal
characters, generated from `uuid4`, and validated — by the store, where it is recorded —
by shape alone, never by version bits, because checking them would assert something the
encoding cannot establish about a value's origin.

**Nothing is encoded in the value** (`ID-3`): no time component, no sequence, no counter,
no ordering and no content derivation, so no later guard can read an order out of it.
**No global-uniqueness claim is made** (`ID-5`): a minted value is stable, opaque and
per-occurrence, and nothing more — not authenticated, not ordered, not fresh, not
tamper-evident.

**This module is not the store.** `AP03-I27` is explicit that storage never mints; the
store records a caller's already-minted identity and checks its shape. Which transition
mints, and under which pre-existing key it may do so (`MC-14`…`MC-19`), is the owning
stage's behaviour and is not here.
"""

from __future__ import annotations

import uuid
from typing import Final

MINTED_VALUE_LENGTH: Final[int] = 32
"""A minted value is exactly this many lowercase hexadecimal characters (`ID-4`)."""


def mint_value() -> str:
    """A fresh opaque minted value: 32 lowercase hex characters from `uuid4` (`ID-3`, `ID-4`)."""
    return uuid.uuid4().hex
