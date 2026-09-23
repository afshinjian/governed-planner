"""The strict-model base every GP-AUTO domain structure is built from.

Design basis: AP-03 §1 (domain-model principles), §3 (identity model); AP-11 §4
(`VL11-2`), §16 (`GP-AUTO-ST-01` deliverables).

Three configuration facts are load-bearing and are set **once**, here, so that no
domain module can land a structure that is quietly looser than its neighbours.

* `strict=True` — a `list` is not a `tuple`, a `str` is not an `int`, and one model
  class is not another. Sibling classes are refused for one another even when they
  share this base, which is what makes AP-03 §3's identity kinds genuinely
  non-interchangeable rather than merely differently named (measured on pydantic
  2.13.5).
* `extra="forbid"` — an undeclared field is refused outright rather than accepted
  and dropped. AP-03 §4.3 rule 1 is fail-closed: content the frozen projection does
  not place is authority-bearing, so a structure that silently swallows an unknown
  field would decide an authority question by discarding it.
* `frozen=True` — AP-03 §7.2.1 and `AP03-I08` turn on records that cannot be edited
  after they are made. Immutability here is a schema property, not a claim about
  storage, which is AP-07's.

**Base classes are never used as field annotations.** Pydantic's strict mode accepts
any subclass where a base is annotated, so annotating a field `DomainModel` would
re-open every substitution this module exists to close. `tests_gpauto` asserts the
absence structurally rather than leaving it to convention.

This module declares configuration and nothing else: it holds no field, no
vocabulary and no behaviour, so there is no second place where a domain rule could
come to live.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict

DOMAIN_MODEL_CONFIG: Final[ConfigDict] = ConfigDict(
    strict=True,
    extra="forbid",
    frozen=True,
)


class DomainModel(BaseModel):
    """Root of every GP-AUTO domain structure. Never annotate a field with it."""

    model_config = DOMAIN_MODEL_CONFIG


class DomainValue(DomainModel):
    """A structured value carried by an entity, with no identity of its own (AP-03 §2)."""


class DomainEntity(DomainModel):
    """An independently identified domain thing (AP-03 §2)."""
