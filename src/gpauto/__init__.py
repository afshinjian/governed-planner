"""`gpauto` — the GP-AUTO-001 coordination package.

Design basis: AP-03 §1–§17 (GP-AUTO-001 coordination domain model); AP-11 §14
(`SD11-17`), §16 (`GP-AUTO-ST-01`).

This package is **separate from `gplanner`** and is not a part, extension or
re-export of it (`EB-14`(iii), `SD11-17`). The separation is architectural: the
GP-SPK-001 spike is closed and frozen, and GP-AUTO neither modifies it nor depends
on its scope-governance vocabulary (`SD11-7`…`SD11-11`, `AP03-I32`).

At `GP-AUTO-ST-01` this package contains **only** AP-03's entity, identity and value
model expressed as strict typed structures. There is no persistence, no state
machine, no authority evaluation, no repository observation, no execution and no
provider surface; each belongs to a later stage that is separately OWNER-authorized.

Nothing is re-exported here, following the boundary discipline the spike's own
`__init__` records: a convenience re-export would let an importer reach a domain
module without naming the layer it came from, and the layer names are what make
`AP03-I01`'s derivation chain readable.
"""

from __future__ import annotations
