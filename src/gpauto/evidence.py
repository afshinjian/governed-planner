"""Content, production, and why they are two levels.

Design basis: AP-03 §2.5 (artifact entities), §3.1 row 7, §8.1 (content, production),
§8.3 (the four classes), §8.4 (`EA-1`…`EA-6`), §16.3; `AP03-I19`, `AP03-I20`,
`AP03-I31`.

A single artifact entity carrying one provenance asserts something false: that one
content identity has exactly one provenance. **Identical content can arise from
different occurrences by different routes** — a measurement captured by the objective
path, and a worker report reproducing the same bytes. Under a one-level model the two
collapse and objective standing propagates to every identical-content copy. The
minimum correct model separates the bytes from the occasion that produced them.

* **Non-mixing.** Provenance is a property of the **whole production**. A production
  is objective only if the whole of what it captured came from the objective path; a
  production containing any worker-authored material is worker-authored, whatever else
  it quotes.
* **Non-propagation.** Standing attaches to the production, never to the content. Two
  productions of identical content may carry different provenance and different
  admissibility, and neither inherits the other's (`AP03-I19`). Storing, indexing,
  surfacing, mirroring or **deduplicating by content** confers no standing and must
  never merge two productions (`EA-4`) — which is a constraint on AP-07's store, and is
  stated here because this is where the two levels are defined.

**Forbidden-transfer material has no representation anywhere in this module** — no
entity, no container, no provenance value, no referent kind (`AP03-I20`). `Provenance`
has exactly two members. Containment rests on not supplying and on placement, not on
detection, and a domain container for material the architecture depends on never
holding would build the vessel whose absence is the control. Observed contamination is
an `EnvelopeViolation` naming the class crossed, carrying no transferred material.

**`DecisionPackage` has no class here, deliberately.** AP-03 §2.5 demotes it to a
derivation with no identity: its content is wholly derivable, and the only fact an
identity would add is *what the OWNER was shown* — which §12.2 forbids claiming
(`AP03-I31`). Retaining an identified projection would offer a later phase something
to treat as authoritative. The structural absence is asserted by `tests_gpauto`.

The bytes themselves, their canonical form and the computation of content identity are
`GP-AUTO-ST-02`'s under AP-07. This module defines the two levels and computes nothing.
"""

from __future__ import annotations

from typing import Literal

from gpauto.identity import ArtifactContentId, ArtifactProductionId, WorkerActivationId
from gpauto.schema import DomainEntity, DomainValue
from gpauto.vocabulary import Provenance


class ArtifactContent(DomainEntity):
    """The bytes, and nothing else (AP-03 §2.5, §8.1).

    Content identity means altered content is different content rather than the same
    content changed, so a verdict cannot cite content that later changed under it.
    **It carries no provenance and no standing** — it is a value, not a claim about how
    it arose — and `tests_gpauto` asserts that structurally.
    """

    identity: ArtifactContentId


class ActivationAttribution(DomainValue):
    """Produced or captured by one worker activation (AP-03 §8.1)."""

    activation: WorkerActivationId


class CoordinatorObservationAttribution(DomainValue):
    """Captured by the coordinator's bounded observation (AP-03 §8.1).

    Necessary because the `EntryStateBoundary` is observed under `RA-09` *before the
    first worker activation exists*; a model attributing every production to an
    activation could not record it.
    """


type ProductionAttribution = ActivationAttribution | CoordinatorObservationAttribution
"""Who or what produced this occurrence (AP-03 §8.1)."""


class ArtifactProduction[P: Provenance](DomainEntity):
    """One production or capture occurrence: *this content, this way, this occasion*.

    Binds exactly one `ArtifactContent`, and carries the **immutable** provenance fixed
    at the occurrence. `frozen=True` is what makes "no operation changes it" a property
    of the type rather than a rule someone must remember (`AP03-I19`).

    `objective` provenance is what §8.3 calls objective evidence; `worker_authored` is
    audit-only narrative — retained, and **structurally inadmissible as basis**,
    because the admissibility relation's domain excludes it (`EA-1`, `activation.py`).
    Retention is never authority.

    **Why the provenance is a type parameter, and why that is not a second artifact
    type.** AP-03 §18.4 removed `EvidenceArtifact`/`NarrativeArtifact` as two artifact
    types: they bought no guarantee the admissibility relation does not already give,
    and they cost a false assertion that one artifact can never contain both objective
    and authored material. So there is still **one** `ArtifactProduction` entity here,
    and `Provenance` still has exactly its two frozen members — nothing is split and no
    provenance class is added. What the parameter does is let a *relation* name the
    provenance it admits, so that §18.4's own reasoning — *"granting standing to
    narrative requires ... passing the admissibility relation, which already excludes
    worker-authored provenance"* — is true of the structure and not only of the prose.
    Before this, the objective reference named an opaque identity and re-asserted
    `OBJECTIVE` beside it, which excluded nothing: a worker-authored production could
    be named and the annotation simply written next to it.

    `ObjectiveArtifactProduction` and `WorkerAuthoredArtifactProduction` below are two
    parametrizations of this one entity, not two entities. `tests_gpauto` asserts the
    entity inventory still holds exactly AP-03 §2's entities.
    """

    identity: ArtifactProductionId
    content: ArtifactContentId
    provenance: P
    attributed_to: ProductionAttribution


ObjectiveArtifactProduction = ArtifactProduction[Literal[Provenance.OBJECTIVE]]
"""An `ArtifactProduction` whose provenance **is** objective — AP-03 §8.3's first class.

A production carrying worker-authored provenance is refused by this parametrization on
construction and on the JSON path alike (`literal_error`), so the exclusion `EA-1`
states is a property of the type rather than of an annotation written beside it.
"""

WorkerAuthoredArtifactProduction = ArtifactProduction[Literal[Provenance.WORKER_AUTHORED]]
"""An `ArtifactProduction` whose provenance **is** worker-authored — §8.3's third class.

Audit-only narrative. It is retained and is structurally inadmissible as basis, because
no admissible reference in `activation.py` names this parametrization.
"""
