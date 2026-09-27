"""GP-AUTO's mutation obligations: per guard, per mutant, killing test named.

Design basis: AP-11 §8 (`MU11-1`…`MU11-8`), §13 (`EV11-1`(c), `EV11-3`, `EV11-6`),
§16 (`GP-AUTO-ST-02` mutation row), §18 (`PG11-2`).

**Two guards, both named by the frozen stage contract, and no others.**

* `ga_equivalence_compare` — fixed on every guarded line of
  `src/gpauto/equivalence.py` (`MU11-3`); a **line** guard; frozen guarantees
  (`MU11-2b`) `EQ-0`, `EQ-3`…`EQ-6`, `AP03-I04`.
* `ga_codec_decode` — fixed on each decode line of `src/gpauto/codec.py`; a
  **model-enforced** guard; frozen guarantees `DC-1`, `DC-3` (which carries `VM-3`), `VM-11`,
  `ID-2`, `EQ-2`.

**From `GP-AUTO-ST-03`, four more guards**, each named by that stage's frozen contract
(*"write-class enforcement; referential-integrity enforcement; stale-schema refusal"*) or
by the root-resolution and key constraints its amendments fix, and each a **line** guard:

* `ga_store_write_class` — `src/gpauto/store_schema.py`: the create-only triggers, and
  the write surface's restriction to the coordination domain; guarantees `AP11-I70`,
  `ID-8`, `AP03-I27`.
* `ga_store_referential_integrity` — `src/gpauto/store_schema.py`: the foreign keys, the
  instance-existence triggers, the classification-context pair and the declared
  references; guarantees `AP03-I35`, `AP03-I10`, `RC-24`, `RC-25`.
* `ga_store_keys` — `src/gpauto/store_schema.py`: the `SRB11-8` keys, the `RO7A-5`
  bindings and `RC-36`'s whole-identity key; guarantees `AP11-I73`, `RC-14`, `RC-17`,
  `RC-18`, `RC-19`, `RC-26`, `RC-33`, `RC-34`, `RC-36`, `RC-37`, `RC-39`, `ID-8`.
* `ga_store_stale_schema` — `src/gpauto/store.py`: the version and structure refusals;
  guarantees `AP11-I69`, `EQ-9`.

**From `GP-AUTO-ST-04`, one more guard**, the one its frozen Mutation cell names as
superseded by the ST-04 amendment: *"each input-selection guard in the derivations and
portions ST-04 implements, where a wrong input would still produce a plausible value"* —
and nothing for `DV-9`, `DV-10`, `RA-00`…`RA-09` or a `DV-11` comparator (`DO11-4`,
`DO11-6`):

* `ga_derivation_input` — `src/gpauto/derivations.py`: every filter by which a derivation
  selects its input records — the read's admission (decodability, agreement of its two
  passes), subject, epoch, activation, stratum, completion, per-effect agreement of
  envelope determinations, verdict, obligation record and set, decision kind and
  referent, unresolved suspension, halt event, completing entry, attested member,
  occurrence link, and the keyed selections of an activation's envelope, its stratum, an
  effect's judgement and the epoch's reached entry; a **line** guard, one mutant per
  tagged line; guarantees `DV-1`, `DV-2`, `DV-3`, `DV-5`, `DV-6`, `DV-7`, `DV-8`,
  `DO11-1`, `DO11-2`. Every other predicate in the module is inventoried, with the reason
  it carries no mutant, in `ST04_UNMUTATED_PREDICATES`; every keyed access, in
  `ST04_KEYED_SELECTIONS` or `ST04_UNQUALIFIED_KEYED_ACCESSES`.

**From `GP-AUTO-ST-05`, two more guards**, exactly the frozen Mutation cell's scope —
*"every transition guard; each `RP-*` and `CE-*` condition individually"* (`SV11-3`) — and
nothing else:

* `ga_transition_guard` — `src/gpauto/state_machine_model.py`: every condition of every
  edge's guard, `RP-1`…`RP-7`, `CE-0a`…`CE-6` and `CP-1`…`CP-5` among them; a **model**
  guard, since a guard is data. One mutant per (edge, alternative or tier, condition),
  generated from the model and removing that one condition from that one edge; its
  killer enumerates the conditions from a snapshot taken before any mutation, so a
  removed condition cannot hide from its own test. The three conditions the
  `ST05-IMPL-R01`…`R03` remediation added — `C1-6` (`V-06`), `C2-8` (`OP-8`) and `B13-4`
  (`HB-1` as restated) — are each killed by their own dedicated test, and each also
  carries one **inversion** mutant admitting exactly the values it refuses.
* `ga_transition_evaluator` — `src/gpauto/state_machine.py`: the lines that read a guard —
  domain closure, condition satisfaction, the pair's expressibility, alternatives, the
  stratified order `CE-T1`…`CE-T3` and the joint coupled act (`K-9`); a **line** guard.

**No harness is installed** (`PG11-2` is undischarged, and a tool install would be a
halt). This module is test code that performs exactly the two kinds of mutation the
obligation needs, and nothing more:

* **Line mutation** (`ga_equivalence_compare`). The guarded module's source is read,
  one fragment on a line carrying the guard's identifier is replaced, and the mutated
  source is compiled. Each mutated function is rebuilt over the **real module's own
  globals** and substituted into the module for the duration of one killing test. The
  mutant therefore sees the real module's classes and constants — including anything
  the killing test itself patches — and differs from the original in the one fragment
  and nowhere else.
* **Schema mutation** (`ga_codec_decode`, `MU11-5`). The decode lines check nothing
  themselves; the guard *is* the models. So a mutant is a model whose schema differs
  in one respect — `extra="forbid"` loosened, a `Literal` tag widened to `str` — built
  as a subclass and substituted for the name the codec resolves at the decode line.
  Deleting the line would remove decoding rather than weaken a check, which is why
  line deletion is the wrong mutation here.

**A mutant is killed only by an assertion.** The killing test is run against the
mutant; `AssertionError` or a `pytest.raises` that saw nothing is a kill, a pass is a
survival, and any other exception propagates as an error — a crash is not counted as
detection. **Every mutant is paired with a control**: the same substitution with the
mutation removed, which must *not* be killed, so a kill cannot be an artefact of the
substitution itself.

**What a result means, and no more** (`MU11-2a`). A kill establishes that *that one
mutation was detected by that one test*. There is no score, no percentage and no
completeness claim over the guard set or the codebase, and no guard outside the two
above is claimed verified by anything here. A mutant not run is **not run**, never
passed (`EV11-6`); `main` reports each mutant's own result.

Runnable on its own: `python tests_gpauto/mutation.py`.
"""

from __future__ import annotations

import importlib
import inspect
import re
import sys
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from pydantic import BaseModel, ConfigDict, create_model

from gpauto import (
    codec,
    derivations,
    equivalence,
    state_machine,
    state_machine_model,
    store,
    store_schema,
)
from gpauto.authorization import AuthorizationRecord
from gpauto.preimage import ArtifactContentPreimage, StageContractContent, StageContractPreimage

GUARD_TAG: Final[re.Pattern[str]] = re.compile(r"# guard:([a-z_]+)")

KILLED = "KILLED"
SURVIVED = "SURVIVED"


@dataclass(frozen=True)
class Guard:
    """A mandatory guard, its location, its kind, and the frozen text behind it."""

    identifier: str
    module: types.ModuleType
    kind: str
    guarantees: tuple[str, ...]


GUARDS: Final[dict[str, Guard]] = {
    "ga_equivalence_compare": Guard(
        identifier="ga_equivalence_compare",
        module=equivalence,
        kind="line",
        guarantees=("EQ-0", "EQ-3", "EQ-4", "EQ-5", "EQ-6", "AP03-I04"),
    ),
    "ga_codec_decode": Guard(
        identifier="ga_codec_decode",
        module=codec,
        kind="schema",
        guarantees=("DC-1", "DC-3", "VM-11", "ID-2", "EQ-2"),
    ),
    "ga_store_write_class": Guard(
        identifier="ga_store_write_class",
        module=store_schema,
        kind="line",
        guarantees=("AP11-I70", "ID-8", "AP03-I27"),
    ),
    "ga_store_referential_integrity": Guard(
        identifier="ga_store_referential_integrity",
        module=store_schema,
        kind="line",
        guarantees=("AP03-I35", "AP03-I10", "RC-24", "RC-25"),
    ),
    "ga_store_keys": Guard(
        identifier="ga_store_keys",
        module=store_schema,
        kind="line",
        guarantees=(
            "AP11-I73",
            "RC-14",
            "RC-17",
            "RC-18",
            "RC-19",
            "RC-26",
            "RC-33",
            "RC-34",
            "RC-36",
            "RC-37",
            "RC-39",
            "ID-8",
        ),  # fmt: skip
    ),
    "ga_store_stale_schema": Guard(
        identifier="ga_store_stale_schema",
        module=store,
        kind="line",
        guarantees=("AP11-I69", "EQ-9"),
    ),
    "ga_derivation_input": Guard(
        identifier="ga_derivation_input",
        module=derivations,
        kind="line",
        guarantees=("DV-1", "DV-2", "DV-3", "DV-5", "DV-6", "DV-7", "DV-8", "DO11-1", "DO11-2"),
    ),
    "ga_transition_guard": Guard(
        identifier="ga_transition_guard",
        module=state_machine_model,
        kind="model",
        guarantees=(
            "A1", "A2", "A3", "A4", "B1", "B2", "B3", "B4", "B5", "B6a", "B6b", "B7", "B8",
            "B9", "B10", "B11", "B12", "B13", "B15", "C1", "C2", "C3", "C4", "C5", "C6",
            "G1", "G2", "G3", "G4", "G5", "G6",
            "RP-1", "RP-2", "RP-3", "RP-4", "RP-5", "RP-6", "RP-7",
            "CE-0a", "CE-0b", "CE-0c", "CE-0d", "CE-1", "CE-2", "CE-3", "CE-4", "CE-5", "CE-6",
            "CP-1", "CP-2", "CP-3", "CP-4", "CP-5",
        ),  # fmt: skip
    ),
    "ga_transition_evaluator": Guard(
        identifier="ga_transition_evaluator",
        module=state_machine,
        kind="line",
        guarantees=("CE-T1", "CE-T2", "CE-T3", "AP04-I21", "AP04-I44", "K-9", "AP04-I39"),
    ),
}


@dataclass(frozen=True)
class LineMutant:
    """Replace `original` — found once, on a line carrying the guard — with `replacement`."""

    guard: str
    identifier: str
    description: str
    original: str
    replacement: str
    killer: str


@dataclass(frozen=True)
class SchemaMutant:
    """Substitute `build()` for the model the codec names `target` at its decode line."""

    guard: str
    identifier: str
    description: str
    target: str
    build: Callable[[], type[BaseModel]]
    killer: str


@dataclass(frozen=True)
class ModelMutant:
    """Remove one condition from one part of one edge's guard in the model data — or, where
    `admitted` is given, keep it and have it admit those values instead (an inversion).

    `part` is the alternative's index for a conjunctive guard, or `own`, `tier0` or
    `tier1` for a stratified one."""

    guard: str
    identifier: str
    description: str
    edge: str
    part: str
    condition: str
    killer: str
    admitted: tuple[str, ...] | None = None


type Mutant = LineMutant | SchemaMutant | ModelMutant

EQUIVALENCE_TESTS = "tests_gpauto/test_ga12_equivalence.py"
CODEC_TESTS = "tests_gpauto/test_ga11_codec.py"


def _envelope_accepting_undeclared_fields() -> type[BaseModel]:
    class Mutant(StageContractPreimage):
        model_config = ConfigDict(extra="ignore")

    return Mutant


def _envelope_accepting_any_version() -> type[BaseModel]:
    return create_model("Mutant", __base__=StageContractPreimage, preimage_version=(str, ...))


def _envelope_accepting_any_class() -> type[BaseModel]:
    return create_model("Mutant", __base__=StageContractPreimage, content_class=(str, ...))


def _content_accepting_undeclared_fields() -> type[BaseModel]:
    class OpenContent(StageContractContent):
        model_config = ConfigDict(extra="ignore")

    return create_model("Mutant", __base__=StageContractPreimage, content=(OpenContent, ...))


def _record_accepting_undeclared_fields() -> type[BaseModel]:
    class Mutant(AuthorizationRecord):
        model_config = ConfigDict(extra="ignore")

    return Mutant


def _artifact_envelope_accepting_any_class() -> type[BaseModel]:
    return create_model("Mutant", __base__=ArtifactContentPreimage, content_class=(str, ...))


def _artifact_envelope_accepting_any_encoding() -> type[BaseModel]:
    return create_model("Mutant", __base__=ArtifactContentPreimage, content_encoding=(str, ...))


STORE_TESTS = "tests_gpauto/test_ga17_st03_store.py"
RESOLUTION_TESTS = "tests_gpauto/test_ga18_st03_root_resolution.py"
KEYS_KILLER = f"{STORE_TESTS}::test_the_frozen_keys_make_each_forbidden_duplicate_inexpressible"
MULTIPLICITY_KILLER = (
    f"{STORE_TESTS}::test_two_outcomes_of_one_stage_coexist_and_each_is_referenced_distinctly"
)
CREATE_ONLY_KILLER = (
    f"{STORE_TESTS}::"
    "test_no_update_delete_or_replace_reaches_any_table_through_a_configured_connection"
)


def _store_mutant(
    guard: str, identifier: str, description: str, original: str, replacement: str, killer: str
) -> LineMutant:
    return LineMutant(guard, identifier, description, original, replacement, killer)


ST03_MUTANTS: Final[tuple[LineMutant, ...]] = (
    _store_mutant(
        "ga_store_write_class",
        "WC-01-update-trigger-neutered",
        "the no-update trigger selects its message instead of raising",
        "BEGIN SELECT RAISE(ABORT, 'GPAUTO_NO_UPDATE: {name}'); END",
        "BEGIN SELECT ('GPAUTO_NO_UPDATE: {name}'); END",
        CREATE_ONLY_KILLER,
    ),
    _store_mutant(
        "ga_store_write_class",
        "WC-02-delete-trigger-neutered",
        "the no-delete trigger selects its message instead of raising",
        "BEGIN SELECT RAISE(ABORT, 'GPAUTO_NO_DELETE: {name}'); END",
        "BEGIN SELECT ('GPAUTO_NO_DELETE: {name}'); END",
        CREATE_ONLY_KILLER,
    ),
    _store_mutant(
        "ga_store_write_class",
        "WC-03-ingest-writable",
        "the write surface admits every domain, the ingest domain included",
        "if layout.spec.domain is Domain.COORDINATION",
        "if layout.spec.domain in Domain",
        f"{STORE_TESTS}::test_an_ingest_record_meets_no_write_operation",
    ),
    _store_mutant(
        "ga_store_referential_integrity",
        "RI-01-foreign-keys-dropped",
        "no FOREIGN KEY clause is emitted for any table",
        "for foreign in table_references(layout, catalogue)[0]:",
        "for foreign in table_references(layout, catalogue)[0][:0]:",
        f"{STORE_TESTS}::test_a_dangling_reference_is_refused_and_nothing_is_committed",
    ),
    _store_mutant(
        "ga_store_referential_integrity",
        "RI-02-instance-triggers-dropped",
        "no instance-existence trigger is emitted",
        "for reference in instances:",
        "for reference in instances[:0]:",
        f"{STORE_TESTS}::test_an_instance_reference_requires_an_ingested_record_bearing_it",
    ),
    _store_mutant(
        "ga_store_referential_integrity",
        "RI-03-context-pair-split",
        "a classification context is keyed as two independent references, not one pair",
        "if node.cls is ClassificationContext:",
        "if node.cls is None:",
        f"{STORE_TESTS}::test_a_classification_context_must_name_a_boundary_fixed_for_its_own_root",
    ),
    _store_mutant(
        "ga_store_referential_integrity",
        "RI-04-declared-references-dropped",
        "the references a table declares — finding membership, obligation membership — vanish",
        "for reference in layout.spec.references:",
        "for reference in layout.spec.references[:0]:",
        f"{STORE_TESTS}::test_a_finding_cannot_exist_outside_its_frozen_set",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-01-epoch-anchor-weakened",
        "MC-17(ii) keyed on (instance, resolution) instead of the instance alone",
        '("result__ResolvedRootResult__resolved_root",)',
        '("result__ResolvedRootResult__resolved_root", "identity__resolution")',
        f"{RESOLUTION_TESTS}::test_at_most_one_completed_resolution_names_an_instance",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-02-a2-binding-unfixed",
        "the A2 edge no longer fixes the resolved-root binding",
        "\"(edge = 'A2') = (result__kind = 'ResolvedRootResult')\"",
        "\"1 OR (result__kind = 'ResolvedRootResult')\"",
        f"{RESOLUTION_TESTS}::test_a_result_binding_is_admitted_only_on_its_own_edge",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-03-a3-binding-unfixed",
        "the A3 edge no longer fixes the refusal binding",
        "\"(edge = 'A3') = (result__kind = 'RefusalResult')\"",
        "\"1 OR (result__kind = 'RefusalResult')\"",
        f"{RESOLUTION_TESTS}::test_a_result_binding_is_admitted_only_on_its_own_edge",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-04-a4-binding-unfixed",
        "the A4 edge no longer fixes the ambiguity binding",
        "\"(edge = 'A4') = (result__kind = 'AmbiguityResult')\"",
        "\"1 OR (result__kind = 'AmbiguityResult')\"",
        f"{RESOLUTION_TESTS}::test_a_result_binding_is_admitted_only_on_its_own_edge",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-05-chain-may-fork",
        "MC-2 widened with the entry's own discriminator, so one predecessor has two successors",
        'Unique((subject, "predecessor__Present__value__discriminator")),',
        'Unique((subject, "predecessor__Present__value__discriminator", '
        '"identity__discriminator")),',
        f"{STORE_TESTS}::test_append_only_classes_accept_only_new_rows_naming_a_predecessor",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-06-two-first-entries",
        "a chain's affirmatively-first entry is no longer unique per subject",
        "Unique((subject,), \"predecessor__kind = 'KnownAbsent'\"),",
        'Unique((subject, "identity__discriminator"), "predecessor__kind = \'KnownAbsent\'"),',
        f"{STORE_TESTS}::test_append_only_classes_accept_only_new_rows_naming_a_predecessor",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-07-second-boundary-per-root",
        "RS7-1: the unique root key on RC-17 removed",
        'unique=(Unique(("resolved_root",)),),  # guard:ga_store_keys (RS7-1)',
        "unique=(),  # guard:ga_store_keys (RS7-1)",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-08-envelope-reuse",
        "CO-7: the unique envelope key on RC-19 removed",
        'unique=(Unique(("envelope",)),),',
        "unique=(),",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-09-second-set-per-epoch",
        "FP-17: the unique root key on RC-26 removed",
        'unique=(Unique(("resolved_root",)),),  # guard:ga_store_keys (FP-17)',
        "unique=(),  # guard:ga_store_keys (FP-17)",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-10-second-dispatch",
        "MH-7: the unique envelope key on the dispatch record removed",
        'unique=(Unique(("correlation__envelope",)),),',
        "unique=(),",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-11-second-ingestion",
        "MH-13: the unique activation key on the ingestion record removed",
        'unique=(Unique(("activation",)),),',
        "unique=(),",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-12-derivation-key-widened",
        "MC-15 widened with the envelope's own identity",
        '"envelope__role",  # guard:ga_store_keys',
        '"envelope__role", "envelope__identity",  # guard:ga_store_keys',
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-13-second-cycle-occurrence",
        "MC-16: the (predecessor entry, S6) key removed",
        "unique=(Unique(CYCLE_OCCURRENCE_KEY),),",
        "unique=(),",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-14-second-adoption",
        "MC-2: adoption no longer unique per activation",
        "\"determination__kind = 'AdoptionDetermination'\",",
        "\"determination__kind = 'NoSuchVariant'\",",
        KEYS_KILLER,
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-15-second-first-attempt",
        "MC-17(i): the first attempt's anchor no longer unique",
        "\"predecessor_terminal_entry__kind = 'KnownAbsent'\",",
        "\"predecessor_terminal_entry__kind = 'NoSuchVariant'\",",
        f"{RESOLUTION_TESTS}::test_one_attempt_anchor_admits_one_occurrence",
    ),
    _store_mutant(
        "ga_store_keys",
        "KY-16-outcome-unique-per-stage",
        "ID-8 (GA03-R01): RC-36 reverted to one outcome per stage — parent stage alone unique",
        '"identity",  # guard:ga_store_keys (ID-8)',
        '"identity", unique=(Unique(("identity__parent_stage",)),),  # guard:ga_store_keys (ID-8)',
        MULTIPLICITY_KILLER,
    ),
    _store_mutant(
        "ga_store_stale_schema",
        "SS-01-version-unchecked",
        "the storage version is not compared",
        "if version != STORAGE_VERSION:",
        "if False:",
        f"{STORE_TESTS}::test_a_store_under_another_storage_version_is_refused_and_left_untouched",
    ),
    _store_mutant(
        "ga_store_stale_schema",
        "SS-02-structure-unchecked",
        "the schema structure is not compared",
        "if actual != expected:",
        "if False:",
        f"{STORE_TESTS}::test_a_store_under_an_altered_structure_is_refused_and_left_untouched",
    ),
    _store_mutant(
        "ga_store_stale_schema",
        "SS-03-refusal-ignored",
        "an incompatibility is found and the store is opened anyway",
        "if reason:",
        "if False:",
        f"{STORE_TESTS}::test_a_store_under_another_storage_version_is_refused_and_left_untouched",
    ),
)

DERIVATION_TESTS = "tests_gpauto/test_ga21_st04_derivations.py"


def _derivation_mutant(
    identifier: str, description: str, original: str, replacement: str, killer: str
) -> LineMutant:
    return LineMutant(
        "ga_derivation_input",
        identifier,
        description,
        original,
        replacement,
        f"{DERIVATION_TESTS}::{killer}",
    )


ST04_MUTANTS: Final[tuple[LineMutant, ...]] = (
    _derivation_mutant(
        "DI-01-m1-any-subject",
        "an M1 chain takes every resolution's entries",
        "if e.identity.resolution == resolution",
        "if True",
        "test_recorded_eligibility_reads_the_completing_entry_and_nothing_else",
    ),
    _derivation_mutant(
        "DI-02-m2-any-subject",
        "an M2 chain takes every epoch's entries",
        "if e.identity.epoch_root == root",
        "if True",
        "test_each_subject_position_is_its_own_chain_walked_by_reference",
    ),
    _derivation_mutant(
        "DI-03-m3-any-subject",
        "an M3 chain takes every envelope's entries",
        "if e.identity.envelope == envelope",
        "if True",
        "test_each_subject_position_is_its_own_chain_walked_by_reference",
    ),
    _derivation_mutant(
        "DI-04-m4-any-subject",
        "an M4 chain takes every instance's entries",
        "if e.identity.authorization == authorization",
        "if True",
        "test_each_subject_position_is_its_own_chain_walked_by_reference",
    ),
    _derivation_mutant(
        "DI-05-any-adoption",
        "completion counts another activation's adoption record",
        "if d.identity.activation == activation.identity",
        "if True",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-06-any-effect",
        "an activation's term takes every activation's effects",
        "if e.identity.parent_activation == activation.identity",
        "if True",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-07-any-conformance",
        "an activation's term reads any envelope-conformance determination",
        "if c.identity.activation == activation.identity",
        "if True",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-08-out-of-envelope-kept",
        "an effect outside the envelope enters the prior state",
        "if judged[e.identity] == {True}",
        "if True",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-09-any-boundary",
        "the prior state takes any epoch's entry boundary",
        "if b.resolved_root == root",
        "if True",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-10-other-epochs-activations",
        "activations of another epoch are strata candidates",
        "if other.resolved_root != root:",
        "if False:",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-11-not-strictly-before",
        "every other stratum, later ones included, is a prior term",
        "if not place < before:",
        "if not place != before:",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-12-uncompleted-kept",
        "an unadopted activation's effects enter the prior state",
        "if not _completed(records, other):",
        "if False:",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-13-any-closure-activation",
        "a closure scope takes every closure activation's assessments",
        "if assessed.closure_activation == closure_activation:",
        "if True:",
        "test_closure_scope_is_the_findings_that_closure_activations_assessments_name",
    ),
    _derivation_mutant(
        "DI-14-non-member-established",
        "an obligation for a non-member is established",
        "if obligation.member_finding not in frozen.members:",
        "if False:",
        "test_an_obligation_not_established_for_a_member_is_not_in_force",
    ),
    _derivation_mutant(
        "DI-15-o6-extinguishes",
        "any decision carrying an obligation referent (O6 too) extinguishes",
        "if isinstance(decision.act, ObligationExtinguishingDecision)",
        'if hasattr(decision.act, "obligation")',
        "test_an_o6_obligation_change_does_not_extinguish_force",
    ),
    _derivation_mutant(
        "DI-16-any-referent",
        "a waiver naming another obligation extinguishes this one",
        "and decision.act.obligation == obligation",
        "and True",
        "test_a_waiver_naming_another_obligation_does_not_extinguish_this_one",
    ),
    _derivation_mutant(
        "DI-17-first-entry-read",
        "the epoch's first entry is read instead of the one reached",
        "epoch[-1].state in TERMINAL_EPOCH_STATES",
        "epoch[0].state in TERMINAL_EPOCH_STATES",
        "test_force_ends_exactly_when_the_epoch_is_terminal",
    ),
    _derivation_mutant(
        "DI-18-any-epochs-set",
        "the bound takes any epoch's frozen set",
        "if s.resolved_root == root",
        "if True",
        "test_cycle_bound_ranges_over_this_epochs_set_only",
    ),
    _derivation_mutant(
        "DI-19-other-sets-obligations",
        "another set's obligations are applicable",
        "if obligation.identity.parent_frozen_set != frozen.identity:",
        "if False:",
        "test_cycle_bound_ranges_over_this_epochs_set_only",
    ),
    _derivation_mutant(
        "DI-20-force-ignored",
        "an extinguished obligation stays applicable",
        "if isinstance(force, ObligationForce) and force.in_force:",
        "if isinstance(force, ObligationForce):",
        "test_a_waived_or_deferred_obligation_leaves_the_applicable_set_and_the_bound",
    ),
    _derivation_mutant(
        "DI-21-any-epochs-closure",
        "another epoch's closure activation attests",
        "if a.resolved_root == root",
        "if True",
        "test_only_this_epochs_completed_closure_activations_attest",
    ),
    _derivation_mutant(
        "DI-22-any-role-attests",
        "a non-closure activation named as closure activation attests",
        "and a.role == Role.BOUNDED_CLOSURE_VERIFIER",
        "and True",
        "test_only_this_epochs_completed_closure_activations_attest",
    ),
    _derivation_mutant(
        "DI-23-unadopted-closure-attests",
        "an unadopted closure activation attests",
        "and _completed(records, a)",
        "and True",
        "test_only_this_epochs_completed_closure_activations_attest",
    ),
    _derivation_mutant(
        "DI-24-any-assessment-attests",
        "an assessment from any activation attests",
        "if r.assessment.identity.closure_activation in closers",
        "if True",
        "test_only_this_epochs_completed_closure_activations_attest",
    ),
    _derivation_mutant(
        "DI-25-not-closed-attests",
        "a NOT_CLOSED verdict attests",
        "and isinstance(r.verdict, ClosedVerdict)",
        "and True",
        "test_cycle_bound_is_the_applicable_set_minus_members_attested_closed",
    ),
    _derivation_mutant(
        "DI-26-any-events-halt",
        "another event's halt occurrence resolves this suspension",
        "if h.event == event",
        "if True",
        "test_a_suspension_with_no_halt_or_only_another_events_resolution_stays_unresolved",
    ),
    _derivation_mutant(
        "DI-27-outstanding-dropped",
        "an outstanding halt occurrence is read as resolved",
        "if o not in resolved",
        "if False",
        "test_an_unresolved_suspending_event_makes_the_instance_not_live",
    ),
    _derivation_mutant(
        "DI-28-any-instances-disposition",
        "another instance's establishing record counts",
        "if r.identity.authorization == authorization",
        "if True",
        "test_consumption_and_revocation_each_end_liveness_for_their_instance_only",
    ),
    _derivation_mutant(
        "DI-29-any-resolution-occurrence",
        "recorded eligibility accepts any RC-14 occurrence",
        "if r.identity == resolution",
        "if True",
        "test_recorded_eligibility_reads_the_completing_entry_and_nothing_else",
    ),
    _derivation_mutant(
        "DI-30-resolved-halt-outstanding",
        "a resolved halt occurrence is outstanding",
        "if h.identity not in named",
        "if True",
        "test_outstanding_halts_are_those_no_resolution_names_and_coexist",
    ),
    _derivation_mutant(
        "DI-31-any-occurrences-closure",
        "an occurrence's closure is any occurrence's",
        "and run.cycle_occurrence.value == occurrence.identity",
        "and True",
        "test_the_series_follows_occurrence_references_and_strictly_decreases",
    ),
    _derivation_mutant(
        "DI-32-any-role-closes",
        "a remediator bound to the occurrence is its closure",
        "and run.role == Role.BOUNDED_CLOSURE_VERIFIER",
        "and True",
        "test_the_series_follows_occurrence_references_and_strictly_decreases",
    ),
    _derivation_mutant(
        "DI-33-unadopted-closes",
        "an unadopted closure activation closes the occurrence",
        "and _completed(records, run)",
        "and True",
        "test_an_occurrence_without_a_completed_closure_ends_the_series_affirmatively",
    ),
    _derivation_mutant(
        "DI-34-any-epochs-occurrence",
        "the series takes another epoch's occurrences",
        "if c.predecessor_entry.epoch_root == root",
        "if True",
        "test_the_series_follows_occurrence_references_and_strictly_decreases",
    ),
    _derivation_mutant(
        "DI-35-any-successor",
        "the series follows any occurrence as successor",
        "and c.predecessor_closure_activation.value == closer",
        "and True",
        "test_the_series_follows_occurrence_references_and_strictly_decreases",
    ),
    _derivation_mutant(
        "DI-36-torn-read-used",
        "a read whose two passes differ is used as the record set",
        "if passes[0] != passes[1]:",
        "if False:",
        "test_a_read_whose_two_passes_differ_is_unstable_and_never_used",
    ),
    _derivation_mutant(
        "DI-37-undecodable-record-dropped",
        "a stored record that does not decode is dropped, and its class read as complete",
        "if isinstance(item, UnreadableRecord):",
        "if False:",
        "test_an_undecodable_stored_record_marks_its_class_unreadable",
    ),
    _derivation_mutant(
        "DI-38-unreadable-class-used",
        "a class with an unreadable record is derived over from its readable remainder",
        "if kind in records.unreadable:",
        "if False:",
        "test_an_unreadable_input_class_makes_the_derivation_indeterminate",
    ),
    _derivation_mutant(
        "DI-39-unstable-class-used",
        "a class not read as one consistent set is derived over as though empty",
        "if kind in records.unstable:",
        "if False:",
        "test_a_read_whose_two_passes_differ_is_unstable_and_never_used",
    ),
    _derivation_mutant(
        "DI-40-conflicting-judgements-admitted",
        "disagreeing envelope determinations for one effect are admitted as input",
        "if any(len(judgements) > 1 for judgements in judged.values()):",
        "if False:",
        "test_conflicting_envelope_determinations_for_one_effect_make_dv1_indeterminate",
    ),
    _derivation_mutant(
        "DI-41-another-activation-assessed",
        "DV-1 is computed for an activation other than the one named",
        "if a.identity == assessed",
        "if a.identity != assessed",
        "test_the_prior_authorized_state_is_computed_for_the_named_activation",
    ),
    _derivation_mutant(
        "DI-42-unrecorded-obligation-established",
        "a member with no obligation record of its own is read as established",
        "if o.identity == obligation",
        "if True",
        "test_an_obligation_is_established_only_by_its_own_record_and_its_own_set",
    ),
    _derivation_mutant(
        "DI-43-another-set-establishes",
        "an obligation naming no recorded set is established by another set",
        "if s.identity == obligation.parent_frozen_set",
        "if True",
        "test_an_obligation_is_established_only_by_its_own_record_and_its_own_set",
    ),
    _derivation_mutant(
        "DI-44-resolved-suspension-kept",
        "a suspension whose event is resolved still ends liveness",
        "and _still_suspending(",
        "and (lambda *_: True)(",
        "test_a_resolution_naming_the_suspending_events_halt_restores_liveness",
    ),
    _derivation_mutant(
        "DI-45-open-entry-read-as-completing",
        "the opening A1 entry is read as the completing entry",
        "if entry.edge in COMPLETING_EDGES",
        "if True",
        "test_recorded_eligibility_reads_the_completing_entry_and_nothing_else",
    ),
    _derivation_mutant(
        "DI-46-attested-member-kept",
        "an obligation whose member is attested closed stays in the bound",
        "if o.member_finding not in attested",
        "if True",
        "test_cycle_bound_is_the_applicable_set_minus_members_attested_closed",
    ),
    _derivation_mutant(
        "DI-47-another-envelope-keyed",
        "an activation's stratum is read from another recorded envelope, the first read",
        "envelopes.get(activation.envelope)",
        "envelopes.get(next(iter(envelopes)))",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-48-another-stratum-keyed",
        "an activation's stratum is read at another M2 entry of its epoch, the first",
        "strata[envelope.predecessor_entry]",
        "strata[next(iter(strata))]",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
    _derivation_mutant(
        "DI-49-another-effects-judgement-keyed",
        "an effect is judged by another effect's envelope judgement, the first recorded",
        "judged[e.identity]",
        "judged[effects[0].identity]",
        "test_the_prior_authorized_state_is_the_boundary_plus_earlier_completed_effects",
    ),
)
"""`GP-AUTO-ST-04`'s mutants: one per input-selection guard line in `derivations.py`, each
feeding the derivation a plausible wrong input — another subject's, another epoch's, a
later stratum's, an unadopted activation's, a non-naming or non-extinguishing decision's,
an undecodable or torn read, a disagreeing determination. Every killer is a `test_ga21`
case whose record set contains that wrong input."""

ST04_UNMUTATED_PREDICATES: Final[dict[tuple[str, str], str]] = {
    # Input selections with no plausible-value mutant: every wrong selection fails closed.
    ("_of", "type(record) is kind"): (
        "class selection: a record of another class lacks the fields read next, so a wrong"
        " class crashes; the record classes have no subclasses, so isinstance is equivalent"
    ),
    ("_walk", "isinstance(entry.predecessor, KnownAbsent)"): (
        "first-entry selection: any other choice fails the one-first and reachability checks"
        " (BROKEN_CHAIN)"
    ),
    ("_completed", "entry.edge == M3Edge.C4"): (
        "C4 selection: any other choice disagrees with the adoption record or is counted"
        " twice (INCONSISTENT_RECORDS)"
    ),
    ("_completed", "isinstance(d.determination, AdoptionDetermination)"): (
        "adoption selection: admitting other RC-39 classes counts a completed activation's"
        " records twice, and an unadopted one's without C4 (INCONSISTENT_RECORDS)"
    ),
    ("_authorized_effects", "isinstance(c.determination, EnvelopeConformanceDetermination)"): (
        "envelope-class selection: other RC-39 classes carry no per-effect judgement, so"
        " admitting them crashes"
    ),
    ("derive_liveness", "isinstance(d, ConsumedDisposition)"): (
        "variant selection: the establishing field read next exists on this variant only"
    ),
    ("derive_liveness", "isinstance(d, RevokedDisposition)"): (
        "variant selection: the establishing field read next exists on this variant only"
    ),
    ("derive_liveness", "isinstance(d, SuspendedDisposition)"): (
        "variant selection: the establishing field read next exists on this variant only"
    ),
    ("_closing_activation", "isinstance(run.cycle_occurrence, Present)"): (
        "presence test: an absent occurrence has no value to read, so admitting it crashes"
    ),
    ("derive_closure_scope_series", "isinstance(c.predecessor_closure_activation, KnownAbsent)"): (
        "first-occurrence selection: any other choice leaves an occurrence unreachable"
        " (BROKEN_CHAIN) or is not unique (INCONSISTENT_RECORDS)"
    ),
    ("derive_closure_scope_series", "isinstance(c.predecessor_closure_activation, Present)"): (
        "presence test: an absent predecessor has no value to read, so admitting it crashes"
    ),
    ("derive_closure_scope_series", "isinstance(s.closure, ClosureScope)"): (
        "step selection: a step with no completed closure has no members, so admitting it crashes"
    ),
    # Not input selections: each raises indeterminacy, or returns a fixed affirmative-absence
    # value, on a cardinality or consistency condition over inputs already selected.
    ("_one", "not found"): "cardinality: MISSING_RECORD",
    ("_one", "len(found) > 1"): "cardinality: INCONSISTENT_RECORDS",
    ("_walk", "not subject_entries"): "empty chain: Unoccupied",
    ("_walk", "len(firsts) != 1"): "chain structure: BROKEN_CHAIN",
    ("_walk", "isinstance(entry.predecessor, Present)"): "chain structure: successor map",
    ("_walk", "entry.predecessor.value in successor"): "chain structure: BROKEN_CHAIN",
    ("_walk", "len(walked) != len(subject_entries)"): "chain structure: BROKEN_CHAIN",
    ("_completed", "len(c4_entries) > 1 or len(adoptions) > 1"): "consistency",
    ("_completed", "c4_entries and chain[-1] is not c4_entries[0]"): "consistency",
    ("_completed", "bool(c4_entries) != bool(adoptions)"): "consistency",
    ("_stratum", "envelope is None"): "cardinality: MISSING_RECORD",
    ("_stratum", "envelope.predecessor_entry not in strata"): "consistency",
    ("_authorized_effects", "not determinations"): "cardinality: MISSING_RECORD",
    ("_authorized_effects", "set(judged) != {effect.identity for effect in effects}"): (
        "consistency: every recorded effect judged, and only those"
    ),
    ("derive_prior_authorized_state", "place in terms"): "consistency",
    ("_obligation_force", "not recorded or not sets"): "affirmative absence: NotEstablished",
    ("_obligation_force", "not epoch"): "cardinality: MISSING_RECORD",
    ("_cycle_bound", "not sets"): "affirmative absence: NoFrozenSet",
    ("derive_recorded_eligibility", "not chain"): "cardinality: MISSING_RECORD",
    ("derive_recorded_eligibility", "not completing"): "affirmative absence: OpenResolution",
    (
        "derive_recorded_eligibility",
        "len(completing) > 1 or chain[-1] is not completing[0]",
    ): "consistency",
    ("_closing_activation", "len(bound) > 1"): "consistency",
    ("derive_closure_scope_series", "not occurrences"): "affirmative absence: empty series",
    ("derive_closure_scope_series", "closer is None"): "affirmative absence: NoCompletedClosure",
    ("derive_closure_scope_series", "not following"): "end of the walk",
    ("derive_closure_scope_series", "len(steps) != len(occurrences)"): "chain: BROKEN_CHAIN",
}
"""ST-04's input-selection inventory, completed (`ST04-IMPL-R02`): every predicate in
`derivations.py` that is **not** a `ga_derivation_input` line, with the reason it carries
no mutant. `test_ga23` enumerates every comprehension filter and `if` test in the module
and requires each to be either on a tagged line or here, so a new selection cannot be
added untagged and unlisted. The Mutation cell's criterion decides membership: a guard is
mutated where a wrong input would still produce a plausible value."""

ST04_KEYED_SELECTIONS: Final[dict[tuple[str, str], tuple[str, ...]]] = {
    ("_stratum", "envelopes.get(activation.envelope)"): ("DI-47-another-envelope-keyed",),
    ("_stratum", "strata[envelope.predecessor_entry]"): ("DI-48-another-stratum-keyed",),
    ("_authorized_effects", "judged[e.identity]"): ("DI-49-another-effects-judgement-keyed",),
    ("_obligation_force", "epoch[-1]"): ("DI-17-first-entry-read",),
}
"""ST-04's keyed input selections (`ST04-IMPL-R02`): each keyed access in `derivations.py`
by which a derivation takes one authoritative record — or one record's judgement or place
— out of several valid ones, where another key selects another valid record and the
derivation still returns a determinate, plausible value. Each is on a `ga_derivation_input`
line and carries a mutant that changes the **key** and nothing else: its activation's own
envelope, that envelope's own `MC-15` predecessor entry, the effect's own judgement, the
epoch's reached M2 entry."""

NON_SELECTION = "non-selection"
SINGLE_LAWFUL_VALUE = "single-lawful-value"
FAIL_CLOSED = "fail-closed"

ST04_UNQUALIFIED_KEYED_ACCESSES: Final[dict[tuple[str, str], tuple[int, str, str]]] = {
    ("read_authoritative_records", "passes[0]"): (
        2,
        SINGLE_LAWFUL_VALUE,
        "the two passes are compared, and the one returned is returned only when both are"
        " equal: either index is the same value",
    ),
    ("read_authoritative_records", "passes[1]"): (
        1,
        NON_SELECTION,
        "an operand of the two-pass agreement test, itself the tagged DI-36 guard",
    ),
    ("_one", "found[0]"): (1, SINGLE_LAWFUL_VALUE, "read only once `found` has exactly one"),
    ("_walk", "firsts[0]"): (1, SINGLE_LAWFUL_VALUE, "read only once `firsts` has exactly one"),
    ("_walk", "successor[entry.predecessor.value]"): (
        1,
        NON_SELECTION,
        "a write: the successor map is keyed by each entry's own recorded predecessor",
    ),
    ("_walk", "walked[-1]"): (
        2,
        FAIL_CLOSED,
        "the walk's cursor: any other walked entry revisits one, so the walk overruns the"
        " subject's entries and the reachability check fails (BROKEN_CHAIN)",
    ),
    ("_walk", "successor[walked[-1].identity]"): (
        1,
        FAIL_CLOSED,
        "follows the cursor's own identity: another walked entry's key repeats an entry"
        " (BROKEN_CHAIN), and an unwalked key is absent from the map",
    ),
    ("derive_m1_position", "chain[-1]"): (
        1,
        NON_SELECTION,
        "projects DV-6's own result — the walked chain's end — and selects no input; its"
        " value is pinned by test_ga21's position cases",
    ),
    ("derive_m2_position", "chain[-1]"): (1, NON_SELECTION, "as derive_m1_position"),
    ("derive_m3_position", "chain[-1]"): (1, NON_SELECTION, "as derive_m1_position"),
    ("derive_m4_position", "chain[-1]"): (1, NON_SELECTION, "as derive_m1_position"),
    ("_completed", "chain[-1]"): (
        1,
        FAIL_CLOSED,
        "an operand of the C4-is-final consistency test: any other entry of a chain holding"
        " C4 raises INCONSISTENT_RECORDS",
    ),
    ("_completed", "c4_entries[0]"): (
        1,
        SINGLE_LAWFUL_VALUE,
        "read only once `c4_entries` has at most one",
    ),
    ("_authorized_effects", "judged.setdefault(item.effect, set())"): (
        1,
        NON_SELECTION,
        "a write: judgements are collected under each one's own recorded effect; any other"
        " key breaks the judged-equals-recorded check (INCONSISTENT_RECORDS)",
    ),
    ("derive_prior_authorized_state", "terms[place]"): (
        2,
        SINGLE_LAWFUL_VALUE,
        "written once per stratum and read back over its own keys, each exactly once",
    ),
    ("derive_recorded_eligibility", "chain[-1]"): (
        1,
        FAIL_CLOSED,
        "an operand of the completing-entry-is-final consistency test (INCONSISTENT_RECORDS)",
    ),
    ("derive_recorded_eligibility", "completing[0]"): (
        2,
        SINGLE_LAWFUL_VALUE,
        "read only once `completing` has exactly one",
    ),
    ("_closing_activation", "bound[0]"): (
        1,
        SINGLE_LAWFUL_VALUE,
        "read only once `bound` has exactly one",
    ),
    ("derive_closure_scope_series", "scopes[1:]"): (
        1,
        NON_SELECTION,
        "a slice pairing every scope with its successor for the CO-18 test over all of"
        " them; it selects no record",
    ),
}
"""Every other keyed access in `derivations.py` — subscript, `.get`, `.setdefault` — with
the number of times its text occurs in its function, its class and its reason. The classes
are the Mutation cell's exclusions: **non-selection** (a write, an operand of a
consistency test already inventoried, or a projection of the derivation's own result);
**single-lawful-value** (only one key or value can exist where it is read); **fail-closed**
(every other key raises indeterminacy or cannot occur). `test_ga23` enumerates every keyed
access outside an annotation and requires each to be here or in `ST04_KEYED_SELECTIONS`,
by text and by count. Membership tests (`in`, `not in`) are predicates, and are
inventoried with them in `ST04_UNMUTATED_PREDICATES` or tagged."""


ST05_MODEL_TESTS = "tests_gpauto/test_ga25_st05_model.py"
ST05_RECORDS_TESTS = "tests_gpauto/test_ga27_st05_restart_and_mutation.py"
ST05_KILLER = f"{ST05_MODEL_TESTS}::test_every_condition_is_individually_falsifiable"
ST05_DEDICATED_KILLERS: Final[dict[str, str]] = {
    "C1-6": f"{ST05_MODEL_TESTS}::test_c1_derives_no_envelope_over_an_unaccounted_mutation",
    "C2-8": f"{ST05_RECORDS_TESTS}::"
    "test_c2_admits_a_dispatch_only_against_the_committed_cycle_bound",
    "B13-4": f"{ST05_RECORDS_TESTS}::"
    "test_b13_refuses_a_cycle_occurrence_binding_that_is_missing_or_inconsistent",
}
"""`ST05-IMPL-R01`…`R03`: the remediated conditions, each killed by its own test."""


def _model_parts(
    rule: state_machine_model.EdgeRule,
) -> tuple[tuple[str, tuple[state_machine_model.Condition, ...]], ...]:
    guard = rule.guard
    if isinstance(guard, state_machine_model.Stratified):
        return (("own", guard.own), ("tier0", guard.tier0), ("tier1", guard.tier1))
    return tuple((str(index), part) for index, part in enumerate(guard.alternatives))


ST05_MODEL_MUTANTS: Final[tuple[ModelMutant, ...]] = tuple(
    ModelMutant(
        guard="ga_transition_guard",
        identifier=f"TG-{rule.edge}-{part}-{condition.identifier}",
        description=f"{rule.edge}'s guard ({part}) without condition {condition.identifier}",
        edge=str(rule.edge),
        part=part,
        condition=condition.identifier,
        killer=ST05_DEDICATED_KILLERS.get(condition.identifier, ST05_KILLER),
    )
    for rule in state_machine_model.EDGES
    for part, conditions in _model_parts(rule)
    for condition in conditions
)
"""One mutant per (edge, part, condition) of the unmutated model — generated, so a
condition added to the model gets its mutant, and `test_ga27` checks none is missing."""

ST05_INVERSION_MUTANTS: Final[tuple[ModelMutant, ...]] = tuple(
    ModelMutant(
        guard="ga_transition_guard",
        identifier=f"TG-{edge}-0-{condition}-inverted",
        description=f"{edge}'s condition {condition} admits {' / '.join(admitted)} instead",
        edge=edge,
        part="0",
        condition=condition,
        killer=ST05_DEDICATED_KILLERS[condition],
        admitted=admitted,
    )
    for edge, condition, admitted in (
        ("C1", "C1-6", state_machine_model.T),
        ("C2", "C2-8", (state_machine_model.UNEQUAL, state_machine_model.NOT_APPLICABLE)),
        ("B13", "B13-4", state_machine_model.F),
    )
)
"""`ST05-IMPL-R01`…`R03`: each remediated condition inverted — `V-06` admitting an
unaccounted mutation, `OP-8` admitting an unequal set, `HB-1` admitting an unbound
occurrence — so omission and inversion are both shown detected."""


def _evaluator_mutant(
    identifier: str, description: str, original: str, replacement: str, killer: str
) -> LineMutant:
    guard = "ga_transition_evaluator"
    return LineMutant(guard, identifier, description, original, replacement, killer)


ST05_EVALUATOR_MUTANTS: Final[tuple[LineMutant, ...]] = (
    _evaluator_mutant(
        "EV-01-domain-open",
        "a value outside its fact's domain is used as it is, not read as INDETERMINATE",
        "return value if value in fact.values else model.INDETERMINATE",
        "return value",
        f"{ST05_MODEL_TESTS}::test_a_value_outside_its_domain_is_indeterminate",
    ),
    _evaluator_mutant(
        "EV-02-unmet-inverted",
        "a condition is reported unmet when its value is admitted",
        "if fact_value(facts, c.fact) not in c.admitted",
        "if fact_value(facts, c.fact) in c.admitted",
        ST05_KILLER,
    ),
    _evaluator_mutant(
        "EV-03-pair-always-expressible",
        "the position is not checked against the edge's sources",
        "if source not in rule.sources:",
        "if source not in rule.sources and False:",
        f"{ST05_MODEL_TESTS}::test_every_illegal_pair_is_refused_under_any_facts",
    ),
    _evaluator_mutant(
        "EV-04-all-alternatives",
        "every alternative must hold, not one",
        "if any(not failed for failed in failures):",
        "if all(not failed for failed in failures):",
        ST05_KILLER,
    ),
    _evaluator_mutant(
        "EV-05-tier0-falls-through",
        "CE-T1/CE-T2: a Tier-0 failure goes on to Tier 1",
        "if tier0:",
        "if tier0 and False:",
        f"{ST05_MODEL_TESTS}::test_the_stratified_cycle_predicate_in_all_four_cases",
    ),
    _evaluator_mutant(
        "EV-06-tier1-indeterminacy-ignored",
        "CE-T3: an indeterminate Tier 1 is read as false",
        "if unknown:",
        "if unknown and False:",
        f"{ST05_MODEL_TESTS}::test_the_stratified_cycle_predicate_in_all_four_cases",
    ),
    _evaluator_mutant(
        "EV-07-tier1-any",
        "Tier 1 holds when any condition holds",
        "holds = all(value in c.admitted for c, value in tier1)",
        "holds = any(value in c.admitted for c, value in tier1)",
        f"{ST05_MODEL_TESTS}::test_the_stratified_cycle_predicate_in_all_four_cases",
    ),
    _evaluator_mutant(
        "EV-08-tier1-polarity-inverted",
        "B8 takes Tier 1 true and B15 takes it false",
        "if holds != guard.tier1_holds:",
        "if holds == guard.tier1_holds:",
        f"{ST05_MODEL_TESTS}::test_the_stratified_cycle_predicate_in_all_four_cases",
    ),
    _evaluator_mutant(
        "EV-09-indeterminate-filter-inverted",
        "the determinate Tier-1 values are the ones reported unknown",
        "if value == model.INDETERMINATE",
        "if value != model.INDETERMINATE",
        f"{ST05_MODEL_TESTS}::test_the_stratified_cycle_predicate_in_all_four_cases",
    ),
    _evaluator_mutant(
        "EV-10-joint-pair-split",
        "K-9: a joint M2 edge is admitted without its M4 edge",
        "if coupling.joint and not moved:",
        "if coupling.joint and not moved and False:",
        f"{ST05_MODEL_TESTS}::test_b13_and_g6_fire_together_or_not_at_all",
    ),
    _evaluator_mutant(
        "EV-11-restoration-unbound",
        "HB-1: B13 takes any given restoration, whatever position the guard read",
        "if restoration is None or restoration.position != restored:",
        "if restoration is None:",
        f"{ST05_MODEL_TESTS}::test_b13_is_bound_to_the_named_halts_cycle_occurrence",
    ),
    _evaluator_mutant(
        "EV-12-halt-context-unbound",
        "SV11-6: B13 takes a restoration of another halt than the one its facts were read for",
        "if facts.get(NAMED_HALT) != restoration.halt.value:",
        "if facts.get(NAMED_HALT) != restoration.halt.value and False:",
        f"{ST05_RECORDS_TESTS}::"
        "test_b13_admits_only_the_restoration_of_the_halt_its_facts_were_read_for",
    ),
)

ST05_MUTANTS: Final[tuple[Mutant, ...]] = (
    *ST05_MODEL_MUTANTS,
    *ST05_INVERSION_MUTANTS,
    *ST05_EVALUATOR_MUTANTS,
)

MUTANTS: Final[tuple[Mutant, ...]] = (
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-01-negated-equality",
        description="`first_form == second_form` -> `first_form != second_form`",
        original="if first_form == second_form:",
        replacement="if first_form != second_form:",
        killer=f"{EQUIVALENCE_TESTS}::test_a_record_is_equivalent_to_itself",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-02-representational-comparison",
        description="compare the projections as objects (`first == second`), not normal forms",
        original="if first_form == second_form:",
        replacement="if first == second:",
        killer=f"{EQUIVALENCE_TESTS}::test_permuted_and_repeated_set_members_are_equivalent",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-03-always-equivalent",
        description="`first_form == second_form` -> `True`",
        original="if first_form == second_form:",
        replacement="if True:",
        killer=f"{EQUIVALENCE_TESTS}::test_differing_content_in_any_projection_class_is_not_equivalent",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-04-indeterminate-read-as-equivalent",
        description="a normal form that cannot be produced returns EQUIVALENT",
        original="return EquivalenceOutcome.INDETERMINATE  # guard:ga_equivalence_compare",
        replacement="return EquivalenceOutcome.EQUIVALENT  # guard:ga_equivalence_compare",
        killer=f"{EQUIVALENCE_TESTS}::test_an_unrepresentable_value_makes_the_comparison_indeterminate",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-05-cross-identity-computed",
        description="the single-identity refusal is skipped, so two identities are compared",
        original="if not same_identity:",
        replacement="if False:",
        killer=f"{EQUIVALENCE_TESTS}::test_cross_identity_comparison_is_refused_not_computed",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-06-totality-check-dropped",
        description="a projection mapping that is not total is compared anyway",
        original="if not (classes_total and fields_total):",
        replacement="if False:",
        killer=f"{EQUIVALENCE_TESTS}::test_a_projection_mapping_that_is_not_total_is_indeterminate",
    ),
    LineMutant(
        guard="ga_equivalence_compare",
        identifier="EQV-07-set-order-kept",
        description="set members keep their given order instead of the canonical order",
        original="return [members[key] for key in sorted(members)]",
        replacement="return list(members.values())",
        killer=f"{EQUIVALENCE_TESTS}::test_permuted_and_repeated_set_members_are_equivalent",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-01-envelope-extra-ignored",
        description='StageContractPreimage: extra="forbid" -> extra="ignore"',
        target="StageContractPreimage",
        build=_envelope_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_envelope_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-02-version-tag-widened",
        description="StageContractPreimage.preimage_version: Literal[...] -> str",
        target="StageContractPreimage",
        build=_envelope_accepting_any_version,
        killer=f"{CODEC_TESTS}::test_a_higher_format_version_is_refused_not_preferred",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-03-content-class-tag-widened",
        description="StageContractPreimage.content_class: Literal[STAGE_CONTRACT] -> str",
        target="StageContractPreimage",
        build=_envelope_accepting_any_class,
        killer=f"{CODEC_TESTS}::test_a_stage_contract_preimage_labelled_as_another_class_is_refused",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-04-content-extra-ignored",
        description='StageContractContent (inside the envelope): extra="forbid" -> "ignore"',
        target="StageContractPreimage",
        build=_content_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_content_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-05-record-extra-ignored",
        description='AuthorizationRecord: extra="forbid" -> extra="ignore"',
        target="AuthorizationRecord",
        build=_record_accepting_undeclared_fields,
        killer=f"{CODEC_TESTS}::test_an_undeclared_authorization_record_field_is_refused_never_dropped",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-06-artifact-class-tag-widened",
        description="ArtifactContentPreimage.content_class: Literal[ARTIFACT_CONTENT] -> str",
        target="ArtifactContentPreimage",
        build=_artifact_envelope_accepting_any_class,
        killer=f"{CODEC_TESTS}::test_an_artifact_preimage_labelled_as_another_class_is_refused",
    ),
    SchemaMutant(
        guard="ga_codec_decode",
        identifier="DEC-07-artifact-encoding-tag-widened",
        description="ArtifactContentPreimage.content_encoding: Literal[BASE16_LOWER] -> str",
        target="ArtifactContentPreimage",
        build=_artifact_envelope_accepting_any_encoding,
        killer=f"{CODEC_TESTS}::test_an_artifact_preimage_under_another_content_encoding_is_refused",
    ),
    *ST03_MUTANTS,
    *ST04_MUTANTS,
    *ST05_MUTANTS,
)


def source_path(module: types.ModuleType) -> Path:
    assert module.__file__ is not None
    return Path(module.__file__)


def guard_tags() -> dict[str, list[str]]:
    """`guard identifier -> ["file:line", ...]` over the GP-AUTO production package."""
    package = source_path(equivalence).parent
    tags: dict[str, list[str]] = {}
    for path in sorted(package.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for identifier in GUARD_TAG.findall(line):
                tags.setdefault(identifier, []).append(f"{path.name}:{number}")
    return tags


def resolve_killer(node_id: str) -> Callable[..., None]:
    """The killing test function a node id names, imported from the test tree."""
    relative, name = node_id.split("::")
    module = importlib.import_module(Path(relative).stem)
    killer = getattr(module, name)
    assert callable(killer)
    return killer  # type: ignore[no-any-return]


def mutated_source(mutant: LineMutant, *, control: bool = False) -> str:
    """The guarded module's source with the mutation applied — or, as a control, not.

    The fragment must occur exactly once, on a line carrying the guard's identifier: a
    mutation that silently matched nothing, or matched an unguarded line, would be a
    mutant of something other than the guard.
    """
    guard = GUARDS[mutant.guard]
    source = source_path(guard.module).read_text(encoding="utf-8")
    assert source.count(mutant.original) == 1, mutant.identifier
    (line,) = [line for line in source.splitlines() if mutant.original in line]
    assert f"# guard:{mutant.guard}" in line, mutant.identifier
    if control:
        return source
    mutated = source.replace(mutant.original, mutant.replacement, 1)
    assert mutated != source, mutant.identifier
    return mutated


@contextmanager
def _line_substituted(
    mutant: LineMutant, monkeypatch: pytest.MonkeyPatch, *, control: bool
) -> Iterator[None]:
    module = GUARDS[mutant.guard].module
    code = compile(mutated_source(mutant, control=control), f"<{mutant.identifier}>", "exec")
    # The mutated source runs as a module of its own, registered for the exec only: a
    # `@dataclass` in the guarded module resolves its annotations through `sys.modules`.
    scratch_module = types.ModuleType(f"{module.__name__}__mutant")
    sys.modules[scratch_module.__name__] = scratch_module
    try:
        exec(code, scratch_module.__dict__)
    finally:
        sys.modules.pop(scratch_module.__name__, None)
    scratch = scratch_module.__dict__
    for name, original in vars(module).items():
        if inspect.isfunction(original) and original.__module__ == module.__name__:
            compiled = scratch[name]
            assert isinstance(compiled, types.FunctionType)
            rebuilt = types.FunctionType(
                compiled.__code__, vars(module), name, compiled.__defaults__, None
            )
            rebuilt.__kwdefaults__ = compiled.__kwdefaults__
            rebuilt.__annotations__ = compiled.__annotations__
            monkeypatch.setattr(module, name, rebuilt)
    yield


@contextmanager
def _schema_substituted(
    mutant: SchemaMutant, monkeypatch: pytest.MonkeyPatch, *, control: bool
) -> Iterator[None]:
    module = GUARDS[mutant.guard].module
    original = getattr(module, mutant.target)
    assert isinstance(original, type) and issubclass(original, BaseModel)
    if control:
        replacement: type[BaseModel] = create_model("Control", __base__=original)
    else:
        replacement = mutant.build()
        assert issubclass(replacement, original), mutant.identifier
        assert _schema(replacement) != _schema(original), mutant.identifier
    monkeypatch.setattr(module, mutant.target, replacement)
    yield


@contextmanager
def _model_substituted(
    mutant: ModelMutant, monkeypatch: pytest.MonkeyPatch, *, control: bool
) -> Iterator[None]:
    """The model's edge table rebuilt with the one condition removed — or, as a control,
    rebuilt unchanged — and substituted for the table the evaluator reads."""
    m = state_machine_model
    rebuilt: list[state_machine_model.EdgeRule] = []
    removed = 0
    for rule in m.EDGES:
        guard = rule.guard
        if str(rule.edge) == mutant.edge and not control:
            before = sum(len(part) for _, part in _model_parts(rule))

            def drop(part: tuple[m.Condition, ...]) -> tuple[m.Condition, ...]:
                if mutant.admitted is None:
                    return tuple(c for c in part if c.identifier != mutant.condition)
                return tuple(
                    replace(c, admitted=mutant.admitted) if c.identifier == mutant.condition else c
                    for c in part
                )

            if isinstance(guard, m.Stratified):
                guard = m.Stratified(
                    own=drop(guard.own) if mutant.part == "own" else guard.own,
                    tier0=drop(guard.tier0) if mutant.part == "tier0" else guard.tier0,
                    tier1=drop(guard.tier1) if mutant.part == "tier1" else guard.tier1,
                    tier1_holds=guard.tier1_holds,
                )
            else:
                guard = m.Conjunctive(
                    tuple(
                        drop(part) if str(index) == mutant.part else part
                        for index, part in enumerate(guard.alternatives)
                    )
                )
            rule = m.EdgeRule(rule.edge, rule.machine, rule.sources, rule.target, guard, rule.row)
            removed += before - sum(len(part) for _, part in _model_parts(rule))
            removed += sum(
                1
                for _, part in _model_parts(rule)
                for c in part
                if mutant.admitted is not None
                and c.identifier == mutant.condition
                and c.admitted == mutant.admitted
            )
        else:
            rule = m.EdgeRule(rule.edge, rule.machine, rule.sources, rule.target, guard, rule.row)
        rebuilt.append(rule)
    assert control or removed == 1, mutant.identifier
    monkeypatch.setattr(m, "EDGES", tuple(rebuilt))
    yield


def _schema(model: type[BaseModel]) -> tuple[object, ...]:
    """What a schema mutation must change: configuration, or a field's annotation."""
    nested = model.model_fields.get("content")
    inner = nested.annotation if nested is not None else None
    inner_config = (
        inner.model_config.get("extra")
        if isinstance(inner, type) and issubclass(inner, BaseModel)
        else None
    )
    return (
        model.model_config.get("extra"),
        tuple((name, info.annotation) for name, info in model.model_fields.items()),
        inner_config,
    )


def run(mutant: Mutant, *, control: bool = False) -> str:
    """Run the named killing test against the mutant (or its control): KILLED or SURVIVED."""
    killer = resolve_killer(mutant.killer)
    with pytest.MonkeyPatch.context() as monkeypatch:
        substitute = (
            _line_substituted(mutant, monkeypatch, control=control)
            if isinstance(mutant, LineMutant)
            else _model_substituted(mutant, monkeypatch, control=control)
            if isinstance(mutant, ModelMutant)
            else _schema_substituted(mutant, monkeypatch, control=control)
        )
        with substitute:
            wants_monkeypatch = "monkeypatch" in inspect.signature(killer).parameters
            try:
                if wants_monkeypatch:
                    with pytest.MonkeyPatch.context() as killer_patch:
                        killer(monkeypatch=killer_patch)
                else:
                    killer()
            except (AssertionError, pytest.fail.Exception):
                return KILLED
    return SURVIVED


def main() -> int:
    print("GP-AUTO mutation obligations (MU11-7): per guard, per mutant.")
    print("No aggregate score, percentage or completeness claim is made (MU11-2a).\n")
    tags = guard_tags()
    status = 0
    for identifier, guard in GUARDS.items():
        print(f"guard {identifier}  [{guard.kind}]  guarantees: {', '.join(guard.guarantees)}")
        print(f"  fixed at: {', '.join(tags.get(identifier, ['<NOT FOUND>']))}")
        for mutant in (m for m in MUTANTS if m.guard == identifier):
            result = run(mutant)
            control = run(mutant, control=True)
            print(f"  {mutant.identifier:<40} {result:<9} control: {control}")
            print(f"      mutation : {mutant.description}")
            print(f"      killed by: {mutant.killer}")
            if result != KILLED or control != SURVIVED:
                status = 1
        print()
    return status


if __name__ == "__main__":
    raise SystemExit(main())


@dataclass(frozen=True)
class CorrectionDDLMutant:
    """ST03C-1 schema mutation, applied in memory without editing authoritative files."""

    identifier: str
    statement: str
    replacement: str
    killer: str = "test_st03c1_schema_content_before_digest"
    guard: str = "ga_store_referential_integrity"


def correction_ddl_mutants() -> tuple[CorrectionDDLMutant, ...]:
    """Each new FK, CHECK and trigger gets an independent deletion mutant."""
    statements = store_schema.schema_statements(store_schema.build_catalogue())
    mutants: list[CorrectionDDLMutant] = []
    for statement in statements:
        if statement.startswith("CREATE TABLE rc13_owner_decision "):
            for line in statement.splitlines():
                if (
                    ("FOREIGN KEY (act__" in line)
                    or ("CHECK (act__" in line and "<> identity" in line)
                    or "length(CAST(act__ObligationChangeDecision" in line
                ):
                    identifier = line.strip().split(" (")[0] + "-" + str(len(mutants))
                    mutants.append(
                        CorrectionDDLMutant(
                            identifier,
                            statement,
                            statement.replace(line + "\n", "")
                            if line.endswith(",")
                            else statement.replace(",\n" + line, ""),
                        )
                    )
            for predicate, replacement, identifier, killer in (
                (
                    "length(CAST(act__ObligationChangeDecision__replacement_requirement AS BLOB))",
                    "length(act__ObligationChangeDecision__replacement_requirement)",
                    "text-length-rejects-nul",
                    "test_st03c1_o6_exact_unicode_and_empty_string",
                ),
                (
                    "FOREIGN KEY (act__StageOutcomeDecision__context__authorization, "
                    "act__StageOutcomeDecision__context__entry_boundary) "
                    "REFERENCES rc17_entry_state_boundary (resolved_root, boundary__identity)",
                    "FOREIGN KEY (act__StageOutcomeDecision__context__authorization) "
                    "REFERENCES rc17_entry_state_boundary (resolved_root),\n    "
                    "FOREIGN KEY (act__StageOutcomeDecision__context__entry_boundary) "
                    "REFERENCES rc17_entry_state_boundary (boundary__identity)",
                    "split-context-pair",
                    "test_st03c1_context_outcome_resolution_and_instance_agreement",
                ),
            ):
                assert statement.count(predicate) == 1
                mutants.append(
                    CorrectionDDLMutant(
                        identifier, statement, statement.replace(predicate, replacement), killer
                    )
                )
            for column in (
                "act__DisputeResolutionDecision__member",
                "act__ObligationExtinguishingDecision__obligation__member_finding",
                "act__ObligationChangeDecision__obligation__member_finding",
                "act__RevocationDecision__revoked",
                "act__RefusalResolutionDecision__halt_occurrence",
                "act__StageOutcomeDecision__context__authorization",
                "act__StageOutcomeDecision__corrects__Present__value",
            ):
                mutants.append(
                    CorrectionDDLMutant(
                        "unique-" + column,
                        statement,
                        statement.replace("\n) STRICT", f",\n    UNIQUE ({column})\n) STRICT"),
                        guard="ga_store_keys",
                    )
                )
        elif statement.startswith(
            ("CREATE TABLE rc32_", "CREATE TABLE rc35_", "CREATE TABLE rc36_")
        ):
            for line in statement.splitlines():
                if "REFERENCES rc13_owner_decision (identity," in line:
                    # This is the last constraint in each affected table.
                    replacement = statement.replace(",\n" + line, "")
                    assert replacement != statement
                    mutants.append(
                        CorrectionDDLMutant(
                            "binding-" + statement.split()[2], statement, replacement
                        )
                    )
            if statement.startswith("CREATE TABLE rc35_"):
                column = (
                    "disposition__SuspendedDisposition__established_by_event__AuthorityAmbiguityId"
                )
                mutants.append(
                    CorrectionDDLMutant(
                        "readmit-ambiguity",
                        statement,
                        statement.replace(" (\n", f" (\n    {column} TEXT,\n", 1),
                    )
                )
        elif statement.startswith("CREATE TRIGGER") and (
            "__prior__" in statement
            or "__no_outcome_succession " in statement
            or "__consumed_context " in statement
            or ("rc13_owner_decision__instance__" in statement)
        ):
            mutants.append(CorrectionDDLMutant(statement.split()[2], statement, ""))
    return tuple(mutants)
