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
from dataclasses import dataclass
from pathlib import Path
from typing import Final

if __package__ in (None, ""):  # pragma: no cover - only when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from pydantic import BaseModel, ConfigDict, create_model

from gpauto import codec, equivalence, store, store_schema
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


type Mutant = LineMutant | SchemaMutant

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


def _schema(model: type[BaseModel]) -> tuple[object, ...]:
    """What a schema mutation must change: configuration, or a field's annotation."""
    nested = model.model_fields.get("content")
    inner = nested.annotation if nested is not None else None
    inner_config = inner.model_config.get("extra") if isinstance(inner, type) and issubclass(
        inner, BaseModel
    ) else None
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
