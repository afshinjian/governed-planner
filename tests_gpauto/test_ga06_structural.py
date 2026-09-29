"""Absence as evidence: the things AP-03 requires to be impossible are not there.

Design basis: AP-03 §2 (merged and demoted concepts), §4.1, §4.3, §4.5, §5.2, §8.1,
§8.3, §11.1, §12, §13; `AP03-I05`, `AP03-I09`, `AP03-I19`, `AP03-I20`, `AP03-I25`,
`AP03-I26`, `AP03-I29`, `AP03-I31`, `AP03-I32`, `AP03-I33`, `AP03-I34`; AP-11 §2
(`VP11-4`, `VP11-5`), §14 (`SD11-16`), §15 (`SG11-11`, `SG11-11a`).

`VP11-4` is the rule this module follows: where a frozen input makes something
*inexpressible*, the verification target is that **no operation exists**, and a test
merely showing an attempt is refused is weaker evidence than the absence. So these
assertions read the package rather than an instance — every class, every field, every
annotation, every import — and the failure they would produce is *"you added the
thing"*, not *"an instance behaved oddly"*.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

from gpauto.activation import ObjectiveProductionReference
from gpauto.authorization import OwnerAuthorization
from gpauto.envelope import AuthorityEnvelope
from gpauto.evidence import ArtifactContent
from gpauto.governance import OwnerDecision, StageOutcome
from gpauto.identity import (
    AuthorizationRecordId,
    DependentIdentity,
    DomainIdentity,
    MintedIdentity,
    OpaqueIdentity,
    OwnerAuthorizationId,
    OwnerDecisionId,
)
from gpauto.identity import ContentIdentity as ContentIdentityBase
from gpauto.identity import SuppliedIdentity as SuppliedIdentityBase
from gpauto.schema import DomainEntity, DomainModel, DomainValue
from introspect import (
    PACKAGE_ROOT,
    annotation_atoms,
    class_names,
    declared_fields,
    imported_modules,
    model_classes,
    source_files,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

ST02_OPERATION_MODULES = frozenset({"content_identity.py", "codec.py", "equivalence.py"})
"""The modules `GP-AUTO-ST-02` was authorized to add operations in, and no others."""

ST03_OPERATION_MODULES = frozenset({"minting.py", "store_schema.py", "store.py"})
"""The modules `GP-AUTO-ST-03` was authorized to add operations in — its store modules
(AP-11 ST-03 amendment §11.1, *Authorized scope*) — and no others. Its vocabulary,
identity and record modules declare no function, and `test_ga16` asserts that."""

ST04_OPERATION_MODULES = frozenset({"derivations.py"})
"""The module `GP-AUTO-ST-04` was authorized to add operations in — its derivations module
(AP-11 §16 ST-04, *Authorized scope*) — and no other. Its functions are pinned in
`test_ga24`."""

ST05_OPERATION_MODULES = frozenset({"state_machine.py"})
"""The module `GP-AUTO-ST-05` was authorized to add operations in — its evaluator, coupling
checks and matrix generator (AP-11 §16 ST-05, *Authorized scope*). Its model data,
`state_machine_model.py`, declares no function, and this test keeps asserting that. Its
functions are pinned in `test_ga28`."""

ST06_OPERATION_MODULES = frozenset({"authority.py"})
"""The module `GP-AUTO-ST-06` was authorized to add operations in — root resolution and
envelope derivation (AP-11 §16 ST-06, *Authorized scope*: *"GP-AUTO authority module"*) —
and no other. Its functions are pinned in `test_ga33`."""

NEVER_AN_ENTITY = {
    "AuthorityCeiling": (
        "an identity-less value inside the authorization: RA-07 is a role-indexed tuple of "
        "AuthorityCeilingMember values, not an AuthorityBounds (AP-03 §2.2; ST-06 "
        "clarification S6G2-1, S6G2-2)"
    ),
    "DecisionPackage": "demoted to a derivation with no identity (AP-03 §2.5, AP03-I31)",
    "InvalidAuthorizationCandidate": "merged into CandidateExclusion (AP-03 §2.7)",
    "EntryStateDivergence": "merged into UnaccountedMutation (AP-03 §2.7)",
    "Acceptance": "merged into a kind of OwnerDecision (AP-03 §2.7)",
    "StageEntryRequest": "deferred as an entity; a statement of shape only (AP-03 §2.7, §16.7)",
    "ExpectedCurrentAuthorizedState": "a derivation, never an entity (AP-03 §2.4, AP03-I09)",
    "ForbiddenTransferMaterial": "no entity, no container, no referent kind (AP03-I20)",
    "HiddenReasoning": "as above",
    "TransferredReasoning": "as above",
}

ABSTRACT_BASES: tuple[type[DomainModel], ...] = (
    DomainModel,
    DomainValue,
    DomainEntity,
    DomainIdentity,
    OpaqueIdentity,
    SuppliedIdentityBase,
    MintedIdentity,
    ContentIdentityBase,
    DependentIdentity,
)

CLOCK_WORDS = frozenset(
    {
        "timestamp",
        "issued",
        "created",
        "expires",
        "expiry",
        "ttl",
        "deadline",
        "freshness",
        "until",
        "clock",
        "time",
        "date",
        "arrival",
        "order",
        "sequence",
        "ordinal",
        "position",
    }
)
"""Matched against snake_case **segments**, not as substrings.

A substring match would flag `candidates` for *date* and `pre_existing_index_state`
for *index* — and AP-03 §7.1 requires that second field by name, so a check that
cannot tell a git index from an ordering index is a check that has to be weakened to
pass. Segment matching keeps it strict instead.
"""

CLAIM_WORDS = ("signature", "signed", "key_material", "certificate", "attestation", "mac")

RECOMMENDATION_WORDS = (
    "recommend",
    "severity",
    "rank",
    "priority",
    "preference",
    "preferred",
    "winner",
    "score",
    "confidence",
)

PROVIDER_SDK_MODULES = frozenset(
    {
        "anthropic",
        "openai",
        "google",
        "google.generativeai",
        "genai",
        "cohere",
        "mistralai",
        "ollama",
        "langchain",
        "langchain_openai",
        "litellm",
        "transformers",
        "llama_cpp",
        "boto3",
    }
)

PROMPT_WORDS = ("prompt", "system_message", "completion", "chat_message", "llm")


@pytest.mark.traces("AP03-I09", "AP03-I31", "ST01-A2")
@pytest.mark.parametrize("name", sorted(NEVER_AN_ENTITY), ids=str)
def test_a_merged_or_demoted_concept_has_no_class(name: str) -> None:
    """Each was merged, demoted or deferred by AP-03, and a class would undo that.

    A separately identified `AuthorityCeiling` could outlive or be shared between
    authorizations — a second authority source. A stored
    `ExpectedCurrentAuthorizedState` is a second, writable baseline. A
    `DecisionPackage` with identity is something a later phase can treat as
    authoritative. Absence is the enforcement.
    """
    assert name not in class_names(), NEVER_AN_ENTITY[name]


@pytest.mark.traces("AP03-I05", "AP03-I26")
def test_the_package_declares_no_function_at_all() -> None:
    """Data and types only — the discipline the spike's `states.py` records.

    This single absence is what closes several invariants at once: there is no
    ordering, ranking, precedence, recency, permissiveness or breadth comparison; no
    merge, union, intersection, reconciliation or selection; no operation taking a
    candidate set and returning one (`AP03-I05`); no reset, reopen, revive or reuse
    (`AP03-I12`, `AP03-I26`); and no derivation of any kind. *The absence is the
    model.* A later stage adds its operations in its own modules under its own
    authorization; none is smuggled in here.

    **Scope from `GP-AUTO-ST-02` on.** ST-02 is the first stage authorized to add
    operations, and adds them in its own modules — `ST02_OPERATION_MODULES`. This
    assertion keeps its meaning over every other module, unchanged: they still declare
    no function at all. The operations ST-02 did add are pinned by name in `test_ga14`,
    and none of them is an ordering, ranking, merge or selection.
    """
    offenders: list[str] = []
    for path in source_files():
        if path.name in (
            ST02_OPERATION_MODULES
            | ST03_OPERATION_MODULES
            | ST04_OPERATION_MODULES
            | ST05_OPERATION_MODULES
            | ST06_OPERATION_MODULES
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                name = getattr(node, "name", "<lambda>")
                offenders.append(f"{path.name}:{node.lineno}: {name}")
    assert offenders == []


@pytest.mark.traces("AP03-I05")
def test_no_model_defines_an_ordering_or_comparison_operator() -> None:
    """No time-derived value, and no value at all, participates in an ordering here."""
    for cls in model_classes():
        for operator in ("__lt__", "__le__", "__gt__", "__ge__"):
            assert operator not in vars(cls), f"{cls.__qualname__}.{operator}"


@pytest.mark.traces("ST01-N3")
def test_no_field_is_annotated_with_a_base_class() -> None:
    """The guarantee every non-interchangeability test rests on.

    Strict mode accepts any subclass where a base is annotated, so one field typed
    `DomainIdentity` — or `DomainValue`, or `MintedIdentity` — would reopen every
    substitution the identity types close. `test_ga02` demonstrates that it would.
    """
    offenders: list[str] = []
    for cls, field_name, annotation in declared_fields():
        for atom in annotation_atoms(annotation):
            if atom in ABSTRACT_BASES:
                offenders.append(f"{cls.__qualname__}.{field_name} -> {atom.__qualname__}")
    assert offenders == []


@pytest.mark.traces("AP03-I29")
def test_no_structure_carries_a_clock_derived_or_ordering_field() -> None:
    """AP-03 §4.1 and §4.3: no expiry, TTL, wall-clock bound, issuance deadline or
    freshness attribute, and no timestamp or clock-derived value in the projection.

    The exclusion of timestamps and arrival order is `P-16` and `D-AP02-01(a)`, not a
    convenience: nothing excluded may enter a comparison, an ordering or a tie-break,
    and the surest way to keep it out of one is for it not to exist (`AP03-I05`,
    `AP03-I29`).
    """
    offenders = [
        f"{cls.__qualname__}.{field_name}"
        for cls, field_name, _ in declared_fields()
        if CLOCK_WORDS & set(field_name.lower().split("_"))
    ]
    assert offenders == []


@pytest.mark.traces("AP03-I29")
def test_no_structure_carries_a_signature_key_or_attestation_field() -> None:
    """*"No claim is created by modelling"* (`AP03-I29`).

    No entity asserts authenticated human identity, authorship, signature, trusted
    time, tamper-evidence or non-repudiation. The OWNER/HUMAN label is a label.
    """
    offenders = [
        f"{cls.__qualname__}.{field_name}"
        for cls, field_name, _ in declared_fields()
        if any(word in field_name.lower() for word in CLAIM_WORDS)
    ]
    assert offenders == []


@pytest.mark.traces("AP03-I29")
def test_no_governance_record_carries_a_recommendation_or_severity_field() -> None:
    """`GE-1`: no record recommends a disposition. It states facts and asks.

    In particular, never which competing authorization the OWNER ought to keep, and
    never a severity judgement over a finding — the coordinator may not triage or rank
    by merit.
    """
    offenders = [
        f"{cls.__qualname__}.{field_name}"
        for cls, field_name, _ in declared_fields()
        if any(word in field_name.lower() for word in RECOMMENDATION_WORDS)
    ]
    assert offenders == []


@pytest.mark.traces("AP03-I33")
def test_an_envelope_names_an_instance_and_can_never_name_a_record() -> None:
    """`AP03-I33`: an `AuthorizationRecord` is never an authority source.

    No envelope, refusal, evidence or effect record may name a *record* identity as
    its root — so no structure outside `AuthorizationRecord` and the resolution's
    candidate list may reference `AuthorizationRecordId` as a root at all.
    """
    assert AuthorityEnvelope.model_fields["resolved_root"].annotation is OwnerAuthorizationId

    root_fields = [
        f"{cls.__qualname__}.{field_name}"
        for cls, field_name, annotation in declared_fields()
        if "root" in field_name.lower()
        and AuthorizationRecordId in set(annotation_atoms(annotation))
    ]
    assert root_fields == []


@pytest.mark.traces("AP03-I34")
def test_only_an_owner_decision_can_establish_a_stage_outcome() -> None:
    """`SO-4`: no worker, coordinator or persistence mechanism may establish one.

    Typed, so a closure assessment, a structural halt or a gate arrival is not a
    refused establisher but an unexpressible one.
    """
    assert StageOutcome.model_fields["established_by"].annotation is OwnerDecisionId


@pytest.mark.traces("AP03-I25")
def test_authorization_and_decision_are_two_types_never_joined_by_subtyping() -> None:
    """`AP03-I25`: subtyping would make an authorization substitutable wherever a
    decision is accepted, including the acceptance slot. The collapse would be
    structural rather than accidental."""
    assert not issubclass(OwnerAuthorization, OwnerDecision)
    assert not issubclass(OwnerDecision, OwnerAuthorization)


@pytest.mark.traces("AP03-I25")
def test_no_structure_derives_an_authorization_from_an_outcome_or_a_decision() -> None:
    """`SO-1`: an authorization is *produced by* a decision, never *derived from* an
    acceptance. `StageOutcome` therefore names no authorization at all."""
    outcome_atoms = {
        atom
        for field_info in StageOutcome.model_fields.values()
        for atom in annotation_atoms(field_info.annotation)
    }
    assert OwnerAuthorizationId not in outcome_atoms


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-D1")
def test_artifact_content_carries_no_provenance_and_no_standing() -> None:
    """Standing attaches to the production occurrence, never to the bytes.

    A worker-produced copy of identical bytes acquires no objective standing from the
    existence of an objective production of the same content.
    """
    assert set(ArtifactContent.model_fields) == {"identity"}


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N5")
def test_the_admissibility_domain_cannot_accept_a_worker_authored_production() -> None:
    """`EA-1`, as a constraint on the relation's domain rather than a flag check.

    The objective reference carries **no provenance field of its own**: there is
    nothing there to assert, and therefore nothing to assert wrongly. Its referent is
    the production occurrence, whose provenance is part of its type — so a
    worker-authored production is not a rejected referent but an unconstructible one
    (`VP11-4`).
    """
    from gpauto.vocabulary import Provenance

    assert set(ObjectiveProductionReference.model_fields) == {"production"}

    referent = ObjectiveProductionReference.model_fields["production"].annotation
    atoms = set(annotation_atoms(referent))
    assert Provenance.OBJECTIVE in atoms
    assert Provenance.WORKER_AUTHORED not in atoms


@pytest.mark.supports("AP03-I19")
@pytest.mark.traces("ST01-N6")
def test_every_governed_fact_variant_binds_its_kind_to_one_typed_referent() -> None:
    """AP-03 §8.2: a governed fact and the identity of its referent are two facts.

    A kind paired with an arbitrary string would admit any referent under any kind's
    name — a label beside an unbound value rather than a reference. Each variant
    therefore pins its `fact_kind` by `Literal` and types its referent, and none
    carries a bare `str`.
    """
    from gpauto.activation import GOVERNED_FACT_VARIANTS
    from gpauto.identity import DomainIdentity
    from gpauto.vocabulary import GovernedFactKind, StageContractPart

    seen_kinds: set[GovernedFactKind] = set()
    for variant in GOVERNED_FACT_VARIANTS:
        fields = dict(variant.model_fields)
        kind_atoms = set(annotation_atoms(fields.pop("fact_kind").annotation))
        kinds = {atom for atom in kind_atoms if isinstance(atom, GovernedFactKind)}
        assert len(kinds) == 1, variant.__qualname__
        seen_kinds |= kinds

        assert fields, variant.__qualname__
        for field_name, field_info in fields.items():
            referent_atoms = set(annotation_atoms(field_info.annotation))
            typed = any(
                isinstance(atom, type) and issubclass(atom, DomainIdentity)
                for atom in referent_atoms
            ) or StageContractPart in referent_atoms
            assert typed, f"{variant.__qualname__}.{field_name}"
            assert str not in referent_atoms, f"{variant.__qualname__}.{field_name}"

    assert seen_kinds == set(GovernedFactKind)


@pytest.mark.traces("AP03-I32", "ST01-A3")
def test_gpauto_imports_no_gp_spk_001_module() -> None:
    """`SD11-16`: the retained spike is inert with respect to GP-AUTO.

    Components classified *retained untouched* are not imported, subclassed, wrapped,
    monkey-patched, re-exported or referenced, and no GP-AUTO behaviour depends on
    their presence. The only two GP-SPK-001 modules GP-AUTO may ever import are
    `canonical` and `digest` — and those are `GP-AUTO-ST-02`'s, not this stage's, so
    the expected count at `GP-AUTO-ST-01` was **zero**.

    **From `GP-AUTO-ST-02` on**, the expected set is exactly the two authorized
    primitives, imported only by ST-02's identity and equivalence modules — and no
    other spike module, from anywhere in the package. The imported *names* are pinned
    in `test_ga14`.

    **From `GP-AUTO-ST-06` on**, `authority.py` imports `canonical` as well: `SD11-16`
    authorizes that module to GP-AUTO, and the frozen ST-06 clarification S6G3-6 requires
    canonical (JCS) byte order. It is the same primitive, so no new coupling exists
    (`SD11-16a`); `digest` is still imported by `content_identity.py` alone.
    """
    spike_imports = {
        (path.name, module)
        for path, module in imported_modules()
        if module == "gplanner" or module.startswith("gplanner.")
    }
    assert spike_imports == {
        ("content_identity.py", "gplanner.canonical"),
        ("content_identity.py", "gplanner.digest"),
        ("equivalence.py", "gplanner.canonical"),
        ("authority.py", "gplanner.canonical"),
    }


@pytest.mark.traces("AP03-I32", "ST01-A3")
def test_no_gp_spk_001_scope_governance_token_appears() -> None:
    """`AP03-I32`: no `SCOPE_*` state, scope transition, `submit_for_review` or
    approval contract appears as a coordination semantic."""
    forbidden = ("SCOPE_DRAFTING", "SCOPE_REVIEW_PENDING", "SCOPE_APPROVED", "submit_for_review")
    offenders = [
        f"{path.name}: {token}"
        for path in source_files()
        for token in forbidden
        if token in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


@pytest.mark.traces("ST01-A3")
def test_the_gpauto_package_is_separate_from_the_spike_package() -> None:
    """`SD11-17`, `EB-14`(iii): a separate package, not a part or a re-export."""
    assert PACKAGE_ROOT.name == "gpauto"
    assert PACKAGE_ROOT.parent.name == "src"
    assert (PACKAGE_ROOT.parent / "gplanner").is_dir()
    assert PACKAGE_ROOT != PACKAGE_ROOT.parent / "gplanner"


@pytest.mark.traces("ST01-A3")
def test_every_gpauto_module_cites_a_gp_auto_design_basis() -> None:
    """The repository's docstring convention, pointed at GP-AUTO's frozen set.

    GP-SPK-001 modules cite `design/GP-SPK-001-governance-kernel.md`; GP-AUTO's design
    basis is the AP-00…AP-11 set (`SD11-11`), and a module citing the spike's design
    document would be claiming a basis it does not have.
    """
    for path in source_files():
        docstring = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        assert docstring is not None, path.name
        assert "Design basis:" in docstring, path.name
        assert "AP-" in docstring.split("Design basis:", 1)[1][:200], path.name
        assert "GP-SPK-001-governance-kernel.md" not in docstring, path.name


def gpauto_test_tree_imports() -> list[tuple[Path, str]]:
    """`(file, imported module)` over the GP-AUTO test tree."""
    found: list[tuple[Path, str]] = []
    for path in sorted(Path(__file__).parent.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend((path, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.append((path, node.module or ""))
    return found


@pytest.mark.traces("AP03-I17", "ST01-A4")
def test_no_provider_sdk_is_imported_anywhere_in_gp_auto() -> None:
    """`SG11-11`, `SG11-11a`: no provider import, conditional, lazy or guarded.

    Over the GP-AUTO package **and** its test tree, because `SG11-11a` closes every
    entry surface and a test fixture keyed to a provider API is one of them.
    """
    offenders = [
        f"{path.name}: {module}"
        for path, module in (*imported_modules(), *gpauto_test_tree_imports())
        if module.split(".")[0] in PROVIDER_SDK_MODULES
    ]
    assert offenders == []


@pytest.mark.traces("ST01-A4")
def test_no_prompt_or_provider_identifier_appears_in_gp_auto() -> None:
    """`SG11-11a` covers every entry surface, not only a call site.

    No prompt, prompt template or prompt fragment in any form; no fixture, stub, mock
    or recorded transcript keyed to a provider API; no dormant, commented-out or
    feature-flagged provider code. Identifiers are what a scan can see, so identifiers
    are what this asserts.

    Scoped to the **production package**, which is where dormant or feature-flagged
    provider code would live. The scan is deliberately not run over the test tree: it
    would match this module's own word list, and a scanner that has to exempt itself
    is a scanner that has been weakened to pass. The test tree is covered by the
    import gate above, which reads import nodes rather than names.
    """
    offenders: list[str] = []
    for path in source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name | ast.Attribute):
                name = node.id if isinstance(node, ast.Name) else node.attr
                if any(word in name.lower() for word in PROMPT_WORDS):
                    offenders.append(f"{path.name}:{node.lineno}: {name}")
            elif isinstance(node, ast.arg) and any(
                word in node.arg.lower() for word in PROMPT_WORDS
            ):
                offenders.append(f"{path.name}:{node.lineno}: {node.arg}")
    assert offenders == []


@pytest.mark.traces("ST01-A4")
def test_the_project_declares_no_provider_sdk_dependency() -> None:
    """`SG11-11a`: *"a declared-but-unimported SDK is an SDK in the repository."*

    Covers the main dependency set and **every** optional extra and dev-only group,
    which is exactly where such a declaration would be easiest to overlook.
    """
    manifest = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = manifest["project"]
    declared: list[str] = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared.extend(extra)
    for group in manifest.get("dependency-groups", {}).values():
        declared.extend(group)

    offenders = [
        requirement
        for requirement in declared
        if requirement.split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip().lower()
        in PROVIDER_SDK_MODULES
    ]
    assert offenders == []
