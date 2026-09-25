"""The external-party ingest writer — a test fixture, never GP-AUTO code.

Design basis: AP-11 ST-03 store-realization amendment §9 (`SRB11-19`…`SRB11-24`); AP-07
§6 (`WP-1`), §17 (`NP-1`, `RC-60`); AP-09 `OD9-1`, `OD9-3`.

`RC-10`, `RC-11` contents, `RC-12` and `RC-13` enter the store from a party outside
GP-AUTO, and no AP-11 stage builds that party (`SRB11-24`). Tests still need ingest rows,
so this module stands in for it — and **only** for it (`SRB11-21`):

* it lives in the test tree, and nothing in `src/gpauto` imports it or can reach it;
* it writes through **its own** connection and **its own** `INSERT` statements, spelled
  out here per class, rather than through any GP-AUTO write path — the store has none for
  these classes, and this module does not borrow one;
* it enables foreign keys when it writes, so its rows meet the same referential rules as
  GP-AUTO's (`SRB11-21`).

It reads two facts from GP-AUTO — the record-format constant and a model's JSON — because
an outside writer must produce what the store's definition interprets.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from gpauto.authorization import AuthorizationRecord
from gpauto.governance import AuthorizingDecision, NonAuthorizingDecision, OwnerDecision
from gpauto.scope_frame import (
    BaselineIdentity,
    GovernedStage,
    Project,
    RepositoryBoundary,
    StageContract,
)
from gpauto.store_schema import RECORD_FORMAT

type IngestRecord = (
    Project
    | GovernedStage
    | RepositoryBoundary
    | BaselineIdentity
    | StageContract
    | AuthorizationRecord
    | OwnerDecision
)

CONTRACT_PARTS = (
    "deliverable_boundary",
    "explicit_out_of_stage",
    "implementation_instructions",
    "review_instructions",
    "acceptance_criteria",
)


@contextmanager
def external_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """The outside party's own connection, foreign keys on (`SRB11-21`)."""
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    finally:
        connection.close()


def _insert(connection: sqlite3.Connection, table: str, row: dict[str, object]) -> None:
    columns = ", ".join(row)
    placeholders = ", ".join("?" for _ in row)
    connection.execute(
        f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", list(row.values())
    )


def _decision_row(decision: OwnerDecision) -> dict[str, object]:
    act = decision.act
    row: dict[str, object] = {
        "identity": decision.identity.value,
        "stage": decision.stage.value,
        "record_format": RECORD_FORMAT,
    }
    if isinstance(act, AuthorizingDecision):
        prefix = "act__AuthorizingDecision"
        row.update(
            {
                "act__kind": "AuthorizingDecision",
                f"{prefix}__kind": act.kind.value,
                f"{prefix}__produced_authorization__state": "PRESENT",
                f"{prefix}__produced_authorization__value": act.produced_authorization.value.value,
            }
        )
    elif isinstance(act, NonAuthorizingDecision):
        prefix = "act__NonAuthorizingDecision"
        row.update(
            {
                "act__kind": "NonAuthorizingDecision",
                f"{prefix}__kind": act.kind.value,
                f"{prefix}__produced_authorization__state": "KNOWN_ABSENT",
                f"{prefix}__produced_authorization__basis": act.produced_authorization.basis,
            }
        )
    else:
        raise NotImplementedError("the fixture writes the decision forms its tests use")
    return row


def write(
    connection: sqlite3.Connection, record: IngestRecord, *, record_format: str = RECORD_FORMAT
) -> None:
    """Write one ingest record, as the outside party would."""
    if isinstance(record, Project):
        _insert(
            connection,
            "rc10_project",
            {"identity": record.identity.value, "record_format": record_format},
        )
    elif isinstance(record, GovernedStage):
        _insert(
            connection,
            "rc10_governed_stage",
            {
                "identity": record.identity.value,
                "project": record.project.value,
                "record_format": record_format,
            },
        )
    elif isinstance(record, RepositoryBoundary):
        _insert(
            connection,
            "rc10_repository_boundary",
            {
                "identity": record.identity.value,
                "repository_location": record.repository_location,
                "branch": record.branch,
                "record_format": record_format,
            },
        )
    elif isinstance(record, BaselineIdentity):
        _insert(
            connection,
            "rc10_baseline_identity",
            {
                "identity": record.identity.value,
                "committed_history_identity": record.committed_history_identity,
                "record_format": record_format,
            },
        )
    elif isinstance(record, StageContract):
        _insert(
            connection,
            "rc11_stage_contract",
            {
                "identity": record.identity.value,
                "objective": record.objective,
                "record_format": record_format,
            },
        )
        for part in CONTRACT_PARTS:
            for slot, text in enumerate(getattr(record, part)):
                _insert(
                    connection,
                    f"rc11_stage_contract__{part}",
                    {"identity": record.identity.value, "tuple_slot": slot, "element": text},
                )
    elif isinstance(record, AuthorizationRecord):
        _insert(
            connection,
            "rc12_authorization_record",
            {
                "identity": record.identity.value,
                "authorization_identity": record.authorization_identity.value,
                "payload": record.model_dump_json(),
                "record_format": record_format,
            },
        )
    else:
        row = _decision_row(record)
        row["record_format"] = record_format
        _insert(connection, "rc13_owner_decision", row)


def ingest(path: Path, records: Iterable[IngestRecord]) -> None:
    """Write `records` in one transaction of the outside party's own."""
    with external_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for record in records:
                write(connection, record)
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
