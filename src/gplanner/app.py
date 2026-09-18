"""DBOS configuration — the engine's entire tuning surface.

Design basis: design/GP-SPK-001-governance-kernel.md §4, §12.

`app.py` and `workflow.py` are the only two modules in this package permitted to
import `dbos` (§4). This one holds no logic at all: it builds the `DBOSConfig`
mapping and nothing else, so every governance module below it stays provable with the
engine absent.

Four settings, each load-bearing rather than taste:

* **`system_database_url` names DBOS's own database and nothing else.** No
  `application_database_url` is supplied, so DBOS creates no application database and
  has no place to put governance data even by accident. §12's two databases stay two,
  and `governance.sqlite` is reached only through `store.py`.
* **`application_version` is pinned.** Workflow recovery is gated on it
  (`dbos/_recovery.py:57`): a process configured with a different version recovers
  nothing. It is a constant here rather than a derived value because a version that
  changed with the environment would make recovery depend on how a process happened to
  be launched.
* **`run_admin_server=False`.** An admin HTTP server would expose workflow control --
  cancel, resume, fork -- on a local port, outside the authority model this spike is
  built to state precisely. There is no governance in GP-SPK-001 for "who may cancel a
  workflow", so the surface is not opened.
* **`enable_otlp=False`.** No telemetry exporter, no network egress: the spike's
  verdict is about durability and authority, and a background exporter would add a
  failure mode belonging to neither.

`DBOSConfig` is a `total=False` `TypedDict`, so the returned mapping is checked
key-by-key against the vendor's own declaration rather than being an untyped `dict`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from dbos import DBOSConfig

#: The DBOS application name. One executor, one name (§2 excludes multi-executor).
APPLICATION_NAME: Final[str] = "governed-planner"

#: The pinned recovery gate. Frozen by the plan of record (revision 5 §13); every
#: process that must recover a workflow started by another has to agree with it
#: exactly, which is why it is a constant and not a parameter with a computed default.
APPLICATION_VERSION: Final[str] = "gp-spk-001"


def make_config(sys_db: Path, app_version: str = APPLICATION_VERSION) -> DBOSConfig:
    """The `DBOSConfig` for a governed-planner process using `sys_db` as DBOS's store.

    `app_version` is a parameter only so a test can prove the recovery gate is the
    thing it claims to be -- that a mismatched version recovers nothing. Production
    callers take the default; every process in one recovery lifetime must pass the
    same value.

    The path is rendered as a SQLAlchemy URL here rather than by the caller, so the one
    place that knows the engine's URL grammar is the one module allowed to know it.
    """
    return {
        "name": APPLICATION_NAME,
        "system_database_url": f"sqlite:///{sys_db}",
        "application_version": app_version,
        "run_admin_server": False,
        "enable_otlp": False,
    }
