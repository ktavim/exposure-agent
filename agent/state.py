"""The agent's own record (docs/exposure-design.md, Backend and agent
protocol): what each exposure holds, its IP reservations, certificates and
DNS records; the plans it made, which are what it deploys; the partition's
declaration from before its deploy, which cancelling restores; a step log
keyed by exposure, version and step; and the sequence number of the next step
it reports. It is what the agent acts on: a restarted agent reuses what an
exposure already holds instead of reserving it twice, a retried deploy
resumes after the last step it completed, and cancelling needs no list from
the backend of what to undo.

SQLite, one file next to the agent: one agent runs, one operation at a time.
"""
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reservations (
    exposure_id TEXT NOT NULL,
    vip_key     TEXT NOT NULL,   -- a group's id, or "app" for the app's VIP
    ip          TEXT NOT NULL,
    PRIMARY KEY (exposure_id, vip_key)
);
CREATE TABLE IF NOT EXISTS certificates (
    exposure_id TEXT NOT NULL,
    vip_key     TEXT NOT NULL,
    name        TEXT NOT NULL,   -- its name on the F5
    names       TEXT NOT NULL,   -- JSON: the DNS names it covers, sorted
    expires     TEXT NOT NULL,
    PRIMARY KEY (exposure_id, vip_key)
);
CREATE TABLE IF NOT EXISTS steps (
    exposure_id TEXT NOT NULL,
    version     INTEGER NOT NULL,
    step        TEXT NOT NULL,
    state       TEXT NOT NULL,
    PRIMARY KEY (exposure_id, version, step)
);
CREATE TABLE IF NOT EXISTS sequences (
    exposure_id TEXT PRIMARY KEY,
    next_seq    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
    exposure_id TEXT NOT NULL,
    version     INTEGER NOT NULL,
    plan_hash   TEXT NOT NULL,
    plan        TEXT NOT NULL,   -- JSON, as reported
    PRIMARY KEY (exposure_id, version)
);
CREATE TABLE IF NOT EXISTS dns_records (
    exposure_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    target      TEXT NOT NULL,
    record_id   TEXT,            -- the DNS service's; NULL until it answers
    PRIMARY KEY (exposure_id, name)
);
CREATE TABLE IF NOT EXISTS previous_declarations (
    exposure_id TEXT PRIMARY KEY,
    partition   TEXT NOT NULL,
    declaration TEXT             -- JSON; NULL when the partition had none
);
"""


@dataclass(frozen=True)
class HeldDnsRecord:
    name: str
    type: str
    target: str
    record_id: Optional[str]


@dataclass(frozen=True)
class PreviousDeclaration:
    """A partition's declaration from before an exposure's deploy; None if
    the partition had none."""

    partition: str
    declaration: Optional[dict[str, Any]]


@dataclass(frozen=True)
class HeldCertificate:
    vip_key: str
    name: str
    names: tuple[str, ...]
    expires: str


class State:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # ---- IP reservations ----------------------------------------------------

    def reservations(self, exposure_id: str) -> dict[str, str]:
        rows = self._db.execute(
            "SELECT vip_key, ip FROM reservations WHERE exposure_id = ?", (exposure_id,)
        )
        return dict(rows.fetchall())

    def hold_reservation(self, exposure_id: str, vip_key: str, ip: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO reservations VALUES (?, ?, ?)", (exposure_id, vip_key, ip)
            )

    def drop_reservation(self, exposure_id: str, vip_key: str) -> None:
        with self._db:
            self._db.execute(
                "DELETE FROM reservations WHERE exposure_id = ? AND vip_key = ?", (exposure_id, vip_key)
            )

    # ---- Certificates -------------------------------------------------------

    def certificates(self, exposure_id: str) -> dict[str, HeldCertificate]:
        rows = self._db.execute(
            "SELECT vip_key, name, names, expires FROM certificates WHERE exposure_id = ?", (exposure_id,)
        )
        return {
            key: HeldCertificate(key, name, tuple(json.loads(names)), expires)
            for key, name, names, expires in rows.fetchall()
        }

    def hold_certificate(self, exposure_id: str, cert: HeldCertificate) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO certificates VALUES (?, ?, ?, ?, ?)",
                (exposure_id, cert.vip_key, cert.name, json.dumps(sorted(cert.names)), cert.expires),
            )

    def drop_certificate(self, exposure_id: str, vip_key: str) -> None:
        with self._db:
            self._db.execute(
                "DELETE FROM certificates WHERE exposure_id = ? AND vip_key = ?", (exposure_id, vip_key)
            )

    # ---- DNS records ----------------------------------------------------------

    def dns_records(self, exposure_id: str) -> list[HeldDnsRecord]:
        rows = self._db.execute(
            "SELECT name, type, target, record_id FROM dns_records WHERE exposure_id = ? ORDER BY name",
            (exposure_id,),
        )
        return [HeldDnsRecord(*row) for row in rows.fetchall()]

    def hold_dns_record(self, exposure_id: str, record: HeldDnsRecord) -> None:
        """Recorded before the record is created, and again with its id
        after, so a record created just before a crash is still released."""
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO dns_records VALUES (?, ?, ?, ?, ?)",
                (exposure_id, record.name, record.type, record.target, record.record_id),
            )

    def drop_dns_record(self, exposure_id: str, name: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM dns_records WHERE exposure_id = ? AND name = ?", (exposure_id, name))

    # ---- Plans ------------------------------------------------------------------

    def hold_plan(self, exposure_id: str, version: int, plan_hash: str, plan: dict[str, Any]) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO plans VALUES (?, ?, ?, ?)",
                (exposure_id, version, plan_hash, json.dumps(plan)),
            )

    def plan(self, exposure_id: str, plan_hash: str) -> Optional[dict[str, Any]]:
        """The plan the agent made for the exposure with this hash, if any."""
        row = self._db.execute(
            "SELECT plan FROM plans WHERE exposure_id = ? AND plan_hash = ? ORDER BY version DESC",
            (exposure_id, plan_hash),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def drop_plans(self, exposure_id: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM plans WHERE exposure_id = ?", (exposure_id,))

    # ---- The declaration a deploy replaced --------------------------------------

    def previous_declaration(self, exposure_id: str) -> Optional[PreviousDeclaration]:
        row = self._db.execute(
            "SELECT partition, declaration FROM previous_declarations WHERE exposure_id = ?", (exposure_id,)
        ).fetchone()
        if row is None:
            return None
        return PreviousDeclaration(row[0], json.loads(row[1]) if row[1] is not None else None)

    def keep_previous_declaration(self, exposure_id: str, previous: PreviousDeclaration) -> None:
        """Kept once, before the first attempt to deploy: a retry must not
        take the exposure's own declaration for the one it replaced."""
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO previous_declarations VALUES (?, ?, ?)",
                (
                    exposure_id,
                    previous.partition,
                    json.dumps(previous.declaration) if previous.declaration is not None else None,
                ),
            )

    def drop_previous_declaration(self, exposure_id: str) -> None:
        with self._db:
            self._db.execute("DELETE FROM previous_declarations WHERE exposure_id = ?", (exposure_id,))

    # ---- Step log and report numbering ----------------------------------------

    def record_step(self, exposure_id: str, version: int, step: str, state: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO steps VALUES (?, ?, ?, ?)", (exposure_id, version, step, state)
            )

    def step_state(self, exposure_id: str, version: int, step: str) -> Optional[str]:
        row = self._db.execute(
            "SELECT state FROM steps WHERE exposure_id = ? AND version = ? AND step = ?",
            (exposure_id, version, step),
        ).fetchone()
        return row[0] if row else None

    def next_seq(self, exposure_id: str) -> int:
        """The next number for a step report. Persisted, so numbers never
        repeat across restarts; a report sent again after a lost response
        keeps the number it was given, and the backend records it once."""
        with self._db:
            row = self._db.execute(
                "SELECT next_seq FROM sequences WHERE exposure_id = ?", (exposure_id,)
            ).fetchone()
            seq = row[0] if row else 0
            self._db.execute(
                "INSERT OR REPLACE INTO sequences VALUES (?, ?)", (exposure_id, seq + 1)
            )
        return seq
