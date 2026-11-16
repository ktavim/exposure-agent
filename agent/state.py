"""The agent's own record (docs/exposure-design.md, Backend and agent
protocol): what each exposure holds, its IP reservations and certificates, a
step log keyed by exposure, version and step, and the sequence number of the
next step it reports. It is what the agent acts on: a restarted agent reuses
what an exposure already holds instead of reserving it twice, and cancelling
needs no list from the backend of what to undo.

SQLite, one file next to the agent: one agent runs, one operation at a time.
"""
import json
import sqlite3
from dataclasses import dataclass
from typing import Optional

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
"""


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
