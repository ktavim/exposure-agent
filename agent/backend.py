"""The backend's agent API (docs/exposure-design.md, Backend and agent
protocol). The agent opens every connection; the backend never calls it.

Authentication comes with phase 6: a Keycloak token for the exposure-agent
client, obtained with a signed JWT. Until then the calls carry none.
"""
from typing import Any, Optional, Protocol

import httpx


class Reporter(Protocol):
    """Where the agent's steps and results go: the backend, or a test's record."""

    async def step(
        self, exposure_id: str, seq: int, version: int, step: str, state: str,
        message: Optional[str] = None, detail: Optional[dict[str, Any]] = None,
    ) -> None: ...

    async def result(
        self, exposure_id: str, version: int, phase: str, outcome: str,
        plan: Optional[dict[str, Any]] = None, step: Optional[str] = None, message: Optional[str] = None,
        deployment: Optional[dict[str, Any]] = None,
    ) -> bool: ...


class BackendClient:
    def __init__(self, base_url: str, *, transport: Optional[httpx.AsyncBaseTransport] = None):
        self._http = httpx.AsyncClient(base_url=base_url, timeout=30.0, transport=transport)

    async def close(self) -> None:
        await self._http.aclose()

    async def pending(self) -> list[dict[str, Any]]:
        response = await self._http.get("/api/agent/pending")
        response.raise_for_status()
        return response.json()

    async def step(
        self, exposure_id: str, seq: int, version: int, step: str, state: str,
        message: Optional[str] = None, detail: Optional[dict[str, Any]] = None,
    ) -> None:
        response = await self._http.post(
            f"/api/agent/exposures/{exposure_id}/events",
            json={"seq": seq, "version": version, "step": step, "state": state, "message": message, "detail": detail},
        )
        response.raise_for_status()

    async def result(
        self, exposure_id: str, version: int, phase: str, outcome: str,
        plan: Optional[dict[str, Any]] = None, step: Optional[str] = None, message: Optional[str] = None,
        deployment: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Report a phase's outcome; False when the backend dropped it as stale."""
        response = await self._http.post(
            f"/api/agent/exposures/{exposure_id}/result",
            json={
                "version": version, "phase": phase, "outcome": outcome, "plan": plan,
                "deployment": deployment, "step": step, "message": message,
            },
        )
        response.raise_for_status()
        return bool(response.json()["applied"])
