"""The agent's loop: ask the backend what is waiting, work through it one
exposure at a time (AS3 refuses a declaration while another is in progress
anyway), sleep, repeat."""
import asyncio
import logging
from typing import Any

from .planner import Planner

logger = logging.getLogger(__name__)


class Agent:
    def __init__(self, planner: Planner, backend, poll_interval_s: float):
        self.planner = planner
        self.backend = backend
        self.poll_interval_s = poll_interval_s

    async def tick(self) -> int:
        """Handle everything pending once; returns how many exposures it worked on."""
        worked = 0
        for item in await self.backend.pending():
            worked += await self._handle(item)
        return worked

    async def _handle(self, item: dict[str, Any]) -> int:
        status = item["status"]
        if status == "planning":
            applied = await self.planner.plan(item)
        elif status == "cancelling":
            applied = await self.planner.cancel(item)
        else:
            # Deploying, verifying, DNS records and the registry are phase 5.
            logger.debug("Skipping %s: %s is not handled yet", item["id"], status)
            return 0
        if not applied:
            logger.info("The backend dropped the result for %s v%d as stale", item["id"], item["version"])
        return 1

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the loop outlives a bad round; the backend keeps the work
                logger.exception("Round failed; trying again in %.0fs", self.poll_interval_s)
            await asyncio.sleep(self.poll_interval_s)
