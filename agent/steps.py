"""How the agent carries out a phase: as named steps, each reported to the
backend as it starts and as it ends, and each recorded in the agent's step
log under the exposure and the version it is for (docs/exposure-design.md,
Backend and agent protocol). A step that failed stops the phase; the backend
hears which, and retry resumes from it."""
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from .backend import Reporter
from .state import State


class StepFailed(Exception):
    def __init__(self, step: str, message: str):
        super().__init__(message)
        self.step = step


@dataclass
class Run:
    """One phase of one exposure: its id, the version it is for, and the
    reports it sends."""

    exposure_id: str
    version: int
    reporter: Reporter
    state: State

    async def report(self, step: str, state: str, message: Optional[str] = None, detail: Optional[dict] = None) -> None:
        self.state.record_step(self.exposure_id, self.version, step, state)
        await self._send(step, state, message, detail)

    async def _send(self, step: str, state: str, message: Optional[str], detail: Optional[dict]) -> None:
        await self.reporter.step(
            self.exposure_id, self.state.next_seq(self.exposure_id), self.version, step, state, message, detail
        )

    def completed(self, step: str) -> bool:
        """Whether the step log has the step done for this version."""
        return self.state.step_state(self.exposure_id, self.version, step) == "done"

    @asynccontextmanager
    async def step(self, name: str) -> AsyncIterator[dict[str, Any]]:
        """Report the step started, then done with whatever the body puts in
        the yielded dict as its message and detail, or failed."""
        await self.report(name, "started")
        outcome: dict[str, Any] = {}
        try:
            yield outcome
        except StepFailed:
            raise
        except Exception as e:  # noqa: BLE001 - any failure fails the step, with its message
            raise StepFailed(name, f"{type(e).__name__}: {e}") from e
        await self.report(name, "done", outcome.get("message"), outcome.get("detail"))

    async def resumable(self, name: str, body: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Run a step unless an earlier attempt at this version completed it,
        in which case it is reported skipped. The log keeps it done, so a
        later retry skips it too."""
        if self.completed(name):
            await self._send(name, "skipped", "done in an earlier attempt", None)
            return
        async with self.step(name) as out:
            await body(out)

    async def fail(self, failed: StepFailed, phase: str) -> bool:
        """Report the failed step and the phase's failure; whether the backend applied it."""
        await self.report(failed.step, "failed", str(failed))
        return await self.reporter.result(
            self.exposure_id, self.version, phase, "failed", step=failed.step, message=str(failed)
        )
