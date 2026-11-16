"""The agent against the fake adapters, with a recorder in place of the backend."""
from typing import Any, Optional

import pytest

from agent.adapters.fake import FakeDnsService, FakeF5, FakeIpReservations, FakeProbe
from agent.config import Settings
from agent.deployer import Deployer
from agent.planner import Planner, plan_hash
from agent.state import State


class Recorder:
    """Stands in for the backend: records steps and results, applies every result."""

    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []

    async def step(self, exposure_id, seq, version, step, state, message=None, detail=None) -> None:
        self.steps.append({"exposure_id": exposure_id, "seq": seq, "version": version, "step": step, "state": state, "message": message})

    async def result(self, exposure_id, version, phase, outcome, plan=None, step=None, message=None, deployment=None) -> bool:
        self.results.append({"exposure_id": exposure_id, "version": version, "phase": phase, "outcome": outcome,
                             "plan": plan, "deployment": deployment, "step": step, "message": message})
        return True


def service(id: str, host: str, *, scheme="https", port=443, ips=("10.20.0.1",), auth="bearer") -> dict:
    return {"id": id, "scheme": scheme, "host": host, "port": port, "auth_method": auth, "ips": list(ips)}


def planning(groups: list[list[dict]], *, exposure_id="exp_1", version=1, published=(), group_prefix="grp_") -> dict:
    return {
        "id": exposure_id,
        "status": "planning",
        "version": version,
        "planning": {
            "app": {"id": "app_payroll", "name": "Payroll", "url": "https://payroll.corp.internal"},
            "groups": [{"id": f"{group_prefix}{i}", "services": g} for i, g in enumerate(groups)],
            "published": list(published),
        },
    }


A = service("svc_a", "api.payroll.corp.internal")
A8443 = service("svc_a8443", "api.payroll.corp.internal", port=8443, ips=("10.20.0.1", "10.20.0.2"))
R = service("svc_r", "reports.corp.internal", scheme="http", port=8080)


class Harness:
    def __init__(self, tmp_path) -> None:
        self.settings = Settings(state_path=str(tmp_path / "state.sqlite3"), vip_ranges=("203.0.113.0/29",))
        self.ips, self.dns, self.f5 = FakeIpReservations(), FakeDnsService(), FakeF5()
        self.reporter = Recorder()
        self.restart()

    def restart(self) -> None:
        """A new agent process on the same state file and services."""
        self.state = State(self.settings.state_path)
        self.planner = Planner(self.settings, self.state, self.ips, self.dns, self.f5, self.reporter)
        self.deployer = Deployer(
            self.settings, self.state, self.ips, self.dns, self.f5, FakeProbe(self.f5), self.reporter
        )

    def last_plan(self) -> Optional[dict]:
        return self.reporter.results[-1]["plan"]

    async def planned(self, item: dict) -> dict:
        """Plan `item`; the plan, which must have succeeded."""
        await self.planner.plan(item)
        result = self.reporter.results[-1]
        assert result["outcome"] == "ok", result
        return result["plan"]

    async def deploy(self, plan: dict, *, exposure_id="exp_1", version=1) -> dict:
        """Deploy the plan as confirmed; the result reported."""
        await self.deployer.deploy({
            "id": exposure_id, "status": "deploying", "version": version,
            "deploying": {"plan_hash": plan_hash(plan)},
        })
        return self.reporter.results[-1]

    async def cancel(self, *, exposure_id="exp_1", version=2) -> dict:
        await self.deployer.release({"id": exposure_id, "status": "cancelling", "version": version, "cancelling": {}})
        return self.reporter.results[-1]

    def steps_of(self, exposure_id="exp_1", version=None) -> list[tuple[str, str]]:
        return [
            (s["step"], s["state"]) for s in self.reporter.steps
            if s["exposure_id"] == exposure_id and (version is None or s["version"] == version)
        ]


@pytest.fixture
def harness(tmp_path) -> Harness:
    return Harness(tmp_path)
