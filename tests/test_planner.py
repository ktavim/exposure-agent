"""Planning and cancelling with the fake adapters: what the agent reserves,
issues, renders and reports, and that planning again reuses what it holds."""
import json
from typing import Any, Optional

import pytest

from agent.adapters.fake import FakeDnsService, FakeF5, FakeIpReservations
from agent.config import Settings
from agent.planner import Planner
from agent.runner import Agent
from agent.state import State


class Recorder:
    """Stands in for the backend: records steps and results, applies every result."""

    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []

    async def step(self, exposure_id, seq, version, step, state, message=None, detail=None) -> None:
        self.steps.append({"exposure_id": exposure_id, "seq": seq, "version": version, "step": step, "state": state, "message": message})

    async def result(self, exposure_id, version, phase, outcome, plan=None, step=None, message=None) -> bool:
        self.results.append({"exposure_id": exposure_id, "version": version, "phase": phase, "outcome": outcome,
                             "plan": plan, "step": step, "message": message})
        return True


def service(id: str, host: str, *, scheme="https", port=443, ips=("10.20.0.1",), auth="bearer") -> dict:
    return {"id": id, "scheme": scheme, "host": host, "port": port, "auth_method": auth, "ips": list(ips)}


def planning(groups: list[list[dict]], *, exposure_id="exp_1", version=1, published=()) -> dict:
    return {
        "id": exposure_id,
        "status": "planning",
        "version": version,
        "planning": {
            "app": {"id": "app_payroll", "name": "Payroll", "url": "https://payroll.corp.internal"},
            "groups": [{"id": f"grp_{i}", "services": g} for i, g in enumerate(groups)],
            "published": list(published),
        },
    }


@pytest.fixture
def harness(tmp_path):
    class Harness:
        def __init__(self) -> None:
            self.settings = Settings(state_path=str(tmp_path / "state.sqlite3"), vip_ranges=("203.0.113.0/29",))
            self.ips, self.dns, self.f5 = FakeIpReservations(), FakeDnsService(), FakeF5()
            self.reporter = Recorder()
            self.restart()

        def restart(self) -> None:
            """A new agent process on the same state file and services."""
            self.state = State(self.settings.state_path)
            self.planner = Planner(self.settings, self.state, self.ips, self.dns, self.f5, self.reporter)

        def last_plan(self) -> Optional[dict]:
            return self.reporter.results[-1]["plan"]

    return Harness()


A = service("svc_a", "api.payroll.corp.internal")
A8443 = service("svc_a8443", "api.payroll.corp.internal", port=8443, ips=("10.20.0.1", "10.20.0.2"))
R = service("svc_r", "reports.corp.internal", scheme="http", port=8080)


async def test_a_plan_reserves_names_certifies_renders_and_dry_runs(harness):
    published = [{"scheme": "https", "host": "hr.corp.internal", "port": 443, "url": "https://hr.example.com"}]
    assert await harness.planner.plan(planning([[A, A8443], [R]], published=published))
    [result] = harness.reporter.results
    assert (result["phase"], result["outcome"], result["version"]) == ("planning", "ok", 1)
    plan = result["plan"]

    assert [v["ip"] for v in plan["vips"]] + [plan["app"]["ip"]] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert [s["url"] for s in plan["vips"][0]["services"]] == [
        "https://api-payroll.example.com", "https://api-payroll-8443.example.com",
    ]
    assert plan["vips"][0]["certificate"]["names"] == ["api-payroll-8443.example.com", "api-payroll.example.com"]
    assert plan["vips"][1]["services"][0] | {"pool": None} == {
        "service_id": "svc_r", "original": "http://reports.corp.internal:8080",
        "url": "https://reports-8080.example.com", "pool": None, "pool_scheme": "http",
    }
    assert plan["app"]["public_url"] == "https://payroll.example.com"
    assert [(r["original"], r["source"]) for r in plan["rewrite"]] == [
        ("https://api.payroll.corp.internal", "new"),
        ("https://api.payroll.corp.internal:8443", "new"),
        ("http://reports.corp.internal:8080", "new"),
        ("https://hr.corp.internal", "published"),
    ]
    assert {r["name"]: r["target"] for r in plan["dns_records"]} == {
        "api-payroll.example.com": "203.0.113.1",
        "api-payroll-8443.example.com": "203.0.113.1",
        "reports-8080.example.com": "203.0.113.2",
        "payroll.example.com": "203.0.113.3",
    }
    # A first plan adds every object; nothing was deployed before.
    assert plan["summary"]["change"] == plan["summary"]["destroy"] == 0
    assert plan["summary"]["add"] > 0 and all(line["op"] in "+@" for line in plan["diff"])
    app = plan["declaration"]["declaration"][plan["partition"]]["app"]
    assert app["vs_grp_0"]["virtualAddresses"] == ["203.0.113.1"]
    assert app["vs_app"]["profileRewrite"] == {"use": "rewrite_app"}
    # Three certificates, installed with their keys on the F5 and nowhere else.
    assert len(harness.f5.certificates) == 3
    assert "PRIVATE KEY" not in json.dumps(plan)
    assert [s["step"] for s in harness.reporter.steps if s["state"] == "done"] == [
        "names", "reserve_ips", "certificates", "render", "dry_run",
    ]
    assert [s["seq"] for s in harness.reporter.steps] == list(range(len(harness.reporter.steps)))


async def test_planning_again_reuses_what_the_exposure_holds(harness):
    await harness.planner.plan(planning([[A], [R]]))
    first = harness.last_plan()
    harness.restart()
    # Version 2: R moved in with A; the second group is gone.
    item = planning([[A, R]], version=2)
    await harness.planner.plan(item)
    second = harness.last_plan()

    assert second["vips"][0]["ip"] == first["vips"][0]["ip"]
    assert second["app"]["ip"] == first["app"]["ip"]
    # The old second group's address went back to the pool.
    assert first["vips"][1]["ip"] not in harness.ips.held.values()
    # Group 0's names changed, so its certificate was replaced; the app's was not.
    assert second["vips"][0]["certificate"]["name"] != first["vips"][0]["certificate"]["name"]
    assert second["app"]["certificate"] == first["app"]["certificate"]
    assert set(harness.f5.certificates) == {second["vips"][0]["certificate"]["name"], second["app"]["certificate"]["name"]}


async def test_the_same_plan_again_issues_nothing(harness):
    await harness.planner.plan(planning([[A]]))
    issued = len(harness.dns.issued)
    await harness.planner.plan(planning([[A]], version=2))
    assert len(harness.dns.issued) == issued


async def test_two_origins_with_one_name_fail_the_plan(harness):
    clash = [service("svc_h", "x.corp.internal", scheme="http", port=80), service("svc_s", "x.corp.internal")]
    await harness.planner.plan(planning([clash]))
    [result] = harness.reporter.results
    assert (result["outcome"], result["step"]) == ("failed", "names")
    assert "open question 1" in result["message"]
    assert harness.ips.held == {}


async def test_an_exhausted_range_fails_at_reserving(harness):
    harness.ips.taken = {f"203.0.113.{i}" for i in range(1, 7)}
    await harness.planner.plan(planning([[A]]))
    [result] = harness.reporter.results
    assert (result["outcome"], result["step"]) == ("failed", "reserve_ips")
    assert "no free address" in result["message"]


async def test_cancelling_releases_everything_held(harness):
    await harness.planner.plan(planning([[A], [R]]))
    harness.restart()
    assert await harness.planner.cancel({"id": "exp_1", "status": "cancelling", "version": 2, "cancelling": {}})
    assert harness.reporter.results[-1] | {"plan": None} == {
        "exposure_id": "exp_1", "version": 2, "phase": "cancelling", "outcome": "ok",
        "plan": None, "step": None, "message": None,
    }
    assert harness.ips.held == {} and harness.f5.certificates == {}
    assert harness.state.reservations("exp_1") == {} and harness.state.certificates("exp_1") == {}


async def test_the_agent_works_through_what_is_pending(harness):
    class Backend:
        async def pending(self):
            return [
                planning([[A]], exposure_id="exp_1"),
                {"id": "exp_2", "status": "deploying", "version": 1, "deploying": {}},
            ]

    agent = Agent(harness.planner, Backend(), poll_interval_s=0)
    assert await agent.tick() == 1  # deploying waits for phase 5
    assert [r["exposure_id"] for r in harness.reporter.results] == ["exp_1"]
