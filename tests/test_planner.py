"""Planning with the fake adapters: what the agent reserves, issues, renders
and reports, and that planning again reuses what it holds."""
import json

from agent.planner import plan_hash
from agent.runner import Agent

from .conftest import A, A8443, R, planning, service


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
        ("https://payroll.corp.internal", "app"),
    ]
    assert plan["rewrite"][-1]["url"] == "https://payroll.example.com"
    rules = plan["declaration"]["declaration"][plan["partition"]]["app"]["rewrite_app"]["uriRules"]
    assert rules[-1] | {"type": None} == {
        "type": None, "leftValue": "https://payroll.corp.internal/", "rightValue": "https://payroll.example.com/",
    }
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


async def test_a_service_on_the_app_origin_fails_the_names_for_now(harness):
    # It would share the app's public name: open question 1. Once that is
    # settled, the rewrite map keeps the service's entry, not the app's.
    own = service("svc_own", "payroll.corp.internal", ips=("10.20.0.9",))
    await harness.planner.plan(planning([[A], [own]]))
    [result] = harness.reporter.results
    assert (result["outcome"], result["step"]) == ("failed", "names")


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


async def test_the_plan_is_kept_under_its_hash(harness):
    plan = await harness.planned(planning([[A]]))
    assert harness.state.plan("exp_1", plan_hash(plan)) == plan
    # The hash survives the trip through JSON, as the backend computes it.
    assert plan_hash(json.loads(json.dumps(plan))) == plan_hash(plan)


async def test_the_agent_works_through_what_is_pending(harness):
    class Backend:
        async def pending(self):
            return [
                planning([[A]], exposure_id="exp_1"),
                {"id": "exp_2", "status": "deploying", "version": 1, "deploying": {"plan_hash": "sha256:unknown"}},
                {"id": "exp_3", "status": "cancelling", "version": 2, "cancelling": {}},
            ]

    agent = Agent(harness.planner, harness.deployer, Backend(), poll_interval_s=0)
    assert await agent.tick() == 3
    assert [(r["exposure_id"], r["phase"], r["outcome"]) for r in harness.reporter.results] == [
        ("exp_1", "planning", "ok"), ("exp_2", "deploying", "failed"), ("exp_3", "cancelling", "ok"),
    ]
