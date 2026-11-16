"""Deploying and cancelling with the fake adapters: the confirmed plan carried
out step by step, what stops it, how a retry resumes, and how cancelling
undoes it."""
from .conftest import A, A8443, R, planning

PARTITION = "exp_app_payroll"


async def test_a_deploy_carries_out_the_confirmed_plan(harness):
    plan = await harness.planned(planning([[A, A8443], [R]]))
    result = await harness.deploy(plan)

    assert (result["phase"], result["outcome"], result["version"]) == ("deploying", "ok", 1)
    assert result["deployment"] | {"dns_records": None} == {
        "partition": PARTITION,
        "public_url": "https://payroll.example.com",
        "virtual_servers": [f"/{PARTITION}/app/vs_grp_0", f"/{PARTITION}/app/vs_grp_1", f"/{PARTITION}/app/vs_app"],
        "dns_records": None,
    }
    assert [(r["name"], r["target"]) for r in result["deployment"]["dns_records"]] == [
        (r["name"], r["target"]) for r in plan["dns_records"]
    ]
    assert all(r["id"].startswith("rec_") for r in result["deployment"]["dns_records"])
    assert harness.f5.declarations[PARTITION] == plan["declaration"]
    assert set(harness.dns.records) == {r["name"] for r in plan["dns_records"]}
    assert harness.steps_of(version=1)[-8:] == [
        ("recheck", "started"), ("recheck", "done"), ("deploy", "started"), ("deploy", "done"),
        ("verify", "started"), ("verify", "done"), ("dns", "started"), ("dns", "done"),
    ]


async def test_only_a_plan_the_agent_made_is_deployed(harness):
    plan = await harness.planned(planning([[A]]))
    plan["declaration"]["declaration"][PARTITION]["app"]["vs_grp_0"]["virtualAddresses"] = ["192.0.2.66"]
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "recheck")
    assert "no plan with the confirmed hash" in result["message"]
    assert harness.f5.posts == 0


async def test_a_drifted_f5_stops_the_deploy(harness):
    plan = await harness.planned(planning([[A]]))
    # Someone changed the partition by hand since the plan.
    harness.f5.declarations[PARTITION] = {
        "class": "AS3",
        "declaration": {"class": "ADC", PARTITION: {"class": "Tenant", "app": {"class": "Application"}}},
    }
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "recheck")
    assert "the F5 changed since the plan" in result["message"]
    assert harness.f5.posts == 0


async def test_a_lapsed_reservation_stops_the_deploy(harness):
    plan = await harness.planned(planning([[A]]))
    harness.ips.lapse("exp_1/grp_0")
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "recheck")
    assert f"the reservation of {plan['vips'][0]['ip']} for grp_0 lapsed" in result["message"]


async def test_a_failed_verify_is_retried_from_verify(harness):
    plan = await harness.planned(planning([[A]]))
    harness.f5.rewriting = False
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "verify")
    assert "still name https://api.payroll.corp.internal" in result["message"]
    assert (harness.f5.posts, harness.dns.records) == (1, {})

    harness.f5.rewriting = True
    harness.restart()
    before = len(harness.reporter.steps)
    result = await harness.deploy(plan)
    assert result["outcome"] == "ok"
    assert harness.f5.posts == 1  # not posted again
    assert [(s["step"], s["state"]) for s in harness.reporter.steps[before:]] == [
        ("recheck", "skipped"), ("deploy", "skipped"),
        ("verify", "started"), ("verify", "done"), ("dns", "started"), ("dns", "done"),
    ]


async def test_verify_needs_a_member_of_every_pool(harness):
    plan = await harness.planned(planning([[A, A8443]]))
    harness.f5.down = {"10.20.0.2:8443"}
    result = await harness.deploy(plan)
    assert result["outcome"] == "ok"
    verified = [s for s in harness.reporter.steps if s["step"] == "verify" and s["state"] == "done"]
    assert "10.20.0.2:8443 down" in verified[0]["message"]

    harness.f5.down = {"10.20.0.1:443"}
    plan2 = await harness.planned(planning([[A]], exposure_id="exp_2", group_prefix="g2_"))
    result = await harness.deploy(plan2, exposure_id="exp_2")
    assert (result["outcome"], result["step"]) == ("failed", "verify")
    assert "no member of pool_svc_a answers" in result["message"]


async def test_a_name_that_exists_elsewhere_is_never_repointed(harness):
    plan = await harness.planned(planning([[A]]))
    harness.dns.records["api-payroll.example.com"] = ("A", "198.51.100.7", "rec_theirs")
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "dns")
    assert "exists already" in result["message"]
    # Cancelling deletes the records the exposure created, not that one.
    await harness.cancel()
    assert harness.dns.records == {"api-payroll.example.com": ("A", "198.51.100.7", "rec_theirs")}


async def test_cancelling_a_failed_deploy_undoes_it_in_reverse(harness):
    plan = await harness.planned(planning([[A], [R]]))
    harness.dns.refuse = {"reports-8080.example.com"}
    result = await harness.deploy(plan)
    assert (result["outcome"], result["step"]) == ("failed", "dns")
    assert "api-payroll.example.com" in harness.dns.records

    harness.restart()
    result = await harness.cancel()
    assert (result["phase"], result["outcome"]) == ("cancelling", "ok")
    assert harness.dns.records == {}
    assert PARTITION not in harness.f5.declarations
    assert harness.f5.certificates == {} and harness.ips.held == {}
    assert harness.state.dns_records("exp_1") == [] and harness.state.previous_declaration("exp_1") is None
    done = [(s["step"], s["message"]) for s in harness.reporter.steps if s["version"] == 2 and s["state"] == "done"]
    assert [step for step, _ in done] == ["remove_dns", "restore_declaration", "remove_certificates", "release_ips"]
    assert done[1][1] == f"removed {PARTITION}, which had nothing before"


async def test_cancelling_a_planned_exposure_releases_what_it_holds(harness):
    await harness.planned(planning([[A], [R]]))
    harness.restart()
    result = await harness.cancel()
    assert result | {"plan": None} == {
        "exposure_id": "exp_1", "version": 2, "phase": "cancelling", "outcome": "ok",
        "plan": None, "deployment": None, "step": None, "message": None,
    }
    assert harness.ips.held == {} and harness.f5.certificates == {}
    assert harness.state.reservations("exp_1") == {} and harness.state.certificates("exp_1") == {}


async def test_a_later_exposure_keeps_the_earlier_deploy_and_cancelling_restores_it(harness):
    first = await harness.planned(planning([[A]]))
    assert (await harness.deploy(first))["outcome"] == "ok"
    deployed = harness.f5.declarations[PARTITION]

    second = await harness.planned(planning([[R]], exposure_id="exp_2", group_prefix="g2_",
                                            published=[{"scheme": "https", "host": "api.payroll.corp.internal",
                                                        "port": 443, "url": "https://api-payroll.example.com"}]))
    app = second["declaration"]["declaration"][PARTITION]["app"]
    assert {"vs_grp_0", "vs_g2_0", "vs_app"} <= set(app)
    assert app["vs_grp_0"] == deployed["declaration"][PARTITION]["app"]["vs_grp_0"]
    # Only the rewrite map changes on the app's VIP, which keeps its address,
    # certificate and name.
    assert (second["summary"]["destroy"], second["summary"]["change"]) == (0, 1)
    assert second["app"]["existing"] and second["app"]["ip"] == first["app"]["ip"]
    assert [r["name"] for r in second["dns_records"]] == ["reports-8080.example.com"]

    harness.f5.rewriting = False
    assert (await harness.deploy(second, exposure_id="exp_2"))["step"] == "verify"
    await harness.cancel(exposure_id="exp_2")
    assert harness.f5.declarations[PARTITION] == deployed
    assert first["app"]["certificate"]["name"] in harness.f5.certificates
    assert "payroll.example.com" in harness.dns.records
