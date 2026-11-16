"""What the agent does for an exposure in `deploying` and in `cancelling`
(docs/exposure-design.md, Order of execution, steps 3 to 5, and Lifecycle).

Deploying carries out the plan an admin confirmed, the agent's own copy of
it, found by the confirmed hash; the backend sends the hash, never a
declaration. Its steps:

1. recheck: the reservations are still the plan's, and a dry run against the
   F5 as it is now gives the diff the admin approved; otherwise stop, since
   the F5 drifted or a reservation lapsed;
2. deploy: keep the partition's current declaration, for cancel to restore,
   and post the plan's;
3. verify: every virtual server is up, every pool has a member that answers,
   and the app's VIP serves responses with no original origin left in them;
4. dns: create the records, only now, so no name ever resolves to an IP
   nothing listens on.

The backend registers the published origins when it hears the deploy
succeeded. A step the step log has done for this version is skipped, so a
retry resumes from the step that failed.

Cancelling undoes what the exposure did, in reverse, from the agent's own
record: delete its DNS records, restore the partition's previous
declaration, remove its certificates, release its reservations. Each is a
no-op for what it never did, so the same steps cancel a planned exposure.
"""
import logging
from typing import Any
from urllib.parse import urlsplit

from . import as3
from .adapters import F5, DnsService, IpReservations, Probe
from .backend import Reporter
from .config import Settings
from .planner import APP_VIP, diff_declarations
from .state import HeldDnsRecord, PreviousDeclaration, State
from .steps import Run, StepFailed

logger = logging.getLogger(__name__)


class Deployer:
    def __init__(
        self, settings: Settings, state: State, ips: IpReservations, dns: DnsService, f5: F5, probe: Probe,
        reporter: Reporter,
    ):
        self.settings, self.state, self.ips, self.dns, self.f5, self.probe = settings, state, ips, dns, f5, probe
        self.reporter = reporter

    # ---- deploying -------------------------------------------------------------

    async def deploy(self, item: dict[str, Any]) -> bool:
        """Deploy the confirmed plan; report the references it created, or
        the step that failed. Returns whether the backend applied the result."""
        run = Run(item["id"], item["version"], self.reporter, self.state)
        try:
            deployment = await self._deploy(run, item["deploying"]["plan_hash"])
        except StepFailed as failed:
            logger.warning("Deploying %s v%d failed at %s: %s", run.exposure_id, run.version, failed.step, failed)
            return await run.fail(failed, "deploying")
        return await self.reporter.result(run.exposure_id, run.version, "deploying", "ok", deployment=deployment)

    async def _deploy(self, run: Run, confirmed_hash: str) -> dict[str, Any]:
        plan = self.state.plan(run.exposure_id, confirmed_hash)
        if plan is None:
            raise StepFailed("recheck", "the agent has no plan with the confirmed hash; it deploys only plans it made")
        partition, declaration = plan["partition"], plan["declaration"]
        if not partition.startswith(self.settings.partition_prefix):
            raise StepFailed("recheck", f"{partition} is not one of the agent's partitions")

        async def recheck(out: dict[str, Any]) -> None:
            await self._check_reservations(run.exposure_id, plan)
            errors = await self.f5.dry_run(partition, declaration)
            if errors:
                raise StepFailed("recheck", "AS3 refused the declaration: " + "; ".join(errors))
            diff, summary = diff_declarations(await self.f5.declaration(partition), declaration, partition)
            if diff != plan["diff"]:
                raise StepFailed(
                    "recheck",
                    "the F5 changed since the plan: a dry run now gives a different diff from the one confirmed",
                )
            out["message"] = f"as planned: +{summary['add']} ~{summary['change']} -{summary['destroy']}"

        async def deploy(out: dict[str, Any]) -> None:
            self.state.keep_previous_declaration(
                run.exposure_id, PreviousDeclaration(partition, await self.f5.declaration(partition))
            )
            await self.f5.deploy(partition, declaration)
            out["message"] = f"posted to {partition}"

        async def verify(out: dict[str, Any]) -> None:
            out["message"] = await self._verify(partition, plan)

        async def dns(out: dict[str, Any]) -> None:
            for record in plan["dns_records"]:
                await self._create_record(run.exposure_id, record)
            out["message"] = f"{len(plan['dns_records'])} records in {self.settings.dns_zone}"

        await run.resumable("recheck", recheck)
        await run.resumable("deploy", deploy)
        await run.resumable("verify", verify)
        await run.resumable("dns", dns)

        app = declaration["declaration"][partition]["app"]
        mine = [as3.object_name("vs_", vip["group_id"]) for vip in plan["vips"]] + ["vs_app"]
        return {
            "partition": partition,
            "public_url": plan["app"]["public_url"],
            "virtual_servers": [f"/{partition}/app/{name}" for name in mine if name in app],
            "dns_records": [
                {"name": r.name, "type": r.type, "target": r.target, "id": r.record_id}
                for r in self.state.dns_records(run.exposure_id)
            ],
        }

    async def _check_reservations(self, exposure_id: str, plan: dict[str, Any]) -> None:
        """Each address the plan uses is still reserved for the exposure."""
        expected = {vip["group_id"]: vip["ip"] for vip in plan["vips"]}
        if not plan["app"]["existing"]:
            expected[APP_VIP] = plan["app"]["ip"]
        for key, ip in expected.items():
            # Idempotent by key: the same address while the reservation holds.
            now = await self.ips.reserve(f"{exposure_id}/{key}", self.settings.vip_ranges)
            self.state.hold_reservation(exposure_id, key, now)
            if now != ip:
                raise StepFailed(
                    "recheck", f"the reservation of {ip} for {key} lapsed; the service now gives {now}"
                )

    async def _verify(self, partition: str, plan: dict[str, Any]) -> str:
        """Every virtual server up, a member of every pool up, and the app's
        responses rewritten; a message for the step, or StepFailed."""
        status = await self.f5.status(partition)
        problems = [f"{name} is not available" for name, up in status.virtual_servers.items() if not up]
        partly = []
        for pool, members in status.pools.items():
            down = sorted(member for member, up in members.items() if not up)
            if len(down) == len(members):
                problems.append(f"no member of {pool} answers")
            elif down:
                partly.append(f"{pool}: {', '.join(down)} down")
        if problems:
            raise StepFailed("verify", "; ".join(problems))

        host = urlsplit(plan["app"]["public_url"]).hostname
        try:
            response = await self.probe.fetch(plan["app"]["ip"], host)
        except Exception as e:  # noqa: BLE001 - a VIP that does not answer fails the step
            raise StepFailed("verify", f"the app's VIP at {plan['app']['ip']} did not answer as {host}: {e}") from e
        if response.status >= 500:
            raise StepFailed("verify", f"the app's VIP answered {response.status} as {host}")
        left = [r["original"] for r in plan["rewrite"] if r["original"] in response.body]
        if left:
            raise StepFailed("verify", "the app's responses still name " + ", ".join(left) + ": the F5 is not rewriting them")

        message = f"{len(status.virtual_servers)} virtual servers up; the app's responses are rewritten"
        return message + (" (" + "; ".join(partly) + ")" if partly else "")

    async def _create_record(self, exposure_id: str, record: dict[str, str]) -> None:
        zone, name = self.settings.dns_zone, record["name"]
        if name != zone and not name.endswith("." + zone):
            raise StepFailed("dns", f"{name} is outside {zone}, the only zone the agent writes to")
        held = HeldDnsRecord(name, record["type"], record["target"], None)
        self.state.hold_dns_record(exposure_id, held)
        record_id = await self.dns.create_record(zone, name, record["type"], record["target"])
        self.state.hold_dns_record(exposure_id, HeldDnsRecord(held.name, held.type, held.target, record_id))

    # ---- cancelling ------------------------------------------------------------

    async def release(self, item: dict[str, Any]) -> bool:
        """Undo what the exposure did and release what it holds, in reverse
        order of doing it, from the agent's own record."""
        run = Run(item["id"], item["version"], self.reporter, self.state)
        exposure_id = run.exposure_id
        try:
            async with run.step("remove_dns") as out:
                records = self.state.dns_records(exposure_id)
                for r in records:
                    await self.dns.delete_record(self.settings.dns_zone, r.name, r.type, r.target)
                    self.state.drop_dns_record(exposure_id, r.name)
                out["message"] = f"{len(records)} deleted" if records else "none created"

            async with run.step("restore_declaration") as out:
                previous = self.state.previous_declaration(exposure_id)
                if previous is None:
                    out["message"] = "nothing deployed"
                elif previous.declaration is None:
                    await self.f5.remove_partition(previous.partition)
                    out["message"] = f"removed {previous.partition}, which had nothing before"
                else:
                    await self.f5.deploy(previous.partition, previous.declaration)
                    out["message"] = f"restored the previous declaration of {previous.partition}"
                self.state.drop_previous_declaration(exposure_id)

            # Only now: the restored declaration no longer refers to them.
            async with run.step("remove_certificates") as out:
                held_certs = self.state.certificates(exposure_id)
                for key, cert in held_certs.items():
                    await self.f5.remove_certificate(cert.name)
                    self.state.drop_certificate(exposure_id, key)
                out["message"] = f"{len(held_certs)} removed"

            async with run.step("release_ips") as out:
                held = self.state.reservations(exposure_id)
                for key in held:
                    await self.ips.release(f"{exposure_id}/{key}")
                    self.state.drop_reservation(exposure_id, key)
                out["message"] = ", ".join(held.values()) or "none held"
        except StepFailed as failed:
            logger.warning("Cancelling %s v%d failed at %s: %s", exposure_id, run.version, failed.step, failed)
            return await run.fail(failed, "cancelling")
        self.state.drop_plans(exposure_id)
        return await self.reporter.result(exposure_id, run.version, "cancelling", "ok")
