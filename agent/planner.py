"""What the agent does for an exposure in `planning` (docs/exposure-design.md,
Order of execution, step 1).

Planning reserves one IP per VIP, requests and installs each VIP's
certificate, renders the AS3 declaration and dry-runs it. Every step reuses
what the exposure already holds, so planning again, after a restart, a retry
or a change to the grouping, reserves nothing twice: a group keeps its IP
while it exists, a VIP keeps its certificate while its names are unchanged,
and what is no longer needed is released. The plan is kept in the agent's
record under its hash: it is what the agent deploys once an admin confirms
that hash. Deploying and cancelling are in deployer.py.
"""
import difflib
import hashlib
import json
import logging
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

from . import as3
from .adapters import F5, DnsService, IpReservations
from .backend import Reporter
from .config import Settings
from .naming import NamingError, origin_text, public_name
from .state import HeldCertificate, State
from .steps import Run, StepFailed

logger = logging.getLogger(__name__)

APP_VIP = "app"


def plan_hash(plan: dict[str, Any]) -> str:
    """sha256 of the plan's canonical JSON, as the backend computes it: the
    hash an admin confirms, and the one a deploy names."""
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _partition(settings: Settings, app_id: str) -> str:
    return as3.object_name(settings.partition_prefix, app_id)


class Planner:
    def __init__(self, settings: Settings, state: State, ips: IpReservations, dns: DnsService, f5: F5, reporter: Reporter):
        self.settings, self.state, self.ips, self.dns, self.f5, self.reporter = settings, state, ips, dns, f5, reporter

    # ---- planning ------------------------------------------------------------

    async def plan(self, item: dict[str, Any]) -> bool:
        """Plan an exposure in `planning`; report its plan, or the step that
        failed. Returns whether the backend applied the result."""
        run = Run(item["id"], item["version"], self.reporter, self.state)
        try:
            plan = await self._plan(run, item["planning"])
        except StepFailed as failed:
            logger.warning("Planning %s v%d failed at %s: %s", run.exposure_id, run.version, failed.step, failed)
            return await run.fail(failed, "planning")
        self.state.hold_plan(run.exposure_id, run.version, plan_hash(plan), plan)
        return await self.reporter.result(run.exposure_id, run.version, "planning", "ok", plan=plan)

    async def _plan(self, run: Run, work: dict[str, Any]) -> dict[str, Any]:
        app, groups, published = work["app"], work["groups"], work["published"]
        partition = _partition(self.settings, app["id"])
        deployed = await self.f5.declaration(partition)
        # What the app's earlier exposures deployed stays; its own VIP, if it
        # has one, keeps its address and certificate and gets a new rewrite map.
        deployed_app = (deployed or {}).get("declaration", {}).get(partition, {}).get("app", {})
        existing_app = deployed_app.get("vs_app")

        async with run.step("names") as out:
            names = self._names(app, groups)
            out["message"] = f"{len(names)} names in {self.settings.dns_zone}"

        async with run.step("reserve_ips") as out:
            keys = [g["id"] for g in groups] + ([] if existing_app else [APP_VIP])
            ips = await self._reserve(run.exposure_id, keys)
            if existing_app:
                ips[APP_VIP] = existing_app["virtualAddresses"][0]
            out["message"] = ", ".join(f"{key} {ip}" for key, ip in ips.items())

        async with run.step("certificates") as out:
            wanted = {g["id"]: tuple(sorted(names[s["id"]] for s in g["services"])) for g in groups}
            if not existing_app:
                wanted[APP_VIP] = (names[APP_VIP],)
            certificates, issued = await self._certificates(run.exposure_id, partition, wanted)
            out["message"] = f"{issued} issued, {len(certificates) - issued} reused"

        async with run.step("render") as out:
            vips = [
                as3.Vip(
                    key=g["id"],
                    ip=ips[g["id"]],
                    certificate_path=certificates[g["id"]].name,
                    services=tuple(
                        as3.PoolService(s["id"], s["scheme"], s["host"], s["port"], tuple(s["ips"]), names[s["id"]])
                        for s in g["services"]
                    ),
                )
                for g in groups
            ]
            # Every service the app calls: the ones this exposure publishes,
            # and the ones already published, at their registry URLs.
            rewrite = [
                {"original": origin_text(s["scheme"], s["host"], s["port"]), "url": f"https://{names[s['id']]}", "source": "new"}
                for g in groups for s in g["services"]
            ] + [
                {"original": origin_text(p["scheme"], p["host"], p["port"]), "url": p["url"], "source": "published"}
                for p in published
            ]
            app_vip = as3.AppVip(
                ip=ips[APP_VIP],
                certificate_path=(
                    certificates[APP_VIP].name if APP_VIP in certificates
                    # The deployed app VIP keeps its own, which its exposure holds.
                    else deployed_app[existing_app["serverTLS"]]["certificates"][0]["certificate"]["bigip"]
                ),
                url=app["url"],
                public_name=names[APP_VIP],
                rewrite=tuple((r["original"], r["url"]) for r in rewrite),
            )
            declaration = as3.render(run.exposure_id, partition, vips, app_vip, keep=deployed_app)
            out["message"] = f"{len(vips)} VIPs and the app's"

        async with run.step("dry_run") as out:
            errors = await self.f5.dry_run(partition, declaration)
            if errors:
                raise StepFailed("dry_run", "AS3 refused the declaration: " + "; ".join(errors))
            diff, summary = diff_declarations(deployed, declaration, partition)
            out["message"] = f"+{summary['add']} ~{summary['change']} -{summary['destroy']}"

        # Created only after the deploy verifies, so no name resolves to an IP
        # nothing listens on. A deployed app VIP has its name already, which
        # its own exposure holds; this one creates only its services' names.
        dns_records = sorted(
            ([] if existing_app else [{"name": names[APP_VIP], "type": "A", "target": ips[APP_VIP]}])
            + [{"name": names[s["id"]], "type": "A", "target": ips[g["id"]]} for g in groups for s in g["services"]],
            key=lambda record: record["name"],
        )
        summary.update({
            "ips": len([k for k in ips if k != APP_VIP or not existing_app]),
            "dns": len(dns_records),
            "certificates": len(certificates),
        })
        return {
            "partition": partition,
            "app": {
                "name": app["name"],
                "url": app["url"],
                "public_url": f"https://{names[APP_VIP]}",
                "ip": ips[APP_VIP],
                "existing": bool(existing_app),
                "certificate": _cert_view(certificates.get(APP_VIP)),
            },
            "vips": [
                {
                    "group_id": vip.key,
                    "ip": vip.ip,
                    "certificate": _cert_view(certificates[vip.key]),
                    "services": [
                        {
                            "service_id": s.service_id,
                            "original": origin_text(s.scheme, s.host, s.port),
                            "url": f"https://{s.public_name}",
                            "pool": [f"{ip}:{s.port}" for ip in s.ips],
                            "pool_scheme": s.scheme,
                        }
                        for s in vip.services
                    ],
                }
                for vip in vips
            ],
            "rewrite": rewrite,
            "dns_records": dns_records,
            "declaration": declaration,
            "diff": diff,
            "summary": summary,
        }

    def _names(self, app: dict[str, Any], groups: list[dict[str, Any]]) -> dict[str, str]:
        """A public name per service by id, and the app's under APP_VIP."""
        try:
            app_url = urlsplit(app["url"])
            app_port = app_url.port or (443 if app_url.scheme == "https" else 80)
            names = {APP_VIP: self._name(app_url.scheme, app_url.hostname, app_port)}
            for g in groups:
                for s in g["services"]:
                    names[s["id"]] = self._name(s["scheme"], s["host"], s["port"])
        except NamingError as e:
            raise StepFailed("names", str(e)) from e
        seen: dict[str, str] = {}
        for key, name in names.items():
            if name in seen:
                raise StepFailed(
                    "names",
                    f"two origins would both be named {name}: telling them apart is open question 1 of the design",
                )
            seen[name] = key
        return names

    def _name(self, scheme: str, host: str, port: int) -> str:
        return public_name(scheme, host, port, self.settings.dns_zone, self.settings.internal_suffixes)

    async def _reserve(self, exposure_id: str, keys: list[str]) -> dict[str, str]:
        held = self.state.reservations(exposure_id)
        for key in held.keys() - set(keys):
            await self.ips.release(f"{exposure_id}/{key}")
            self.state.drop_reservation(exposure_id, key)
        out = {}
        for key in keys:
            ip = await self.ips.reserve(f"{exposure_id}/{key}", self.settings.vip_ranges)
            self.state.hold_reservation(exposure_id, key, ip)
            out[key] = ip
        return out

    async def _certificates(
        self, exposure_id: str, partition: str, wanted: dict[str, tuple[str, ...]]
    ) -> tuple[dict[str, HeldCertificate], int]:
        """Each VIP's certificate, reused while its names are unchanged; a new
        one replaces it otherwise, and the old one leaves the F5."""
        held = self.state.certificates(exposure_id)
        for key in held.keys() - wanted.keys():
            await self.f5.remove_certificate(held[key].name)
            self.state.drop_certificate(exposure_id, key)
        out, issued = {}, 0
        for key, names in wanted.items():
            current = held.get(key)
            if current is not None and current.names == names:
                out[key] = current
                continue
            certificate = await self.dns.issue_certificate(names)
            name = as3.object_name("cert_", f"{key}_{uuid.uuid4().hex[:8]}")
            path = await self.f5.install_certificate(partition, name, certificate)
            if current is not None:
                await self.f5.remove_certificate(current.name)
            out[key] = HeldCertificate(key, path, names, certificate.expires)
            self.state.hold_certificate(exposure_id, out[key])
            issued += 1
        return out, issued


def _cert_view(cert: Optional[HeldCertificate]) -> Optional[dict[str, Any]]:
    """What the plan shows of a certificate: never its key."""
    if cert is None:
        return None
    return {"name": cert.name, "names": list(cert.names), "expires": cert.expires}


def diff_declarations(
    deployed: Optional[dict[str, Any]], declaration: dict[str, Any], partition: str
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """The dry run's diff of the partition, unified, and how many of its
    objects it adds, changes and destroys."""
    before = ((deployed or {}).get("declaration", {}).get(partition) or {})
    after = declaration["declaration"][partition]
    lines = []
    for line in difflib.unified_diff(
        json.dumps(before, indent=2, sort_keys=True).splitlines() if before else [],
        json.dumps(after, indent=2, sort_keys=True).splitlines(),
        lineterm="",
        n=3,
    ):
        if line.startswith(("---", "+++")):
            continue
        op = "@" if line.startswith("@@") else line[:1] or " "
        lines.append({"op": op, "text": line if op == "@" else line[1:]})
    old_app, new_app = before.get("app", {}), after.get("app", {})
    objects = lambda app: {k: v for k, v in app.items() if k != "class"}  # noqa: E731
    old, new = objects(old_app), objects(new_app)
    summary = {
        "add": len(new.keys() - old.keys()),
        "change": sum(1 for k in new.keys() & old.keys() if new[k] != old[k]),
        "destroy": len(old.keys() - new.keys()),
    }
    return lines, summary

