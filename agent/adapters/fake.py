"""In-memory stand-ins for the IP reservation service, the DNS service, the
F5 and the probe, for development and tests. They keep the real services'
contracts as the agent relies on them: reservations idempotent by key and
drawn from the given ranges, certificates issued for exactly the names asked,
records never repointed, a dry run that checks the declaration's shape and
the certificates it refers to, a deploy that is all or nothing. Each has
knobs a test turns to make it fail the way the real one could."""
import copy
import ipaddress
from datetime import date, timedelta
from typing import Any, Optional

from . import IssuedCertificate, PartitionStatus, ProbeResponse


class FakeIpReservations:
    def __init__(self) -> None:
        self.held: dict[str, str] = {}
        # Addresses something else holds, for tests of an exhausted range.
        self.taken: set[str] = set()

    async def reserve(self, key: str, ranges: tuple[str, ...]) -> str:
        if key in self.held:
            return self.held[key]
        in_use = set(self.held.values()) | self.taken
        for cidr in ranges:
            for address in ipaddress.ip_network(cidr).hosts():
                if str(address) not in in_use:
                    self.held[key] = str(address)
                    return str(address)
        raise RuntimeError(f"no free address in {', '.join(ranges)}")

    async def release(self, key: str) -> None:
        self.held.pop(key, None)

    def lapse(self, key: str) -> None:
        """A reservation that expired, its address since given to someone else."""
        self.taken.add(self.held.pop(key))


class FakeDnsService:
    def __init__(self) -> None:
        self.issued: list[tuple[str, ...]] = []
        # name -> (type, target, record id)
        self.records: dict[str, tuple[str, str, str]] = {}
        self._next_record = 0
        # Names the service refuses, for tests of a failure halfway.
        self.refuse: set[str] = set()

    async def issue_certificate(self, names: tuple[str, ...]) -> IssuedCertificate:
        self.issued.append(names)
        serial = len(self.issued)
        return IssuedCertificate(
            names=names,
            certificate_pem=f"-----BEGIN CERTIFICATE-----\nfake {serial} for {' '.join(names)}\n-----END CERTIFICATE-----\n",
            private_key_pem=f"-----BEGIN PRIVATE KEY-----\nfake key {serial}\n-----END PRIVATE KEY-----\n",
            expires=(date.today() + timedelta(days=365)).isoformat(),
        )

    async def create_record(self, zone: str, name: str, type: str, target: str) -> str:
        if name in self.refuse:
            raise RuntimeError(f"the DNS service refused {name}")
        current = self.records.get(name)
        if current is not None:
            if current[:2] == (type, target):
                return current[2]
            raise RuntimeError(f"{name} exists already, as {current[0]} {current[1]}")
        self._next_record += 1
        record_id = f"rec_{self._next_record}"
        self.records[name] = (type, target, record_id)
        return record_id

    async def delete_record(self, zone: str, name: str, type: str, target: str) -> None:
        if self.records.get(name, ())[:2] == (type, target):
            del self.records[name]


class FakeF5:
    def __init__(self) -> None:
        self.certificates: dict[str, IssuedCertificate] = {}
        self.declarations: dict[str, dict[str, Any]] = {}
        # How many declarations were posted, to tell a resumed deploy from a repeated one.
        self.posts = 0
        # Virtual servers by name, and pool members as "address:port", that are down.
        self.down: set[str] = set()
        # Whether the app VIP's rewrite profile rewrites; off, to test verification.
        self.rewriting = True

    async def install_certificate(self, partition: str, name: str, cert: IssuedCertificate) -> str:
        path = f"/{partition}/{name}"
        self.certificates[path] = cert
        return path

    async def remove_certificate(self, path: str) -> None:
        self.certificates.pop(path, None)

    async def declaration(self, partition: str) -> Optional[dict[str, Any]]:
        found = self.declarations.get(partition)
        return copy.deepcopy(found) if found is not None else None

    async def dry_run(self, partition: str, declaration: dict[str, Any]) -> list[str]:
        errors = []
        adc = declaration.get("declaration", {})
        if adc.get("class") != "ADC":
            errors.append("declaration: class must be ADC")
        tenant = adc.get(partition)
        if not isinstance(tenant, dict) or tenant.get("class") != "Tenant":
            errors.append(f"{partition}: missing, or not a Tenant")
            return errors
        for app_name, app in tenant.items():
            if not isinstance(app, dict) or app.get("class") != "Application":
                continue
            for name, item in app.items():
                if not isinstance(item, dict):
                    continue
                if item.get("class") == "Service_HTTPS":
                    for ref in ("serverTLS", "policyEndpoint", "pool"):
                        if ref in item and item[ref] not in app:
                            errors.append(f"{app_name}/{name}: {ref} {item[ref]!r} is not declared")
                if item.get("class") == "TLS_Server":
                    for cert in item.get("certificates", []):
                        path = cert.get("certificate", {}).get("bigip")
                        if path not in self.certificates:
                            errors.append(f"{app_name}/{name}: certificate {path} is not on the device")
        return errors

    async def deploy(self, partition: str, declaration: dict[str, Any]) -> None:
        errors = await self.dry_run(partition, declaration)
        if errors:
            raise RuntimeError("AS3 refused the declaration: " + "; ".join(errors))
        self.declarations[partition] = copy.deepcopy(declaration)
        self.posts += 1

    async def remove_partition(self, partition: str) -> None:
        if self.declarations.pop(partition, None) is not None:
            self.posts += 1

    async def status(self, partition: str) -> PartitionStatus:
        app = _application(self.declarations.get(partition), partition)
        virtuals, pools = {}, {}
        for name, item in app.items():
            if not isinstance(item, dict):
                continue
            if item.get("class") == "Service_HTTPS":
                virtuals[name] = name not in self.down
            elif item.get("class") == "Pool":
                members = {}
                for member in item.get("members", []):
                    for address in member.get("serverAddresses") or [member.get("hostname")]:
                        key = f"{address}:{member['servicePort']}"
                        members[key] = key not in self.down
                pools[name] = members
        return PartitionStatus(virtuals, pools)


class FakeProbe:
    """Requests a page through the fake F5. Behind the app's VIP stands an
    app whose page names every origin in its rewrite map, as the scan found
    them; the VIP's rewrite profile, while it works, replaces each one."""

    def __init__(self, f5: FakeF5) -> None:
        self.f5 = f5

    async def fetch(self, ip: str, host: str, path: str = "/") -> ProbeResponse:
        for partition, declaration in self.f5.declarations.items():
            app = _application(declaration, partition)
            for name, item in app.items():
                if not (isinstance(item, dict) and item.get("class") == "Service_HTTPS"):
                    continue
                if ip not in item.get("virtualAddresses", []):
                    continue
                if name in self.f5.down:
                    raise ConnectionError(f"{ip}:443 does not answer")
                rules = app[item["profileRewrite"]["use"]]["uriRules"] if "profileRewrite" in item else []
                page = "\n".join(f'<script src="{rule["leftValue"]}app.js"></script>' for rule in rules)
                if self.f5.rewriting:
                    for rule in rules:
                        page = page.replace(rule["leftValue"], rule["rightValue"])
                return ProbeResponse(200, page)
        raise ConnectionError(f"nothing listens on {ip}:443")


def _application(declaration: Optional[dict[str, Any]], partition: str) -> dict[str, Any]:
    return ((declaration or {}).get("declaration", {}).get(partition) or {}).get("app", {})
