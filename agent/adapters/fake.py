"""In-memory stand-ins for the IP reservation service, the DNS service and the
F5, for development and tests. They keep the real services' contracts as the
agent relies on them: reservations idempotent by key and drawn from the given
ranges, certificates issued for exactly the names asked, a dry run that checks
the declaration's shape."""
import ipaddress
from datetime import date, timedelta
from typing import Any, Optional

from . import IssuedCertificate


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


class FakeDnsService:
    def __init__(self) -> None:
        self.issued: list[tuple[str, ...]] = []

    async def issue_certificate(self, names: tuple[str, ...]) -> IssuedCertificate:
        self.issued.append(names)
        serial = len(self.issued)
        return IssuedCertificate(
            names=names,
            certificate_pem=f"-----BEGIN CERTIFICATE-----\nfake {serial} for {' '.join(names)}\n-----END CERTIFICATE-----\n",
            private_key_pem=f"-----BEGIN PRIVATE KEY-----\nfake key {serial}\n-----END PRIVATE KEY-----\n",
            expires=(date.today() + timedelta(days=365)).isoformat(),
        )


class FakeF5:
    def __init__(self) -> None:
        self.certificates: dict[str, IssuedCertificate] = {}
        self.declarations: dict[str, dict[str, Any]] = {}

    async def install_certificate(self, partition: str, name: str, cert: IssuedCertificate) -> str:
        path = f"/{partition}/{name}"
        self.certificates[path] = cert
        return path

    async def remove_certificate(self, path: str) -> None:
        self.certificates.pop(path, None)

    async def declaration(self, partition: str) -> Optional[dict[str, Any]]:
        return self.declarations.get(partition)

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
                if isinstance(item, dict) and item.get("class") == "Service_HTTPS":
                    for ref in ("serverTLS", "policyEndpoint"):
                        if ref in item and item[ref] not in app:
                            errors.append(f"{app_name}/{name}: {ref} {item[ref]!r} is not declared")
        return errors
