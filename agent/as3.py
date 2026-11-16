"""The agent's AS3 template (docs/exposure-design.md, Grouping and Rewriting).
The backend sends data, never AS3; the declaration is rendered here.

One partition (tenant) per app, one application in it:

- a VIP per group: one virtual server on 443 that terminates TLS with a
  certificate covering its services' names, and an endpoint policy that
  routes by the Host header to each service's pool, setting the header back
  to the original name on the way;
- a pool per service, its members the service's addresses and port; one that
  serves HTTPS gets a TLS client profile, with the original name as SNI;
- the app's own VIP, whose rewrite profile replaces each original origin in
  the app's responses with the URL that publishes it.

AS3 declares a partition whole: what a declaration leaves out is removed. So
an app's later exposure keeps the VIPs its earlier ones deployed, passed in
as `keep`, and re-renders only the app's VIP, whose rewrite map it replaces.

How the F5 rewrites is open question 4: the rewrite profile here is in
URI-translation mode, and its exact properties depend on the AS3 version in
use (question 6). The structure is what the console and the dry run need now.
"""
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

SCHEMA_VERSION = "3.50.0"

# The objects of the app's own VIP, which each exposure renders afresh.
APP_VIP_OBJECTS = frozenset({"pool_app", "tls_to_app", "tls_app", "rewrite_app", "vs_app"})


@dataclass(frozen=True)
class PoolService:
    service_id: str
    scheme: str
    host: str
    port: int
    ips: tuple[str, ...]
    public_name: str


@dataclass(frozen=True)
class Vip:
    key: str  # the group's id
    ip: str
    certificate_path: str
    services: tuple[PoolService, ...]


@dataclass(frozen=True)
class AppVip:
    ip: str
    certificate_path: str
    url: str  # the app's own URL: its pool, by name
    public_name: str
    rewrite: tuple[tuple[str, str], ...]  # (original origin, replacing URL)


def object_name(prefix: str, value: str) -> str:
    """An AS3 object name: letters, digits and underscores, at most 48 characters."""
    return (prefix + re.sub(r"[^A-Za-z0-9_]", "_", value))[:48]


def _pool(service: PoolService) -> dict[str, Any]:
    pool: dict[str, Any] = {
        "class": "Pool",
        "monitors": ["tcp"],
        "members": [{"servicePort": service.port, "serverAddresses": list(service.ips)}],
    }
    return pool


def render(
    exposure_id: str, partition: str, vips: list[Vip], app: AppVip, keep: Optional[dict[str, Any]] = None
) -> dict[str, Any]:
    """The partition's declaration: `keep`, the objects already deployed
    there that are not the app VIP's, then this exposure's VIPs and the app's."""
    application: dict[str, Any] = {"class": "Application"}
    for name, item in (keep or {}).items():
        if name != "class" and name not in APP_VIP_OBJECTS:
            application[name] = item

    for vip in vips:
        vs, tls, policy = object_name("vs_", vip.key), object_name("tls_", vip.key), object_name("route_", vip.key)
        application[tls] = {"class": "TLS_Server", "certificates": [{"certificate": {"bigip": vip.certificate_path}}]}
        rules = []
        for service in vip.services:
            pool = object_name("pool_", service.service_id[:16])
            application[pool] = _pool(service)
            if service.scheme == "https":
                client = object_name("tls_to_", service.service_id[:16])
                application[client] = {"class": "TLS_Client", "serverName": service.host}
                application[pool]["members"][0]["clientTLS"] = {"use": client}
            original_host = service.host if service.port in (80, 443) else f"{service.host}:{service.port}"
            rules.append({
                "name": object_name("to_", service.service_id[:16]),
                "conditions": [{
                    "type": "httpHeader", "event": "request", "name": "host",
                    "all": {"values": [service.public_name]},
                }],
                "actions": [
                    {"type": "httpHeader", "event": "request", "replace": {"name": "host", "value": original_host}},
                    {"type": "forward", "event": "request", "select": {"pool": {"use": pool}}},
                ],
            })
        application[policy] = {"class": "Endpoint_Policy", "rules": rules}
        application[vs] = {
            "class": "Service_HTTPS",
            "virtualAddresses": [vip.ip],
            "virtualPort": 443,
            "serverTLS": tls,
            "policyEndpoint": policy,
            "redirect80": False,
        }

    app_url = urlsplit(app.url)
    app_port = app_url.port or (443 if app_url.scheme == "https" else 80)
    application["pool_app"] = {
        "class": "Pool",
        "monitors": ["tcp"],
        "members": [{"servicePort": app_port, "addressDiscovery": "fqdn", "hostname": app_url.hostname}],
    }
    if app_url.scheme == "https":
        application["tls_to_app"] = {"class": "TLS_Client", "serverName": app_url.hostname}
        application["pool_app"]["members"][0]["clientTLS"] = {"use": "tls_to_app"}
    application["tls_app"] = {"class": "TLS_Server", "certificates": [{"certificate": {"bigip": app.certificate_path}}]}
    application["rewrite_app"] = {
        "class": "Rewrite_Profile",
        "rewriteMode": "uri-translation",
        "uriRules": [
            {"type": "both", "leftValue": original + "/", "rightValue": url + "/"}
            for original, url in app.rewrite
        ],
    }
    application["vs_app"] = {
        "class": "Service_HTTPS",
        "virtualAddresses": [app.ip],
        "virtualPort": 443,
        "serverTLS": "tls_app",
        "pool": "pool_app",
        "profileRewrite": {"use": "rewrite_app"},
        "redirect80": False,
    }

    return {
        "class": "AS3",
        "action": "deploy",
        "persist": True,
        "declaration": {
            "class": "ADC",
            "schemaVersion": SCHEMA_VERSION,
            "id": exposure_id,
            partition: {"class": "Tenant", "app": application},
        },
    }
