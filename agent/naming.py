"""Public DNS names for the origins an exposure publishes.

A placeholder rule until open question 1 (docs/exposure-design.md) settles
the convention: the host without its internal suffix, dots turned to dashes,
the port added when it is not the scheme's default, in the configured zone.
`reports.corp.internal` becomes `reports.example.com`, and
`api.payroll.corp.internal:8443` becomes `api-payroll-8443.example.com`.

A name follows from the origin alone, so it stays the same across re-plans
and superseding exposures. Two origins that would get the same name, which
this rule allows for http and https on their default ports, refuse the plan.
"""
import re

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class NamingError(ValueError):
    pass


def public_name(scheme: str, host: str, port: int, zone: str, internal_suffixes: tuple[str, ...]) -> str:
    base = host.lower().rstrip(".")
    for suffix in sorted(internal_suffixes, key=len, reverse=True):
        if base.endswith(suffix) and base != suffix.lstrip("."):
            base = base[: -len(suffix)]
            break
    label = base.replace(".", "-")
    if _DEFAULT_PORTS.get(scheme) != port:
        label += f"-{port}"
    if not _LABEL.match(label):
        raise NamingError(f"{scheme}://{host}:{port} gives {label!r}, which is not a valid DNS label")
    return f"{label}.{zone}"


def origin_text(scheme: str, host: str, port: int) -> str:
    """An origin as the backend formats it: the port only when not the default."""
    host_part = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host_part}" if _DEFAULT_PORTS.get(scheme) == port else f"{scheme}://{host_part}:{port}"
