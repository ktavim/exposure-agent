"""The agent's settings, from the environment. Credentials for the F5, the IP
reservation service and the DNS service will be read here too, and only here:
the agent is their one holder (docs/exposure-design.md, Topology)."""
import ipaddress
import os
from dataclasses import dataclass, field


def _list(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    # The backend's API, through its VIP.
    backend_url: str = "http://127.0.0.1:8000"
    poll_interval_s: float = 3.0
    # The agent's own record: what each exposure holds, and its step log.
    state_path: str = "agent-state.sqlite3"
    # "fake" until the real services' APIs are known (open questions 2, 3, 6).
    adapters: str = "fake"
    # VIP addresses come only from these ranges, whatever the backend sends.
    vip_ranges: tuple[str, ...] = ("203.0.113.0/24",)
    # DNS names are created only in this zone.
    dns_zone: str = "example.com"
    # Internal suffixes left off a host when its public name is formed.
    internal_suffixes: tuple[str, ...] = field(default=(".corp.internal", ".internal"))
    # The agent writes only to partitions with this prefix (one per app), and
    # never to those holding the console's, the backend's and Keycloak's VIPs.
    partition_prefix: str = "exp_"

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        settings = cls(
            backend_url=env("BACKEND_URL", cls.backend_url).rstrip("/"),
            poll_interval_s=float(env("POLL_INTERVAL_S", cls.poll_interval_s)),
            state_path=env("AGENT_STATE_PATH", cls.state_path),
            adapters=env("AGENT_ADAPTERS", cls.adapters),
            vip_ranges=_list(env("VIP_RANGES", ",".join(cls.vip_ranges))),
            dns_zone=env("DNS_ZONE", cls.dns_zone).strip(".").lower(),
            internal_suffixes=_list(env("INTERNAL_SUFFIXES", ".corp.internal,.internal")),
            partition_prefix=env("PARTITION_PREFIX", cls.partition_prefix),
        )
        for cidr in settings.vip_ranges:
            ipaddress.ip_network(cidr)  # a bad range stops the agent here, not mid-plan
        if not settings.vip_ranges:
            raise ValueError("VIP_RANGES must name at least one range")
        return settings
