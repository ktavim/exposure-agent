"""python -m agent: run the deployment agent until stopped."""
import asyncio
import logging
import sys

from .backend import BackendClient
from .config import Settings
from .deployer import Deployer
from .planner import Planner
from .runner import Agent
from .state import State


async def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    settings = Settings.from_env()
    if settings.adapters != "fake":
        print(f"AGENT_ADAPTERS={settings.adapters!r}: only the fake adapters exist so far", file=sys.stderr)
        return 2
    from .adapters.fake import FakeDnsService, FakeF5, FakeIpReservations, FakeProbe

    state = State(settings.state_path)
    backend = BackendClient(settings.backend_url)
    ips, dns, f5 = FakeIpReservations(), FakeDnsService(), FakeF5()
    planner = Planner(settings, state, ips, dns, f5, backend)
    deployer = Deployer(settings, state, ips, dns, f5, FakeProbe(f5), backend)
    logging.getLogger(__name__).info(
        "Agent polling %s every %.0fs, with fake adapters", settings.backend_url, settings.poll_interval_s
    )
    try:
        await Agent(planner, deployer, backend, settings.poll_interval_s).run()
    finally:
        await backend.close()
        state.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
