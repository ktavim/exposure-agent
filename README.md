# exposure-agent

The deployment agent for publishing submitted apps through the F5 BIG-IP. The design is `network-interceptor/docs/exposure-design.md`. The agent runs on the management network and is the only holder of the F5, IP reservation and DNS service credentials. It carries out what the backend approved:

- **Planning:** reserve one IP per VIP, request each VIP's certificate and install it on the F5, render the AS3 declaration from the agent's own template, dry-run it, and report the plan.
- **Cancelling:** release every reservation and certificate the exposure holds.
- **Deploying:** deploy, verify, create the DNS records and register the published origins. Phase 5; not built yet.

The agent pulls: it polls the backend's `/api/agent/*` endpoints for what is waiting, reports each step, and reports the outcome for the version it worked on. The backend never calls the agent.

## Status

Phase 4, with **fake adapters** only. The IP reservation service, the DNS service and the F5 are in-memory stand-ins (`agent/adapters/fake.py`) until their APIs are known: open questions 2, 3 and 6 in the design. The public DNS names follow a placeholder rule (`agent/naming.py`) until open question 1 is settled. The AS3 rewrite profile is illustrative until open question 4.

There is no authentication yet. Phase 6 adds a Keycloak token for the `exposure-agent` client, obtained with a signed JWT.

## Run

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e ".[dev]"
$env:BACKEND_URL = "http://127.0.0.1:8000"
python -m agent
```

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_URL` | `http://127.0.0.1:8000` | The backend's API |
| `POLL_INTERVAL_S` | 3 | Seconds between polls |
| `AGENT_STATE_PATH` | `agent-state.sqlite3` | The agent's record of what each exposure holds, and its step log |
| `AGENT_ADAPTERS` | `fake` | Only `fake` exists |
| `VIP_RANGES` | `203.0.113.0/24` | Comma-separated CIDRs; VIP addresses come only from these |
| `DNS_ZONE` | `example.com` | The zone public names are created in |
| `INTERNAL_SUFFIXES` | `.corp.internal,.internal` | Left off a host when its public name is formed |
| `PARTITION_PREFIX` | `exp_` | The agent writes only to partitions with this prefix |

The fake adapters keep their state in memory, so a restart forgets the fake reservations and certificates while the agent's own record (`AGENT_STATE_PATH`) remembers them. That doesn't happen with real services.

## Test

```powershell
pytest
```

## Layout

```
agent/config.py        settings from the environment
agent/backend.py       the backend's agent API
agent/runner.py        the poll loop
agent/planner.py       planning and cancelling, step by step
agent/as3.py           the AS3 template
agent/naming.py        public DNS names (placeholder rule)
agent/state.py         the agent's own record: holdings, step log, report numbers
agent/adapters/        the services' interfaces, and the fakes
```
