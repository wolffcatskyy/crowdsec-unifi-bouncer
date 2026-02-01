# Contributing to CrowdSec UniFi Bouncer

Contributions welcome — from humans, AIs, or both working together.

This guide is structured so you can paste it (or a section of it) directly into your AI assistant (Claude, ChatGPT, Copilot, etc.) along with an issue, and get a useful PR out of it.

## Quick Start

```bash
git clone https://github.com/wolffcatskyy/crowdsec-unifi-bouncer.git
cd crowdsec-unifi-bouncer

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env with your CrowdSec API key and UniFi credentials

# Run locally
export CROWDSEC_BOUNCER_API_KEY="your-key"
export CROWDSEC_URL="http://localhost:8080"
export UNIFI_HOST="https://192.168.1.1"
export UNIFI_USER="admin"
export UNIFI_PASS="your-password"
export UNIFI_SKIP_TLS_VERIFY="true"
python bouncer.py

# Or with Docker
docker compose up --build
```

## Architecture Overview (for AI context)

**Single-file application** — everything is in `bouncer.py` (~900 lines).

```
bouncer.py
├── Configuration (env vars loaded at module level)
├── Helpers
│   ├── get_memory_usage_mb() / log_memory_usage() — memory monitoring
│   ├── is_ipv6() — IPv6 detection
│   └── parse_duration_seconds() — parse CrowdSec duration strings like "167h30m5.123s"
├── HealthStatus (thread-safe health tracker with lock)
├── HealthCheckHandler (HTTP handler: /health, /ready, /live endpoints)
├── start_health_server() — background HTTP server on HEALTH_PORT
├── CrowdSecClient (LAPI client)
│   ├── get_decisions_stream() — stream API for delta updates (startup=true/false)
│   └── get_all_decisions() — fetch all active ban decisions
├── UniFiClient (UniFi controller API with cookie auth)
│   ├── login() — authenticate, extract CSRF token from JWT
│   ├── _request_with_retry() — exponential backoff for 502/503/504/429
│   ├── _request() — API request with auto-retry on 401 (session expired)
│   ├── get/create/update/delete_firewall_group() — address group CRUD
│   ├── get_firewall_rules() — list existing rules
│   └── create_firewall_rule() — create WAN_IN/WAN_LOCAL drop rules
├── UniFiBouncer (main orchestration)
│   ├── _filter_ips() — exclude IPv6 if disabled
│   ├── _prioritize_and_cap() — tier1 (local) + tier2 (community) with MAX_IPS cap
│   ├── _chunk_ips() — split IPs into max_group_size chunks
│   ├── load_existing_groups() — discover bouncer-managed firewall groups
│   ├── ensure_firewall_rules() — create WAN_IN + WAN_LOCAL drop rules per group
│   ├── sync_decisions() — sync IP set to UniFi firewall groups
│   ├── initial_sync() — full sync on startup
│   └── run_stream() — continuous polling loop with delta updates
├── send_telemetry() — anonymous startup ping
└── main() — entry point:
    1. Validate config
    2. Start health check server
    3. Initialize CrowdSecClient + UniFiClient
    4. Login to UniFi controller
    5. Load existing firewall groups
    6. Ensure firewall rules exist
    7. Run stream-based sync loop (poll every UPDATE_INTERVAL seconds)
```

**Data flow:**
```
CrowdSec LAPI ──(stream API)──► CrowdSecClient
                                      │
                              parse ban decisions
                              prioritize by freshness
                              cap at MAX_IPS
                                      │
                                      ▼
                               UniFiBouncer.sync_decisions()
                                      │
                              chunk into groups (max 10k IPs each)
                              create/update firewall address groups
                              ensure WAN_IN + WAN_LOCAL drop rules
                                      │
                                      ▼
                               UniFi Controller API
                              (firewall groups + rules)
```

**Key design principles:**
- **Stream-based sync** — uses CrowdSec `/v1/decisions/stream` for efficient delta updates
- **Freshness prioritization** — when MAX_IPS cap is set, local detections always kept, community IPs sorted by remaining ban duration
- **Periodic full refresh** — every 10 cycles, re-fetches all decisions to rotate stale IPs for fresher ones
- **Memory-conscious** — explicit `gc.collect()`, batch processing, memory usage logging
- **Exponential backoff** — retries on UniFi 502/503/504/429 with configurable backoff
- **Auto-recovery** — re-authenticates on 401, retries on transient failures
- **Health endpoints** — `/health` (JSON status), `/ready` (readiness probe), `/live` (liveness probe)
- **Single dependency** — `requests` only

**Environment variables (key ones):**
| Variable | Default | Purpose |
|----------|---------|---------|
| `CROWDSEC_URL` | `http://localhost:8080` | CrowdSec LAPI URL |
| `CROWDSEC_BOUNCER_API_KEY` | (required) | Bouncer API key |
| `UNIFI_HOST` | `https://192.168.1.1` | UniFi controller URL |
| `UNIFI_USER` / `UNIFI_PASS` | (required) | UniFi credentials |
| `UNIFI_SITE` | `default` | UniFi site name |
| `UPDATE_INTERVAL` | `60` | Polling interval in seconds |
| `UNIFI_MAX_GROUP_SIZE` | `10000` | Max IPs per firewall group |
| `MAX_IPS` | `0` (unlimited) | Total IP cap with freshness prioritization |
| `GROUP_PREFIX` | `crowdsec-ban` | Firewall group name prefix |
| `ENABLE_IPV6` | `false` | Include IPv6 addresses |
| `HEALTH_PORT` | `8080` | Health check endpoint port |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## How to Contribute with AI

### Step 1: Pick an issue

Browse [open issues](https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues). There are currently **10 open issues** (all enhancements), organized by version milestones (v1.1, v1.2, v1.3) — great for targeted contributions.

### Step 2: Give your AI context

Copy this into your AI assistant:

```
I want to contribute to crowdsec-unifi-bouncer. Here's the project context:

- Single Python file: bouncer.py (~900 lines)
- Only dependency: requests
- Docker: python:3.11-alpine, non-root user, health check on port 8080
- Config: all environment variables (loaded at module level, no helper functions)
- Classes: HealthStatus, HealthCheckHandler, CrowdSecClient, UniFiClient, UniFiBouncer
- CrowdSecClient talks to LAPI stream API for delta updates
- UniFiClient manages firewall address groups + drop rules via UniFi controller API
- UniFiBouncer orchestrates: poll CrowdSec → chunk IPs → sync to UniFi groups → ensure drop rules
- Exponential backoff on UniFi API errors (502/503/504/429)
- Auto re-auth on 401 (expired session)
- MAX_IPS cap with freshness prioritization (local detections > community, sorted by remaining duration)
- Health endpoints: /health (JSON), /ready, /live
- Memory-conscious: gc.collect(), batch processing, memory logging

The issue I want to work on is: [paste issue title and body here]
```

Then paste the contents of `bouncer.py` and ask your AI to implement the fix/feature.

### Step 3: Submit a PR

- Fork the repo
- Create a branch (`feat/your-feature` or `fix/your-fix`)
- Make your changes
- Test with your UniFi setup if possible (or describe your test approach)
- Open a PR with a clear description of what changed and why

## Writing Good Issues (for maintainers)

When creating issues, structure them for AI consumption:

```markdown
## What
[One sentence describing the desired outcome]

## Why
[Context on why this matters]

## Where in the code
[File, class, method, or line range in bouncer.py]

## Acceptance criteria
- [ ] Specific, testable requirement 1
- [ ] Specific, testable requirement 2

## Constraints
- Must not break existing env var config
- Must degrade gracefully if not configured
- Single file only (no new files)
- No new dependencies without discussion
```

## Code Style

- **Python 3.11+**, no type stubs needed
- **f-strings** for formatting
- **logging** via the module-level `log` object (not print)
- **Environment variables** for all config — loaded at module level with `os.getenv()` and sensible defaults
- **Error handling**: catch specific exceptions, log and continue (don't crash the polling loop)
- **Exponential backoff** for retryable errors (see `_request_with_retry()`)
- **Thread safety** — `HealthStatus` uses `threading.Lock()`; be aware of concurrent access
- **Memory management** — use `del` + `gc.collect()` for large data structures; log memory usage
- **No new dependencies** without discussion — the single-dependency constraint is intentional
- Keep it in **one file** — `bouncer.py` should remain self-contained

## Testing

There's no test suite yet (good first contribution!). For now:

1. Run and verify log output with `LOG_LEVEL=DEBUG`
2. Check the `/health` endpoint returns correct JSON status
3. Verify that new env vars have sensible defaults
4. Test graceful degradation (what happens if CrowdSec is unreachable? UniFi is unreachable?)
5. Test the happy path and at least one error path
6. If you have a UniFi device, verify firewall groups are created/updated correctly

## Open Issues — Great Starting Points

There are **10 open enhancement issues**, organized by version milestones:

- **v1.1** — Near-term improvements
- **v1.2** — Medium-term features
- **v1.3** — Longer-term goals

Browse them at: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer/issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
