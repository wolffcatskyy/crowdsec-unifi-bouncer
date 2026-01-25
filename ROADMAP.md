# Roadmap

## v1.1.0 - Stability & Reliability

### Idempotency & Drift Detection
- [ ] Hash current decision set, skip no-op updates
- [ ] Detect when UniFi groups were manually edited/removed
- [ ] Reconcile and recreate missing groups automatically

### Deterministic Group Layout
- [ ] Sort IPs before chunking for stable ordering
- [ ] Ensure group names don't churn between runs
- [ ] Document the IP → group mapping algorithm

### Defensive API Handling
- [ ] Backoff + jitter on 4xx/5xx errors
- [ ] Better error categorization (auth vs connectivity vs validation)
- [ ] Retry logic with configurable max attempts

### Startup Validation
- [ ] Test CrowdSec LAPI reachable before starting loop
- [ ] Test UniFi controller reachable before starting loop
- [ ] Fail fast with clear summary of all config errors
- [ ] Loud warning when `UNIFI_SKIP_TLS_VERIFY=true`

---

## v1.2.0 - Observability

### Structured Logging
- [ ] JSON log format option (`LOG_FORMAT=json`)
- [ ] Consistent key=value format: `event=sync_complete ip_count=1234 groups=3 duration_ms=500`
- [ ] Summary log line per cycle showing drift/growth

### Health Monitoring
- [ ] HTTP `/health` endpoint for Docker/K8s probes
- [ ] Status file option (`/tmp/bouncer-status.json`)
- [ ] Metrics: last_sync_time, last_error, ip_count, group_count

---

## v1.3.0 - Advanced Features

### Authentication Options
- [ ] Support UniFi API token auth (feature flag for token vs user/pass)
- [ ] Custom CA bundle path instead of just verify on/off

### CrowdSec Streaming Improvements
- [ ] Long-polling where possible instead of fixed interval
- [ ] Track decision IDs to avoid reprocessing

### Origin Filtering Defaults
- [ ] Document approximate IP counts per origin combo
- [ ] Suggest defaults based on UniFi device limits
- [ ] Example configs for different scenarios

---

## Completed (v1.0.0)

- [x] Cookie-based UniFi authentication
- [x] Session re-login on auth expiry
- [x] Batch updates per group (not per-IP)
- [x] 120s timeouts on all requests
- [x] Non-root user in Dockerfile
- [x] Basic startup validation
- [x] IPv6 toggle with logging
- [x] Origin filtering support
- [x] Multiple groups to bypass 10K limit
- [x] Proper User-Agent identification

---

## Contributing

PRs welcome! Pick an item from the roadmap and submit a PR.
