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

---

## Performance Benchmarks (To Document)

| IP Count | Expected Sync Time | Memory |
|----------|-------------------|--------|
| 1,000 | ~2s | ~50MB |
| 5,000 | ~5s | ~60MB |
| 10,000 | ~10s | ~80MB |
| 60,000 | ~60s | ~150MB |

**UniFi API Limits:**
- Max 10,000 IPs per firewall group
- Rate limit: ~60 requests/minute (estimated)
- Group update: ~1-2s per group

---

## Failure Modes & Recovery

| Scenario | Current Behavior | Target Behavior |
|----------|-----------------|-----------------|
| UniFi unreachable | Loop continues, logs error | Backoff + retry, alert after N failures |
| CrowdSec LAPI unreachable | Loop continues, logs error | Backoff + retry, keep last known state |
| Group creation fails | Logs error, skips group | Retry with backoff, create on next cycle |
| Partial update | Inconsistent state possible | Atomic updates or full reconciliation |
| Auth expired | Re-login automatically ✅ | Already implemented |

---

## Testing Strategy

### Unit Tests
- [ ] CrowdSecClient API wrapper
- [ ] UniFiClient API wrapper
- [ ] IP chunking algorithm
- [ ] IPv6 filtering

### Integration Tests
- [ ] Mock UniFi controller
- [ ] Mock CrowdSec LAPI
- [ ] End-to-end sync flow

### Load Tests
- [ ] 10K IPs sync performance
- [ ] 60K IPs sync performance
- [ ] Memory profiling
- [ ] Concurrent update handling

---

## Security Considerations

### Authentication
- **Current:** Cookie-based auth (user/pass)
- **Planned:** API token support (v1.3.0)
- **Risk:** Passwords in environment variables
- **Mitigation:** Docker secrets support planned

### TLS Verification
- **Current:** Skip TLS option available
- **Planned:** Loud warning when disabled (v1.1.0)
- **Planned:** Custom CA bundle support (v1.3.0)

### Logging
- Never log API keys or passwords
- Redact sensitive data in error messages
- Log rotation recommended

---

## Contributing

PRs welcome! Pick an item from the roadmap and submit a PR.
