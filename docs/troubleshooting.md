# Troubleshooting

## Bouncer starts but no IPs blocked

```bash
curl -s http://YOUR_LAPI:8080/v1/decisions -H "X-Api-Key: YOUR_KEY" | head
tail -50 /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log
```

## iptables rules keep disappearing

```bash
crontab -l | grep ensure-rules
/data/crowdsec-bouncer/ensure-rules.sh
```

## Service gone after firmware update

```bash
ln -sf /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service /etc/systemd/system/
systemctl daemon-reload
systemctl start crowdsec-firewall-bouncer
```

## Device becomes unresponsive

1. Reboot via UniFi app or power cycle
2. Reduce `ipset_size` in config (or reduce sidecar `max_decisions`) before restarting bouncer

## Sidecar not filtering decisions

```bash
# Check sidecar health
curl http://YOUR_SIDECAR_HOST:8084/health

# Check sidecar metrics (look at decisions_total vs decisions_dropped)
curl http://YOUR_SIDECAR_HOST:8084/metrics

# Check sidecar logs
docker logs crowdsec-sidecar --tail 50

# Verify bouncer points to sidecar (should show port 8084)
grep api_url /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
```

## Sidecar returns 502 Bad Gateway

```bash
# LAPI is unreachable from sidecar — check upstream_lapi_url in sidecar config
curl http://YOUR_LAPI:8080/health
docker exec crowdsec-sidecar wget -q -O- http://YOUR_LAPI:8080/health
```

## Ipset capacity full

When ipset reaches capacity, new IPs can't be added and the bouncer logs "Hash is full" errors.

```bash
# Check current ipset usage
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status

# Check for capacity errors in logs
grep -i "hash is full\|set is full" /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log
```

Solutions:
- Deploy the [sidecar proxy](sidecar.md) to prioritize decisions
- Reduce `max_decisions` in sidecar config if already using it
- Set `MEMORY_OPTIMIZED=true` if running other memory-intensive services

See [device-compatibility.md](device-compatibility.md) for per-device capacity limits.
