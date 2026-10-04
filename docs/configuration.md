# Configuration Reference

## Config File Location

```bash
$EDITOR /data/crowdsec-bouncer/crowdsec-firewall-bouncer.yaml
```

## Critical Settings

```yaml
# Direct LAPI connection (default):
api_url: http://192.168.1.100:8080/
api_key: YOUR_BOUNCER_API_KEY

# Or, if using the sidecar proxy:
# api_url: http://192.168.1.100:8084/
# api_key: YOUR_BOUNCER_API_KEY
```

## Config Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `mode` | `ipset` | Use ipset for efficient IP matching |
| `update_frequency` | `10s` | How often to poll for new decisions |
| `api_url` | -- | LAPI address (port 8080) or sidecar address (port 8084) |
| `api_key` | -- | Bouncer API key from `cscli bouncers add` |
| `disable_ipv6` | `false` (v2.6+ template; `true` in older configs) | When `false`, the bouncer fills the `crowdsec6-blacklists` inet6 set and setup.sh mirrors DROP rules into `ip6tables` |
| `deny_action` | `DROP` | `DROP` (silent) or `REJECT` (sends reset) |

## Starting the Bouncer

```bash
# Link and start systemd service
ln -sf /data/crowdsec-bouncer/crowdsec-firewall-bouncer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable crowdsec-firewall-bouncer
systemctl start crowdsec-firewall-bouncer

# Install cron for rule persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * /data/crowdsec-bouncer/ensure-rules.sh") | crontab -
```

## Verifying the Installation

```bash
# Service running?
systemctl status crowdsec-firewall-bouncer

# IPs being blocked?
ipset list crowdsec-blacklists | head -20

# How many IPs loaded?
ipset list crowdsec-blacklists -t | grep "Number of entries"

# iptables rules in place?
iptables -L INPUT -n | grep crowdsec
iptables -L FORWARD -n | grep crowdsec

# Logs
tail -f /data/crowdsec-bouncer/log/crowdsec-firewall-bouncer.log

# Check from CrowdSec LAPI host
cscli bouncers list
```

## Capacity Monitoring

When ipset reaches capacity, the bouncer logs errors and new IPs can't be added. The `ipset-capacity-monitor.sh` script detects this and exposes metrics:

```bash
# Check current status (includes sidecar detection)
/data/crowdsec-bouncer/ipset-capacity-monitor.sh --status
```

The status output shows current ipset usage, dropped decision counts, whether you're using a sidecar, and device-specific tuning recommendations.

## Uninstalling

```bash
systemctl stop crowdsec-firewall-bouncer
systemctl disable crowdsec-firewall-bouncer
rm /etc/systemd/system/crowdsec-firewall-bouncer.service
systemctl daemon-reload

iptables -D INPUT -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
iptables -D FORWARD -m set --match-set crowdsec-blacklists src -j DROP 2>/dev/null
ipset destroy crowdsec-blacklists 2>/dev/null

crontab -l | grep -v ensure-rules.sh | crontab -
rm -rf /data/crowdsec-bouncer
```

## TLS-enabled LAPI (sidecar)

If your CrowdSec LAPI is served over HTTPS, set `upstream_lapi_url` to the `https://` address and configure trust in the sidecar's `config.yaml`:

```yaml
upstream_tls:
  ca_cert_path: "/certs/ca.pem"          # CA that signed the LAPI certificate
  client_cert_path: "/certs/client.pem"  # only for mutual TLS
  client_key_path: "/certs/client-key.pem"
```

| Option | Environment variable | Notes |
|---|---|---|
| `upstream_tls.ca_cert_path` | `UPSTREAM_LAPI_CA_CERT` | PEM CA bundle, added to the system trust store |
| `upstream_tls.client_cert_path` | `UPSTREAM_LAPI_CLIENT_CERT` | PEM client certificate; requires the key |
| `upstream_tls.client_key_path` | `UPSTREAM_LAPI_CLIENT_KEY` | PEM client key; requires the certificate |
| `upstream_tls.insecure_skip_verify` | `UPSTREAM_LAPI_TLS_INSECURE_SKIP_VERIFY` | Disables certificate verification. Testing only |

With Docker, mount the certificates into the container and point the variables at the mounted paths:

```yaml
services:
  sidecar:
    environment:
      - UPSTREAM_LAPI_CA_CERT=/certs/ca.pem
    volumes:
      - ./certs:/certs:ro
```

The settings apply to every outgoing request to the LAPI. If none are set, behaviour is unchanged.
