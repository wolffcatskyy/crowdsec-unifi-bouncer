# Preparing a v2.6 upgrade

v2.6 is not a released, hardware-verified version yet. This checklist separates
software checks from the required UDR and UDM SE hardware run. Do not interpret
a passing sidecar test as verification of UniFi rule persistence or capacity.

## Before the hardware run

- Save your current bouncer and sidecar configuration outside the device.
- Record the installed version, current IPv4/IPv6 decision counts, configured
  family caps, memory use, and rule placement. Do not infer free capacity from
  the device model alone.
- Review `docs/zone-placement.md` and `docs/device-compatibility.md`.
- Run the sidecar software tests: `cd sidecar && go test ./...`.

## IPv6 is a separate opt-in for existing installations

The installer does not rewrite an existing bouncer configuration. An old
`disable_ipv6: true` setting stays in place on upgrade. After the hardware run,
IPv6 can be enabled by changing that setting to `false` and restarting the
bouncer. New candidate installations use the IPv6-enabled template.

The default IPv6 ipset cap is 2,000 (`MAXELEM_V6_OVERRIDE`); the sidecar's separate
IPv6 decision cap is 1,000 (`max_decisions_v6`). IPv4 capacity is separate, but
both sets consume the same device memory. A prior IPv4 capacity result does not
prove the combined IPv4/IPv6 footprint is safe.

## TLS and mTLS to upstream LAPI

Use `upstream_tls.ca_cert_path` for a private CA. For mTLS, set both
`client_cert_path` and `client_key_path`. Mount those files read-only and do not
commit them. Leave `insecure_skip_verify` off outside a deliberate test.

An invalid TLS configuration currently logs an error and falls back to the
system trust store, without the configured client certificate. It does not
silently turn on insecure verification. Check startup logs and confirm the
actual request succeeds with the intended CA and client identity before relying
on the connection. Missing client credentials may cause a connection failure.

## Hardware checks still required

On the UDR and then UDM SE, check IPv4 and IPv6 blocking, rule position above
UniFi chains, reboot/reprovision persistence, and combined memory/capacity under
load. Record device and firmware versions with results. Retain the previous
working configuration for rollback. No release tag or tested-device claims
should be inferred from this document.
