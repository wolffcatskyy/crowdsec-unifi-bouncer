#!/usr/bin/env python3
"""Assertions for the live-LAPI feed-scoring CI job.

Reads the sidecar's /v1/decisions/stream?startup=true response (JSON on
stdin) and checks:

- exactly the 3 highest-priority decisions survived max_decisions=3:
  the manual ban and both c95 imports; the c30 import was dropped
- scenario names round-tripped through LAPI and the sidecar byte-for-byte
"""
import json
import sys

PREFIX = "external/blocklist-import"
LOW = f"{PREFIX}/custom-blocklist-0/c30"
HIGH = f"{PREFIX}/custom-blocklist-1/c95"
MANUAL_IP = "203.0.113.50"
SHARED_IP = "203.0.113.7"   # listed by both feeds -> highest confidence wins
LOW_ONLY_IP = "203.0.113.8"  # only on the c30 feed -> dropped first
HIGH_ONLY_IP = "203.0.113.9"


def main() -> int:
    body = sys.stdin.read()
    data = json.loads(body) if body.strip() else {}
    new = data.get("new") or []

    got = {d.get("value"): d.get("scenario") for d in new}
    assert len(new) == 3, f"expected 3 surviving decisions, got {len(new)}: {got}"

    # The lowest-confidence import is the one truncation drops.
    assert LOW_ONLY_IP not in got, f"c30 import should have been dropped: {got}"

    # The manual ban (no feed provenance, no penalty) always survives.
    assert got.get(MANUAL_IP) == "manual test ban", got

    # Multi-feed IP carries the highest confidence, byte-for-byte.
    assert got.get(SHARED_IP) == HIGH, got
    assert got.get(HIGH_ONLY_IP) == HIGH, got
    assert all(not s.endswith("/c30") for s in got.values()), got

    print("OK: scenarios round-tripped byte-for-byte through LAPI + sidecar;")
    print("OK: truncation dropped the c30 import first and kept the manual ban")
    return 0


if __name__ == "__main__":
    sys.exit(main())
