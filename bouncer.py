#!/usr/bin/env python3
"""
CrowdSec UniFi Bouncer
A simple Python bouncer that syncs CrowdSec decisions to UniFi firewall groups.

Author: Claude (Anthropic) + Human collaboration
License: MIT
Repository: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer
"""

__version__ = "1.5.0"
__author__ = "wolffcatskyy"

import os
import sys
import time
import json
import logging
import threading
import gc
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any
from urllib3.exceptions import InsecureRequestWarning

import requests

# Suppress SSL warnings when UNIFI_SKIP_TLS_VERIFY is enabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# User-Agent for CrowdSec to identify this bouncer
USER_AGENT = f"crowdsec-unifi-bouncer/{__version__}"

# Configuration from environment
CROWDSEC_URL = os.getenv("CROWDSEC_URL", "http://localhost:8080")
CROWDSEC_API_KEY = os.getenv("CROWDSEC_BOUNCER_API_KEY", "")
CROWDSEC_ORIGINS = os.getenv("CROWDSEC_ORIGINS", "").split()  # Filter by origin
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "60"))  # seconds

UNIFI_HOST = os.getenv("UNIFI_HOST", "https://192.168.1.1")
UNIFI_USER = os.getenv("UNIFI_USER", "")
UNIFI_PASS = os.getenv("UNIFI_PASS", "")
UNIFI_SITE = os.getenv("UNIFI_SITE", "default")
UNIFI_SKIP_TLS = os.getenv("UNIFI_SKIP_TLS_VERIFY", "false").lower() == "true"
UNIFI_MAX_GROUP_SIZE = int(os.getenv("UNIFI_MAX_GROUP_SIZE", "10000"))
MAX_IPS = int(os.getenv("MAX_IPS", "0"))  # 0 = unlimited; cap total IPs synced to UniFi
ENABLE_IPV6 = os.getenv("ENABLE_IPV6", "false").lower() == "true"

GROUP_PREFIX = os.getenv("GROUP_PREFIX", "crowdsec-ban")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Health check configuration
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8080"))
HEALTH_ENABLED = os.getenv("HEALTH_ENABLED", "true").lower() == "true"

# Batch processing configuration (for memory management)
SYNC_BATCH_SIZE = int(os.getenv("SYNC_BATCH_SIZE", "1000"))  # IPs per batch during sync

# Retry configuration for UniFi API
UNIFI_MAX_RETRIES = int(os.getenv("UNIFI_MAX_RETRIES", "5"))
UNIFI_INITIAL_BACKOFF = float(os.getenv("UNIFI_INITIAL_BACKOFF", "1.0"))  # seconds
UNIFI_MAX_BACKOFF = float(os.getenv("UNIFI_MAX_BACKOFF", "60.0"))  # seconds

# Anonymous telemetry (enabled by default, set TELEMETRY_ENABLED=false to disable)
TELEMETRY_ENABLED = os.getenv("TELEMETRY_ENABLED", "true").lower() == "true"
TELEMETRY_URL = "https://bouncer-telemetry.ms2738.workers.dev/ping"

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


def get_memory_usage_mb() -> float:
    """Get current process memory usage in MB."""
    try:
        import resource
        # Returns memory in KB on Linux
        usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # On macOS it's in bytes, on Linux it's in KB
        if sys.platform == "darwin":
            return usage_kb / (1024 * 1024)
        return usage_kb / 1024
    except Exception:
        return 0.0


def log_memory_usage(context: str = ""):
    """Log current memory usage with optional context."""
    mem_mb = get_memory_usage_mb()
    if mem_mb > 0:
        prefix = f"[{context}] " if context else ""
        log.debug(f"{prefix}Memory usage: {mem_mb:.1f} MB")


# Global health status for the health check endpoint
class HealthStatus:
    """Thread-safe health status tracker."""

    def __init__(self):
        self._lock = threading.Lock()
        self._crowdsec_connected = False
        self._unifi_connected = False
        self._last_sync_time: Optional[float] = None
        self._last_sync_ips: int = 0
        self._last_error: Optional[str] = None
        self._startup_time = time.time()

    def set_crowdsec_connected(self, connected: bool):
        with self._lock:
            self._crowdsec_connected = connected

    def set_unifi_connected(self, connected: bool):
        with self._lock:
            self._unifi_connected = connected

    def set_last_sync(self, ip_count: int):
        with self._lock:
            self._last_sync_time = time.time()
            self._last_sync_ips = ip_count
            self._last_error = None

    def set_error(self, error: str):
        with self._lock:
            self._last_error = error

    def is_healthy(self) -> bool:
        with self._lock:
            return self._crowdsec_connected and self._unifi_connected

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            uptime = time.time() - self._startup_time
            return {
                "status": "healthy" if self._crowdsec_connected and self._unifi_connected else "unhealthy",
                "version": __version__,
                "uptime_seconds": int(uptime),
                "crowdsec_connected": self._crowdsec_connected,
                "unifi_connected": self._unifi_connected,
                "last_sync_time": self._last_sync_time,
                "last_sync_ips": self._last_sync_ips,
                "last_error": self._last_error,
                "memory_mb": round(get_memory_usage_mb(), 1)
            }


# Global health status instance
health_status = HealthStatus()


class HealthCheckHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for health checks."""

    def log_message(self, format, *args):
        # Suppress default logging to avoid spam
        pass

    def do_GET(self):
        if self.path == "/health" or self.path == "/":
            status = health_status.get_status()
            is_healthy = status["status"] == "healthy"

            self.send_response(200 if is_healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(status, indent=2).encode())
        elif self.path == "/ready":
            # Readiness probe - are we ready to serve?
            is_ready = health_status.is_healthy()
            self.send_response(200 if is_ready else 503)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ready" if is_ready else b"not ready")
        elif self.path == "/live":
            # Liveness probe - is the process alive?
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"alive")
        else:
            self.send_response(404)
            self.end_headers()


def start_health_server():
    """Start the health check HTTP server in a background thread."""
    if not HEALTH_ENABLED:
        log.info("Health check endpoint disabled")
        return None

    try:
        server = HTTPServer(("0.0.0.0", HEALTH_PORT), HealthCheckHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        log.info(f"Health check endpoint started on port {HEALTH_PORT}")
        log.info(f"  GET /health - Full status JSON")
        log.info(f"  GET /ready  - Readiness probe")
        log.info(f"  GET /live   - Liveness probe")
        return server
    except Exception as e:
        log.warning(f"Failed to start health check server: {e}")
        return None


class CrowdSecClient:
    """Simple CrowdSec LAPI client."""

    def __init__(self, url: str, api_key: str, origins: list = None):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.origins = origins or []
        self.session = requests.Session()
        self.session.headers["X-Api-Key"] = api_key
        self.session.headers["User-Agent"] = USER_AGENT

    def get_decisions_stream(self, startup: bool = False) -> dict:
        """Get decisions from stream endpoint."""
        params = {"startup": "true" if startup else "false"}
        if self.origins:
            params["origins"] = ",".join(self.origins)

        url = f"{self.url}/v1/decisions/stream"
        log.debug(f"Fetching decisions from {url} with params {params}")

        resp = self.session.get(url, params=params, timeout=120)
        resp.raise_for_status()
        health_status.set_crowdsec_connected(True)
        return resp.json()

    def get_all_decisions(self) -> list:
        """Get all active ban decisions."""
        params = {"type": "ban"}
        if self.origins:
            params["origins"] = ",".join(self.origins)

        url = f"{self.url}/v1/decisions"
        log.debug(f"Fetching all decisions from {url}")

        resp = self.session.get(url, params=params, timeout=120)
        resp.raise_for_status()
        health_status.set_crowdsec_connected(True)
        return resp.json() or []


class UniFiClient:
    """Simple UniFi controller client using cookie auth with exponential backoff."""

    # HTTP status codes that should trigger retry with backoff
    RETRYABLE_STATUS_CODES = {502, 503, 504, 429}

    def __init__(self, host: str, username: str, password: str,
                 site: str = "default", verify_ssl: bool = True,
                 max_retries: int = 5, initial_backoff: float = 1.0,
                 max_backoff: float = 60.0):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.csrf_token = None

        # Retry configuration
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff

    def login(self) -> bool:
        """Authenticate and get session cookie."""
        url = f"{self.host}/api/auth/login"
        payload = {"username": self.username, "password": self.password}

        log.debug(f"Logging in to UniFi at {url}")

        try:
            resp = self.session.post(url, json=payload, timeout=120)
        except requests.exceptions.RequestException as e:
            log.error(f"UniFi login connection error: {e}")
            health_status.set_unifi_connected(False)
            return False

        if resp.status_code == 200:
            # Extract CSRF token from response if present
            try:
                for cookie in self.session.cookies:
                    if cookie.name == "TOKEN":
                        import base64
                        # Decode JWT to get CSRF token
                        parts = cookie.value.split(".")
                        if len(parts) >= 2:
                            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            payload_data = json.loads(base64.b64decode(payload_b64))
                            self.csrf_token = payload_data.get("csrfToken")
            except Exception as e:
                log.debug(f"Could not extract CSRF token: {e}")

            log.info("Successfully logged in to UniFi")
            health_status.set_unifi_connected(True)
            return True
        else:
            log.error(f"UniFi login failed: {resp.status_code} - {resp.text[:200]}")
            health_status.set_unifi_connected(False)
            return False

    def _api_url(self, endpoint: str) -> str:
        """Build full API URL for endpoint."""
        return f"{self.host}/proxy/network/api/s/{self.site}/{endpoint}"

    def _request_with_retry(self, method: str, url: str, headers: dict, **kwargs) -> requests.Response:
        """Execute request with exponential backoff for retryable errors."""
        last_error = None
        backoff = self.initial_backoff

        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.request(method, url, headers=headers, timeout=120, **kwargs)

                # Check if we got a retryable status code
                if resp.status_code in self.RETRYABLE_STATUS_CODES:
                    if attempt < self.max_retries:
                        log.warning(
                            f"UniFi API returned {resp.status_code}, "
                            f"retrying in {backoff:.1f}s (attempt {attempt + 1}/{self.max_retries + 1})"
                        )
                        time.sleep(backoff)
                        backoff = min(backoff * 2, self.max_backoff)
                        continue
                    else:
                        log.error(
                            f"UniFi API returned {resp.status_code} after {self.max_retries + 1} attempts, giving up"
                        )

                return resp

            except requests.exceptions.Timeout as e:
                last_error = e
                if attempt < self.max_retries:
                    log.warning(
                        f"UniFi API timeout, retrying in {backoff:.1f}s "
                        f"(attempt {attempt + 1}/{self.max_retries + 1})"
                    )
                    time.sleep(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                else:
                    log.error(f"UniFi API timeout after {self.max_retries + 1} attempts")
                    raise

            except requests.exceptions.ConnectionError as e:
                last_error = e
                if attempt < self.max_retries:
                    log.warning(
                        f"UniFi API connection error: {e}, retrying in {backoff:.1f}s "
                        f"(attempt {attempt + 1}/{self.max_retries + 1})"
                    )
                    time.sleep(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                else:
                    log.error(f"UniFi API connection failed after {self.max_retries + 1} attempts: {e}")
                    raise

        # Should not reach here, but just in case
        if last_error:
            raise last_error
        raise RuntimeError("Unexpected retry loop exit")

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        """Make API request with auto-retry on auth failure and exponential backoff."""
        url = self._api_url(endpoint)
        headers = kwargs.pop("headers", {})
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token

        try:
            resp = self._request_with_retry(method, url, headers, **kwargs)
        except requests.exceptions.RequestException as e:
            log.error(f"API request failed: {method} {endpoint} -> {e}")
            health_status.set_unifi_connected(False)
            health_status.set_error(f"UniFi API error: {e}")
            return None

        if resp.status_code == 401:
            log.warning("Session expired, re-authenticating...")
            if self.login():
                if self.csrf_token:
                    headers["X-CSRF-Token"] = self.csrf_token
                try:
                    resp = self._request_with_retry(method, url, headers, **kwargs)
                except requests.exceptions.RequestException as e:
                    log.error(f"API request failed after re-auth: {method} {endpoint} -> {e}")
                    health_status.set_error(f"UniFi API error after re-auth: {e}")
                    return None

        if resp.status_code >= 400:
            error_msg = f"API error: {method} {endpoint} -> {resp.status_code}: {resp.text[:200]}"
            log.error(error_msg)
            health_status.set_error(error_msg)
            return None

        health_status.set_unifi_connected(True)

        try:
            return resp.json()
        except Exception:
            return {"meta": {"rc": "ok"}}

    def get_firewall_groups(self) -> list:
        """Get all firewall groups."""
        result = self._request("GET", "rest/firewallgroup")
        return result.get("data", []) if result else []

    def create_firewall_group(self, name: str, members: list) -> Optional[dict]:
        """Create a new firewall address group."""
        payload = {
            "name": name,
            "group_type": "address-group",
            "group_members": members
        }
        result = self._request("POST", "rest/firewallgroup", json=payload)
        if result and result.get("data"):
            log.info(f"Created firewall group '{name}' with {len(members)} IPs")
            return result["data"][0]
        return None

    def update_firewall_group(self, group_id: str, name: str, members: list) -> bool:
        """Update an existing firewall group."""
        payload = {
            "_id": group_id,
            "name": name,
            "group_type": "address-group",
            "group_members": members
        }
        result = self._request("PUT", f"rest/firewallgroup/{group_id}", json=payload)
        if result:
            log.info(f"Updated firewall group '{name}' with {len(members)} IPs")
            return True
        return False

    def delete_firewall_group(self, group_id: str) -> bool:
        """Delete a firewall group."""
        result = self._request("DELETE", f"rest/firewallgroup/{group_id}")
        return result is not None

    def get_firewall_rules(self) -> list:
        """Get all firewall rules."""
        result = self._request("GET", "rest/firewallrule")
        return result.get("data", []) if result else []

    def create_firewall_rule(self, name: str, ruleset: str, rule_index: int,
                              src_group_id: str) -> Optional[dict]:
        """Create a firewall drop rule referencing a source address group.

        UDM SE API notes:
        - rule_index must match pattern 2[0-9]{4} or 4[0-9]{4} (e.g. 20000-29999)
        - ruleset: WAN_IN (external->LAN), WAN_LOCAL (external->router)
        - Use requests.Session with CSRF token (extracted from JWT in TOKEN cookie)
        """
        payload = {
            "enabled": True,
            "name": name,
            "action": "drop",
            "protocol": "all",
            "protocol_match_excepted": False,
            "logging": False,
            "state_established": False,
            "state_invalid": False,
            "state_new": True,
            "state_related": False,
            "ruleset": ruleset,
            "rule_index": rule_index,
            "src_firewallgroup_ids": [src_group_id],
            "src_mac_address": "",
            "dst_firewallgroup_ids": [],
            "dst_address": "",
            "src_address": "",
            "src_networkconf_id": "",
            "src_networkconf_type": "NETv4",
            "dst_networkconf_id": "",
            "dst_networkconf_type": "NETv4",
            "ipsec": "",
            "icmp_typename": "",
            "setting_preference": "manual"
        }
        result = self._request("POST", "rest/firewallrule", json=payload)
        if result and result.get("data"):
            log.info(f"Created firewall rule '{name}' ({ruleset})")
            return result["data"][0]
        return None


def is_ipv6(ip: str) -> bool:
    """Check if IP is IPv6."""
    return ":" in ip


def parse_duration_seconds(duration_str: str) -> int:
    """Parse CrowdSec duration string (e.g., '167h30m5.123s') to total seconds."""
    total = 0
    for value, unit in re.findall(r'([\d.]+)([hms])', str(duration_str)):
        value = float(value)
        if unit == 'h':
            total += value * 3600
        elif unit == 'm':
            total += value * 60
        elif unit == 's':
            total += value
    return int(total)


class UniFiBouncer:
    """Main bouncer logic with memory-conscious batch processing."""

    def __init__(self, crowdsec: CrowdSecClient, unifi: UniFiClient,
                 max_group_size: int = 10000, group_prefix: str = "crowdsec-ban",
                 enable_ipv6: bool = False, sync_batch_size: int = 1000,
                 max_ips: int = 0):
        self.crowdsec = crowdsec
        self.unifi = unifi
        self.max_group_size = max_group_size
        self.group_prefix = group_prefix
        self.enable_ipv6 = enable_ipv6
        self.sync_batch_size = sync_batch_size
        self.max_ips = max_ips
        self.current_ips = set()
        self.groups = {}  # name -> id mapping
        self._delta_count = 0
        self._full_refresh_interval = 10  # Full refresh every N polling cycles
        self._processed_decision_ids = set()  # Track decision IDs to avoid reprocessing
        self._ip_to_decision_ids = {}  # IP -> set of decision IDs (for cleanup)

    def _filter_ips(self, ips: set) -> set:
        """Filter IPs based on IPv6 setting."""
        if self.enable_ipv6:
            return ips
        return {ip for ip in ips if not is_ipv6(ip)}

    def _prioritize_and_cap(self, decisions: list) -> set:
        """Apply MAX_IPS cap with freshness prioritization.

        Priority tiers:
        1. Local detections (crowdsec, cscli origins) - always included
        2. Community detections (CAPI, etc.) - sorted by remaining duration, freshest first

        Returns a set of IP strings, capped at self.max_ips.
        """
        if not decisions:
            return set()

        tier1 = []  # Local detections (always keep)
        tier2 = []  # Community/other data (cap by freshness)

        for d in decisions:
            if d.get("type") != "ban" or d.get("scope") != "Ip":
                continue
            ip = d.get("value")
            if not ip:
                continue
            origin = d.get("origin", "")

            if origin in ("crowdsec", "cscli"):
                tier1.append(ip)
            else:
                dur = parse_duration_seconds(d.get("duration", "0s"))
                tier2.append((dur, ip))

        # Build result: always include tier1
        result = set(tier1)

        if self.max_ips > 0:
            remaining_capacity = max(0, self.max_ips - len(result))
            # Sort tier2 by duration descending (freshest bans first)
            tier2.sort(key=lambda x: x[0], reverse=True)
            for dur, ip in tier2[:remaining_capacity]:
                result.add(ip)

            log.info(
                f"IP cap: {len(tier1)} local + "
                f"{min(len(tier2), remaining_capacity)} community "
                f"(from {len(tier2)} available) = {len(result)} total "
                f"(cap: {self.max_ips})"
            )
        else:
            for _, ip in tier2:
                result.add(ip)

        return result

    def _chunk_ips(self, ips: list) -> list:
        """Split IPs into chunks of max_group_size."""
        ips = list(ips)
        return [ips[i:i + self.max_group_size]
                for i in range(0, len(ips), self.max_group_size)]

    def _group_name(self, index: int) -> str:
        """Generate group name for index."""
        return f"{self.group_prefix}-{index}"

    def load_existing_groups(self):
        """Load existing bouncer-managed groups from UniFi."""
        log.info("Loading existing firewall groups from UniFi...")
        groups = self.unifi.get_firewall_groups()

        if groups is None:
            log.error("Failed to fetch firewall groups from UniFi")
            return

        for g in groups:
            name = g.get("name", "")
            if name.startswith(self.group_prefix):
                self.groups[name] = g["_id"]
                member_count = len(g.get("group_members", []))
                log.debug(f"Found existing group: {name} ({g['_id']}) with {member_count} IPs")

        log.info(f"Loaded {len(self.groups)} existing bouncer groups")

    def ensure_firewall_rules(self):
        """Ensure WAN_IN and WAN_LOCAL drop rules exist for each bouncer group.

        Creates firewall rules that reference the address groups so that
        banned IPs are actually blocked. Without rules, groups do nothing.

        UDM SE API notes:
        - rule_index must be 5 digits starting with 2 or 4 (20000-29999, 40000-49999)
        - WAN_IN blocks traffic from external to LAN
        - WAN_LOCAL blocks traffic from external to the router itself
        """
        if not self.groups:
            log.debug("No groups loaded yet, skipping rule creation")
            return

        existing_rules = self.unifi.get_firewall_rules()
        # Map group IDs already covered by existing rules (per ruleset)
        covered = {}  # (ruleset, group_id) -> rule_id
        for r in existing_rules:
            for gid in r.get("src_firewallgroup_ids", []):
                covered[(r.get("ruleset"), gid)] = r["_id"]

        created = 0
        for name, group_id in sorted(self.groups.items()):
            # Extract index from group name (e.g. "crowdsec-ban-0" -> 0)
            try:
                idx = int(name.rsplit("-", 1)[1])
            except (ValueError, IndexError):
                idx = list(self.groups.keys()).index(name)

            for ruleset, offset in [("WAN_IN", 20000), ("WAN_LOCAL", 20010)]:
                rule_index = offset + idx
                key = (ruleset, group_id)

                if key in covered:
                    log.debug(f"Rule already exists: {ruleset} for {name}")
                    continue

                rule_name = f"CrowdSec Ban {idx} ({ruleset.replace('_', ' ')})"
                result = self.unifi.create_firewall_rule(
                    rule_name, ruleset, rule_index, group_id
                )
                if result:
                    created += 1
                else:
                    log.warning(f"Failed to create rule: {rule_name}")

        if created > 0:
            log.info(f"Created {created} firewall rules for bouncer groups")
        else:
            log.info("All firewall rules already exist")

    def sync_decisions(self, ips: set):
        """Sync IP set to UniFi firewall groups with memory-conscious processing."""
        sync_start = time.time()
        log_memory_usage("sync_start")

        # Filter IPv6 if disabled
        original_count = len(ips)
        ips = self._filter_ips(ips)
        filtered_count = original_count - len(ips)

        if filtered_count > 0:
            log.debug(f"Filtered out {filtered_count} IPv6 addresses")

        if ips == self.current_ips:
            log.debug(f"No changes in IP set (currently {len(ips)} IPs)")
            return

        added = ips - self.current_ips
        removed = self.current_ips - ips
        log.info(f"Syncing {len(ips)} total IPs to UniFi (+{len(added)} added, -{len(removed)} removed)")

        # Convert to sorted list for consistent chunking
        ip_list = sorted(ips)
        log_memory_usage("after_sort")

        chunks = self._chunk_ips(ip_list)
        log.info(f"Split into {len(chunks)} groups (max {self.max_group_size} IPs per group)")

        # Clear the list to free memory
        del ip_list
        gc.collect()
        log_memory_usage("after_gc")

        # Update or create groups for each chunk
        success_count = 0
        error_count = 0

        for i, chunk in enumerate(chunks):
            name = self._group_name(i)
            log.debug(f"Processing group {name} with {len(chunk)} IPs...")

            if name in self.groups:
                if self.unifi.update_firewall_group(self.groups[name], name, chunk):
                    success_count += 1
                else:
                    error_count += 1
                    log.error(f"Failed to update group {name}")
            else:
                result = self.unifi.create_firewall_group(name, chunk)
                if result:
                    self.groups[name] = result["_id"]
                    success_count += 1
                else:
                    error_count += 1
                    log.error(f"Failed to create group {name}")

            # Small delay between group updates to reduce API pressure
            if i < len(chunks) - 1:
                time.sleep(0.5)

        # Delete any extra groups that are no longer needed
        needed_groups = {self._group_name(i) for i in range(len(chunks))}
        groups_to_delete = [name for name in self.groups.keys() if name not in needed_groups]

        for name in groups_to_delete:
            group_id = self.groups[name]
            log.info(f"Deleting unused group: {name}")
            if self.unifi.delete_firewall_group(group_id):
                del self.groups[name]
            else:
                log.error(f"Failed to delete group {name}")

        self.current_ips = ips
        sync_duration = time.time() - sync_start

        log.info(
            f"Sync complete: {len(ips)} IPs in {len(chunks)} groups "
            f"({success_count} succeeded, {error_count} failed) in {sync_duration:.1f}s"
        )
        log_memory_usage("sync_complete")

        # Update health status
        health_status.set_last_sync(len(ips))

    def initial_sync(self):
        """Do initial full sync from CrowdSec."""
        log.info("Performing initial sync from CrowdSec...")
        log_memory_usage("initial_sync_start")

        try:
            # Get all current decisions
            decisions = self.crowdsec.get_all_decisions()
            log.info(f"Received {len(decisions)} decisions from CrowdSec")

            # Apply freshness-prioritized cap
            ips = self._prioritize_and_cap(decisions)
            log.info(f"Selected {len(ips)} IPs (cap: {self.max_ips or 'unlimited'})")
            log_memory_usage("after_extraction")

            # Clear decisions list to free memory before sync
            del decisions
            gc.collect()
            log_memory_usage("after_gc")

            self.sync_decisions(ips)

        except requests.exceptions.RequestException as e:
            log.error(f"Failed to fetch decisions from CrowdSec: {e}")
            health_status.set_crowdsec_connected(False)
            health_status.set_error(f"CrowdSec API error: {e}")
            raise

    def run_stream(self):
        """Run continuous sync using stream API."""
        # Initial full sync
        log.info("Starting stream-based synchronization...")

        try:
            log.info("Fetching initial decision stream (startup=true)...")
            stream = self.crowdsec.get_decisions_stream(startup=True)
            new_decisions = stream.get("new") or []

            log.info(f"Received {len(new_decisions)} decisions in initial stream")
            log_memory_usage("after_initial_stream")

            ips = self._prioritize_and_cap(new_decisions)
            log.info(f"Selected {len(ips)} IPs from initial stream (cap: {self.max_ips or 'unlimited'})")

            # Clear to free memory
            del new_decisions
            gc.collect()

            self.sync_decisions(ips)
            # Send telemetry after initial sync
            send_telemetry(len(self.current_ips))

        except requests.exceptions.RequestException as e:
            log.error(f"Initial stream sync failed: {e}")
            health_status.set_crowdsec_connected(False)
            health_status.set_error(f"CrowdSec stream error: {e}")
            # Fall back to regular query
            log.info("Falling back to regular decision query...")
            self.initial_sync()
            send_telemetry(len(self.current_ips))

        # Continuous polling
        log.info(f"Starting continuous polling (interval: {UPDATE_INTERVAL}s)...")
        consecutive_errors = 0
        max_consecutive_errors = 10

        while True:
            time.sleep(UPDATE_INTERVAL)
            self._delta_count += 1

            try:
                # Periodic full refresh to rotate stale IPs for fresher ones
                if self.max_ips > 0 and self._delta_count >= self._full_refresh_interval:
                    log.info("Performing periodic full refresh for freshness rotation...")
                    self._delta_count = 0
                    stream = self.crowdsec.get_decisions_stream(startup=True)
                    new_decisions = stream.get("new") or []
                    ips = self._prioritize_and_cap(new_decisions)
                    del new_decisions
                    gc.collect()
                    self.sync_decisions(ips)
                    consecutive_errors = 0
                    continue

                # Normal delta update
                stream = self.crowdsec.get_decisions_stream(startup=False)
                new_decisions = stream.get("new") or []
                deleted_decisions = stream.get("deleted") or []

                consecutive_errors = 0  # Reset on success

                # Add new bans (with decision ID tracking to avoid reprocessing)
                added = 0
                skipped = 0
                for d in new_decisions:
                    if d.get("type") == "ban" and d.get("scope") == "Ip":
                        decision_id = d.get("id")
                        ip = d.get("value")

                        # Skip already-processed decisions
                        if decision_id and decision_id in self._processed_decision_ids:
                            skipped += 1
                            continue

                        if ip:
                            self.current_ips.add(ip)
                            added += 1

                            # Track decision ID
                            if decision_id:
                                self._processed_decision_ids.add(decision_id)
                                if ip not in self._ip_to_decision_ids:
                                    self._ip_to_decision_ids[ip] = set()
                                self._ip_to_decision_ids[ip].add(decision_id)

                # Remove expired/deleted
                removed = 0
                for d in deleted_decisions:
                    if d.get("scope") == "Ip":
                        ip = d.get("value")
                        decision_id = d.get("id")

                        if ip:
                            self.current_ips.discard(ip)
                            removed += 1

                            # Clean up decision ID tracking
                            if decision_id:
                                self._processed_decision_ids.discard(decision_id)
                            if ip in self._ip_to_decision_ids:
                                if decision_id:
                                    self._ip_to_decision_ids[ip].discard(decision_id)
                                if not self._ip_to_decision_ids[ip]:
                                    del self._ip_to_decision_ids[ip]

                if new_decisions or deleted_decisions:
                    log.info(
                        f"Stream update: +{len(new_decisions)} decisions (+{added} bans, "
                        f"{skipped} skipped), -{len(deleted_decisions)} decisions (-{removed} removed), "
                        f"tracking {len(self._processed_decision_ids)} decision IDs"
                    )
                    self.sync_decisions(self.current_ips)
                else:
                    log.debug(f"No changes in stream (maintaining {len(self.current_ips)} IPs)")

            except requests.exceptions.RequestException as e:
                consecutive_errors += 1
                log.error(
                    f"Stream update failed ({consecutive_errors}/{max_consecutive_errors}): {e}"
                )
                health_status.set_crowdsec_connected(False)
                health_status.set_error(f"CrowdSec stream error: {e}")

                if consecutive_errors >= max_consecutive_errors:
                    log.critical(
                        f"Too many consecutive errors ({consecutive_errors}), "
                        "consider checking CrowdSec connectivity"
                    )


def send_telemetry(ip_count: int = 0):
    """Send anonymous startup ping with version and IP count."""
    if not TELEMETRY_ENABLED:
        return
    try:
        payload = {"tool": "bouncer", "version": __version__, "ip_count": ip_count}
        resp = requests.post(TELEMETRY_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            log.debug(f"Telemetry: startup #{data.get('instance', '?')}")
    except Exception:
        pass  # Silently ignore telemetry failures


def main():
    """Main entry point."""
    log.info(f"Starting CrowdSec UniFi Bouncer v{__version__}")
    log.info(f"CrowdSec URL: {CROWDSEC_URL}")
    log.info(f"UniFi Host: {UNIFI_HOST}")
    log.info(f"Update interval: {UPDATE_INTERVAL}s")
    log.info(f"Max group size: {UNIFI_MAX_GROUP_SIZE}")
    log.info(f"Max IPs cap: {MAX_IPS if MAX_IPS > 0 else 'unlimited'}")
    log.info(f"Sync batch size: {SYNC_BATCH_SIZE}")

    if CROWDSEC_ORIGINS:
        log.info(f"Filtering origins: {CROWDSEC_ORIGINS}")

    log_memory_usage("startup")

    # Validate config
    if not CROWDSEC_API_KEY:
        log.error("CROWDSEC_BOUNCER_API_KEY is required")
        sys.exit(1)
    if not UNIFI_USER or not UNIFI_PASS:
        log.error("UNIFI_USER and UNIFI_PASS are required")
        sys.exit(1)

    # Start health check server
    health_server = start_health_server()

    # Initialize clients
    crowdsec = CrowdSecClient(CROWDSEC_URL, CROWDSEC_API_KEY, CROWDSEC_ORIGINS)
    unifi = UniFiClient(
        UNIFI_HOST, UNIFI_USER, UNIFI_PASS,
        UNIFI_SITE, verify_ssl=not UNIFI_SKIP_TLS,
        max_retries=UNIFI_MAX_RETRIES,
        initial_backoff=UNIFI_INITIAL_BACKOFF,
        max_backoff=UNIFI_MAX_BACKOFF
    )

    # Login to UniFi
    log.info("Connecting to UniFi controller...")
    if not unifi.login():
        log.error("Failed to connect to UniFi controller")
        health_status.set_error("Initial UniFi login failed")
        sys.exit(1)

    # Create bouncer and run
    bouncer = UniFiBouncer(
        crowdsec, unifi, UNIFI_MAX_GROUP_SIZE, GROUP_PREFIX,
        ENABLE_IPV6, SYNC_BATCH_SIZE, MAX_IPS
    )
    log.info(f"IPv6: {'enabled' if ENABLE_IPV6 else 'disabled'}")

    if TELEMETRY_ENABLED:
        log.info("Telemetry: enabled (anonymous startup ping)")

    log.info(f"Retry config: max_retries={UNIFI_MAX_RETRIES}, initial_backoff={UNIFI_INITIAL_BACKOFF}s, max_backoff={UNIFI_MAX_BACKOFF}s")

    bouncer.load_existing_groups()
    bouncer.ensure_firewall_rules()

    try:
        bouncer.run_stream()
    except KeyboardInterrupt:
        log.info("Shutting down...")
    except Exception as e:
        log.critical(f"Fatal error: {e}")
        health_status.set_error(f"Fatal: {e}")
        raise


if __name__ == "__main__":
    main()
