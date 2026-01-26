#!/usr/bin/env python3
"""
CrowdSec UniFi Bouncer
A simple Python bouncer that syncs CrowdSec decisions to UniFi firewall groups.

Author: Claude (Anthropic) + Human collaboration
License: MIT
Repository: https://github.com/wolffcatskyy/crowdsec-unifi-bouncer
"""

__version__ = "1.2.2"
__author__ = "wolffcatskyy"

import os
import sys
import time
import json
import logging
import requests
from typing import Optional
from urllib3.exceptions import InsecureRequestWarning

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
ENABLE_IPV6 = os.getenv("ENABLE_IPV6", "false").lower() == "true"

GROUP_PREFIX = os.getenv("GROUP_PREFIX", "crowdsec-ban")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


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
        return resp.json() or []


class UniFiClient:
    """Simple UniFi controller client using cookie auth."""

    def __init__(self, host: str, username: str, password: str,
                 site: str = "default", verify_ssl: bool = True):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.csrf_token = None

    def login(self) -> bool:
        """Authenticate and get session cookie."""
        url = f"{self.host}/api/auth/login"
        payload = {"username": self.username, "password": self.password}

        log.debug(f"Logging in to UniFi at {url}")
        resp = self.session.post(url, json=payload, timeout=120)

        if resp.status_code == 200:
            # Extract CSRF token from response if present
            try:
                data = resp.json()
                # CSRF token might be in cookie or response
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
            return True
        else:
            log.error(f"UniFi login failed: {resp.status_code} - {resp.text[:200]}")
            return False

    def _api_url(self, endpoint: str) -> str:
        """Build full API URL for endpoint."""
        return f"{self.host}/proxy/network/api/s/{self.site}/{endpoint}"

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        """Make API request with auto-retry on auth failure."""
        url = self._api_url(endpoint)
        headers = kwargs.pop("headers", {})
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token

        resp = self.session.request(method, url, headers=headers, timeout=120, **kwargs)

        if resp.status_code == 401:
            log.warning("Session expired, re-authenticating...")
            if self.login():
                if self.csrf_token:
                    headers["X-CSRF-Token"] = self.csrf_token
                resp = self.session.request(method, url, headers=headers, timeout=120, **kwargs)

        if resp.status_code >= 400:
            log.error(f"API error: {method} {endpoint} -> {resp.status_code}: {resp.text[:200]}")
            return None

        try:
            return resp.json()
        except:
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


def is_ipv6(ip: str) -> bool:
    """Check if IP is IPv6."""
    return ":" in ip


class UniFiBouncer:
    """Main bouncer logic."""

    def __init__(self, crowdsec: CrowdSecClient, unifi: UniFiClient,
                 max_group_size: int = 10000, group_prefix: str = "crowdsec-ban",
                 enable_ipv6: bool = False):
        self.crowdsec = crowdsec
        self.unifi = unifi
        self.max_group_size = max_group_size
        self.group_prefix = group_prefix
        self.enable_ipv6 = enable_ipv6
        self.current_ips = set()
        self.groups = {}  # name -> id mapping

    def _filter_ips(self, ips: set) -> set:
        """Filter IPs based on IPv6 setting."""
        if self.enable_ipv6:
            return ips
        return {ip for ip in ips if not is_ipv6(ip)}

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
        groups = self.unifi.get_firewall_groups()
        for g in groups:
            name = g.get("name", "")
            if name.startswith(self.group_prefix):
                self.groups[name] = g["_id"]
                log.debug(f"Found existing group: {name} ({g['_id']})")
        log.info(f"Loaded {len(self.groups)} existing bouncer groups")

    def sync_decisions(self, ips: set):
        """Sync IP set to UniFi firewall groups."""
        # Filter IPv6 if disabled
        ips = self._filter_ips(ips)

        if ips == self.current_ips:
            log.debug("No changes in IP set")
            return

        log.info(f"Syncing {len(ips)} IPs to UniFi")
        chunks = self._chunk_ips(ips)

        # Update or create groups for each chunk
        for i, chunk in enumerate(chunks):
            name = self._group_name(i)
            if name in self.groups:
                self.unifi.update_firewall_group(self.groups[name], name, chunk)
            else:
                result = self.unifi.create_firewall_group(name, chunk)
                if result:
                    self.groups[name] = result["_id"]

        # Delete any extra groups that are no longer needed
        needed_groups = {self._group_name(i) for i in range(len(chunks))}
        for name, group_id in list(self.groups.items()):
            if name not in needed_groups:
                log.info(f"Deleting unused group: {name}")
                if self.unifi.delete_firewall_group(group_id):
                    del self.groups[name]

        self.current_ips = ips
        log.info(f"Sync complete: {len(ips)} IPs in {len(chunks)} groups")

    def initial_sync(self):
        """Do initial full sync from CrowdSec."""
        log.info("Performing initial sync...")

        # Get all current decisions
        decisions = self.crowdsec.get_all_decisions()
        ips = set()

        for d in decisions:
            if d.get("type") == "ban" and d.get("scope") == "Ip":
                ips.add(d.get("value"))

        log.info(f"Got {len(ips)} banned IPs from CrowdSec")
        self.sync_decisions(ips)

    def run_stream(self):
        """Run continuous sync using stream API."""
        # Initial full sync
        try:
            stream = self.crowdsec.get_decisions_stream(startup=True)
            new_decisions = stream.get("new") or []

            ips = set()
            for d in new_decisions:
                if d.get("type") == "ban" and d.get("scope") == "Ip":
                    ips.add(d.get("value"))

            log.info(f"Initial stream: {len(ips)} banned IPs")
            self.sync_decisions(ips)
        except Exception as e:
            log.error(f"Initial stream sync failed: {e}")
            # Fall back to regular query
            self.initial_sync()

        # Continuous polling
        while True:
            time.sleep(UPDATE_INTERVAL)

            try:
                stream = self.crowdsec.get_decisions_stream(startup=False)
                new_decisions = stream.get("new") or []
                deleted_decisions = stream.get("deleted") or []

                # Add new bans
                for d in new_decisions:
                    if d.get("type") == "ban" and d.get("scope") == "Ip":
                        self.current_ips.add(d.get("value"))

                # Remove expired/deleted
                for d in deleted_decisions:
                    if d.get("scope") == "Ip":
                        self.current_ips.discard(d.get("value"))

                if new_decisions or deleted_decisions:
                    log.info(f"Stream update: +{len(new_decisions)} -{len(deleted_decisions)}")
                    self.sync_decisions(self.current_ips)
                else:
                    log.debug("No changes in stream")

            except Exception as e:
                log.error(f"Stream update failed: {e}")


def main():
    """Main entry point."""
    log.info(f"Starting CrowdSec UniFi Bouncer v{__version__}")
    log.info(f"CrowdSec URL: {CROWDSEC_URL}")
    log.info(f"UniFi Host: {UNIFI_HOST}")
    log.info(f"Update interval: {UPDATE_INTERVAL}s")
    if CROWDSEC_ORIGINS:
        log.info(f"Filtering origins: {CROWDSEC_ORIGINS}")

    # Validate config
    if not CROWDSEC_API_KEY:
        log.error("CROWDSEC_BOUNCER_API_KEY is required")
        sys.exit(1)
    if not UNIFI_USER or not UNIFI_PASS:
        log.error("UNIFI_USER and UNIFI_PASS are required")
        sys.exit(1)

    # Initialize clients
    crowdsec = CrowdSecClient(CROWDSEC_URL, CROWDSEC_API_KEY, CROWDSEC_ORIGINS)
    unifi = UniFiClient(UNIFI_HOST, UNIFI_USER, UNIFI_PASS,
                        UNIFI_SITE, verify_ssl=not UNIFI_SKIP_TLS)

    # Login to UniFi
    if not unifi.login():
        log.error("Failed to connect to UniFi")
        sys.exit(1)

    # Create bouncer and run
    bouncer = UniFiBouncer(crowdsec, unifi, UNIFI_MAX_GROUP_SIZE, GROUP_PREFIX, ENABLE_IPV6)
    log.info(f"IPv6: {'enabled' if ENABLE_IPV6 else 'disabled'}")
    bouncer.load_existing_groups()

    try:
        bouncer.run_stream()
    except KeyboardInterrupt:
        log.info("Shutting down...")


if __name__ == "__main__":
    main()
