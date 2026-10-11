"""
Background-refreshed threat intelligence: TOR exit nodes + known
datacenter/cloud-hosting IP ranges. Both are legitimate signals for a
consumer-facing site - real visitors browse from residential/mobile ISPs, so
traffic from a TOR exit or a cloud provider's IP space is disproportionately
likely to be automated/adversarial (not a hard rule, just one more signal
for heuristics.py's composite score).

Fetched from public, no-auth-required sources and cached to disk so a
network hiccup or the remote source being briefly down never breaks
ingestion - the in-memory set just keeps serving the last-known-good data
(or an empty set on a totally fresh box, which is a safe default: no false
positives, just a missing signal until the first successful fetch).

Runs as its own background thread, started from main.py's startup event,
same pattern as ingest.py's log tailer.
"""

import ipaddress
import json
import os
import threading
import time
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).parent
TOR_CACHE_FILE = SCRIPT_DIR / ".tor_exits.json"
DC_CACHE_FILE = SCRIPT_DIR / ".datacenter_ranges.json"
SPAMHAUS_CACHE_FILE = SCRIPT_DIR / ".spamhaus_ranges.json"

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

REFRESH_INTERVAL_SECONDS = 6 * 3600
FETCH_TIMEOUT = 20

# Providers without a convenient public JSON feed - a representative (not
# exhaustive) sample of their well-documented core ranges, good enough for a
# "this looks like a datacenter, not a home connection" signal rather than a
# complete inventory. Safe to extend over time.
STATIC_DATACENTER_RANGES = {
    "DigitalOcean": ["104.131.0.0/16", "104.236.0.0/16", "138.68.0.0/16", "159.65.0.0/16",
                     "157.230.0.0/16", "165.22.0.0/16", "167.71.0.0/16", "178.62.0.0/16"],
    "Hetzner": ["88.99.0.0/16", "78.46.0.0/15", "116.202.0.0/16", "135.181.0.0/16",
                "168.119.0.0/16", "5.9.0.0/16", "176.9.0.0/16"],
    "OVH": ["37.59.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "54.36.0.0/16",
            "137.74.0.0/16", "141.94.0.0/16", "145.239.0.0/16", "167.114.0.0/16"],
    "Linode": ["45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "172.104.0.0/15",
               "173.230.128.0/17", "192.53.120.0/22", "198.58.96.0/19"],
    "Vultr": ["45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "104.156.224.0/19",
              "108.61.0.0/16", "149.28.0.0/16", "207.148.0.0/20"],
}

_lock = threading.Lock()
_tor_exits: set = set()
_dc_networks: list = []  # list of (ipaddress.ip_network, provider_name)
_spamhaus_networks: list = []  # list of (ipaddress.ip_network, "Spamhaus DROP"/"Spamhaus EDROP")
_status = {
    "tor_count": 0, "tor_last_refresh": None, "tor_last_error": None,
    "dc_count": 0, "dc_last_refresh": None, "dc_last_error": None,
    "spamhaus_count": 0, "spamhaus_last_refresh": None, "spamhaus_last_error": None,
}

_stop = threading.Event()


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _save_json(path, data):
    try:
        tmp = str(path) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception as e:
        print(f"[threat-intel] failed to save {path}: {e}")


def _load_from_cache():
    global _tor_exits, _dc_networks, _spamhaus_networks
    tor_cache = _load_json(TOR_CACHE_FILE)
    if tor_cache:
        with _lock:
            _tor_exits = set(tor_cache.get("ips", []))
            _status["tor_count"] = len(_tor_exits)
            _status["tor_last_refresh"] = tor_cache.get("fetched_at")

    dc_cache = _load_json(DC_CACHE_FILE)
    if dc_cache:
        nets = []
        for provider, cidrs in dc_cache.get("ranges", {}).items():
            for c in cidrs:
                try:
                    nets.append((ipaddress.ip_network(c, strict=False), provider))
                except ValueError:
                    continue
        with _lock:
            _dc_networks = nets
            _status["dc_count"] = len(_dc_networks)
            _status["dc_last_refresh"] = dc_cache.get("fetched_at")

    spamhaus_cache = _load_json(SPAMHAUS_CACHE_FILE)
    if spamhaus_cache:
        nets = []
        for list_name, cidrs in spamhaus_cache.get("ranges", {}).items():
            for c in cidrs:
                try:
                    nets.append((ipaddress.ip_network(c, strict=False), list_name))
                except ValueError:
                    continue
        with _lock:
            _spamhaus_networks = nets
            _status["spamhaus_count"] = len(_spamhaus_networks)
            _status["spamhaus_last_refresh"] = spamhaus_cache.get("fetched_at")


def _fetch_tor_exits():
    resp = requests.get(TOR_EXIT_LIST_URL, timeout=FETCH_TIMEOUT, headers={"User-Agent": "sentrynet-threat-intel"})
    resp.raise_for_status()
    ips = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
    return ips


def _fetch_datacenter_ranges():
    ranges = {name: list(cidrs) for name, cidrs in STATIC_DATACENTER_RANGES.items()}

    try:
        resp = requests.get(AWS_RANGES_URL, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        aws_cidrs = sorted({p["ip_prefix"] for p in data.get("prefixes", []) if p.get("ip_prefix")})
        ranges["AWS"] = aws_cidrs
    except Exception as e:
        print(f"[threat-intel] AWS range fetch failed: {e}")

    try:
        resp = requests.get(GCP_RANGES_URL, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        gcp_cidrs = sorted({
            p.get("ipv4Prefix") or p.get("ipv6Prefix")
            for p in data.get("prefixes", [])
            if p.get("ipv4Prefix") or p.get("ipv6Prefix")
        })
        ranges["Google Cloud"] = gcp_cidrs
    except Exception as e:
        print(f"[threat-intel] GCP range fetch failed: {e}")

    return ranges


def _fetch_spamhaus_ranges():
    """DROP/EDROP: netblocks Spamhaus considers fully hijacked/leased by
    spammers/cybercriminals - a hit here is a stronger, more specific signal
    than the generic datacenter-IP one (that's just "cloud provider," this is
    "known-bad")."""
    ranges = {}
    for list_name, url in (("Spamhaus DROP", SPAMHAUS_DROP_URL), ("Spamhaus EDROP", SPAMHAUS_EDROP_URL)):
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "sentrynet-threat-intel"})
            resp.raise_for_status()
            cidrs = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                cidr = line.split(";")[0].strip()
                if cidr:
                    cidrs.append(cidr)
            ranges[list_name] = cidrs
        except Exception as e:
            print(f"[threat-intel] {list_name} fetch failed: {e}")
    return ranges


def _refresh_once():
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        ips = _fetch_tor_exits()
        with _lock:
            global _tor_exits
            _tor_exits = ips
            _status["tor_count"] = len(ips)
            _status["tor_last_refresh"] = now_iso
            _status["tor_last_error"] = None
        _save_json(TOR_CACHE_FILE, {"ips": sorted(ips), "fetched_at": now_iso})
    except Exception as e:
        with _lock:
            _status["tor_last_error"] = str(e)
        print(f"[threat-intel] TOR exit list refresh failed (keeping last-known-good): {e}")

    try:
        ranges = _fetch_datacenter_ranges()
        nets = []
        for provider, cidrs in ranges.items():
            for c in cidrs:
                try:
                    nets.append((ipaddress.ip_network(c, strict=False), provider))
                except ValueError:
                    continue
        with _lock:
            global _dc_networks
            _dc_networks = nets
            _status["dc_count"] = len(nets)
            _status["dc_last_refresh"] = now_iso
            _status["dc_last_error"] = None
        _save_json(DC_CACHE_FILE, {"ranges": ranges, "fetched_at": now_iso})
    except Exception as e:
        with _lock:
            _status["dc_last_error"] = str(e)
        print(f"[threat-intel] datacenter range refresh failed (keeping last-known-good): {e}")

    try:
        ranges = _fetch_spamhaus_ranges()
        nets = []
        for list_name, cidrs in ranges.items():
            for c in cidrs:
                try:
                    nets.append((ipaddress.ip_network(c, strict=False), list_name))
                except ValueError:
                    continue
        with _lock:
            global _spamhaus_networks
            _spamhaus_networks = nets
            _status["spamhaus_count"] = len(nets)
            _status["spamhaus_last_refresh"] = now_iso
            _status["spamhaus_last_error"] = None
        _save_json(SPAMHAUS_CACHE_FILE, {"ranges": ranges, "fetched_at": now_iso})
    except Exception as e:
        with _lock:
            _status["spamhaus_last_error"] = str(e)
        print(f"[threat-intel] Spamhaus range refresh failed (keeping last-known-good): {e}")


def is_tor_exit(ip: str) -> bool:
    with _lock:
        return ip in _tor_exits


def is_datacenter(ip: str):
    """Returns provider name if ip falls in a known datacenter range, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    with _lock:
        nets = list(_dc_networks)
    for net, provider in nets:
        if addr.version == net.version and addr in net:
            return provider
    return None


def is_spamhaus_listed(ip: str):
    """Returns the list name ("Spamhaus DROP"/"Spamhaus EDROP") if ip falls
    in a known-hijacked/leased netblock, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    with _lock:
        nets = list(_spamhaus_networks)
    for net, list_name in nets:
        if addr.version == net.version and addr in net:
            return list_name
    return None


def get_status() -> dict:
    with _lock:
        return dict(_status)


def _run():
    _load_from_cache()
    # First refresh happens right away in the background (not blocking
    # main.py's startup) so a freshly-deployed box gets real data within
    # seconds rather than waiting a full REFRESH_INTERVAL.
    while not _stop.is_set():
        _refresh_once()
        _stop.wait(REFRESH_INTERVAL_SECONDS)


def start():
    t = threading.Thread(target=_run, daemon=True, name="threat-intel-refresh")
    t.start()
    return t


def stop():
    _stop.set()
