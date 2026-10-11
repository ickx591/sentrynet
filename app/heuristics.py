"""
Threat scoring: runs incrementally as new request rows are ingested, over a
short rolling in-memory window per IP (no need to hit Postgres per-request -
the window is small and this runs in the same process as the tailer).

Composite, not pass/fail: each signal that fires is recorded with its own
detail and severity, and a flagged IP shows *why* it was flagged, not just a
score. The overall score is the SUM of active signals' severities (not a
count of signal types) - see SIGNAL_SEVERITY below - so one severe signal
(a known scanner tool's UA) can trigger auto-block on its own, while several
mild/ambiguous signals (TOR, datacenter IP) never do by themselves.
"""

import ipaddress
import re
import statistics
import time
from collections import defaultdict, deque
from urllib.parse import unquote

from geoua import SCANNER_UA_SIGNATURES
import threat_intel
import ip_reputation

WINDOW_SECONDS = 120          # how far back each IP's rolling window looks
RATE_THRESHOLD = 120          # requests within WINDOW_SECONDS -> "high request rate"
ERROR_RATE_THRESHOLD = 0.5    # fraction of 4xx/5xx over MIN_SAMPLE -> "scanning"
MIN_SAMPLE = 15               # minimum requests before error-rate/path-scan/timing signals apply
DISTINCT_PATH_THRESHOLD = 25  # distinct paths within WINDOW_SECONDS -> "path scanning"
BRUTE_FORCE_THRESHOLD = 8     # POSTs to a login-shaped path within WINDOW_SECONDS
COORDINATED_IP_THRESHOLD = 20 # distinct IPs hitting the same rare path within COORD_WINDOW
COORD_WINDOW_SECONDS = 60
SUBNET_SCAN_IP_THRESHOLD = 8       # distinct IPs from the same /24 within SUBNET_SCAN_WINDOW_SECONDS
SUBNET_SCAN_TARGET_THRESHOLD = 15  # ...collectively hitting this many distinct paths/hosts...
SUBNET_SCAN_WINDOW_SECONDS = 120
SLOW_REQUEST_SECONDS = 5.0    # a single request taking this long counts as "slow"
SLOW_REQUEST_MIN_COUNT = 5    # this many slow requests in the window -> signal
ROBOTIC_CV_THRESHOLD = 0.15   # coefficient of variation below this -> suspiciously regular
ROBOTIC_MAX_MEAN_INTERVAL = 5.0  # only flag "fast and regular", not "slow and regular"

_LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|auth|admin)\b", re.IGNORECASE)

_HEADLESS_UA_SIGNATURES = ("headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium")

# WAF-style attack-payload signatures, matched against path + (decoded) query
# string only - deliberately never the request body, see nginx.conf's
# net_json log_format comment for why. Each is (label, compiled regex);
# label goes in the signal detail so a flagged IP shows exactly what matched.
_WAF_SIGNATURES = [
    ("SQL injection", re.compile(r"(\bunion\b[\s\S]{0,40}\bselect\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|'\s*or\s*'[^']*'\s*=\s*'|\bsleep\(\s*\d|\bbenchmark\s*\(|;\s*drop\s+table|\bxp_cmdshell\b|\binformation_schema\b)", re.IGNORECASE)),
    ("XSS", re.compile(r"(<script[\s>/]|javascript:|on(error|load|mouseover|focus)\s*=|<img[^>]+onerror)", re.IGNORECASE)),
    ("path traversal", re.compile(r"(\.\./\.\./|\.\.%2f|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.IGNORECASE)),
    ("command injection", re.compile(r"(;\s*(cat|wget|curl|nc|bash|sh)\s+|\|\s*(nc|bash|sh)\s+|`[^`]+`|\$\([^)]+\)|&&\s*(wget|curl))", re.IGNORECASE)),
    ("recon probe", re.compile(r"(\.env$|\.git/config|wp-login\.php|wp-admin/|phpmyadmin|\.aws/credentials|id_rsa)", re.IGNORECASE)),
]

# Severity weight per signal type - the sum of a flagged IP's active signals'
# severities is what actually drives auto-block (see ingest.py's
# AUTO_BLOCK_SCORE), not the number of distinct signal types firing.
SIGNAL_SEVERITY = {
    "scanner_ua":       5,  # an actual attack-tool signature - unambiguous
    "brute_force":       4,
    "headless_browser":  3,
    "coordinated":       3,
    "high_rate":         2,
    "scanning":          2,
    "path_scanning":     2,
    "no_user_agent":     2,
    "slow_requests":     2,
    "robotic_timing":    1,  # ambiguous on its own (legit polling looks like this too)
    "tor_exit":          1,  # privacy tool, not inherently malicious
    "datacenter_ip":     1,  # informational only - plenty of legit traffic is cloud-hosted
    "waf_payload":       5,  # an actual attack payload in the path/query - unambiguous
    "spamhaus_listed":   4,  # known-hijacked/leased netblock - stronger than generic datacenter_ip
    "ip_reputation":     3,  # base weight; actual severity scales with AbuseIPDB's own confidence
    "subnet_scan":       3,  # many IPs from one /24 spreading across many distinct targets
}

# ip_reputation's severity scales with AbuseIPDB's abuseConfidenceScore (0-100)
# rather than using the flat SIGNAL_SEVERITY entry above.
IP_REPUTATION_MIN_SEVERITY = 3
IP_REPUTATION_MAX_SEVERITY = 5

# Per-IP rolling state: deque of (ts, path, status, request_time)
_ip_window: dict[str, deque] = defaultdict(lambda: deque())
# Per-path rolling state for the "coordinated" signal: deque of (ts, ip)
_path_window: dict[str, deque] = defaultdict(lambda: deque())
# Per-/24-subnet rolling state for "subnet_scan": deque of (ts, ip, target),
# target being whichever of host/path is available (see _subnet_key below -
# this is a distributed-scan detector, not path-specific like "coordinated").
_subnet_window: dict[str, deque] = defaultdict(lambda: deque())
# No threading.Lock here on purpose: ingest.py's tailer is the only writer
# (single background thread); reads happen from that same thread when
# building the /api/flagged response - see main.py.

_last_sweep = time.time()
_SWEEP_INTERVAL = 60
_MAX_TRACKED_KEYS = 50_000


def _prune(dq: deque, now: float, window: float):
    while dq and now - dq[0][0] > window:
        dq.popleft()


def _subnet_key(ip: str):
    """/24 for IPv4 (a solid, zero-dependency proxy for "same network" - true
    ASN correlation would need a MaxMind ASN database, not worth it for this).
    Returns None for IPv6/unparseable IPs - no equivalent grouping convention
    for those is implemented here, so they're simply not covered by this
    signal (still covered by every other signal)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
    except ValueError:
        return None


def _sweep_empty_keys(now: float):
    """_ip_window/_path_window/_subnet_window keys are never removed by
    _prune() alone (it only trims each deque's contents) - without this,
    every IP/path/subnet ever seen would keep an empty-deque dict entry
    forever in this long-running process. Cheap periodic sweep instead of
    doing this on every call."""
    global _last_sweep
    if now - _last_sweep < _SWEEP_INTERVAL:
        return
    _last_sweep = now
    for d, window in ((_ip_window, WINDOW_SECONDS),
                      (_path_window, COORD_WINDOW_SECONDS),
                      (_subnet_window, SUBNET_SCAN_WINDOW_SECONDS)):
        for dq in d.values():
            _prune(dq, now, window)
        for key in [k for k, dq in d.items() if not dq]:
            del d[key]


def _tracked_window(store: dict, key):
    if key not in store and len(store) >= _MAX_TRACKED_KEYS:
        del store[next(iter(store))]
    return store[key]


def _sig(sig_type: str, detail: str) -> dict:
    return {"type": sig_type, "detail": detail, "severity": SIGNAL_SEVERITY.get(sig_type, 1)}


def score_request(ip: str, path: str, status: int, method: str, ua: str, request_time: float = None, query: str = None, host: str = None) -> list[dict]:
    """Call once per ingested request. Returns the list of signals currently
    active for this IP (empty list if none)."""
    now = time.time()
    _sweep_empty_keys(now)

    dq = _tracked_window(_ip_window, ip)
    dq.append((now, path, status, request_time))
    _prune(dq, now, WINDOW_SECONDS)

    pdq = _tracked_window(_path_window, path)
    pdq.append((now, ip))
    _prune(pdq, now, COORD_WINDOW_SECONDS)

    subnet_signal = None
    subnet_key = _subnet_key(ip)
    if subnet_key is not None:
        target = host or path
        sdq = _tracked_window(_subnet_window, subnet_key)
        sdq.append((now, ip, target))
        _prune(sdq, now, SUBNET_SCAN_WINDOW_SECONDS)
        distinct_subnet_ips = len({i for _, i, _ in sdq})
        distinct_targets = len({t for _, _, t in sdq})
        if distinct_subnet_ips >= SUBNET_SCAN_IP_THRESHOLD and distinct_targets >= SUBNET_SCAN_TARGET_THRESHOLD:
            subnet_signal = _sig(
                "subnet_scan",
                f"{distinct_subnet_ips} IPs from {subnet_key}/24 hit {distinct_targets} distinct "
                f"{'hosts' if host else 'paths'} in {SUBNET_SCAN_WINDOW_SECONDS}s",
            )

    signals = []

    # 1. Rate
    if len(dq) >= RATE_THRESHOLD:
        signals.append(_sig("high_rate", f"{len(dq)} requests in {WINDOW_SECONDS}s"))

    # 2. Error rate (scanning)
    if len(dq) >= MIN_SAMPLE:
        errors = sum(1 for _, _, s, _ in dq if s >= 400)
        rate = errors / len(dq)
        if rate >= ERROR_RATE_THRESHOLD:
            signals.append(_sig("scanning", f"{errors}/{len(dq)} requests were 4xx/5xx"))

    # 3. Scanner UA signature
    low_ua = (ua or "").lower()
    hit = next((sig for sig in SCANNER_UA_SIGNATURES if sig in low_ua), None)
    if hit:
        signals.append(_sig("scanner_ua", f'user-agent matched "{hit}"'))

    # 3b. Headless browser automation
    headless_hit = next((sig for sig in _HEADLESS_UA_SIGNATURES if sig in low_ua), None)
    if headless_hit:
        signals.append(_sig("headless_browser", f'user-agent matched "{headless_hit}"'))

    # 3c. No User-Agent at all - most real browsers always send one
    if not (ua or "").strip():
        signals.append(_sig("no_user_agent", "request had no User-Agent header"))

    # 4. Brute force on login-shaped paths
    if method == "POST":
        login_hits = sum(1 for _, p, _, _ in dq if _LOGIN_PATH_RE.search(p or ""))
        if login_hits >= BRUTE_FORCE_THRESHOLD:
            signals.append(_sig("brute_force", f"{login_hits} POSTs to login-shaped paths in {WINDOW_SECONDS}s"))

    # 5. Path enumeration
    if len(dq) >= MIN_SAMPLE:
        distinct_paths = len({p for _, p, _, _ in dq})
        if distinct_paths >= DISTINCT_PATH_THRESHOLD:
            signals.append(_sig("path_scanning", f"{distinct_paths} distinct paths in {WINDOW_SECONDS}s"))

    # 6. Coordinated hit on a rare path (checked regardless of this IP's own history)
    distinct_ips = len({i for _, i in pdq})
    if distinct_ips >= COORDINATED_IP_THRESHOLD:
        signals.append(_sig("coordinated", f"{distinct_ips} distinct IPs hit {path!r} in {COORD_WINDOW_SECONDS}s"))

    # 7. Slow requests (potential slowloris / resource exhaustion attempt)
    slow_count = sum(1 for _, _, _, rt in dq if rt is not None and rt >= SLOW_REQUEST_SECONDS)
    if slow_count >= SLOW_REQUEST_MIN_COUNT:
        signals.append(_sig("slow_requests", f"{slow_count} requests took >={SLOW_REQUEST_SECONDS:.0f}s in {WINDOW_SECONDS}s"))

    # 8. Robotic timing - suspiciously regular intervals between requests.
    # Ambiguous signal (legit dashboard polling looks similar), kept low
    # severity and gated on a large sample so it's rarely the only thing
    # that fires.
    if len(dq) >= MIN_SAMPLE:
        timestamps = [t for t, _, _, _ in dq]
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b - a > 0]
        if len(intervals) >= MIN_SAMPLE - 1:
            mean = statistics.mean(intervals)
            if 0 < mean <= ROBOTIC_MAX_MEAN_INTERVAL and len(intervals) > 1:
                stdev = statistics.stdev(intervals)
                cv = stdev / mean if mean else 1.0
                if cv <= ROBOTIC_CV_THRESHOLD:
                    signals.append(_sig("robotic_timing", f"requests spaced ~{mean:.2f}s apart, CV={cv:.2f}"))

    # 9. TOR exit node
    if threat_intel.is_tor_exit(ip):
        signals.append(_sig("tor_exit", "IP is a known TOR exit node"))

    # 10. Known datacenter/cloud-hosting IP
    dc_provider = threat_intel.is_datacenter(ip)
    if dc_provider:
        signals.append(_sig("datacenter_ip", f"IP belongs to {dc_provider}'s published ranges"))

    # 11. WAF-style attack payload in the path or query string
    try:
        probe_text = (path or "") + " " + unquote(query or "")
    except Exception:
        probe_text = (path or "") + " " + (query or "")
    waf_hit = next((label for label, rx in _WAF_SIGNATURES if rx.search(probe_text)), None)
    if waf_hit:
        signals.append(_sig("waf_payload", f"{waf_hit} pattern matched in path/query"))

    # 12. Spamhaus DROP/EDROP - a known-hijacked/leased netblock, a stronger
    # and more specific signal than the generic datacenter_ip check above.
    spamhaus_list = threat_intel.is_spamhaus_listed(ip)
    if spamhaus_list:
        signals.append(_sig("spamhaus_listed", f"IP is listed on {spamhaus_list}"))

    # 13. Subnet-level distributed scan - many IPs from the same /24 spreading
    # requests across many distinct targets, unlike "coordinated" above (which
    # only catches many IPs hitting the SAME single path).
    if subnet_signal:
        signals.append(subnet_signal)

    # 14. AbuseIPDB reputation - only spent on IPs already flagged by at
    # least one signal above, to protect AbuseIPDB's free-tier daily quota.
    if signals:
        confidence = ip_reputation.is_bad_reputation(ip)
        if confidence:
            severity = round(
                IP_REPUTATION_MIN_SEVERITY
                + (IP_REPUTATION_MAX_SEVERITY - IP_REPUTATION_MIN_SEVERITY) * (confidence / 100)
            )
            signals.append({
                "type": "ip_reputation",
                "detail": f"AbuseIPDB confidence score {confidence}/100",
                "severity": severity,
            })

    return signals
