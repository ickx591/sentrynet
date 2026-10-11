"""
Webserver-agnostic backend for the handful of things that differ between
nginx and Apache: where the access log lives, how its JSON fields need
normalizing to match nginx's semantics exactly, and how the IP blocklist
gets enforced. Selected via the WEBSERVER env var (written into
.env.postgres by install.sh) - "nginx" or "apache".

nginx enforces its blocklist through its own `deny` directive - reliable,
since nginx's http-level config applies uniformly server-wide with no
per-vhost merge ambiguity. Apache's blocklist is enforced at the firewall
level (iptables, blocking ports 80+443 for the banned IP) instead of
through Apache's own access-control directives - this was empirically
confirmed during development, not assumed: a global `<Location />` block
declared in a separate conf-available file did NOT reliably override a
vhost's own directory/location config (Apache's authz merge order across
Directory/Location sections is genuinely vhost-config-dependent), whereas
the exact same rule declared directly inside a `<VirtualHost>` worked fine.
Since SentryNet has to block an IP across whatever arbitrary vhosts a
customer already has, without editing every one of them, the firewall
layer sidesteps that fragility entirely - same proven mechanism already
used for SSH bans (ssh_ban.py), just different ports.

Apache's `%D` log token is request time in MICROSECONDS (nginx's
$request_time is seconds) - REQUEST_TIME_DIVISOR converts it. Apache's
`%{Host}i` includes the port and its `%q` query string keeps the leading
"?" (nginx's $host and $args don't) - ingest.py normalizes both using the
helpers here. Apache also logs "-" for absent referer/UA/SSL fields where
nginx logs an empty string - normalize_apache_fields() converts those to
match, so the rest of the ingest pipeline doesn't need to know or care
which webserver produced a given line.
"""

import os
import subprocess
import tempfile
import threading

WEBSERVER = os.environ.get("WEBSERVER", "nginx").strip().lower()
ACCESS_LOG = os.environ.get(
    "ACCESS_LOG_PATH",
    "/var/log/nginx/access.log" if WEBSERVER == "nginx" else "/var/log/apache2/access.log",
)
REQUEST_TIME_DIVISOR = 1_000_000.0 if WEBSERVER == "apache" else 1.0

_NGINX_BLOCKLIST_CONF = "/etc/nginx/conf.d/sentrynet-blocklist.conf"
_APACHE_HTTP_PORTS = (80, 443)
_APACHE_FW_COMMENT_PREFIX = "sentrynet-http-ban-"
_APACHE_DASH_FIELDS = ("referer", "ua", "ssl")
_blocklist_lock = threading.Lock()


def normalize_apache_fields(d: dict) -> dict:
    """Mutates and returns d, converting Apache-specific log quirks to
    match nginx's exact conventions so the rest of ingest.py's parser
    doesn't need any webserver-specific branching beyond this one call."""
    for key in _APACHE_DASH_FIELDS:
        if d.get(key) == "-":
            d[key] = ""
    host = d.get("host") or ""
    if ":" in host:
        d["host"] = host.rsplit(":", 1)[0]
    query = d.get("query") or ""
    if query.startswith("?"):
        d["query"] = query[1:]
    return d


def test_config() -> bool:
    if WEBSERVER == "apache":
        r = subprocess.run(["apache2ctl", "configtest"], capture_output=True)
    else:
        r = subprocess.run(["nginx", "-t"], capture_output=True)
    return r.returncode == 0


def reload():
    unit = "apache2" if WEBSERVER == "apache" else "nginx"
    result = subprocess.run(["systemctl", "reload", unit], capture_output=True, timeout=15)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip() if isinstance(result.stderr, bytes) else result.stderr.strip()
        raise RuntimeError(f"{unit} reload failed: {detail or 'unknown error'}")


def _apache_fw_comment(ip: str) -> str:
    return f"{_APACHE_FW_COMMENT_PREFIX}{ip}"


def _apache_fw_rule_spec(ip: str) -> list:
    ports = ",".join(str(p) for p in _APACHE_HTTP_PORTS)
    return ["-s", ip, "-p", "tcp", "-m", "multiport", "--dports", ports,
            "-m", "comment", "--comment", _apache_fw_comment(ip), "-j", "DROP"]


def _apache_fw_rule_exists(ip: str) -> bool:
    r = subprocess.run(["iptables", "-C", "INPUT"] + _apache_fw_rule_spec(ip), capture_output=True)
    return r.returncode == 0


def _apache_add_fw_rule(ip: str):
    if _apache_fw_rule_exists(ip):
        return
    subprocess.run(["iptables", "-I", "INPUT", "1"] + _apache_fw_rule_spec(ip), capture_output=True)


def _apache_remove_fw_rule(ip: str):
    for _ in range(5):
        if not _apache_fw_rule_exists(ip):
            break
        subprocess.run(["iptables", "-D", "INPUT"] + _apache_fw_rule_spec(ip), capture_output=True)


def _apache_current_fw_ips() -> set:
    # Parsed from the comment text, not the "-s" value - iptables silently
    # normalizes a bare IP passed to -s into CIDR form ("1.2.3.4" becomes
    # "1.2.3.4/32" in `iptables -S` output), which would otherwise never
    # round-trip back to what _apache_add_fw_rule/_apache_fw_comment were
    # originally called with, breaking the exact-match -C/-D lookups this
    # relies on. The comment string isn't touched by iptables, so it's the
    # reliable source of truth for "what IP did we actually ban".
    r = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True)
    ips = set()
    for line in r.stdout.splitlines():
        idx = line.find(_APACHE_FW_COMMENT_PREFIX)
        if idx == -1:
            continue
        rest = line[idx + len(_APACHE_FW_COMMENT_PREFIX):]
        ip = rest.split()[0].strip('"')
        if ip:
            ips.add(ip)
    return ips


def _apache_sync_fw_rules(desired_ips: set):
    current = _apache_current_fw_ips()
    for ip in current - desired_ips:
        _apache_remove_fw_rule(ip)
    for ip in desired_ips - current:
        _apache_add_fw_rule(ip)


def regenerate_blocklist():
    """Reads every currently-blocked IP/CIDR from Postgres and re-applies
    enforcement. Raises RuntimeError if nginx's config test fails (mirrors
    the pre-existing stricter behavior callers already expect); the Apache
    path can't fail this way since it's pure firewall rules, no config to
    test or reload."""
    from models import BlockedIp
    with _blocklist_lock:
        ips = {b.ip for b in BlockedIp.select(BlockedIp.ip)}

        if WEBSERVER == "apache":
            _apache_sync_fw_rules(ips)
            return

        lines = ["# Managed by SentryNet - do not edit by hand.\n"]
        lines.extend(f"deny {ip};\n" for ip in sorted(ips))
        destination = os.path.abspath(_NGINX_BLOCKLIST_CONF)
        directory = os.path.dirname(destination)
        previous = open(destination, "rb").read() if os.path.exists(destination) else None
        fd, temporary = tempfile.mkstemp(prefix=".sentrynet-blocklist.", dir=directory)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.writelines(lines)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            if not test_config():
                if previous is None:
                    os.unlink(destination)
                else:
                    rollback_fd, rollback = tempfile.mkstemp(prefix=".sentrynet-rollback.", dir=directory)
                    with os.fdopen(rollback_fd, "wb") as stream:
                        stream.write(previous)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(rollback, destination)
                raise RuntimeError("nginx config test failed; previous blocklist restored")
            reload()
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
