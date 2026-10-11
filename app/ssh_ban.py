"""
Firewall-level SSH bans - separate from the nginx-based HTTP block list
(BlockedIp/_regenerate_blocklist in ingest.py/main.py), since nginx never
sees SSH traffic at all. Stopping SSH brute-force needs an actual OS
firewall rule for whichever port(s) sshd is actually listening on - NOT
hardcoded to 22, since running SSH on a non-standard port is a common
hardening practice, and a rule blocking the wrong port would show up as
"banned" in the dashboard while doing nothing at all.

The port is auto-detected once at startup (see _detect_ssh_ports): first by
asking the kernel what sshd is actually bound to (`ss -ltnp`, the ground
truth - catches multiple Port directives, -o Port= overrides, etc.), falling
back to parsing /etc/ssh/sshd_config, falling back to 22 if neither works.
Detected once per process start, not re-checked continuously - changing
sshd's port is a deliberate, rare admin action, and picking up a change
just needs a restart of this service, same as it needs a restart of sshd
itself to take effect.

Uses `iptables` directly, inserted at the very top of the INPUT chain -
that means it's evaluated (and drops the traffic) before anything else,
regardless of whatever else manages this box's firewall (ufw, firewalld,
nothing). Each rule carries a comment tag so it can be found and removed
reliably later without depending on rule ordering or reconstructing an
exact match.

Bans are temporary (BAN_DURATION_HOURS) and DB-backed - SshBannedIp is the
source of truth, not the live iptables state. A periodic sweep (and one run
at startup) reconciles the two: re-applies any ban whose rule is missing
(e.g. after a reboot - raw iptables rules don't survive one on their own),
and removes any rule whose ban has expired.
"""

import ipaddress
import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from models import SshBannedIp
from notify import send_discord_alert
import alert_settings

BAN_DURATION_HOURS = 24
SWEEP_INTERVAL_SECONDS = 60
_COMMENT_PREFIX = "sentrynet-ssh-ban-"

_stop = threading.Event()


def _detect_ssh_ports() -> list:
    try:
        r = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=5)
        ports = set()
        for line in r.stdout.splitlines():
            if '"sshd"' not in line:
                continue
            m = re.search(r":(\d+)\s", line)
            if m:
                ports.add(int(m.group(1)))
        if ports:
            return sorted(ports)
    except Exception:
        pass
    try:
        text = Path("/etc/ssh/sshd_config").read_text()
        found = sorted({int(l.split()[1]) for l in text.splitlines()
                         if l.strip().lower().startswith("port ")})
        if found:
            return found
    except Exception:
        pass
    return [22]


SSH_PORTS = _detect_ssh_ports()


def _is_valid_ip(ip: str) -> bool:
    """A single IPv4/IPv6 address only - never a CIDR range, hostname, or
    anything else. SSH bans are always exact addresses (sshd only ever logs
    a real connection-source IP), so this should never legitimately fail;
    it's a fail-closed check against a firewall rule ever getting built
    from unvalidated/unexpected input."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _comment_for(ip: str) -> str:
    return f"{_COMMENT_PREFIX}{ip}"


def _rule_spec(ip: str) -> list:
    ports = ",".join(str(p) for p in SSH_PORTS)
    return ["-s", ip, "-p", "tcp", "-m", "multiport", "--dports", ports,
            "-m", "comment", "--comment", _comment_for(ip), "-j", "DROP"]


def _rule_exists(ip: str) -> bool:
    r = subprocess.run(["iptables", "-C", "INPUT"] + _rule_spec(ip), capture_output=True)
    return r.returncode == 0


def _add_rule(ip: str):
    if not _is_valid_ip(ip):
        print(f"[ssh-ban] refusing to add a firewall rule for invalid IP: {ip!r}")
        return
    if _rule_exists(ip):
        return
    subprocess.run(["iptables", "-I", "INPUT", "1"] + _rule_spec(ip), capture_output=True)


def _remove_rule(ip: str):
    # Loop in case of a rare duplicate (only one -C/-D pass is normally needed).
    for _ in range(5):
        if not _rule_exists(ip):
            break
        subprocess.run(["iptables", "-D", "INPUT"] + _rule_spec(ip), capture_output=True)


def ban_ip(ip: str, reason: str):
    if not _is_valid_ip(ip):
        print(f"[ssh-ban] refusing to ban invalid IP: {ip!r}")
        return
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=BAN_DURATION_HOURS)
    row = SshBannedIp.get_or_none(SshBannedIp.ip == ip)
    was_already_banned = row is not None
    if row:
        row.expires_at = expires_at
        row.reason = reason
        row.save()
    else:
        SshBannedIp.create(ip=ip, banned_at=now, expires_at=expires_at, reason=reason)
    _add_rule(ip)
    if not was_already_banned and alert_settings.is_enabled("ip_blocks"):
        port_desc = ",".join(str(p) for p in SSH_PORTS)
        send_discord_alert(
            f":no_entry: **SSH IP auto-banned**: `{ip}` for {BAN_DURATION_HOURS}h (port {port_desc} only)\n{reason}"
        )


def unban_ip(ip: str, actor: str = "auto"):
    existed = SshBannedIp.get_or_none(SshBannedIp.ip == ip) is not None
    SshBannedIp.delete().where(SshBannedIp.ip == ip).execute()
    _remove_rule(ip)
    if existed and alert_settings.is_enabled("ip_blocks"):
        suffix = "expired" if actor == "auto" else f"by {actor}"
        send_discord_alert(f":white_check_mark: **SSH ban lifted**: `{ip}` ({suffix})")


def is_banned(ip: str) -> bool:
    return SshBannedIp.get_or_none(SshBannedIp.ip == ip) is not None


def list_banned() -> list:
    rows = SshBannedIp.select().order_by(SshBannedIp.banned_at.desc())
    return [{"ip": r.ip, "banned_at": r.banned_at.isoformat(),
              "expires_at": r.expires_at.isoformat(), "reason": r.reason} for r in rows]


def _reconcile():
    # Postgres returns naive datetimes for these timestamp columns - strip
    # tzinfo from `now` rather than compare naive-vs-aware.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for row in list(SshBannedIp.select()):
        if row.expires_at <= now:
            unban_ip(row.ip)
        else:
            _add_rule(row.ip)  # idempotent - re-applies if the rule is missing (e.g. after a reboot)


def _sweep_loop():
    try:
        _reconcile()
    except Exception as e:
        print(f"[ssh-ban] startup reconcile failed: {e}")
    while not _stop.wait(SWEEP_INTERVAL_SECONDS):
        try:
            _reconcile()
        except Exception as e:
            print(f"[ssh-ban] sweep failed: {e}")


def start():
    t = threading.Thread(target=_sweep_loop, daemon=True, name="ssh-ban-sweep")
    t.start()
    return t


def stop():
    _stop.set()
