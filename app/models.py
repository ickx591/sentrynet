"""Peewee models for SentryNet. db is a Proxy - db_backend.init_db() binds it."""

import uuid
from peewee import (
    Model, Proxy, CharField, IntegerField, BigIntegerField, FloatField, TextField,
    DateTimeField, UUIDField, BooleanField,
)

db = Proxy()


class BaseModel(Model):
    class Meta:
        database = db


class Request(BaseModel):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    ts = DateTimeField(index=True)
    ip = CharField(index=True)
    country = CharField(null=True, index=True)
    host = CharField(index=True)
    method = CharField()
    path = TextField()
    query = TextField(null=True)  # raw query string ($args) - path never includes it
    status = IntegerField(index=True)
    bytes = BigIntegerField(default=0)
    referer = TextField(null=True)
    user_agent = TextField(null=True)
    device = CharField(null=True)
    os = CharField(null=True)
    browser = CharField(null=True)
    is_bot = BooleanField(default=False)
    request_time = FloatField(null=True)
    ssl_protocol = CharField(null=True)

    class Meta:
        table_name = "requests"


class BlockedIp(BaseModel):
    ip = CharField(unique=True)  # bare IP or CIDR ("1.2.3.0/24") - nginx `deny` accepts both
    reason = TextField(null=True)
    blocked_at = DateTimeField()
    blocked_by = CharField(null=True)
    expires_at = DateTimeField(null=True, index=True)  # null = permanent

    class Meta:
        table_name = "blocked_ips"


class FlaggedIp(BaseModel):
    ip = CharField(unique=True, index=True)
    country = CharField(null=True)
    signals = TextField()  # JSON list of {"type": ..., "detail": ..., "severity": ...}
    score = IntegerField(default=0)  # sum of active signals' severities
    first_seen = DateTimeField()
    last_seen = DateTimeField(index=True)

    class Meta:
        table_name = "flagged_ips"


class AllowedIp(BaseModel):
    """Trusted IPs/CIDRs that are never scored, flagged, or auto-blocked -
    e.g. admin's own IP, monitoring services, known-good partners."""
    ip = CharField(unique=True)
    reason = TextField(null=True)
    added_at = DateTimeField()
    added_by = CharField(null=True)

    class Meta:
        table_name = "allowed_ips"


class BlockedCountry(BaseModel):
    country = CharField(unique=True)  # ISO 3166-1 alpha-2
    reason = TextField(null=True)
    blocked_at = DateTimeField()
    blocked_by = CharField(null=True)

    class Meta:
        table_name = "blocked_countries"


class BlockAudit(BaseModel):
    """Full history of every block/unblock/allow/country-block action, manual
    or automatic - the individual tables only hold *current* state, so this
    is the only place to see e.g. "why was this IP unblocked, and by whom" or
    a full list of everything auto-blocked overnight."""
    ts = DateTimeField(index=True)
    action = CharField()  # block | unblock | allow | unallow | block_country | unblock_country
    target = CharField()  # ip/cidr or country code
    reason = TextField(null=True)
    actor = CharField(null=True)  # username, or "auto"/"system"

    class Meta:
        table_name = "block_audit"


class SshAuthEvent(BaseModel):
    """Every SSH auth attempt against this box, parsed from journalctl -u ssh.
    Separate from FlaggedIp/BlockedIp - see ssh_monitor.py - since the SSH
    monitor deliberately never auto-blocks (a firewall-level mistake here
    could lock out legitimate admin access), it only alerts."""
    ts = DateTimeField(index=True)
    ip = CharField(index=True)
    country = CharField(null=True)
    username = CharField(null=True)
    result = CharField()  # accepted | failed | invalid_user

    class Meta:
        table_name = "ssh_auth_events"


class IntegrityEvent(BaseModel):
    """A watched config file's hash changed since the last check. Never
    stores file contents - only paths and hashes - so this is safe to keep
    even for files (.env*) that hold secrets."""
    ts = DateTimeField(index=True)
    path = CharField()
    change_type = CharField()  # created | modified | deleted
    old_hash = CharField(null=True)
    new_hash = CharField(null=True)

    class Meta:
        table_name = "integrity_events"


class DefacementEvent(BaseModel):
    """A top-level file in a discovered web root (nginx/Apache vhost
    root/DocumentRoot) changed since the last check. Same hash-only shape as
    IntegrityEvent, but kept as its own model/category since a defaced
    customer-facing page is a meaningfully different, more urgent event than
    a config file touch."""
    ts = DateTimeField(index=True)
    path = CharField()
    change_type = CharField()  # created | modified | deleted
    old_hash = CharField(null=True)
    new_hash = CharField(null=True)

    class Meta:
        table_name = "defacement_events"


class EgressEvent(BaseModel):
    """An outbound connection to a (process, remote_ip, remote_port) tuple
    not seen during egress_monitor.py's baseline learning window - alert-only,
    never auto-blocked (see egress_monitor.py's module docstring for why)."""
    ts = DateTimeField(index=True)
    process = CharField()
    remote_ip = CharField(index=True)
    remote_port = IntegerField()

    class Meta:
        table_name = "egress_events"


class AppLogEvent(BaseModel):
    """ERROR/CRITICAL/traceback-shaped lines tailed from journalctl across
    every service this box runs - see log_aggregator.py. A lightweight
    substitute for full log centralization: not every line, just the ones
    that look like something broke."""
    ts = DateTimeField(index=True)
    unit = CharField(index=True)
    level = CharField()  # error | critical
    message = TextField()

    class Meta:
        table_name = "app_log_events"


class ServiceResourceSample(BaseModel):
    """Periodic per-systemd-unit resource snapshot - see resource_monitor.py.
    Powers both the resource-trend charts and leak-detection alerting
    (current usage vs. that same service's own recent median)."""
    ts = DateTimeField(index=True)
    unit = CharField(index=True)
    memory_bytes = BigIntegerField(null=True)
    cpu_percent = FloatField(null=True)  # cpu-seconds consumed / wall-seconds since last sample

    class Meta:
        table_name = "service_resource_samples"


class AlertSetting(BaseModel):
    """Per-category on/off toggle for Discord alerts - see alert_settings.py
    for the fixed set of known keys, their defaults, and human labels. Rows
    are seeded on startup; the dashboard's Alerts tab reads/writes these."""
    key = CharField(unique=True)
    enabled = BooleanField()

    class Meta:
        table_name = "alert_settings"


class SshBannedIp(BaseModel):
    """A firewall-level (iptables, port 22 only) SSH ban - see ssh_ban.py.
    Separate from BlockedIp (the nginx-based HTTP block list): nginx never
    sees SSH traffic, so stopping SSH brute-force needs an actual OS
    firewall rule, not a deny rule. Bans are temporary; expires_at is swept
    periodically."""
    ip = CharField(unique=True, index=True)
    banned_at = DateTimeField()
    expires_at = DateTimeField(index=True)
    reason = TextField(null=True)

    class Meta:
        table_name = "ssh_banned_ips"


class User(BaseModel):
    """A dashboard login - see users.py for roles, hashing, and the one-time
    migration from the old single-admin .admin.json file. Exactly one row
    ever has role="owner" (the account created at install time); it can't
    be created, demoted, or deleted through the API."""
    username = CharField(unique=True, index=True)
    password_hash = CharField()
    role = CharField()  # owner | administrator | operator | spectator
    created_at = DateTimeField()
    created_by = CharField(null=True)  # None for the bootstrap Owner row

    class Meta:
        table_name = "users"


class DailyStatRollup(BaseModel):
    """One row per (date, host) - plus one extra row per date with host=NULL
    for the all-hosts-combined total - produced by rollup_daily.py, a nightly
    cron job (not an in-process thread - see that file's docstring for why).
    Exists because requests rows are hard-deleted after 30 days
    (cleanup_old_requests.py), so this is the only way to see traffic trends
    beyond that window; every analytics endpoint that reads `requests`
    directly is capped at hours<=720 (30 days) to match."""
    date = DateTimeField(index=True)
    host = CharField(null=True, index=True)  # NULL = combined/all-hosts row
    total_requests = IntegerField(default=0)
    unique_ips = IntegerField(default=0)
    bot_requests = IntegerField(default=0)
    avg_response_time = FloatField(null=True)
    p95_response_time = FloatField(null=True)
    status_5xx_count = IntegerField(default=0)
    top_country = CharField(null=True)

    class Meta:
        table_name = "daily_stat_rollups"
        # Not a true uniqueness guarantee for host=NULL rows (Postgres never
        # treats two NULLs as equal, so this index can't prevent duplicate
        # combined-total rows) - rollup_daily.py enforces that itself by
        # deleting a day's rows before re-inserting, not by relying on this.
        indexes = ((("date", "host"), True),)


class BandwidthReport(BaseModel):
    """One row per monitoring window - a self-contained traffic/bandwidth
    report produced by bandwidth_report.py, a nightly cron job. The window
    is offset from a calendar day: it runs from 06:00 UTC until 06:00 UTC
    the next day (a complete 24-hour window), and `date` is that window's
    *start* timestamp (06:00 UTC) as the unique key.

    Unlike DailyStatRollup, the full breakdown (top sites, paths, countries,
    IPs, per-hour bytes) is frozen into the `details` JSON at rollup time -
    a report is meant to stay a complete, viewable document even after
    cleanup_old_requests.py has hard-deleted the raw requests rows it was
    built from (30 days). The scalar columns duplicate the headline numbers
    so list/trend endpoints never have to parse the JSON."""
    date = DateTimeField(unique=True, index=True)  # window start (06:00 UTC)
    window_start = DateTimeField()
    window_end = DateTimeField()             # 06:00 UTC the next day
    total_bytes = BigIntegerField(default=0)
    total_requests = IntegerField(default=0)
    unique_ips = IntegerField(default=0)
    bot_requests = IntegerField(default=0)
    human_requests = IntegerField(default=0)
    status_2xx = IntegerField(default=0)
    status_3xx = IntegerField(default=0)
    status_4xx = IntegerField(default=0)
    status_5xx = IntegerField(default=0)
    avg_response_time = FloatField(null=True)
    top_host = TextField(null=True)           # busiest site by request count
    top_host_bytes = BigIntegerField(default=0)  # busiest site by bytes sent
    top_country = CharField(null=True)
    top_path = TextField(null=True)
    details = TextField(default="{}")         # JSON snapshot - see docstring
    created_at = DateTimeField()

    class Meta:
        table_name = "bandwidth_reports"


class Incident(BaseModel):
    """Persistent case created from a security or infrastructure signal."""
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    source_ref = CharField(unique=True, index=True)
    category = CharField(index=True)
    severity = CharField(index=True)  # low | medium | high | critical
    title = CharField()
    summary = TextField(null=True)
    status = CharField(default="open", index=True)  # open | investigating | resolved
    assignee = CharField(null=True, index=True)
    notes = TextField(null=True)
    created_at = DateTimeField(index=True)
    updated_at = DateTimeField(index=True)
    resolved_at = DateTimeField(null=True)

    class Meta:
        table_name = "incidents"


class SavedView(BaseModel):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    owner = CharField(index=True)
    name = CharField()
    query = TextField()  # JSON-encoded search/filter state
    created_at = DateTimeField()

    class Meta:
        table_name = "saved_views"
        indexes = ((("owner", "name"), True),)


class ResponsePolicy(BaseModel):
    id = UUIDField(primary_key=True, default=uuid.uuid4)
    name = CharField()
    enabled = BooleanField(default=False)
    dry_run = BooleanField(default=True)
    min_score = IntegerField(default=8)
    countries = TextField(default="[]")  # JSON list of ISO country codes
    duration_hours = IntegerField(null=True)
    created_by = CharField(null=True)
    managed_by_fleet = BooleanField(default=False)
    fleet_policy_id = CharField(null=True, unique=True)
    last_run_at = DateTimeField(null=True)
    last_match_count = IntegerField(default=0)

    class Meta:
        table_name = "response_policies"


class IntegrationConfig(BaseModel):
    """Optional outbound notification destination; config is JSON."""
    key = CharField(unique=True)
    kind = CharField()  # slack | teams | pagerduty | webhook | siem
    name = CharField()
    enabled = BooleanField(default=False)
    config = TextField(default="{}")
    created_at = DateTimeField()
    updated_at = DateTimeField()

    class Meta:
        table_name = "integration_configs"


class MfaCredential(BaseModel):
    username = CharField(unique=True, index=True)
    secret = CharField()
    enabled = BooleanField(default=False)
    created_at = DateTimeField()
    confirmed_at = DateTimeField(null=True)

    class Meta:
        table_name = "mfa_credentials"


class OidcSettings(BaseModel):
    """Singleton OIDC configuration (row key is always 'primary')."""
    key = CharField(primary_key=True, default="primary")
    issuer = CharField()
    client_id = CharField()
    client_secret = TextField()
    default_role = CharField(default="spectator")
    enabled = BooleanField(default=False)
    updated_at = DateTimeField()

    class Meta:
        table_name = "oidc_settings"


class OidcIdentity(BaseModel):
    subject = CharField(unique=True, index=True)
    issuer = CharField()
    username = CharField(index=True)
    email = CharField(null=True)
    created_at = DateTimeField()

    class Meta:
        table_name = "oidc_identities"


class PasskeyCredential(BaseModel):
    username = CharField(index=True)
    credential_id = TextField(unique=True)
    public_key_pem = TextField()
    sign_count = IntegerField(default=0)
    label = CharField(default="Passkey")
    created_at = DateTimeField()
    last_used_at = DateTimeField(null=True)

    class Meta:
        table_name = "passkey_credentials"


ALL_MODELS = [Request, BlockedIp, FlaggedIp, AllowedIp, BlockedCountry, BlockAudit,
              SshAuthEvent, IntegrityEvent, DefacementEvent, EgressEvent, AppLogEvent,
              ServiceResourceSample, AlertSetting, SshBannedIp, User, DailyStatRollup,
              BandwidthReport, Incident, SavedView, ResponsePolicy, IntegrationConfig, MfaCredential,
              OidcSettings, OidcIdentity, PasskeyCredential]
