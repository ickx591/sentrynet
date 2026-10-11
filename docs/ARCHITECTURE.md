# Architecture

SentryNet is a single-host security operations application built around a
FastAPI control plane, PostgreSQL persistence, and independent monitoring
workers supervised by an in-process watchdog.

## Data flow

```text
nginx / Apache JSON access log
            |
            v
      access-log tailer -----> request records -----> analytics / reports
            |                         |
            v                         v
      threat heuristics ------> flagged sources ----> incidents / policies
                                                        |
                                                        v
                                              web server / firewall blocks

systemd journal --+--> SSH monitor / bans
                  +--> application error aggregation
                  +--> service resource monitoring

filesystem -------> integrity and defacement monitors
network state -----> egress baseline monitor
TLS endpoints -----> certificate monitor
```

## Control plane

`app/main.py` exposes the browser UI and JSON API. Authentication and
authorization are local by default, with Owner, Administrator, Operator, and
Spectator roles. TOTP, passkeys, and OIDC can be enabled without replacing the
local account system.

Mutating browser requests use a double-submit CSRF token. Sessions have an
absolute lifetime, sensitive authentication changes require recent login, and
the generated reverse-proxy configuration normalizes trusted forwarding
headers.

## Monitoring workers

Workers are intentionally separated by concern:

- `ingest.py` — structured access-log ingestion and scoring
- `ssh_monitor.py` / `ssh_ban.py` — SSH activity and firewall bans
- `integrity_monitor.py` — configured file hash monitoring
- `defacement_monitor.py` — web-content baseline monitoring
- `egress_monitor.py` — outbound connection baselining
- `cert_monitor.py` — certificate expiry monitoring
- `log_aggregator.py` — selected systemd journal errors
- `resource_monitor.py` — systemd service health and resource trends
- `operations.py` — incident correlation and response policies
- `watchdog.py` — detects and restarts failed monitoring threads

The Community Edition license compatibility module never gates functionality or
makes a remote entitlement request. The fleet adapter reports only the local
node by default.

## Persistence

PostgreSQL stores requests, detections, blocks, audit events, incidents, users,
resource samples, daily rollups, and bandwidth reports. High-volume raw data is
retained for a bounded period while daily aggregate jobs preserve long-term
trends.

Small root-only JSON and environment files under the runtime directory hold
bootstrap credentials, sessions, baselines, and integration configuration.
They are excluded from version control.

## Installation layout

```text
/opt/sentrynet/                 application and root-only runtime state
/opt/sentrynet/venv/            isolated Python environment
/etc/systemd/system/sentrynet.service
/etc/cron.d/sentrynet-*         rollup, bandwidth, and cleanup jobs
/usr/local/bin/sentrynet-terminal
```

The service binds to loopback. Public access is optional and is provided by a
managed nginx or Apache reverse-proxy virtual host.
