<div align="center">
  <img src="app/static/sentrynet-icon.svg" width="112" height="112" alt="SentryNet shield logo">
  <h1>SentryNet</h1>
  <p><strong>Self-hosted security operations and observability for Linux web servers.</strong></p>
  <p>
    Monitor traffic, investigate threats, protect services, and understand your
    infrastructure from one focused dashboard.
  </p>

  <p>
    <img alt="Community Edition" src="https://img.shields.io/badge/edition-Community-3478F6?style=for-the-badge">
    <img alt="MIT License" src="https://img.shields.io/badge/license-MIT-16A66A?style=for-the-badge">
    <img alt="Python 3.10 or newer" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&amp;logo=python&amp;logoColor=white">
    <img alt="Debian and Ubuntu" src="https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-A81D33?style=for-the-badge&amp;logo=linux&amp;logoColor=white">
  </p>
  <p>
    <img alt="Self-hosted" src="https://img.shields.io/badge/deployment-self--hosted-6E56CF?style=flat-square">
    <img alt="nginx and Apache" src="https://img.shields.io/badge/web-nginx%20%7C%20Apache-009639?style=flat-square">
    <img alt="PostgreSQL" src="https://img.shields.io/badge/database-PostgreSQL-4169E1?style=flat-square&amp;logo=postgresql&amp;logoColor=white">
    <img alt="GitHub Actions" src="https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&amp;logo=githubactions&amp;logoColor=white">
  </p>
  <p>
    <a href="SUPPORT.md"><img alt="Support SentryNet" src="https://img.shields.io/badge/Buy%20me%20a%20coffee-Support%20SentryNet-F5A623?style=for-the-badge&amp;logo=buymeacoffee&amp;logoColor=white"></a>
  </p>

  <p>
    <a href="#capabilities">Capabilities</a> &bull;
    <a href="#quick-start">Quick start</a> &bull;
    <a href="#configuration">Configuration</a> &bull;
    <a href="#terminal-console">Terminal</a> &bull;
    <a href="docs/ARCHITECTURE.md">Architecture</a> &bull;
    <a href="SECURITY.md">Security</a> &bull;
    <a href="SUPPORT.md">Support</a>
  </p>
</div>

---

> [!NOTE]
> **SentryNet Community Edition is fully unlocked.** It requires no activation
> key, has no expiry or remote entitlement check, and has no license-server
> dependency.

SentryNet watches the traffic, authentication activity, services, certificates,
files, and outbound connections that make up a production server. It brings
those signals into a browser dashboard and a keyboard-first terminal console,
with practical tools to investigate suspicious behavior and respond without
jumping between log files and one-off shell commands. Monitoring data stays on
your server unless you explicitly configure an outbound integration.

| Traffic intelligence | Active defense | Infrastructure health |
| --- | --- | --- |
| Live requests, site analytics, trends, geographic activity, and bandwidth reports | Threat scoring, incident triage, allowlists, policy blocks, and firewall-level SSH bans | Services, resources, restarts, error logs, TLS certificates, files, and outbound connections |
| **Secure access** | **Reporting & automation** | **Two operator interfaces** |
| Local accounts, roles, audit trails, TOTP MFA, passkeys, and optional OIDC SSO | Webhooks, Discord alerts, scheduled digests, frozen reports, and export tools | A full web dashboard plus the compact `sentrynet-terminal` console |

## Capabilities

SentryNet combines several jobs that are often handled by separate utilities:

- Ingests structured nginx or Apache access logs in real time.
- Scores suspicious requests using explainable security heuristics.
- Tracks active threats, incidents, allowlists, blocked addresses, and countries.
- Applies manual or policy-driven HTTP blocks and firewall-level SSH bans.
- Monitors SSH authentication attempts and repeated failures.
- Detects unexpected changes to selected configuration and application files.
- Watches web content for defacement and learns normal outbound network behavior.
- Tracks systemd service health, CPU, memory, restarts, and error logs.
- Warns before TLS certificates expire.
- Builds long-term traffic trends and frozen 06:00–06:00 UTC bandwidth reports.
- Sends optional Discord, generic webhook, and scheduled digest notifications.
- Exports operational reports and maintains an operator audit trail.

The web application includes global search, incident triage, response policies,
per-site analytics, live traffic, role-based access, TOTP MFA, passkeys, and
optional OpenID Connect SSO.

For SSH sessions and small screens, `sentrynet-terminal` provides a compact
terminal UI with the same local accounts and permissions. It covers overview,
threats, blocks, SSH activity, incidents, sites, trends, audit events, alerts,
users, service health, and edition status. A one-shot `--snapshot` mode is also
available for scripts and status checks.

## Who it is for

SentryNet is designed for:

- Self-hosters running several sites or APIs on one Debian or Ubuntu server.
- Small operations and platform teams that need useful visibility without a
  hosted SIEM or a large agent fleet.
- MSPs, homelab operators, and independent developers responsible for public
  nginx or Apache services.
- Security-conscious administrators who want their traffic and operational data
  to remain on infrastructure they control.

It is not a replacement for endpoint detection across employee devices, packet
capture across an enterprise network, or a staffed SOC. Its scope is the Linux
server on which it is installed and the web traffic and services visible there.

## Requirements

- Debian or Ubuntu with `systemd` and `apt`
- Root access during installation
- At least 512 MB RAM and 1 GB free disk space

nginx or Apache and PostgreSQL are detected automatically. The installer can
install missing components and creates a dedicated PostgreSQL role and database;
it does not reuse or alter another application's database.

## Quick start

Clone the repository somewhere other than the final installation directory. The
default runtime location is `/opt/sentrynet`.

```bash
git clone https://github.com/ickx591/sentrynet.git sentrynet-source
cd sentrynet-source
sudo ./install.sh --check
sudo ./install.sh
```

The installer:

1. Verifies the host, selected port, disk space, and configuration.
2. Installs required system and Python packages.
3. Creates an isolated virtual environment under the install directory.
4. Creates or reuses a dedicated PostgreSQL role and database.
5. Adds the structured access-log format for nginx or Apache.
6. Installs and starts a hardened `systemd` service.
7. Installs `sentrynet-terminal` and maintenance cron jobs.
8. Optionally creates a reverse-proxy virtual host and Let's Encrypt certificate.

On first start, SentryNet generates a random Owner username and password. They
are printed once in the installer output and stored root-only at
`/opt/sentrynet/.admin.json`.

The default dashboard binds only to `127.0.0.1:8103`. Without a public domain,
open an SSH tunnel:

```bash
ssh -L 8103:localhost:8103 user@your-server
```

Then visit `http://localhost:8103/`.

## Configuration

Interactive installation asks only for decisions it cannot safely infer. Every
setting can also be supplied through environment variables or a config file:

```bash
sudo ./install.sh --non-interactive --config ./sentrynet.conf
```

Start with [`sentrynet.conf.example`](sentrynet.conf.example):

| Setting | Default | Purpose |
| --- | --- | --- |
| `SENTRYNET_DIR` | `/opt/sentrynet` | Runtime installation directory |
| `SENTRYNET_PORT` | `8103` | Loopback dashboard port |
| `SENTRYNET_DB_NAME` | `sentrynet` | PostgreSQL database |
| `SENTRYNET_DB_USER` | `sentrynet_app` | PostgreSQL role |
| `SENTRYNET_SERVICE_NAME` | `sentrynet` | systemd unit name |
| `SENTRYNET_WEBSERVER` | auto-detected | `nginx` or `apache` |
| `SENTRYNET_DOMAIN` | empty | Optional public dashboard hostname |
| `SENTRYNET_CERTBOT_EMAIL` | empty | Optional Let's Encrypt email |
| `SENTRYNET_DISCORD_WEBHOOK` | empty | Optional Discord alert webhook |

Environment values take precedence over values in the config file.

### Feed web traffic to SentryNet

The installer defines a `sentrynet_json` log format but does not silently change
your existing site logs. Enable it on each site you want to monitor.

nginx:

```nginx
access_log /var/log/nginx/access.log sentrynet_json;
```

Then validate and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Apache, inside a `<VirtualHost>`:

```apache
CustomLog ${APACHE_LOG_DIR}/access.log sentrynet_json
```

Then validate and restart:

```bash
sudo apache2ctl configtest && sudo systemctl restart apache2
```

### Select services and files to monitor

Edit these runtime files after installation:

- `/opt/sentrynet/config/watched_units.txt` — systemd units for health,
  resource, and journal monitoring.
- `/opt/sentrynet/config/watched_files.txt` — file paths or globs for SHA-256
  integrity monitoring.
- `/opt/sentrynet/config/egress_allowlist.txt` — expected outbound destinations.
- `/opt/sentrynet/config/resource_maintenance_windows.txt` — recurring resource
  spike windows that should not trigger degradation alerts.

Restart after changing watched services or files:

```bash
sudo systemctl restart sentrynet
```

## Terminal console

```bash
sentrynet-terminal
sentrynet-terminal --snapshot
```

The terminal console connects to `http://127.0.0.1:8103` by default. Override it
for a different trusted endpoint:

```bash
sentrynet-terminal --server https://security.example.com
# or
export SENTRYNET_TERMINAL_URL=https://security.example.com
```

Passwords are prompted interactively and are never accepted as command-line
arguments.

## Operations

```bash
sudo systemctl status sentrynet
sudo journalctl -u sentrynet -f
sudo systemctl restart sentrynet
```

Daily jobs are installed under `/etc/cron.d/`:

- `sentrynet-rollup` preserves long-term trends.
- `sentrynet-bandwidth` freezes daily traffic and bandwidth reports.
- `sentrynet-cleanup` applies retention limits to high-volume tables.

Backfill retained history when needed:

```bash
cd /opt/sentrynet
sudo venv/bin/python3 rollup_daily.py --backfill 30
sudo venv/bin/python3 bandwidth_report.py --backfill 30
```

## Upgrades

From a fresh checkout of the new release:

```bash
sudo ./install.sh --upgrade
```

Upgrade mode requires an existing installation, creates a timestamped backup in
`/var/backups/sentrynet`, and restores the previous application if a later step
fails. Database credentials and runtime configuration are preserved.

## Uninstall

```bash
sudo ./uninstall.sh
```

The safe default removes the service, runtime application, SentryNet firewall
rules, cron jobs, and managed dashboard virtual host. It leaves PostgreSQL data,
TLS certificates, and the shared web-server log format in place. Remove those
explicitly only when desired:

```bash
sudo ./uninstall.sh --purge-db --purge-log-format --purge-cert
```

## Security and privacy

- The dashboard listens on loopback unless you explicitly configure a domain.
- Authentication uses random first-run credentials, role-based permissions,
  short-lived sessions, CSRF protection, and login throttling.
- TOTP, WebAuthn/passkeys, and OIDC SSO are optional.
- Integration URLs are validated to reduce server-side request forgery risk.
- Runtime secrets and generated state are excluded from version control.
- Community Edition performs no activation or license-server telemetry.

Please report security issues using the process in [`SECURITY.md`](SECURITY.md),
not a public issue.

## Development and tests

Create a virtual environment and run the unit tests:

```bash
python3 -m venv .venv
.venv/bin/pip install -r app/requirements.txt
cd app
../.venv/bin/python -m unittest discover -s tests -v
```

Installer validation that makes no system changes:

```bash
sudo SENTRYNET_DIR=/opt/sentrynet-test ./install.sh --check
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution guidance and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component model.

## License

SentryNet Community Edition is available under the [MIT License](LICENSE).
