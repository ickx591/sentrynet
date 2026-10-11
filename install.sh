#!/usr/bin/env bash
# SentryNet installer - self-hosted network security & monitoring dashboard.
#
# Usage:
#   sudo ./install.sh [--check] [--upgrade] [--non-interactive] [--config FILE]
#
# Environment overrides (all optional):
#   SENTRYNET_DIR              Install directory        (default: /opt/sentrynet)
#   SENTRYNET_PORT             Dashboard port            (default: 8103)
#   SENTRYNET_DB_NAME          Postgres database name    (default: sentrynet)
#   SENTRYNET_DB_USER          Postgres role name        (default: sentrynet_app)
#   SENTRYNET_DISCORD_WEBHOOK  Discord webhook URL       (default: none - alerts disabled)
#   SENTRYNET_SERVICE_NAME     systemd unit name         (default: sentrynet)
#   SENTRYNET_DOMAIN           Domain/subdomain for the dashboard (default: none - localhost only)
#   SENTRYNET_CERTBOT_EMAIL    Email for Let's Encrypt renewal notices (default: none)
#   SENTRYNET_WEBSERVER        "nginx" or "apache" (default: auto-detect; prompts if neither is found)
#
# Requires: Debian/Ubuntu (apt). nginx/Apache and Postgres are installed and
# configured automatically if not already present - see the "Checking
# dependencies" step for exactly what that means for each.

set -euo pipefail

# ── Output helpers ───────────────────────────────────────────────────────
BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
BLUE=$'\033[34m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
step() { echo "${BOLD}${BLUE}==>${RESET} ${BOLD}$1${RESET}"; }
info() { echo "    $1"; }
warn() { echo "${YELLOW}    warning: $1${RESET}"; }
die()  { echo "${RED}error: $1${RESET}" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="$SCRIPT_DIR/app"

CHECK_ONLY=0
UPGRADE_ONLY=0
NON_INTERACTIVE=0
CONFIG_FILE=""
usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [options]

  --check               Run preflight checks without changing the system
  --upgrade             Require an existing installation and create a rollback backup
  --non-interactive     Never prompt; all required values must be configured
  --config FILE         Read SENTRYNET_* values from a key=value file
  -h, --help            Show this help

Environment variables still override values loaded from --config.
EOF
}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --upgrade) UPGRADE_ONLY=1 ;;
        --non-interactive) NON_INTERACTIVE=1 ;;
        --config) shift; [ "$#" -gt 0 ] || die "--config requires a file"; CONFIG_FILE="$1" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (use --help)" ;;
    esac
    shift
done

if [ -n "$CONFIG_FILE" ]; then
    [ -f "$CONFIG_FILE" ] || die "config file not found: $CONFIG_FILE"
    while IFS= read -r config_line || [ -n "$config_line" ]; do
        config_line="${config_line%$'\r'}"
        [ -z "$config_line" ] && continue
        case "$config_line" in \#*) continue ;; esac
        config_name="${config_line%%=*}"
        config_value="${config_line#*=}"
        case "$config_name" in
            SENTRYNET_DIR|SENTRYNET_PORT|SENTRYNET_DB_NAME|SENTRYNET_DB_USER|SENTRYNET_DISCORD_WEBHOOK|SENTRYNET_SERVICE_NAME|SENTRYNET_DOMAIN|SENTRYNET_CERTBOT_EMAIL|SENTRYNET_WEBSERVER)
                if [ -z "${!config_name+x}" ]; then printf -v "$config_name" '%s' "$config_value"; fi ;;
            *) die "unsupported setting '$config_name' in $CONFIG_FILE" ;;
        esac
    done < "$CONFIG_FILE"
fi

# ── Config (overridable via env) ────────────────────────────────────────
INSTALL_DIR="${SENTRYNET_DIR:-/opt/sentrynet}"
PORT="${SENTRYNET_PORT:-8103}"
DB_NAME="${SENTRYNET_DB_NAME:-sentrynet}"
DB_USER="${SENTRYNET_DB_USER:-sentrynet_app}"
DISCORD_WEBHOOK="${SENTRYNET_DISCORD_WEBHOOK:-}"
SERVICE_NAME="${SENTRYNET_SERVICE_NAME:-sentrynet}"
DOMAIN="${SENTRYNET_DOMAIN:-}"
CERTBOT_EMAIL="${SENTRYNET_CERTBOT_EMAIL:-}"
WEBSERVER="${SENTRYNET_WEBSERVER:-}"
LOG_FORMAT_NAME="sentrynet_json"
NGINX_BLOCKLIST_CONF="/etc/nginx/conf.d/sentrynet-blocklist.conf"
TERMINAL_COMMAND="/usr/local/bin/sentrynet-terminal"

# These values are later embedded in SQL, systemd/cron files, and webserver
# configuration while this script is running as root. Validate them before
# any package installation or filesystem mutation.
[[ "$INSTALL_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    && [ "$INSTALL_DIR" != "/" ] \
    && [[ "$INSTALL_DIR" =~ ^/[^/]+/[^/]+ ]] \
    && [[ "/$INSTALL_DIR/" != *"/../"* ]] \
    || die "SENTRYNET_DIR must be a safe absolute path without spaces or '..'"
[ ! -L "$INSTALL_DIR" ] || die "SENTRYNET_DIR must not be a symbolic link"
CANONICAL_INSTALL_DIR="$(realpath -m -- "$INSTALL_DIR")"
[ "$CANONICAL_INSTALL_DIR" = "$INSTALL_DIR" ] \
    || die "SENTRYNET_DIR must already be in canonical form ($CANONICAL_INSTALL_DIR)"
[ "$SCRIPT_DIR" != "$INSTALL_DIR" ] \
    || die "the Git checkout and install directory must differ; clone elsewhere or set SENTRYNET_DIR (for example /opt/sentrynet-app)"
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
    || die "SENTRYNET_PORT must be an integer from 1 to 65535"
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
    || die "SENTRYNET_DB_NAME must be a PostgreSQL identifier (letters, numbers, underscore; max 63)"
[[ "$DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
    || die "SENTRYNET_DB_USER must be a PostgreSQL identifier (letters, numbers, underscore; max 63)"
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] \
    || die "SENTRYNET_SERVICE_NAME contains unsafe characters"
if [ -n "$DISCORD_WEBHOOK" ]; then
    [[ "$DISCORD_WEBHOOK" =~ ^https://(discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9._-]+$ ]] \
        || die "SENTRYNET_DISCORD_WEBHOOK must be an official Discord HTTPS webhook URL"
fi
if [ -n "$CERTBOT_EMAIL" ]; then
    [[ "$CERTBOT_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] \
        || die "SENTRYNET_CERTBOT_EMAIL is not a valid email address"
fi

validate_domain() {
    local candidate="$1" label
    [ -z "$candidate" ] && return 0
    [ "${#candidate}" -le 253 ] || return 1
    [[ "$candidate" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ "$candidate" == *.* ]] || return 1
    IFS='.' read -r -a domain_labels <<< "$candidate"
    for label in "${domain_labels[@]}"; do
        [ "${#label}" -ge 1 ] && [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}
validate_domain "$DOMAIN" || die "SENTRYNET_DOMAIN must be a valid hostname"

EXISTING_INSTALL=0
[ -f "$INSTALL_DIR/VERSION" ] && EXISTING_INSTALL=1
[ "$UPGRADE_ONLY" = "0" ] || [ "$EXISTING_INSTALL" = "1" ] || die "--upgrade requires an existing installation at $INSTALL_DIR"

PKG_VERSION="$(cat "$APP_SRC/VERSION" 2>/dev/null || echo "unknown")"

echo ""
echo "${BOLD}SentryNet installer${RESET} ${DIM}v${PKG_VERSION}${RESET}"
echo "${DIM}Self-hosted network security & monitoring${RESET}"
echo ""

# ── System requirements check ────────────────────────────────────────────
# Every check runs up front and reports together, rather than dying on the
# first failure - so a customer sees everything wrong with their box in one
# pass instead of fixing issues one at a time across repeated re-runs.
step "Checking system requirements"

REQ_FAIL=0
ok()   { echo "    ${GREEN}✓${RESET} $1"; }
bad()  { echo "    ${RED}✗ $1${RESET}"; REQ_FAIL=1; }

if [ "$(id -u)" -eq 0 ]; then ok "running as root"; else bad "must run as root (sudo ./install.sh)"; fi

if command -v apt-get >/dev/null 2>&1; then
    OS_PRETTY="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" )"
    ok "apt-based system (${OS_PRETTY:-unknown})"
else
    bad "this installer supports Debian/Ubuntu (apt) only"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    ok "systemd present"
else
    bad "systemd is required (no /run/systemd/system found) - unsupported init system"
fi

if [ -d "$APP_SRC" ]; then
    ok "application source found ($APP_SRC)"
else
    bad "application source not found at $APP_SRC - run this script from the extracted SentryNet package"
fi

if [ ! -e "$TERMINAL_COMMAND" ] || grep -qF "Managed by SentryNet" "$TERMINAL_COMMAND" 2>/dev/null; then
    ok "terminal command path available ($TERMINAL_COMMAND)"
else
    bad "$TERMINAL_COMMAND already exists and is not managed by SentryNet"
fi

DISK_CHECK_PATH="$(dirname "$INSTALL_DIR")"
[ -d "$DISK_CHECK_PATH" ] || DISK_CHECK_PATH="/"
AVAIL_MB="$(df -Pm "$DISK_CHECK_PATH" 2>/dev/null | awk 'NR==2{print $4}')"
if [ -n "$AVAIL_MB" ] && [ "$AVAIL_MB" -ge 1024 ]; then
    ok "disk space: ${AVAIL_MB}MB free in $DISK_CHECK_PATH"
else
    bad "at least 1GB free disk space required in $DISK_CHECK_PATH (found ${AVAIL_MB:-unknown}MB)"
fi

TOTAL_MEM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
if [ "$TOTAL_MEM_MB" -ge 512 ]; then
    ok "memory: ${TOTAL_MEM_MB}MB total"
else
    echo "    ${YELLOW}warning: only ${TOTAL_MEM_MB}MB RAM detected - SentryNet + Postgres may struggle below 512MB${RESET}"
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORT\$"; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        ok "port $PORT in use by the existing '$SERVICE_NAME' service (re-run detected)"
    else
        bad "port $PORT is already in use by another process - set SENTRYNET_PORT to a free port (check: ss -ltnp | grep :$PORT)"
    fi
else
    ok "port $PORT is free"
fi

if [ "$REQ_FAIL" = "1" ]; then
    echo ""
    die "one or more requirements not met - fix the ✗ items above and re-run"
fi
if [ "$CHECK_ONLY" = "1" ]; then
    echo ""
    echo "${BOLD}${GREEN}Preflight passed.${RESET} No changes were made."
    exit 0
fi

# ── Edition ──────────────────────────────────────────────────────────────
step "Community Edition"
info "free to install and use; no activation key or license server required"

# ── Which web server? ─────────────────────────────────────────────────────
# SENTRYNET_WEBSERVER wins if set; otherwise whichever is already running;
# otherwise (neither present) ask - defaulting to nginx for non-interactive
# installs (e.g. curl ... | bash, which has no terminal to prompt on).
if [ -z "$WEBSERVER" ]; then
    if systemctl is-active --quiet nginx 2>/dev/null; then
        WEBSERVER=nginx
    elif systemctl is-active --quiet apache2 2>/dev/null; then
        WEBSERVER=apache
    fi
fi
if [ -z "$WEBSERVER" ] && [ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ]; then
    step "Web server"
    info "No nginx or Apache found running on this box - which should SentryNet set up?"
    read -r -p "    (1) nginx  (2) apache  [1]: " WS_CHOICE || true
    case "${WS_CHOICE:-}" in
        2) WEBSERVER=apache ;;
        *) WEBSERVER=nginx ;;
    esac
fi
WEBSERVER="${WEBSERVER:-nginx}"
case "$WEBSERVER" in
    nginx|apache) ;;
    *) die "SENTRYNET_WEBSERVER must be 'nginx' or 'apache' (got: $WEBSERVER)" ;;
esac

# ── Checking dependencies ────────────────────────────────────────────────
# Unlike the hard requirements above, these are things this installer can
# fix itself - report what's already there vs. what's about to be installed
# and configured, before actually touching anything.
step "Checking dependencies"
note() { echo "    ${BLUE}→${RESET} $1"; }

WEBSERVER_UNIT="nginx"; [ "$WEBSERVER" = "apache" ] && WEBSERVER_UNIT="apache2"
if command -v "$WEBSERVER_UNIT" >/dev/null 2>&1 && systemctl is-active --quiet "$WEBSERVER_UNIT" 2>/dev/null; then
    ok "$WEBSERVER: installed and running"
    WEBSERVER_PRESENT=1
else
    note "$WEBSERVER: not found - will install, start, and enable it"
    WEBSERVER_PRESENT=0
fi

if systemctl is-active --quiet postgresql 2>/dev/null || systemctl list-units --type=service 2>/dev/null | grep -q "postgresql@.*main"; then
    ok "postgresql: installed and running"
    POSTGRES_PRESENT=1
else
    note "postgresql: not found - will install, start, and create a dedicated random-password role/database for SentryNet"
    POSTGRES_PRESENT=0
fi

ok "python3/build tools/GeoIP data: will be ensured via apt (already-installed packages are skipped automatically)"

# ── System packages ──────────────────────────────────────────────────────
step "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

PKGS="python3 python3-venv python3-pip python3-dev build-essential libssl-dev libgeoip-dev geoip-database curl"
if [ "$WEBSERVER_PRESENT" = "0" ]; then
    if [ "$WEBSERVER" = "apache" ]; then
        PKGS="$PKGS apache2"
    else
        PKGS="$PKGS nginx"
    fi
fi
apt-get install -y -qq $PKGS >/dev/null
info "python3, venv, build tools, GeoIP data: installed"

if [ "$WEBSERVER_PRESENT" = "0" ]; then
    systemctl enable --quiet --now "$WEBSERVER_UNIT"
    info "$WEBSERVER: installed, started, and enabled"
fi

if [ "$POSTGRES_PRESENT" = "0" ]; then
    apt-get install -y -qq postgresql postgresql-contrib >/dev/null
    sleep 2
    info "postgresql: installed and started"
fi

# ── Application files ─────────────────────────────────────────────────────
step "Installing application to $INSTALL_DIR"
BACKUP_DIR=""
OLD_VERSION=""
rollback_install() {
    failure_status="${1:-1}"
    trap - ERR
    set +e
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR/app" ]; then
        warn "installation failed; restoring the previous application from $BACKUP_DIR"
        cp -a "$BACKUP_DIR/app/." "$INSTALL_DIR/"
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    exit "$failure_status"
}
if [ "$EXISTING_INSTALL" = "1" ]; then
    OLD_VERSION="$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo unknown)"
    [[ "$OLD_VERSION" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || OLD_VERSION="unknown"
    BACKUP_DIR="/var/backups/sentrynet/$(date -u +%Y%m%dT%H%M%SZ)-v${OLD_VERSION}"
    mkdir -p "$BACKUP_DIR"
    cp -a --reflink=auto "$INSTALL_DIR" "$BACKUP_DIR/app"
    info "rollback backup created: $BACKUP_DIR"
    trap 'rollback_install $?' ERR
fi
mkdir -p "$INSTALL_DIR"
cp -r "$APP_SRC"/. "$INSTALL_DIR"/
info "copied application source${OLD_VERSION:+ over v$OLD_VERSION}"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
info "created venv and installed Python dependencies"

# ── Postgres: role + database ─────────────────────────────────────────────
# Whether Postgres was just installed above or was already present, the
# same thing happens here: a fresh, dedicated, random-password role/database
# just for SentryNet - never touching whatever else that Postgres instance
# might already be running. This is the one genuinely re-run-safe path: if
# .env.postgres already exists, its credentials are the actual source of
# truth (they're what the role's password really is) and get reused as-is,
# rather than generating a new password that wouldn't match the real role.
step "Setting up the database"
ENV_FILE="$INSTALL_DIR/.env.postgres"
DB_FRESHLY_CREATED=0

if [ "$WEBSERVER" = "apache" ]; then
    ACCESS_LOG_PATH="/var/log/apache2/access.log"
else
    ACCESS_LOG_PATH="/var/log/nginx/access.log"
fi

if [ -f "$ENV_FILE" ]; then
    info "existing $ENV_FILE found - reusing its database credentials as-is (this looks like a re-run)"
    DB_PASSWORD="$(grep '^DATABASE_URL=' "$ENV_FILE" | sed -E 's#.*://[^:]+:([^@]+)@.*#\1#')"
else
    DB_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"

    ROLE_EXISTS="$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null || true)"
    if [ "$ROLE_EXISTS" = "1" ]; then
        die "Postgres role '$DB_USER' already exists, but no $ENV_FILE was found to recover its real password from - I won't guess and write a wrong one. Either drop it first (sudo -u postgres psql -c \"DROP ROLE $DB_USER;\") or set SENTRYNET_DB_USER to a different name and re-run."
    fi
    sudo -u postgres psql -q -c "CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';" >/dev/null
    info "created Postgres role: $DB_USER"

    DB_EXISTS="$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || true)"
    if [ "$DB_EXISTS" = "1" ]; then
        die "Database '$DB_NAME' already exists (owned by something else, since role '$DB_USER' didn't) - set SENTRYNET_DB_NAME to a different name and re-run."
    fi
    sudo -u postgres psql -q -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >/dev/null
    info "created database: $DB_NAME"

    cat > "$ENV_FILE" <<EOF
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME
DISCORD_WEBHOOK_URL=$DISCORD_WEBHOOK
WEBSERVER=$WEBSERVER
ACCESS_LOG_PATH=$ACCESS_LOG_PATH
EOF
    chmod 600 "$ENV_FILE"
    info "wrote $ENV_FILE"
    DB_FRESHLY_CREATED=1
fi

# ── Discord webhook (prompt only if not already provided and a TTY exists) ─
if [ -z "$DISCORD_WEBHOOK" ] && [ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ]; then
    step "Discord alerts (optional)"
    info "SentryNet can post real-time alerts to a Discord channel via webhook."
    read -r -p "    Discord webhook URL (leave blank to skip): " DISCORD_WEBHOOK_INPUT || true
    if [ -n "${DISCORD_WEBHOOK_INPUT:-}" ]; then
        [[ "$DISCORD_WEBHOOK_INPUT" =~ ^https://(discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9._-]+$ ]] \
            || die "Discord webhook must be an official Discord HTTPS webhook URL"
        sed -i "s#^DISCORD_WEBHOOK_URL=.*#DISCORD_WEBHOOK_URL=$DISCORD_WEBHOOK_INPUT#" "$INSTALL_DIR/.env.postgres"
        info "saved"
    else
        info "skipped - you can add one later, see the summary at the end"
    fi
fi

# ── Domain (prompt only if not already provided and a TTY exists) ────────
if [ -z "$DOMAIN" ] && [ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ]; then
    step "Public access (optional)"
    info "If you already have a domain/subdomain pointed at this server, SentryNet"
    info "can set up a vhost and a real Let's Encrypt certificate for it."
    read -r -p "    Domain for the dashboard (leave blank for localhost-only): " DOMAIN_INPUT || true
    DOMAIN="${DOMAIN_INPUT:-}"
fi
validate_domain "$DOMAIN" || die "SENTRYNET_DOMAIN must be a valid hostname"

# ── Web server: log format + blocklist ───────────────────────────────────
if [ "$WEBSERVER" = "apache" ]; then
    step "Configuring Apache"
    LOGFORMAT_CONF="/etc/apache2/conf-available/sentrynet-logformat.conf"

    if [ -f "$LOGFORMAT_CONF" ]; then
        info "LogFormat '$LOG_FORMAT_NAME' already present - leaving it as-is"
    else
        cat > "$LOGFORMAT_CONF" <<EOF
# Managed by SentryNet - do not edit by hand.
LogFormat "{\\"ts\\":\\"%{%Y-%m-%dT%H:%M:%S%z}t\\",\\"ip\\":\\"%a\\",\\"host\\":\\"%{Host}i\\",\\"method\\":\\"%m\\",\\"path\\":\\"%U\\",\\"query\\":\\"%q\\",\\"status\\":%>s,\\"bytes\\":%B,\\"referer\\":\\"%{Referer}i\\",\\"ua\\":\\"%{User-Agent}i\\",\\"request_time\\":%D,\\"ssl\\":\\"%{SSL_PROTOCOL}x\\"}" $LOG_FORMAT_NAME
EOF
        a2enmod ssl >/dev/null 2>&1   # needed for %{SSL_PROTOCOL}x to even be recognized, regardless of whether TLS is actually used anywhere yet
        a2enconf sentrynet-logformat >/dev/null 2>&1
        info "added LogFormat '$LOG_FORMAT_NAME' (conf-available/sentrynet-logformat.conf)"
    fi
    info "blocklist is enforced at the firewall (iptables) for Apache - nothing to configure in Apache itself"

    if apache2ctl configtest >/dev/null 2>&1; then
        # A full restart, not reload - reload does not reliably pick up a
        # brand-new LogFormat/log file path (confirmed during development).
        systemctl restart apache2
        info "Apache config valid, restarted"
    else
        warn "apache2ctl configtest failed after our changes - check its output"
        apache2ctl configtest
    fi
else
    step "Configuring nginx"
    NGINX_CONF="/etc/nginx/nginx.conf"

    if grep -q "log_format $LOG_FORMAT_NAME" "$NGINX_CONF" 2>/dev/null; then
        info "log_format '$LOG_FORMAT_NAME' already present in nginx.conf - leaving it as-is"
    else
        cp "$NGINX_CONF" "$NGINX_CONF.sentrynet-bak-$(date +%Y%m%d%H%M%S)"
        LOG_FORMAT_BLOCK="\\tlog_format $LOG_FORMAT_NAME escape=json '{\"ts\":\"\$time_iso8601\",\"ip\":\"\$remote_addr\",'\\n\\t\\t'\"host\":\"\$host\",\"method\":\"\$request_method\",\"path\":\"\$uri\",\"query\":\"\$args\",\"status\":\$status,'\\n\\t\\t'\"bytes\":\$body_bytes_sent,\"referer\":\"\$http_referer\",\"ua\":\"\$http_user_agent\",'\\n\\t\\t'\"request_time\":\$request_time,\"ssl\":\"\$ssl_protocol\"}';\\n"
        awk -v block="$LOG_FORMAT_BLOCK" '
            /^http[[:space:]]*\{/ { print; printf "%s", block; next }
            { print }
        ' "$NGINX_CONF" > "$NGINX_CONF.sentrynet-tmp"
        mv "$NGINX_CONF.sentrynet-tmp" "$NGINX_CONF"
        info "added log_format '$LOG_FORMAT_NAME' to nginx.conf (backup saved alongside it)"
    fi

    if ! grep -q "zone=sentrynet_login:" "$NGINX_CONF" 2>/dev/null; then
        RATE_LIMIT_BLOCK="\\tlimit_req_zone \$binary_remote_addr zone=sentrynet_login:10m rate=5r/s;\\n\\tlimit_conn_zone \$binary_remote_addr zone=sentrynet_addr:10m;\\n"
        awk -v block="$RATE_LIMIT_BLOCK" '
            /^http[[:space:]]*\{/ { print; printf "%s", block; next }
            { print }
        ' "$NGINX_CONF" > "$NGINX_CONF.sentrynet-tmp"
        mv "$NGINX_CONF.sentrynet-tmp" "$NGINX_CONF"
        info "added SentryNet authentication rate-limit zones to nginx.conf"
    fi

    touch "$NGINX_BLOCKLIST_CONF"
    if ! grep -q "Managed by SentryNet" "$NGINX_BLOCKLIST_CONF" 2>/dev/null; then
        echo "# Managed by SentryNet - do not edit by hand." > "$NGINX_BLOCKLIST_CONF"
    fi
    info "blocklist file ready: $NGINX_BLOCKLIST_CONF (auto-included via nginx's conf.d/*.conf glob)"

    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx
        info "nginx config valid, reloaded"
    else
        warn "nginx -t failed after our changes - reverted is NOT automatic, check nginx -t output and your backup at $NGINX_CONF.sentrynet-bak-*"
        nginx -t
    fi
fi

echo ""
echo "    ${YELLOW}IMPORTANT:${RESET} the log format now exists, but no site is using it yet."
echo "    See the 'Next steps' section at the end of this output."

# ── Dashboard vhost + TLS (only if a domain was given) ───────────────────
CERT_OK=0
VHOST_CREATED=0
if [ -n "$DOMAIN" ]; then
    step "Setting up $DOMAIN"

    if [ "$WEBSERVER" = "apache" ]; then
        VHOST_FILE="/etc/apache2/sites-available/$SERVICE_NAME.conf"
        if [ -f "$VHOST_FILE" ] && grep -q "ProxyPass / http://127.0.0.1:$PORT/" "$VHOST_FILE" 2>/dev/null; then
            info "vhost already configured for this install - leaving it as-is"
            VHOST_CREATED=1
        elif [ -f "$VHOST_FILE" ]; then
            warn "$VHOST_FILE already exists and isn't one of ours - not touching it."
            warn "set up the reverse proxy manually, or move that file aside and re-run."
        else
            a2enmod proxy proxy_http >/dev/null 2>&1
            cat > "$VHOST_FILE" <<EOF
# Managed by SentryNet - do not edit by hand.
<VirtualHost *:80>
    ServerName $DOMAIN
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:$PORT/
    ProxyPassReverse / http://127.0.0.1:$PORT/
</VirtualHost>
EOF
            a2ensite "$SERVICE_NAME" >/dev/null 2>&1
            if apache2ctl configtest >/dev/null 2>&1; then
                systemctl restart apache2
                info "created Apache vhost for $DOMAIN (HTTP for now, TLS next)"
                VHOST_CREATED=1
            else
                warn "apache2ctl configtest failed after adding the vhost - check its output, removing it"
                a2dissite "$SERVICE_NAME" >/dev/null 2>&1
                rm -f "$VHOST_FILE"
                apache2ctl configtest
            fi
        fi
        CERTBOT_FLAG="--apache"
        CERTBOT_PLUGIN_PKG="python3-certbot-apache"
    else
        VHOST_FILE="/etc/nginx/sites-available/$SERVICE_NAME"
        if [ -f "$VHOST_FILE" ] && grep -q "proxy_pass http://127.0.0.1:$PORT;" "$VHOST_FILE" 2>/dev/null; then
            info "vhost already configured for this install - leaving it as-is"
            VHOST_CREATED=1
        elif [ -f "$VHOST_FILE" ]; then
            warn "$VHOST_FILE already exists and isn't one of ours - not touching it."
            warn "set up the reverse proxy manually, or move that file aside and re-run."
        else
            cat > "$VHOST_FILE" <<EOF
# Managed by SentryNet - do not edit by hand.
server {
    listen 80;
    server_name $DOMAIN;

    location = /login {
        limit_req zone=sentrynet_login burst=10 nodelay;
        limit_conn sentrynet_addr 5;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ^~ /api/auth/passkey/ {
        limit_req zone=sentrynet_login burst=10 nodelay;
        limit_conn sentrynet_addr 5;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /auth/oidc/start {
        limit_req zone=sentrynet_login burst=10 nodelay;
        limit_conn sentrynet_addr 5;
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
            ln -sf "$VHOST_FILE" "/etc/nginx/sites-enabled/$SERVICE_NAME"
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx
                info "created nginx vhost for $DOMAIN (HTTP for now, TLS next)"
                VHOST_CREATED=1
            else
                warn "nginx -t failed after adding the vhost - check nginx -t output, removing it"
                rm -f "$VHOST_FILE" "/etc/nginx/sites-enabled/$SERVICE_NAME"
                nginx -t
            fi
        fi
        CERTBOT_FLAG="--nginx"
        CERTBOT_PLUGIN_PKG="python3-certbot-nginx"
    fi

    if [ "$VHOST_CREATED" = "1" ]; then
        if ! command -v certbot >/dev/null 2>&1; then
            info "installing certbot..."
            apt-get install -y -qq certbot "$CERTBOT_PLUGIN_PKG" >/dev/null
        else
            apt-get install -y -qq "$CERTBOT_PLUGIN_PKG" >/dev/null
        fi

        if [ -z "$CERTBOT_EMAIL" ] && [ "$NON_INTERACTIVE" = "0" ] && [ -t 0 ]; then
            read -r -p "    Email for Let's Encrypt renewal notices (leave blank to skip): " CERTBOT_EMAIL_INPUT || true
            CERTBOT_EMAIL="${CERTBOT_EMAIL_INPUT:-}"
        fi

        CERTBOT_ARGS=("$CERTBOT_FLAG" -d "$DOMAIN" --non-interactive --agree-tos --redirect)
        if [ -n "$CERTBOT_EMAIL" ]; then
            CERTBOT_ARGS+=(--email "$CERTBOT_EMAIL")
        else
            CERTBOT_ARGS+=(--register-unsafely-without-email)
        fi

        if certbot "${CERTBOT_ARGS[@]}" >/tmp/sentrynet-certbot.log 2>&1; then
            info "TLS certificate issued - $DOMAIN is live over HTTPS"
            CERT_OK=1
        else
            warn "certbot failed - see /tmp/sentrynet-certbot.log"
            warn "common cause: $DOMAIN's DNS doesn't actually point at this server's IP yet"
            warn "the vhost is still in place over plain HTTP; re-run certbot manually once DNS is fixed:"
            warn "  certbot $CERTBOT_FLAG -d $DOMAIN"
        fi
    fi
else
    info "no domain given - dashboard stays on 127.0.0.1:$PORT only (see summary for how to reach it)"
fi

# ── Watched services/files config (auto-detect a sensible starting set) ──
step "Detecting services to monitor"
WATCHED_UNITS_FILE="$INSTALL_DIR/config/watched_units.txt"
WATCHED_FILES_FILE="$INSTALL_DIR/config/watched_files.txt"

if ! grep -qxF "$WEBSERVER_UNIT" "$WATCHED_UNITS_FILE" 2>/dev/null; then
    echo "$WEBSERVER_UNIT" >> "$WATCHED_UNITS_FILE"
    info "added $WEBSERVER_UNIT to $WATCHED_UNITS_FILE"
fi

if [ "$WEBSERVER" = "apache" ]; then
    for p in "/etc/apache2/apache2.conf" "/etc/apache2/sites-available/*"; do
        grep -qxF "$p" "$WATCHED_FILES_FILE" 2>/dev/null || echo "$p" >> "$WATCHED_FILES_FILE"
    done
else
    for p in "/etc/nginx/nginx.conf" "/etc/nginx/sites-available/*"; do
        grep -qxF "$p" "$WATCHED_FILES_FILE" 2>/dev/null || echo "$p" >> "$WATCHED_FILES_FILE"
    done
fi

PG_UNIT="$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^postgresql(@.*)?\.service$' | sed 's/\.service$//' | head -1 || true)"
if [ -n "$PG_UNIT" ] && ! grep -qxF "$PG_UNIT" "$WATCHED_UNITS_FILE"; then
    echo "$PG_UNIT" >> "$WATCHED_UNITS_FILE"
    info "added detected Postgres unit: $PG_UNIT"
fi
info "edit $WATCHED_UNITS_FILE and $WATCHED_FILES_FILE any time to add your own apps (restart $SERVICE_NAME after editing)"

# ── systemd service ───────────────────────────────────────────────────────
step "Installing systemd service"
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=SentryNet - network security & monitoring dashboard
After=network.target postgresql.service

[Service]
EnvironmentFile=$INSTALL_DIR/.env.postgres
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/uvicorn main:app --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=-/etc/nginx/conf.d -/etc/apache2
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --quiet "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
info "service '$SERVICE_NAME' installed and started"

# ── Wait for startup + capture bootstrap admin credentials ───────────────
step "Waiting for SentryNet to start"
READY=0
for _ in $(seq 1 15); do
    if systemctl is-active --quiet "$SERVICE_NAME" && curl -fsS "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done
if [ "$READY" = "1" ]; then
    trap - ERR
else
    warn "service didn't respond within 15s - check: journalctl -u $SERVICE_NAME -n 50"
    if [ "$EXISTING_INSTALL" = "1" ]; then
        rollback_install 1
    fi
    die "SentryNet did not become healthy; no system cron jobs were installed"
fi

ADMIN_CREDS="$(journalctl -u "$SERVICE_NAME" --no-pager 2>/dev/null | grep -A2 "first run, generated admin credentials" | tail -3 || true)"

# ── Terminal client ──────────────────────────────────────────────────────
step "Installing terminal console"
chmod 0755 "$INSTALL_DIR/terminal.py"
cat > "$TERMINAL_COMMAND" <<EOF
#!/usr/bin/env bash
# Managed by SentryNet installer. Do not edit; re-run install.sh to regenerate.
exec "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/terminal.py" --server "\${SENTRYNET_TERMINAL_URL:-http://127.0.0.1:$PORT}" "\$@"
EOF
chmod 0755 "$TERMINAL_COMMAND"
info "installed $TERMINAL_COMMAND"

# ── Cron: daily trend rollup ──────────────────────────────────────────────
# Scheduled before the retention cleanup below - not that the two could
# actually race (this only reads yesterday's data, cleanup only deletes
# 30-day-old data), just good hygiene to keep them ordered.
step "Scheduling daily trend rollup"
cat > /etc/cron.d/sentrynet-rollup <<EOF
# Rolls up yesterday's requests into long-term daily stats that survive
# past the 30-day cleanup below.
0 4 * * * root cd $INSTALL_DIR && venv/bin/python3 rollup_daily.py >> /var/log/sentrynet-rollup.log 2>&1
EOF
info "installed /etc/cron.d/sentrynet-rollup (daily, 04:00)"

# ── Cron: daily bandwidth / traffic report ────────────────────────────────
# Each report covers the 24-hour monitoring window that closes at 06:00 UTC
# (it opens at 06:00 UTC the day before). Cron follows the host timezone, so
# evaluate hourly and use UTC to select the first :10 run during the 06:00
# hour. The full breakdown is frozen into the report row, so it stays
# viewable after the 30-day raw-request cleanup below.
step "Scheduling daily bandwidth reports"
cat > /etc/cron.d/sentrynet-bandwidth <<EOF
# Freezes the 06:00-06:00 UTC traffic window that just closed into a
# viewable bandwidth/traffic report (see the dashboard's Bandwidth tab).
10 * * * * root [ "\$(date -u +\%H)" = "06" ] && cd $INSTALL_DIR && venv/bin/python3 bandwidth_report.py >> /var/log/sentrynet-bandwidth.log 2>&1
EOF
info "installed /etc/cron.d/sentrynet-bandwidth (daily, first hourly check after 06:00 UTC)"

# ── Cron: retention cleanup ───────────────────────────────────────────────
step "Scheduling daily cleanup"
cat > /etc/cron.d/sentrynet-cleanup <<EOF
# Deletes request rows older than 30 days and stale flagged-IP entries.
15 5 * * * root cd $INSTALL_DIR && venv/bin/python3 cleanup_old_requests.py >> /var/log/sentrynet-cleanup.log 2>&1
EOF
info "installed /etc/cron.d/sentrynet-cleanup (daily, 05:15)"

# ── Summary ────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}${GREEN}SentryNet is installed and running.${RESET}"
echo ""
if [ "$CERT_OK" = "1" ]; then
    echo "  Dashboard:  ${BOLD}https://$DOMAIN/${RESET}"
elif [ "$VHOST_CREATED" = "1" ]; then
    echo "  Dashboard:  ${BOLD}http://$DOMAIN/${RESET} (no TLS yet - see the certbot note above)"
else
    echo "  Dashboard:  ${BOLD}http://127.0.0.1:$PORT/${RESET} (localhost only - SSH tunnel or browse on this box)"
fi
echo "  Install dir: $INSTALL_DIR"
echo "  Service:     systemctl status $SERVICE_NAME"
echo "  Terminal:    sentrynet-terminal"
echo ""
echo "  Bandwidth reports are built automatically after 06:00 UTC for the"
echo "  06:00-06:00 UTC window that just closed. To seed history from the"
echo "  request logs already on this box (up to the 30-day retention limit):"
echo "    cd $INSTALL_DIR && venv/bin/python3 bandwidth_report.py --backfill 30"
echo ""
if [ -n "$ADMIN_CREDS" ]; then
    echo "  ${BOLD}Owner login (shown only this once):${RESET}"
    echo "$ADMIN_CREDS" | sed 's/^/    /'
    echo "    This is the main administrator account - it's the only one that can"
    echo "    add/edit/remove other users. Do that from the dashboard's Users tab."
else
    echo "  ${YELLOW}Owner credentials weren't captured automatically.${RESET} Run:"
    echo "    journalctl -u $SERVICE_NAME | grep -A2 'first run'"
fi
if [ "$DB_FRESHLY_CREATED" = "1" ]; then
    echo ""
    echo "  ${BOLD}Database (shown only this once):${RESET}"
    echo "    host: 127.0.0.1:5432   database: $DB_NAME   user: $DB_USER"
    echo "    password: $DB_PASSWORD"
    echo "    (also saved in $ENV_FILE, root-readable only)"
fi
echo ""
echo "${BOLD}Next steps${RESET}"
if [ "$WEBSERVER_PRESENT" = "0" ]; then
echo "  0. $WEBSERVER was just installed fresh, so there's nothing configured for"
echo "     SentryNet to monitor yet - add your own site vhost(s) first, then"
echo "     come back to step 1."
fi
echo "  1. Point a site's traffic at SentryNet by switching its access log to the"
echo "     new format:"
if [ "$WEBSERVER" = "apache" ]; then
echo "       CustomLog \${APACHE_LOG_DIR}/access.log $LOG_FORMAT_NAME"
echo "     (in that site's <VirtualHost> block), then: apache2ctl configtest &&"
echo "     systemctl restart apache2"
else
echo "       access_log /var/log/nginx/access.log $LOG_FORMAT_NAME;"
echo "     (globally in nginx.conf's http block, or per-site), then:"
echo "     nginx -t && systemctl reload nginx"
fi
if [ -z "$DOMAIN" ]; then
echo "  2. No domain was configured, so the dashboard only listens on"
echo "     127.0.0.1:$PORT. Reach it via 'ssh -L $PORT:localhost:$PORT user@this-server'"
echo "     and then http://localhost:$PORT/ - or re-run this installer to add a domain."
fi
echo "  3. Add your own services to $INSTALL_DIR/config/watched_units.txt and"
echo "     your own app secrets/configs to $INSTALL_DIR/config/watched_files.txt,"
echo "     then: systemctl restart $SERVICE_NAME"
if [ -z "$DISCORD_WEBHOOK" ]; then
echo "  4. To enable Discord alerts later: use the dashboard's Alerts tab, or edit"
echo "     $INSTALL_DIR/.env.postgres and set DISCORD_WEBHOOK_URL=..., then restart."
fi
echo ""
