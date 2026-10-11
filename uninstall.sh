#!/usr/bin/env bash
# Uninstalls SentryNet. Safe by default: stops/removes the service and
# install directory, but leaves the log_format, the dashboard's TLS
# certificate, and the Postgres database/role in place unless you opt in
# with flags.
#
# This never touches nginx, Apache, or Postgres themselves (the packages,
# the services, or any of their other data/sites) - only the specific
# config snippets/files SentryNet added. Removing SentryNet should never
# take your actual websites down with it.
#
# Usage:
#   sudo ./uninstall.sh [--purge-db] [--purge-log-format] [--purge-cert]
#
# Environment overrides (must match what install.sh used, if you changed them):
#   SENTRYNET_DIR              (default: /opt/sentrynet)
#   SENTRYNET_DB_NAME           (default: sentrynet)
#   SENTRYNET_DB_USER           (default: sentrynet_app)
#   SENTRYNET_SERVICE_NAME      (default: sentrynet)

set -euo pipefail

BOLD=$'\033[1m'; RESET=$'\033[0m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'
step() { echo "${BOLD}==>${RESET} $1"; }
info() { echo "    $1"; }
warn() { echo "${YELLOW}    warning: $1${RESET}"; }

[ "$(id -u)" -eq 0 ] || { echo "must be run as root (try: sudo ./uninstall.sh)"; exit 1; }

INSTALL_DIR="${SENTRYNET_DIR:-/opt/sentrynet}"
DB_NAME="${SENTRYNET_DB_NAME:-sentrynet}"
DB_USER="${SENTRYNET_DB_USER:-sentrynet_app}"
SERVICE_NAME="${SENTRYNET_SERVICE_NAME:-sentrynet}"
NGINX_BLOCKLIST_CONF="/etc/nginx/conf.d/sentrynet-blocklist.conf"
TERMINAL_COMMAND="/usr/local/bin/sentrynet-terminal"

# The uninstaller removes paths and database objects as root. Refuse broad
# or syntactically dangerous override values before doing anything.
[[ "$INSTALL_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    && [ "$INSTALL_DIR" != "/" ] \
    && [[ "$INSTALL_DIR" =~ ^/[^/]+/[^/]+ ]] \
    && [[ "/$INSTALL_DIR/" != *"/../"* ]] \
    || { echo "unsafe SENTRYNET_DIR: $INSTALL_DIR" >&2; exit 1; }
[ ! -L "$INSTALL_DIR" ] || { echo "SENTRYNET_DIR must not be a symbolic link" >&2; exit 1; }
CANONICAL_INSTALL_DIR="$(realpath -m -- "$INSTALL_DIR")"
[ "$CANONICAL_INSTALL_DIR" = "$INSTALL_DIR" ] \
    || { echo "SENTRYNET_DIR must be in canonical form" >&2; exit 1; }
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
    || { echo "unsafe SENTRYNET_DB_NAME" >&2; exit 1; }
[[ "$DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
    || { echo "unsafe SENTRYNET_DB_USER" >&2; exit 1; }
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] \
    || { echo "unsafe SENTRYNET_SERVICE_NAME" >&2; exit 1; }

# Figure out which web server this install actually used, before the
# install dir (and its .env.postgres) gets removed below. Defaults to
# nginx for installs from before Apache support existed.
WEBSERVER="nginx"
if [ -f "$INSTALL_DIR/.env.postgres" ]; then
    FOUND_WS="$(grep '^WEBSERVER=' "$INSTALL_DIR/.env.postgres" 2>/dev/null | cut -d= -f2- || true)"
    [ -n "$FOUND_WS" ] && WEBSERVER="$FOUND_WS"
fi
case "$WEBSERVER" in nginx|apache) ;; *) echo "invalid WEBSERVER in environment file" >&2; exit 1 ;; esac

PURGE_DB=0
PURGE_LOG_FORMAT=0
PURGE_CERT=0
for arg in "$@"; do
    case "$arg" in
        --purge-db) PURGE_DB=1 ;;
        --purge-log-format|--purge-nginx-log-format) PURGE_LOG_FORMAT=1 ;;
        --purge-cert) PURGE_CERT=1 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

echo ""
echo "${BOLD}SentryNet uninstaller${RESET} ${YELLOW}($WEBSERVER)${RESET}"
echo ""

step "Stopping service"
if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable --quiet "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    info "stopped, disabled, and removed the '$SERVICE_NAME' unit"
else
    info "no '$SERVICE_NAME' unit found, skipping"
fi

step "Removing cron jobs"
rm -f /etc/cron.d/sentrynet-cleanup /etc/cron.d/sentrynet-rollup /etc/cron.d/sentrynet-bandwidth
info "removed /etc/cron.d/sentrynet-cleanup, /etc/cron.d/sentrynet-rollup and /etc/cron.d/sentrynet-bandwidth"

step "Removing terminal command"
if [ -f "$TERMINAL_COMMAND" ] && grep -qF "Managed by SentryNet" "$TERMINAL_COMMAND" 2>/dev/null; then
    rm -f "$TERMINAL_COMMAND"
    info "removed $TERMINAL_COMMAND"
elif [ -e "$TERMINAL_COMMAND" ]; then
    warn "$TERMINAL_COMMAND is not managed by SentryNet; leaving it in place"
else
    info "no terminal command found, skipping"
fi

step "Removing install directory"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    info "removed $INSTALL_DIR"
else
    info "$INSTALL_DIR not found, skipping"
fi

step "Firewall rules (SSH/HTTP auto-bans)"
# Unlike everything else here, these are never left in place even without
# a --purge flag: they're active DROP rules with no expiry once the
# service that manages/expires them is gone, so leaving them would mean
# permanently (and invisibly) blocking whatever IPs happened to be banned
# at uninstall time.
#
# Fields are extracted and a clean -D command rebuilt from them, rather
# than replaying the "-A INPUT ..." line `iptables -S` prints - that line
# contains the comment wrapped in literal double-quote characters, which
# (if replayed via naive word-splitting) become part of the argument value
# itself and never match the real rule, silently failing every delete.
REMOVED_RULES=0
while true; do
    LINE="$(iptables -S INPUT 2>/dev/null | grep -m1 "sentrynet-ssh-ban-\|sentrynet-http-ban-" || true)"
    [ -z "$LINE" ] && break
    RULE_IP="$(echo "$LINE" | grep -oP '(?<=-s )\S+' || true)"
    RULE_PORTS="$(echo "$LINE" | grep -oP '(?<=--dports )\S+' || true)"
    RULE_COMMENT="$(echo "$LINE" | grep -oP '(?<=--comment ")[^"]+' || true)"
    if [ -z "$RULE_IP" ] || [ -z "$RULE_PORTS" ] || [ -z "$RULE_COMMENT" ]; then
        warn "couldn't parse a firewall rule cleanly - stopping early, check manually: iptables -S INPUT | grep sentrynet"
        break
    fi
    if iptables -D INPUT -s "$RULE_IP" -p tcp -m multiport --dports "$RULE_PORTS" -m comment --comment "$RULE_COMMENT" -j DROP 2>/dev/null; then
        REMOVED_RULES=$((REMOVED_RULES + 1))
    else
        warn "failed to remove a firewall rule for $RULE_IP - stopping early, check manually: iptables -S INPUT | grep sentrynet"
        break
    fi
done
if [ "$REMOVED_RULES" -gt 0 ]; then
    info "removed $REMOVED_RULES firewall ban rule(s)"
else
    info "no SentryNet firewall rules found, skipping"
fi

if [ "$WEBSERVER" = "apache" ]; then
    step "Apache LogFormat"
    LOGFORMAT_CONF="/etc/apache2/conf-available/sentrynet-logformat.conf"
    if [ -f "$LOGFORMAT_CONF" ]; then
        a2disconf sentrynet-logformat >/dev/null 2>&1 || true
        rm -f "$LOGFORMAT_CONF"
        if apache2ctl configtest >/dev/null 2>&1; then
            systemctl reload apache2 2>/dev/null || true
            info "removed sentrynet-logformat.conf and reloaded Apache"
            warn "any site's CustomLog directive still referencing 'sentrynet_json' will now fail configtest - revert those first if you see errors"
        else
            warn "apache2ctl configtest failed after removing the LogFormat - check its output"
        fi
    else
        info "no sentrynet-logformat.conf found, skipping"
    fi

    step "Dashboard vhost"
    VHOST_FILE="/etc/apache2/sites-available/$SERVICE_NAME.conf"
    if [ -f "$VHOST_FILE" ] && grep -q "Managed by SentryNet" "$VHOST_FILE" 2>/dev/null; then
        CERT_DOMAIN="$(grep -oP 'ServerName\s+\K\S+' "$VHOST_FILE" 2>/dev/null | head -1 || true)"
        a2dissite "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$VHOST_FILE"
        if apache2ctl configtest >/dev/null 2>&1; then
            systemctl reload apache2 2>/dev/null || true
            info "removed vhost for ${CERT_DOMAIN:-$SERVICE_NAME} and reloaded Apache"
        else
            warn "apache2ctl configtest failed after removing the vhost - check its output"
        fi
    else
        info "no SentryNet-managed vhost found, skipping"
    fi
else
    step "nginx blocklist file"
    if [ -f "$NGINX_BLOCKLIST_CONF" ]; then
        rm -f "$NGINX_BLOCKLIST_CONF"
        info "removed $NGINX_BLOCKLIST_CONF"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx
            info "nginx reloaded"
        fi
    else
        info "$NGINX_BLOCKLIST_CONF not found, skipping"
    fi

    step "Dashboard vhost"
    VHOST_FILE="/etc/nginx/sites-available/$SERVICE_NAME"
    if [ -f "$VHOST_FILE" ] && grep -q "Managed by SentryNet" "$VHOST_FILE" 2>/dev/null; then
        CERT_DOMAIN="$(grep -oP 'server_name\s+\K[^;]+' "$VHOST_FILE" 2>/dev/null | head -1 || true)"
        rm -f "$VHOST_FILE" "/etc/nginx/sites-enabled/$SERVICE_NAME"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx
            info "removed vhost for ${CERT_DOMAIN:-$SERVICE_NAME} and reloaded nginx"
        else
            warn "nginx -t failed after removing the vhost - check nginx -t output"
            nginx -t
        fi
    else
        info "no SentryNet-managed vhost found, skipping"
    fi
fi

if [ -n "${CERT_DOMAIN:-}" ] && command -v certbot >/dev/null 2>&1 && certbot certificates 2>/dev/null | grep -q "Domains: $CERT_DOMAIN"; then
    if [ "$PURGE_CERT" = "1" ]; then
        certbot delete --cert-name "$CERT_DOMAIN" --non-interactive >/dev/null 2>&1 \
            && info "deleted Let's Encrypt certificate for $CERT_DOMAIN" \
            || warn "failed to delete the certificate - run manually: certbot delete --cert-name $CERT_DOMAIN"
    else
        info "TLS certificate for $CERT_DOMAIN left in place (pass --purge-cert to remove it)"
    fi
fi

if [ "$WEBSERVER" = "nginx" ]; then
    step "nginx log_format"
    if [ "$PURGE_LOG_FORMAT" = "1" ]; then
        if grep -q "log_format sentrynet_json" /etc/nginx/nginx.conf 2>/dev/null; then
            cp /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.sentrynet-uninstall-bak-$(date +%Y%m%d%H%M%S)"
            awk '
                /log_format sentrynet_json/ { in_block=1 }
                in_block { if (/;$/) { in_block=0 }; next }
                { print }
            ' /etc/nginx/nginx.conf > /etc/nginx/nginx.conf.sentrynet-tmp
            mv /etc/nginx/nginx.conf.sentrynet-tmp /etc/nginx/nginx.conf
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx
                info "removed the sentrynet_json log_format block and reloaded nginx"
                warn "any site's access_log directive still referencing 'sentrynet_json' will now fail nginx -t - revert those first if you see errors"
            else
                warn "removing the log_format broke 'nginx -t' - restoring from backup"
                cp "/etc/nginx/nginx.conf.sentrynet-uninstall-bak-"* /etc/nginx/nginx.conf 2>/dev/null || true
                nginx -t
            fi
        else
            info "no sentrynet_json log_format found, skipping"
        fi
    else
        info "left in place (pass --purge-log-format to remove it)"
        info "note: this is harmless to leave - it only defines a log line format, unused unless a site's access_log points at it"
    fi
fi

step "Postgres database and role"
if [ "$PURGE_DB" = "1" ]; then
    sudo -u postgres psql -q -c "DROP DATABASE IF EXISTS $DB_NAME;" >/dev/null
    sudo -u postgres psql -q -c "DROP ROLE IF EXISTS $DB_USER;" >/dev/null
    info "dropped database '$DB_NAME' and role '$DB_USER'"
else
    info "left in place (pass --purge-db to drop database '$DB_NAME' and role '$DB_USER')"
fi

echo ""
echo "${BOLD}${GREEN}SentryNet has been uninstalled.${RESET}"
echo "nginx/Apache and Postgres themselves - and everything else running on them - were never touched."
echo ""
