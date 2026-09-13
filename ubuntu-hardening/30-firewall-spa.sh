#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root
load_config

fwknop_service() {
    if systemctl list-unit-files fwknop-server.service --no-legend 2>/dev/null | grep -q fwknop-server; then
        printf 'fwknop-server.service\n'
    elif systemctl list-unit-files fwknopd.service --no-legend 2>/dev/null | grep -q fwknopd; then
        printf 'fwknopd.service\n'
    else
        die "No fwknop server service unit was installed."
    fi
}

status() {
    ufw status verbose 2>&1 || true
    systemctl status "$(fwknop_service)" --no-pager 2>&1 || true
    iptables -S INPUT 2>&1 | sed -n '1,12p'
    iptables -S FWKNOP_INPUT 2>&1 || true
}

case ${1:-} in
    --status)
        status
        exit 0
        ;;
    --confirm)
        systemctl is-active --quiet "$(fwknop_service)" || die "fwknop is not active; rollback remains scheduled."
        ufw status | grep -q '^Status: active' || die "UFW is not active; rollback remains scheduled."
        iptables -S INPUT | awk '$1 == "-A" {print; exit}' | grep -q -- '-A INPUT -j FWKNOP_INPUT' \
            || die "FWKNOP_INPUT is not first in INPUT; rollback remains scheduled."
        cancel_rollback company-access-rollback
        log "SPA/firewall access confirmed; rollback cancelled."
        exit 0
        ;;
    --prepare|--apply) action=$1 ;;
    *) die "Usage: $0 --prepare | --apply | --status | --confirm" ;;
esac

ip -4 -o address show dev "$NETWORK_INTERFACE" | awk '{print $4}' | grep -q "^$SERVER_IPV4/" \
    || die "$SERVER_IPV4 is not configured on $NETWORK_INTERFACE."

if [[ $action == "--prepare" ]]; then
    new_backup_dir spa-prepare >/dev/null
    backup_path /etc/fwknop
    backup_path /etc/default/fwknop-server
    backup_path /etc/systemd/system/fwknop-server.service.d

    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y fwknop-apparmor-profile fwknop-server

    service_name=$(fwknop_service)
    install -d -m 0700 /etc/fwknop
    install -d -m 0755 /etc/systemd/system/fwknop-server.service.d

    key_file=/etc/fwknop/company-generated.keys
    if [[ ! -s $key_file ]]; then
        umask 077
        fwknopd --key-gen --key-gen-file "$key_file"
        chmod 0600 "$key_file"
    fi

    encryption_key=$(awk -F': ' '$1 == "KEY_BASE64" {print $2}' "$key_file")
    hmac_key=$(awk -F': ' '$1 == "HMAC_KEY_BASE64" {print $2}' "$key_file")
    [[ -n $encryption_key && -n $hmac_key ]] || die "fwknop key generation failed."

    install_text 0600 root root /etc/fwknop/access.conf <<EOF
# Managed by company-hardening. Only the reserved management workstation may authorize SSH.
SOURCE                  $MANAGEMENT_IPV4
DESTINATION             $SERVER_IPV4
OPEN_PORTS              tcp/22
REQUIRE_SOURCE_ADDRESS  Y
FW_ACCESS_TIMEOUT       $SPA_ACCESS_SECONDS
MAX_FW_TIMEOUT          $SPA_ACCESS_SECONDS
KEY_BASE64              $encryption_key
HMAC_KEY_BASE64         $hmac_key
EOF

    install_text 0600 root root /etc/fwknop/fwknopd.conf <<EOF
# Managed by company-hardening.
PCAP_INTF $NETWORK_INTERFACE;
ENABLE_PCAP_PROMISC N;
PCAP_FILTER udp dst port $SPA_UDP_PORT;
ENABLE_SPA_PACKET_AGING Y;
MAX_SPA_PACKET_AGE 60;
ENABLE_DIGEST_PERSISTENCE Y;
ENABLE_RULE_PREPEND Y;
ENABLE_DESTINATION_RULE Y;
FLUSH_IPT_AT_INIT Y;
FLUSH_IPT_AT_EXIT Y;
ENABLE_IPT_FORWARDING N;
IPT_INPUT_ACCESS ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1;
FIREWALL_EXE /usr/sbin/iptables;
EOF

    install_text 0644 root root /etc/default/fwknop-server <<'EOF'
START_DAEMON="yes"
DAEMON_ARGS=""
EOF

    install_text 0644 root root /etc/systemd/system/fwknop-server.service.d/ordering.conf <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target ufw.service
EOF

    client_export="/home/$ADMIN_USER/fwknop-${SERVER_NAME}.conf"
    install_text 0600 "$ADMIN_USER" "$ADMIN_USER" "$client_export" <<EOF
# Secret client profile generated on $SERVER_NAME. Move it to the management PC,
# install as ~/.fwknoprc mode 0600, then securely delete this server-side export.
[$SERVER_NAME]
SPA_SERVER              $SERVER_IPV4
SPA_SERVER_PROTO        udp
SPA_SERVER_PORT         $SPA_UDP_PORT
ACCESS                  tcp/22
ALLOW_IP                $MANAGEMENT_IPV4
FW_TIMEOUT              $SPA_ACCESS_SECONDS
DIGEST_TYPE             sha256
HMAC_DIGEST_TYPE        sha256
USE_HMAC                Y
KEY_BASE64              $encryption_key
HMAC_KEY_BASE64         $hmac_key
EOF

    install_text 0640 root root /etc/audit/rules.d/51-company-fwknop.rules <<'EOF'
-w /etc/fwknop/ -p wa -k firewall
EOF
    command -v augenrules >/dev/null 2>&1 && augenrules --load || true

    fwknopd --exit-parse-config
    systemctl daemon-reload
    systemctl enable --now "$service_name"
    systemctl restart "$service_name"

    log "SPA server prepared without enabling the firewall."
    log "Client secret export: $client_export"
    log "Copy it to the management PC, install fwknop-client there, and set ACK_SPA_CLIENT_COPIED=\"yes\"."
    log "Preparation backup: $STAGE_BACKUP"
    exit 0
fi

assert_yes ACK_SPA_CLIENT_COPIED "${ACK_SPA_CLIENT_COPIED:-no}" \
    "The generated SPA client profile must be installed on the management PC first."

[[ -s /etc/fwknop/access.conf ]] || die "Run --prepare before --apply."
fwknopd --exit-parse-config
service_name=$(fwknop_service)
systemctl is-active --quiet "$service_name" || die "fwknop is not active."

if ufw status | grep -q '^Status: active' && [[ ! -f /var/lib/company-hardening/ufw-managed ]]; then
    die "UFW is already active but was not created by this bundle; refusing to replace its rules."
fi

new_backup_dir access-cutover >/dev/null
backup_path /etc/ufw
prior_ufw_active=no
ufw status | grep -q '^Status: active' && prior_ufw_active=yes

rollback="$STAGE_BACKUP/rollback-access.sh"
install_text 0700 root root "$rollback" <<EOF
#!/usr/bin/env bash
set -u
logger -t company-hardening 'access rollback started'
systemctl stop '$service_name' 2>/dev/null || true
ufw --force disable 2>/dev/null || true
if [[ -d '$STAGE_BACKUP/etc/ufw' ]]; then
    cp -a '$STAGE_BACKUP/etc/ufw/.' /etc/ufw/
fi
if [[ '$prior_ufw_active' == yes ]]; then
    ufw --force enable
fi
logger -t company-hardening 'access rollback completed; SSH firewall gate removed'
EOF

schedule_rollback company-access-rollback "${ACCESS_ROLLBACK_SECONDS:-900}" "$rollback"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw logging low
ufw --force enable

# UFW reloads the base chains, so restart fwknop after enabling UFW. Its jump
# must be first or UFW's default drop would make valid SPA grants ineffective.
systemctl restart "$service_name"
install -d -m 0755 /var/lib/company-hardening
touch /var/lib/company-hardening/ufw-managed
chmod 0600 /var/lib/company-hardening/ufw-managed

iptables -S INPUT | awk '$1 == "-A" {print; exit}' | grep -q -- '-A INPUT -j FWKNOP_INPUT' \
    || die "FWKNOP_INPUT was not inserted first; leave rollback running."

log "Firewall enabled: inbound services are closed until valid SPA authorization."
log "From a NEW management-PC terminal run: fwknop -n $SERVER_NAME && ssh $ADMIN_USER@$SERVER_IPV4"
log "After that succeeds, run here: sudo $0 --confirm"
log "Automatic rollback remains active for ${ACCESS_ROLLBACK_SECONDS:-900} seconds."
