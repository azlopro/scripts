#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root
load_config

case ${1:-} in
    --check)
        networkctl status "$NETWORK_INTERFACE" --no-pager
        ip -4 address show dev "$NETWORK_INTERFACE"
        ip route
        exit 0
        ;;
    --confirm)
        cancel_rollback company-network-rollback
        log "Network configuration confirmed; rollback cancelled."
        exit 0
        ;;
    --apply) ;;
    *) die "Usage: $0 --check | --apply | --confirm" ;;
esac

assert_yes ACK_DHCP_RESERVATIONS "${ACK_DHCP_RESERVATIONS:-no}" \
    "Both management and server DHCP reservations must be confirmed."

[[ ${USE_DHCP4:-no} == "yes" ]] || die "This version currently supports the agreed DHCPv4 reservation design only."

new_backup_dir network >/dev/null
backup_path /etc/netplan

rollback="$STAGE_BACKUP/rollback-network.sh"
install_text 0700 root root "$rollback" <<EOF
#!/usr/bin/env bash
set -u
logger -t company-hardening 'network rollback started'
if [[ -d '$STAGE_BACKUP/etc/netplan' ]]; then
    find /etc/netplan -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.pre-company-hardening' \) -delete
    cp -a '$STAGE_BACKUP/etc/netplan/.' /etc/netplan/
    netplan generate && netplan apply
fi
if command -v dhcpcd >/dev/null 2>&1; then
    systemctl start dhcpcd.service 2>/dev/null || dhcpcd '$NETWORK_INTERFACE' 2>/dev/null || true
fi
logger -t company-hardening 'network rollback completed'
EOF

schedule_rollback company-network-rollback "${NETWORK_ROLLBACK_SECONDS:-300}" "$rollback"

# Netplan merges all YAML files. Disable the installer file after preserving
# it so an old per-interface definition cannot override this one.
while IFS= read -r old_file; do
    [[ $old_file == "/etc/netplan/00-company-server.yaml" ]] && continue
    mv -- "$old_file" "${old_file}.pre-company-hardening"
done < <(find /etc/netplan -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) -print)

dhcp6=false
[[ ${USE_DHCP6:-no} == "yes" ]] && dhcp6=true

install_text 0600 root root /etc/netplan/00-company-server.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $NETWORK_INTERFACE:
      dhcp4: true
      dhcp6: $dhcp6
      accept-ra: true
      optional: false
EOF

netplan generate
if command -v dhcpcd >/dev/null 2>&1; then
    dhcpcd -x "$NETWORK_INTERFACE" 2>/dev/null || true
    systemctl disable --now dhcpcd.service 2>/dev/null || true
fi
netplan apply

for _ in {1..20}; do
    if ip -4 -o address show dev "$NETWORK_INTERFACE" | awk '{print $4}' | grep -q "^$SERVER_IPV4/"; then
        break
    fi
    sleep 1
done

ip -4 -o address show dev "$NETWORK_INTERFACE" | awk '{print $4}' | grep -q "^$SERVER_IPV4/" \
    || die "Reserved address $SERVER_IPV4 was not obtained; leave the rollback timer running."
ip route | grep -q '^default ' || die "No IPv4 default route; leave the rollback timer running."

log "Network is healthy. Test a new SSH connection, then run: sudo $0 --confirm"
log "Backup and manual rollback: $STAGE_BACKUP"
