#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root
load_config

stamp=$(date -u +'%Y%m%dT%H%M%SZ')
report_dir="$EVIDENCE_ROOT/$stamp"
install -d -m 0700 "$report_dir"
report="$report_dir/system-audit.txt"

section() {
    printf '\n===== %s =====\n' "$1"
}

{
    printf 'generated_utc=%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    printf 'server_name=%s\n' "$SERVER_NAME"
    printf 'script_sha256=%s\n' "$(sha256sum "$0" | awk '{print $1}')"

    section "OS AND HARDWARE"
    sed -n '1,20p' /etc/os-release
    uname -a
    systemd-detect-virt || true
    uptime
    mokutil --sb-state 2>&1 || true

    section "IDENTITY"
    id "$ADMIN_USER"
    getent passwd | awk -F: '$3 == 0 || $3 >= 1000 {print $1 ":uid=" $3 ":shell=" $7}'
    passwd -S root 2>&1 || true
    passwd -S "$ADMIN_USER" 2>&1 || true

    section "NETWORK"
    ip -brief address
    ip route
    ip -6 route
    networkctl status "$NETWORK_INTERFACE" --no-pager 2>&1 || true
    ss -lntup

    section "FIREWALL"
    ufw status verbose 2>&1 || true
    iptables -S 2>&1 || true
    ip6tables -S 2>&1 || true

    section "SSH EFFECTIVE CONFIGURATION"
    /usr/sbin/sshd -T -C "user=$ADMIN_USER,addr=$MANAGEMENT_IPV4,host=$SERVER_NAME" 2>&1 \
        | awk '$1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|usepam|allowusers|allowgroups|maxauthtries|maxstartups|loglevel|x11forwarding|allowtcpforwarding|allowagentforwarding|permituserenvironment)$/ {print}'
    stat -c '%n mode=%a owner=%U:%G' "/home/$ADMIN_USER" "/home/$ADMIN_USER/.ssh" "/home/$ADMIN_USER/.ssh/authorized_keys" 2>&1 || true
    ssh-keygen -lf "/home/$ADMIN_USER/.ssh/authorized_keys" 2>&1 || true

    section "STORAGE"
    lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS
    findmnt -no SOURCE,FSTYPE,OPTIONS /

    section "SECURITY SERVICES"
    for service in apparmor auditd chrony fail2ban fwknop-server rsyslog unattended-upgrades; do
        printf '%s enabled=' "$service"
        systemctl is-enabled "$service" 2>&1 || true
        printf '%s active=' "$service"
        systemctl is-active "$service" 2>&1 || true
    done
    aa-status 2>&1 || true

    section "UPDATES"
    apt-config dump 2>/dev/null | awk '/APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)/'
    apt-get --simulate upgrade 2>&1 || true
    if [[ -f /var/run/reboot-required ]]; then
        sed -n '1,20p' /var/run/reboot-required
    else
        printf 'reboot_not_required\n'
    fi

    section "SELECTED KERNEL CONTROLS"
    sysctl \
        kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict \
        kernel.unprivileged_bpf_disabled fs.suid_dumpable \
        fs.protected_hardlinks fs.protected_symlinks \
        net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.all.send_redirects net.ipv4.conf.all.rp_filter \
        net.ipv4.icmp_echo_ignore_all net.ipv6.conf.all.accept_redirects 2>&1 || true

    section "RUNNING AND FAILED SERVICES"
    systemctl list-units --type=service --state=running --no-pager
    systemctl --failed --no-pager

    section "RECENT ADMINISTRATIVE LOGINS"
    last -F -n 30 2>&1 || true
    journalctl -u ssh.service --since '-7 days' --no-pager -n 200 2>&1 || true
} >"$report"

chmod 0600 "$report"
sha256_evidence "$report_dir"
log "Read-only audit written to $report"

