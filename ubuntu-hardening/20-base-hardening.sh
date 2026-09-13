#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root
load_config
require_apply "${1:-}"

root_source=$(findmnt -no SOURCE /)
root_ancestry=$(lsblk -s -no TYPE "$root_source" 2>/dev/null || true)
if ! grep -qx crypt <<<"$root_ancestry"; then
    assert_yes ACK_UNENCRYPTED_ROOT "${ACK_UNENCRYPTED_ROOT:-no}" \
        "Root storage does not appear to use LUKS; this is a recorded physical-loss risk."
fi

[[ -z ${REMOTE_LOG_HOST:-} ]] \
    || die "Remote TLS logging needs the log server CA and policy; leave REMOTE_LOG_HOST empty until those are defined."

new_backup_dir base >/dev/null
for path in \
    /etc/apt/apt.conf.d/52company-hardening \
    /etc/sysctl.d/60-company-hardening.conf \
    /etc/systemd/journald.conf.d/60-company-hardening.conf \
    /etc/systemd/coredump.conf.d/60-company-hardening.conf \
    /etc/security/limits.d/60-company-hardening.conf \
    /etc/security/pwquality.conf.d/60-company-hardening.conf \
    /etc/audit/rules.d/50-company-hardening.rules; do
    backup_path "$path"
done

log "Installing baseline security packages."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    aide apparmor-utils auditd audispd-plugins debsums libpam-pwquality \
    unattended-upgrades

install_text 0644 root root /etc/apt/apt.conf.d/52company-hardening <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

install_text 0644 root root /etc/sysctl.d/60-company-hardening.conf <<EOF
# Managed by company-hardening. Do not disable ICMP globally.
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

net.ipv4.ip_forward = $([[ ${ALLOW_IP_FORWARDING:-no} == yes ]] && printf 1 || printf 0)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

install -d -m 0755 /etc/systemd/journald.conf.d /etc/systemd/coredump.conf.d
install_text 0644 root root /etc/systemd/journald.conf.d/60-company-hardening.conf <<'EOF'
[Journal]
Storage=persistent
Compress=yes
Seal=yes
ForwardToSyslog=yes
SystemMaxUse=1G
MaxRetentionSec=6month
EOF

install_text 0644 root root /etc/systemd/coredump.conf.d/60-company-hardening.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

install_text 0644 root root /etc/security/limits.d/60-company-hardening.conf <<'EOF'
* hard core 0
EOF

install -d -m 0755 /etc/security/pwquality.conf.d
install_text 0644 root root /etc/security/pwquality.conf.d/60-company-hardening.conf <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

install_text 0640 root root /etc/audit/rules.d/50-company-hardening.rules <<'EOF'
## Managed by company-hardening.
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privileged
-w /etc/sudoers.d/ -p wa -k privileged
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/netplan/ -p wa -k network
-w /etc/ufw/ -p wa -k firewall
-w /etc/systemd/system/ -p wa -k services
-w /var/lib/dpkg/ -p wa -k software
-w /etc/audit/ -p wa -k auditconfig
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged-exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged-exec
EOF

sysctl --system
systemctl restart systemd-journald
systemctl enable --now auditd unattended-upgrades apparmor
augenrules --load

if [[ ${DISABLE_WIFI:-no} == "yes" ]]; then
    systemctl disable --now wpa_supplicant.service 2>/dev/null || true
    rfkill block wifi 2>/dev/null || true
fi

if [[ ${DISABLE_MODEM_MANAGER:-no} == "yes" ]]; then
    systemctl disable --now ModemManager.service 2>/dev/null || true
fi

if [[ ${REMOVE_ADMIN_FROM_LXD_GROUP:-no} == "yes" ]] && id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx lxd; then
    gpasswd -d "$ADMIN_USER" lxd
    log "Removed $ADMIN_USER from root-equivalent lxd group; effective at next login."
fi

log "Base hardening applied. Configuration backup: $STAGE_BACKUP"
log "Run 00-audit.sh again after all stages to capture final evidence."
