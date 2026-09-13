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
report="$report_dir/verification.txt"
failures=0
warnings=0

pass() {
    printf 'PASS  %s\n' "$*"
}

fail() {
    printf 'FAIL  %s\n' "$*"
    failures=$((failures + 1))
}

warn() {
    printf 'WARN  %s\n' "$*"
    warnings=$((warnings + 1))
}

check_command() {
    local description=$1
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$description"
    else
        fail "$description"
    fi
}

sshd_value() {
    local key=$1
    /usr/sbin/sshd -T -C "user=$ADMIN_USER,addr=$MANAGEMENT_IPV4,host=$SERVER_NAME" \
        | awk -v wanted="$key" '$1 == wanted {$1=""; sub(/^ /, ""); print; exit}'
}

{
    printf 'generated_utc=%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    printf 'server=%s address=%s management_source=%s\n\n' "$SERVER_NAME" "$SERVER_IPV4" "$MANAGEMENT_IPV4"

    grep -q '^ID=ubuntu$' /etc/os-release && pass "Ubuntu operating system" || fail "Ubuntu operating system"
    grep -q '^VERSION_ID="\?26\.04"\?$' /etc/os-release \
        && pass "Expected Ubuntu 26.04 release" || warn "Release differs from the assessed Ubuntu 26.04"
    passwd -S root | awk '$2 == "L" {found=1} END {exit !found}' \
        && pass "Local root password is locked" || warn "Local root password is not locked"

    check_command "Reserved IPv4 is present on $NETWORK_INTERFACE" \
        bash -c "ip -4 -o address show dev '$NETWORK_INTERFACE' | awk '{print \$4}' | grep -q '^$SERVER_IPV4/'"
    check_command "IPv4 default route exists" bash -c "ip route | grep -q '^default '"
    pgrep -x dhcpcd >/dev/null 2>&1 && fail "Manual dhcpcd is not running" || pass "Manual dhcpcd is not running"

    ufw status | grep -q '^Status: active' && pass "UFW is active" || fail "UFW is active"
    if ufw status numbered | grep -Eq '22/tcp.*ALLOW'; then
        fail "UFW has no permanent SSH allow rule"
    else
        pass "UFW has no permanent SSH allow rule"
    fi
    iptables -S INPUT | awk '$1 == "-A" {print; exit}' | grep -q -- '-A INPUT -j FWKNOP_INPUT' \
        && pass "fwknop authorization chain precedes UFW" || fail "fwknop authorization chain precedes UFW"
    check_command "fwknop server is active" systemctl is-active --quiet fwknop-server.service
    [[ $(stat -c '%a:%U:%G' /etc/fwknop/access.conf 2>/dev/null) == '600:root:root' ]] \
        && pass "fwknop access secrets are root-only" || fail "fwknop access secrets are root-only"
    grep -Eq "^SOURCE[[:space:]]+$MANAGEMENT_IPV4$" /etc/fwknop/access.conf 2>/dev/null \
        && pass "SPA is restricted to the management IPv4" || fail "SPA is restricted to the management IPv4"
    grep -Eq '^OPEN_PORTS[[:space:]]+tcp/22$' /etc/fwknop/access.conf 2>/dev/null \
        && pass "SPA can authorize SSH only" || fail "SPA can authorize SSH only"

    [[ $(sshd_value permitrootlogin) == no ]] && pass "SSH root login disabled" || fail "SSH root login disabled"
    [[ $(sshd_value passwordauthentication) == no ]] && pass "SSH password login disabled" || fail "SSH password login disabled"
    [[ $(sshd_value kbdinteractiveauthentication) == yes ]] && pass "SSH TOTP prompt enabled" || fail "SSH TOTP prompt enabled"
    [[ $(sshd_value authenticationmethods) == 'publickey,keyboard-interactive' ]] \
        && pass "SSH requires public key plus TOTP" || fail "SSH requires public key plus TOTP"
    [[ $(sshd_value allowusers) == "$ADMIN_USER@$MANAGEMENT_IPV4" ]] \
        && pass "SSH user and source restricted" || fail "SSH user and source restricted"
    [[ $(sshd_value x11forwarding) == no ]] && pass "SSH X11 forwarding disabled" || fail "SSH X11 forwarding disabled"
    grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_google_authenticator\.so' /etc/pam.d/sshd \
        && pass "PAM TOTP rule present" || fail "PAM TOTP rule present"

    for service in apparmor auditd chrony unattended-upgrades; do
        check_command "$service is active" systemctl is-active --quiet "$service"
    done

    [[ $(sysctl -n net.ipv4.conf.all.accept_redirects) == 0 ]] \
        && pass "IPv4 redirects rejected" || fail "IPv4 redirects rejected"
    [[ $(sysctl -n net.ipv6.conf.all.accept_redirects) == 0 ]] \
        && pass "IPv6 redirects rejected" || fail "IPv6 redirects rejected"
    [[ $(sysctl -n net.ipv4.icmp_echo_ignore_all) == 0 ]] \
        && pass "ICMP is not unsafely disabled wholesale" || warn "IPv4 echo is disabled; confirm this is intentional"

    if lsblk -s -no TYPE "$(findmnt -no SOURCE /)" 2>/dev/null | grep -qx crypt; then
        pass "Root storage has a dm-crypt/LUKS ancestor"
    else
        warn "Root storage is not encrypted; physical-loss risk is recorded"
    fi

    find /var/lib/aide -maxdepth 1 -type f -name 'aide.db*' -print -quit 2>/dev/null | grep -q . \
        && pass "AIDE database exists" || warn "AIDE baseline has not been initialized"
    check_command "Daily AIDE timer is active" systemctl is-active --quiet dailyaidecheck.timer

    if id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx lxd; then
        warn "$ADMIN_USER remains in the root-equivalent lxd group"
    else
        pass "$ADMIN_USER is not in the lxd group"
    fi

    failed_units=$(systemctl --failed --no-legend --plain | awk 'NF {print $1}' | paste -sd, -)
    [[ -z $failed_units ]] && pass "No failed systemd units" || warn "Failed units: $failed_units"

    printf '\nSUMMARY failures=%d warnings=%d\n' "$failures" "$warnings"
} >"$report"

chmod 0600 "$report"
sha256_evidence "$report_dir"
sed -n '1,240p' "$report"
log "Verification evidence written to $report"

(( failures == 0 )) || exit 1
