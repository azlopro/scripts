#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_NAME="company-hardening"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONFIG_FILE="${HARDENING_CONFIG:-$SCRIPT_DIR/hardening.conf}"
BACKUP_ROOT="/var/backups/$PROJECT_NAME"
EVIDENCE_ROOT="/var/log/$PROJECT_NAME"

log() {
    printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

die() {
    log "ERROR: $*" >&2
    exit 1
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this stage with sudo."
}

require_apply() {
    [[ ${1:-} == "--apply" ]] || die "No changes made. Re-run with --apply after reviewing the script and configuration."
}

load_config() {
    [[ -r "$CONFIG_FILE" ]] || die "Missing configuration: $CONFIG_FILE (copy hardening.conf.example first)."
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        [[ $(stat -c '%U' "$CONFIG_FILE") == root ]] || die "Configuration must be owned by root: $CONFIG_FILE"
        [[ $(stat -c '%a' "$CONFIG_FILE") == 600 ]] || die "Configuration must have mode 0600: $CONFIG_FILE"
    fi
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"

    : "${SERVER_NAME:?missing SERVER_NAME}"
    : "${SERVER_IPV4:?missing SERVER_IPV4}"
    : "${MANAGEMENT_IPV4:?missing MANAGEMENT_IPV4}"
    : "${NETWORK_INTERFACE:?missing NETWORK_INTERFACE}"
    : "${ADMIN_USER:?missing ADMIN_USER}"
    : "${SPA_UDP_PORT:?missing SPA_UDP_PORT}"
    : "${SPA_ACCESS_SECONDS:?missing SPA_ACCESS_SECONDS}"

    [[ $SERVER_IPV4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "SERVER_IPV4 is not an IPv4 address."
    [[ $MANAGEMENT_IPV4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "MANAGEMENT_IPV4 is not an IPv4 address."
    local address octet
    local -a address_octets
    for address in "$SERVER_IPV4" "$MANAGEMENT_IPV4"; do
        IFS=. read -r -a address_octets <<<"$address"
        for octet in "${address_octets[@]}"; do
            (( 10#$octet <= 255 )) || die "IPv4 octet is out of range in $address."
        done
    done
    [[ $SERVER_NAME =~ ^[a-zA-Z0-9.-]+$ ]] || die "Unsafe SERVER_NAME value."
    [[ $NETWORK_INTERFACE =~ ^[a-zA-Z0-9_.:-]+$ ]] || die "Unsafe NETWORK_INTERFACE value."
    [[ $ADMIN_USER =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Unsafe ADMIN_USER value."
    (( SPA_UDP_PORT >= 1024 && SPA_UDP_PORT <= 65535 )) || die "SPA_UDP_PORT must be between 1024 and 65535."
    (( SPA_ACCESS_SECONDS >= 10 && SPA_ACCESS_SECONDS <= 300 )) || die "SPA_ACCESS_SECONDS must be between 10 and 300."
    [[ ${NETWORK_ROLLBACK_SECONDS:-} =~ ^[0-9]+$ ]] || die "NETWORK_ROLLBACK_SECONDS must be numeric."
    [[ ${ACCESS_ROLLBACK_SECONDS:-} =~ ^[0-9]+$ ]] || die "ACCESS_ROLLBACK_SECONDS must be numeric."
    (( NETWORK_ROLLBACK_SECONDS >= 120 && NETWORK_ROLLBACK_SECONDS <= 3600 )) || die "Unsafe network rollback interval."
    (( ACCESS_ROLLBACK_SECONDS >= 300 && ACCESS_ROLLBACK_SECONDS <= 3600 )) || die "Unsafe access rollback interval."
    getent passwd "$ADMIN_USER" >/dev/null || die "ADMIN_USER does not exist: $ADMIN_USER"
    [[ -d "/sys/class/net/$NETWORK_INTERFACE" ]] || die "Network interface does not exist: $NETWORK_INTERFACE"
}

new_backup_dir() {
    local label=$1
    local stamp
    stamp=$(date -u +'%Y%m%dT%H%M%SZ')
    STAGE_BACKUP="$BACKUP_ROOT/${stamp}-${label}"
    install -d -m 0700 "$STAGE_BACKUP"
    printf '%s\n' "$STAGE_BACKUP"
}

backup_path() {
    local path=$1
    [[ -e "$path" || -L "$path" ]] || return 0
    install -d -m 0700 "$STAGE_BACKUP$(dirname -- "$path")"
    cp -a -- "$path" "$STAGE_BACKUP$path"
}

install_text() {
    local mode=$1 owner=$2 group=$3 destination=$4
    local temporary
    temporary=$(mktemp)
    trap 'rm -f -- "$temporary"' RETURN
    tee "$temporary" >/dev/null
    install -o "$owner" -g "$group" -m "$mode" "$temporary" "$destination"
    rm -f -- "$temporary"
    trap - RETURN
}

assert_yes() {
    local variable_name=$1 value=$2 reason=$3
    [[ $value == "yes" ]] || die "$reason Set $variable_name=\"yes\" only after accepting it."
}

cancel_rollback() {
    local unit=$1
    systemctl stop "${unit}.timer" "${unit}.service" 2>/dev/null || true
    systemctl reset-failed "${unit}.service" 2>/dev/null || true
}

schedule_rollback() {
    local unit=$1 seconds=$2 script=$3
    cancel_rollback "$unit"
    systemd-run \
        --unit="$unit" \
        --on-active="${seconds}s" \
        --timer-property=AccuracySec=1s \
        "$script" >/dev/null
    log "Rollback timer ${unit}.timer scheduled for ${seconds} seconds."
}

sha256_evidence() {
    local directory=$1
    find "$directory" -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
        | sort -z \
        | xargs -0r sha256sum >"$directory/SHA256SUMS"
    chmod 0600 "$directory/SHA256SUMS"
}
