#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ ${1:-} == "--enroll" ]]; then
    [[ ${EUID:-$(id -u)} -ne 0 ]] || {
        printf 'Run enrollment as the SSH administrator, not as root or through sudo.\n' >&2
        exit 1
    }
    command -v google-authenticator >/dev/null 2>&1 || {
        printf 'The server preparation step must install libpam-google-authenticator first.\n' >&2
        exit 1
    }
    exec google-authenticator
fi

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
require_root
load_config

effective_value() {
    local key=$1
    /usr/sbin/sshd -T -C "user=$ADMIN_USER,addr=$MANAGEMENT_IPV4,host=$SERVER_NAME" \
        | awk -v wanted="$key" '$1 == wanted {$1=""; sub(/^ /, ""); print; exit}'
}

case ${1:-} in
    --prepare)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y libpam-google-authenticator
        log "TOTP software installed; SSH policy is unchanged."
        log "Now log in as $ADMIN_USER and run: $SCRIPT_DIR/40-ssh-totp.sh --enroll"
        exit 0
        ;;
    --status)
        /usr/sbin/sshd -T -C "user=$ADMIN_USER,addr=$MANAGEMENT_IPV4,host=$SERVER_NAME" \
            | awk '$1 ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|allowusers|maxauthtries|maxstartups|x11forwarding|allowtcpforwarding|allowagentforwarding|debianbanner)$/ {print}'
        grep -nE 'common-auth|pam_google_authenticator' /etc/pam.d/sshd || true
        stat -c '%n mode=%a owner=%U:%G' "/home/$ADMIN_USER/.google_authenticator" 2>&1 || true
        exit 0
        ;;
    --confirm)
        [[ $(effective_value passwordauthentication) == no ]] || die "Password authentication is not disabled."
        [[ $(effective_value kbdinteractiveauthentication) == yes ]] || die "Keyboard-interactive authentication is not enabled."
        [[ $(effective_value authenticationmethods) == "publickey,keyboard-interactive" ]] \
            || die "Key plus TOTP is not the effective authentication policy."
        grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_google_authenticator\.so' /etc/pam.d/sshd \
            || die "The TOTP PAM rule is missing."
        cancel_rollback company-ssh-rollback
        log "SSH key-plus-TOTP login confirmed; rollback cancelled."
        exit 0
        ;;
    --apply) ;;
    *) die "Usage: $0 --prepare | --enroll (without sudo) | --apply | --status | --confirm" ;;
esac

totp_file="/home/$ADMIN_USER/.google_authenticator"
[[ -s $totp_file ]] || die "$ADMIN_USER has not completed TOTP enrollment."
[[ $(stat -c '%U' "$totp_file") == "$ADMIN_USER" ]] || die "TOTP secret has the wrong owner."
totp_mode=$(stat -c '%a' "$totp_file")
[[ $totp_mode == 600 || $totp_mode == 400 ]] || die "TOTP secret must have mode 0600 or 0400, not $totp_mode."

chronyc tracking 2>/dev/null | grep -q '^Leap status[[:space:]]*:[[:space:]]*Normal' \
    || die "chrony does not report normal synchronization; TOTP would be unreliable."

[[ -s "/home/$ADMIN_USER/.ssh/authorized_keys" ]] || die "No SSH public key is enrolled for $ADMIN_USER."

new_backup_dir ssh-totp >/dev/null
backup_path /etc/ssh
backup_path /etc/pam.d/sshd

rollback="$STAGE_BACKUP/rollback-ssh.sh"
install_text 0700 root root "$rollback" <<EOF
#!/usr/bin/env bash
set -u
logger -t company-hardening 'SSH/TOTP rollback started'
rm -f /etc/ssh/sshd_config.d/00-company-hardening.conf
if [[ -d '$STAGE_BACKUP/etc/ssh' ]]; then
    cp -a '$STAGE_BACKUP/etc/ssh/.' /etc/ssh/
fi
if [[ -f '$STAGE_BACKUP/etc/pam.d/sshd' ]]; then
    cp -a '$STAGE_BACKUP/etc/pam.d/sshd' /etc/pam.d/sshd
fi
/usr/sbin/sshd -t && systemctl try-reload-or-restart ssh.service
logger -t company-hardening 'SSH/TOTP rollback completed'
EOF

schedule_rollback company-ssh-rollback "${ACCESS_ROLLBACK_SECONDS:-900}" "$rollback"

forwarding=no
[[ ${ALLOW_SSH_FORWARDING:-no} == yes ]] && forwarding=yes

install_text 0644 root root /etc/ssh/sshd_config.d/00-company-hardening.conf <<EOF
# Managed by company-hardening; loaded before installer/cloud-init snippets.
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
UsePAM yes
PermitEmptyPasswords no
AllowUsers $ADMIN_USER@$MANAGEMENT_IPV4
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
MaxStartups 3:50:10
X11Forwarding no
AllowAgentForwarding $forwarding
AllowTcpForwarding $forwarding
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
DebianBanner no
LogLevel VERBOSE
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

if grep -Eq '^[[:space:]]*@include[[:space:]]+common-auth' /etc/pam.d/sshd; then
    pam_temporary=$(mktemp)
    awk '
        /^[[:space:]]*@include[[:space:]]+common-auth/ {
            print "# @include common-auth -- replaced by company-hardening for SSH only"
            print "auth required pam_google_authenticator.so"
            next
        }
        { print }
    ' /etc/pam.d/sshd >"$pam_temporary"
    install -o root -g root -m 0644 "$pam_temporary" /etc/pam.d/sshd
    rm -f -- "$pam_temporary"
elif ! grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_google_authenticator\.so' /etc/pam.d/sshd; then
    die "Unexpected PAM SSH layout; rollback remains scheduled."
fi

/usr/sbin/sshd -t || die "sshd rejected the new configuration; rollback remains scheduled."
systemctl try-reload-or-restart ssh.service

[[ $(effective_value passwordauthentication) == no ]] || die "Password authentication override did not take effect."
[[ $(effective_value authenticationmethods) == "publickey,keyboard-interactive" ]] \
    || die "Key-plus-TOTP policy did not take effect."

log "SSH now requires the existing public key plus TOTP and is restricted to $MANAGEMENT_IPV4."
log "Keep this session open. From a NEW terminal (after SPA), test:"
log "  ssh -o ControlMaster=no -o ControlPath=none $ADMIN_USER@$SERVER_IPV4"
log "After successful TOTP login, run here: sudo $0 --confirm"
log "Automatic rollback remains active for ${ACCESS_ROLLBACK_SECONDS:-900} seconds."
