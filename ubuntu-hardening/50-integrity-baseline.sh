#!/usr/bin/env bash

set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

require_root
load_config
require_apply "${1:-}"

command -v aideinit >/dev/null 2>&1 || die "AIDE is not installed; run 20-base-hardening.sh first."

log "Creating the AIDE baseline after configuration is complete; this can take several minutes."
aideinit --yes --force
systemctl enable --now dailyaidecheck.timer

stamp=$(date -u +'%Y%m%dT%H%M%SZ')
evidence="$EVIDENCE_ROOT/$stamp"
install -d -m 0700 "$evidence"
find /var/lib/aide -maxdepth 1 -type f -print0 | sort -z | xargs -0r sha256sum >"$evidence/aide-database.sha256"
chmod 0600 "$evidence/aide-database.sha256"
sha256_evidence "$evidence"

log "AIDE baseline initialized. Export its database and hashes to protected off-server evidence storage."
log "Daily AIDE checks are enabled through dailyaidecheck.timer."
log "Local evidence: $evidence"
