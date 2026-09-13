#!/usr/bin/env bash

set -Eeuo pipefail

profile=${1:-}
[[ -n $profile && -f $profile ]] || {
    printf 'Usage: %s /path/to/fwknop-server-name.conf\n' "$0" >&2
    exit 1
}

[[ $(stat -c '%a' "$profile") == 600 ]] || {
    printf 'Refusing profile with mode other than 0600: %s\n' "$profile" >&2
    exit 1
}

if ! command -v fwknop >/dev/null 2>&1; then
    printf 'Install the client first: sudo apt-get install fwknop-client\n' >&2
    exit 1
fi

destination="$HOME/.fwknoprc"
if [[ -e $destination ]]; then
    printf 'Refusing to overwrite existing %s; merge the named stanza manually.\n' "$destination" >&2
    exit 1
fi

install -m 0600 "$profile" "$destination"
printf 'Installed %s with mode 0600. Test with: fwknop -n <server-name>\n' "$destination"
printf 'After testing, securely remove the exported source profile yourself.\n'

