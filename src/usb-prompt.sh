#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Unprivileged desktop companion. It only offers review; the authenticated GUI
# broker revalidates the attachment and effective profile before any approval.

usb_prompt::private_directory() {
    local directory=$1 metadata
    [[ -d $directory && ! -L $directory ]] || return 1
    metadata=$(stat -c '%u:%a' -- "$directory") || return 1
    [[ $metadata == "$UID:700" ]]
}

usb_prompt::prepare() {
    local runtime=${XDG_RUNTIME_DIR:-} directory
    [[ $runtime == /* ]] && usb_prompt::private_directory "$runtime" || return 1
    USB_PROMPT_DIRECTORY="$runtime/octoshield/usb-prompts"
    for directory in "$runtime/octoshield" "$USB_PROMPT_DIRECTORY"; do
        [[ ! -L $directory ]] || return 1
        if [[ ! -e $directory ]]; then mkdir -m 0700 -- "$directory" || return 1; fi
        usb_prompt::private_directory "$directory" || return 1
    done
}

usb_prompt::private_file() {
    local file=$1 maximum=$2 metadata
    [[ -f $file && ! -L $file ]] || return 1
    metadata=$(stat -c '%u:%a:%h:%s' -- "$file") || return 1
    [[ $metadata =~ ^$UID:600:1:([0-9]{1,9})$ ]] || return 1
    ((BASH_REMATCH[1] <= maximum))
}

usb_prompt::lock() {
    local file="$USB_PROMPT_DIRECTORY/agent.lock"
    [[ ! -L $file ]] || return 1
    if [[ ! -e $file ]]; then (
        umask 077
        set -o noclobber
        : >"$file"
    ) 2>/dev/null || return 1; fi
    usb_prompt::private_file "$file" 0 || return 1
    exec {USB_PROMPT_LOCK}<"$file" || return 1
    flock -n "$USB_PROMPT_LOCK"
}

usb_prompt::enabled() {
    local directory=${XDG_CONFIG_HOME:-${HOME:-}/.config} file data value
    [[ $directory == /* ]] || return 1
    file="$directory/octoshield/preferences.ini"
    [[ ! -L $directory/octoshield && ! -L $file ]] || return 1
    [[ -e $file ]] || return 0
    usb_prompt::private_file "$file" 65536 || return 1
    data=$(head -c 65537 -- "$file") || return 1
    ((${#data} <= 65536)) || return 1
    value=$(awk '
        /^[[:space:]]*[#;]/ {next}
        /^[[:space:]]*\[/ {section=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", section); next}
        section == "[USB]" && /^[[:space:]]*automatic-prompts[[:space:]]*=/ {
            value=$0; sub(/^[^=]*=/, "", value); gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); found=1
        }
        END {print found ? value : "true"}
    ' <<<"$data") || return 1
    [[ $value == true ]]
}

usb_prompt::unlocked() {
    local session=${XDG_SESSION_ID:-} report key value user='' active='' remote='' locked='' type=''
    if [[ -z $session ]]; then
        session=$(timeout 3s loginctl show-user "$UID" --property=Display --value 2>/dev/null) || return 1
    fi
    [[ $session =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || return 1
    report=$(timeout 3s loginctl show-session "$session" --property=User --property=Active --property=Remote --property=LockedHint --property=Type 2>/dev/null) || return 1
    while IFS='=' read -r key value; do
        case "$key" in User) user=$value ;; Active) active=$value ;; Remote) remote=$value ;; LockedHint) locked=$value ;; Type) type=$value ;; esac
    done <<<"$report"
    [[ $user == "$UID" && $active == yes && $remote == no && $locked == no && ($type == wayland || $type == x11) ]]
}

usb_prompt::read_seen() {
    local file="$USB_PROMPT_DIRECTORY/seen.json" document
    [[ ! -L $file ]] || return 1
    if [[ ! -e $file ]]; then
        printf '[]\n'
        return
    fi
    usb_prompt::private_file "$file" 32768 || return 1
    document=$(head -c 32769 -- "$file") || return 1
    ((${#document} <= 32768)) || return 1
    jq -ce 'type == "array" and length <= 256 and all(.[]; type == "string" and test("^[a-z][a-z0-9-]{0,31}:[a-f0-9]{64}$"))' <<<"$document" >/dev/null || return 1
    printf '%s\n' "$document"
}

usb_prompt::write_seen() (
    local document=$1 temporary file="$USB_PROMPT_DIRECTORY/seen.json"
    [[ ! -L $file ]] || return 1
    if [[ -e $file ]]; then usb_prompt::private_file "$file" 32768 || return 1; fi
    temporary=$(mktemp "$USB_PROMPT_DIRECTORY/.seen.XXXXXXXX") || return 1
    trap 'rm -f -- "$temporary"' EXIT
    printf '%s\n' "$document" >"$temporary" || return 1
    chmod 0600 -- "$temporary" || return 1
    mv -fT -- "$temporary" "$file"
)

usb_prompt::keys() {
    jq -ce '
        .usb.devices | if type == "array" and length <= 256 and all(.[];
            (.profile | type == "string" and test("^[a-z][a-z0-9-]{0,31}$")) and
            (.token | type == "string" and test("^[a-f0-9]{64}$")) and
            (.state | IN("allowed", "blocked", "rejected")))
        then {connected:map(.profile + ":" + .token) | unique,
              pending:map(select(.state != "allowed") | .profile + ":" + .token) | unique}
        else error("Invalid USB attachment status") end'
}

usb_prompt::available() { [[ -x /usr/bin/octoshield-gtk && -x /usr/bin/systemd-run ]]; }

usb_prompt::launch() {
    # A separate user unit keeps the GUI alive when this observer is restarted.
    # Neither USB descriptors nor device IDs ever become process arguments.
    timeout --kill-after=1s 5s /usr/bin/systemd-run --user --collect --quiet \
        --service-type=exec -- /usr/bin/octoshield-gtk --usb-review
}

usb_prompt::poll() {
    local document keys seen retained pending next
    document=$(status::read_usb 2>/dev/null) || return 1
    jq -e '.usb.available == true and (.usb.state | IN("active", "partial"))' <<<"$document" >/dev/null || return 1
    keys=$(usb_prompt::keys <<<"$document") || return 1
    seen=$(usb_prompt::read_seen) || return 1
    # Prune only against a successfully validated full device snapshot. A stale
    # or missing cache must not erase dismissed attachments and cause a storm.
    retained=$(jq -cn --argjson seen "$seen" --argjson keys "$keys" '$seen - ($seen - $keys.connected)') || return 1
    if [[ $retained != "$seen" ]]; then usb_prompt::write_seen "$retained" || return 1; fi
    usb_prompt::enabled && usb_prompt::unlocked && usb_prompt::available || return 0
    pending=$(jq -cn --argjson seen "$retained" --argjson keys "$keys" '$keys.pending - $seen') || return 1
    [[ $pending != '[]' ]] || return 0
    next=$(jq -cn --argjson seen "$retained" --argjson pending "$pending" '$seen + $pending | unique') || return 1
    # Record before launching. Cancelled authentication, a dismissed dialog, or
    # an unavailable GUI leaves USB blocked without repeated automatic prompts.
    usb_prompt::write_seen "$next" || return 1
    usb_prompt::launch
}

usb_prompt::run() {
    [[ $EUID -ne 0 ]] || {
        printf 'Run the USB prompt agent as your desktop user.\n' >&2
        return 1
    }
    usb_prompt::prepare && usb_prompt::lock || return 1
    while :; do
        usb_prompt::poll || :
        sleep 2
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -u
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    usb_prompt_source=$(readlink -f -- "${BASH_SOURCE[0]}") || exit 1
    # shellcheck source=src/lib/status.sh
    source "${usb_prompt_source%/*}/lib/status.sh"
    unset usb_prompt_source
    usb_prompt::run
fi
