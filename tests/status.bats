#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2030,SC2031,SC2317,SC2329
setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_DIRECTORY="$BATS_TEST_TMPDIR/run"
    STATUS_ETC="$BATS_TEST_TMPDIR/etc"
    STATUS_SYS="$BATS_TEST_TMPDIR/sys"
    STATUS_PROC="$BATS_TEST_TMPDIR/proc"
    mkdir -m 0755 "$STATUS_DIRECTORY"
    mkdir -p "$STATUS_ETC/default" "$STATUS_SYS" "$STATUS_PROC"
    # Production requires root ownership. The fixtures remain usable in CI as an
    # ordinary user; every other permission and size check uses real stat data.
    stat() {
        local value
        value=$(command stat "$@") || return 1
        if [[ $1 == -c && $2 == '%u:%g:%a'* ]]; then value="0:0:${value#*:*:}"; fi
        printf '%s\n' "$value"
    }
    profiles::public_status() {
        printf '%s\n' '{"global":"conference","active":{"firewall":"conference","usb":"office"},"overrides":{"usb":"office"},"results":{},"catalog":[{"id":"conference","name":"Conference"},{"id":"home","name":"Home"}]}'
    }
    status::control() { status::result active 'Verified test control'; }
    repair::status() { status::result active 'No known retired settings need repair.'; }
    status::secure_boot() { status::result unknown 'Not verified'; }
    status::disk_encryption() { status::result unknown 'Not verified'; }
    status::thunderbolt() { status::result unsupported 'Not available'; }
    status::containers() { status::result unknown 'Not verified'; }
    status::forwarding() { status::result partial 'Forwarding enabled'; }
    status::network_snapshot() { printf '{"connected_count":1,"fingerprint":"%064d"}\n' 0; }
    usb::devices_json() { printf '[]\n'; }
}

@test 'native status probes keep the observer process group without inheriting operation locks' {
    exec 6>"$BATS_TEST_TMPDIR/admission" 8>"$BATS_TEST_TMPDIR/reader" 9>"$BATS_TEST_TMPDIR/writer"
    core::timeout() {
        [[ $1 == --foreground && $2 == --kill-after=1s && $3 == 6s && $4 == env && $5 == LC_ALL=C ]] || return 99
        local descriptor
        for descriptor in 6 8 9; do
            if { : >&"$descriptor"; } 2>/dev/null; then return 98; fi
        done
        printf '%s\n' "${@:6}"
    }
    run status::run systemctl show 'unit with spaces'
    [ "$status" -eq 0 ]
    [ "$output" = $'systemctl\nshow\nunit with spaces' ]
    # Redirections affect only the probe; its observer still owns its locks.
    : >&6
    : >&8
    : >&9
    exec 6>&- 8>&- 9>&-
}

@test 'background status uses the canonical CLI version without a second version constant' {
    unset OCTOSHIELD_VERSION
    run status::version
    [ "$status" -eq 0 ]
    [ "$output" = "$(bash "$BATS_TEST_DIRNAME/../scripts/version.sh")" ]
}

@test 'passive container inspection never activates a stopped Docker service' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    status::unit() { printf 'inactive\n'; }
    status::run() {
        printf 'must not connect to Docker\n' >"$BATS_TEST_TMPDIR/activated"
        return 1
    }
    run status::containers
    [ "$status" -eq 0 ]
    [ "$(jq -r .state <<<"$output")" = unknown ]
    [ ! -e "$BATS_TEST_TMPDIR/activated" ]
}

fixture() {
    status::collect >"$STATUS_DIRECTORY/status.json"
    chmod 0644 "$STATUS_DIRECTORY/status.json"
}

@test 'cache carries actual states, profile overrides and unmodified names' {
    fixture
    run status::read
    [ "$status" -eq 0 ]
    jq -e '.schema == 1 and .profiles.available and .profiles.active == "conference" and .profiles.overrides.usb == "office" and .profiles.catalog[1].name == "Home" and .exposures.forwarding.state == "partial"' <<<"$output"
}

@test 'repair observations replace the retired sudo control without publishing private fields' {
    repair::status() { printf '%s\n' '{"state":"partial","summary":"A retired setting can be repaired.","private":"PRIVATE RECOVERY DATA"}'; }
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '(.controls | has("sudo") | not) and .recovery.repairs == {state:"partial",summary:"A retired setting can be repaired."}' <<<"$output"
    [[ $output != *'PRIVATE RECOVERY DATA'* ]]
    status::validate_document <<<"$output"
}

@test 'missing or failed repair inspection leaves other observations usable' {
    unset -f repair::status
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.recovery.repairs.state == "unknown" and .controls.firewall.state == "active"' <<<"$output"
    status::validate_document <<<"$output"
    repair::status() { return 1; }
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.recovery.repairs.state == "unknown" and .controls.firewall.state == "active"' <<<"$output"
    status::validate_document <<<"$output"
}

@test 'invalid repair output falls back to unknown instead of claiming a completed repair' {
    local repair_fixture
    repair::status() { printf '%s\n' "$repair_fixture"; }
    for repair_fixture in '' 'not json' 'null' '[]' '{"state":"active"}' '{"state":"complete","summary":"Invalid state"}' $'{"state":"active","summary":"First"}\n{"state":"active","summary":"Second"}'; do
        run status::collect
        [ "$status" -eq 0 ]
        jq -e '.recovery.repairs.state == "unknown" and .controls.firewall.state == "active"' <<<"$output"
        status::validate_document <<<"$output"
    done
}

@test 'older status caches remain readable without an optional repair observation' {
    local document
    document=$(status::collect)
    document=$(jq 'del(.recovery) | .controls.sudo = {state:"partial",summary:"Legacy observer output"}' <<<"$document")
    printf '%s\n' "$document" >"$STATUS_DIRECTORY/status.json"
    chmod 0644 "$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -eq 0 ]
    jq -e '(has("recovery") | not) and .controls.firewall.state == "active"' <<<"$output"
    status::validate_document <<<"$(jq '.recovery = {}' <<<"$document")"
}

@test 'optional repair observations are validated when present' {
    local document alteration
    document=$(status::collect)
    for alteration in '.recovery = null' '.recovery = []' '.recovery.repairs = null' '.recovery.repairs = []' '.recovery.repairs.state = "complete"' '.recovery.repairs.summary = 10' '.recovery.repairs.summary = ("x" * 1025)'; do
        run status::validate_document <<<"$(jq "$alteration" <<<"$document")"
        [ "$status" -ne 0 ]
    done
}

@test 'profile projection removes control bytes and private fields' {
    profiles::public_status() {
        printf '%s\n' '{"global":"conference","active":{},"overrides":{},"results":{"firewall":{"status":"failed","message":"secret source"}},"catalog":[{"id":"home","name":"Ho\nme","secret":"SERIAL"}],"private":"SECRET"}'
    }
    run status::profile_snapshot
    [ "$status" -eq 0 ]
    jq -e '.catalog[0].name == "Home" and .results.firewall.status == "failed" and .results.firewall.message == null and .private == null and .catalog[0].secret == null' <<<"$output"
}

@test 'failed and pending profile transitions never report green controls' {
    profiles::public_status() {
        printf '%s\n' '{"global":"conference","active":{},"overrides":{},"catalog":[],"results":{"firewall":{"status":"failed","message":"details"},"usb":{"status":"pending","message":"details"}}}'
    }
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.controls.firewall.state == "partial" and .controls.usb.state == "partial" and (.controls.firewall.summary | contains("failed"))' <<<"$output"
}

@test 'unreadable saved profile state is unknown even when native checks pass' {
    profiles::public_status() { return 1; }
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.profiles.available == false and .controls.firewall.state == "unknown" and .controls.usb.state == "unknown"' <<<"$output"
}

@test 'public USB inventory includes safe names and allowed devices without private identities' {
    usb::devices_json() {
        jq -cn --arg token "$(printf '%064d' 1)" '
            {token:$token,category:"storage",profile:"office",vendor_product:"1234:abcd",port:"1-2",remembered:false} as $base |
            [$base + {id:2,state:"blocked",name:"Office\u202e USB\n disk",serial:"SECRET",hash:"HASH"},
             $base + {id:3,state:"allowed",name:"Allowed drive",remembered:true},
             $base + {id:4,state:"rejected"}, $base + {id:-5,state:"blocked"},
             $base + {id:6,state:"blocked",token:"invalid"}]'
    }
    run status::pending_devices
    [ "$status" -eq 0 ]
    jq -e 'length == 3 and .[0].label == "Office USB disk" and .[1].state == "allowed" and .[1].remembered and .[2].label == "USB device" and all(.[]; .hash == null and .serial == null)' <<<"$output"
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.usb.pending == 2 and (.usb.devices | length == 3)' <<<"$output"
    status::validate_document <<<"$output"
}

@test 'cache validation refuses unsafe USB labels and invalid attachment tokens' {
    local document row
    document=$(status::collect)
    row=$(jq -cn --arg token "$(printf '%064d' 1)" '{id:2,token:$token,state:"blocked",category:"storage",profile:"office",vendor_product:"1234:abcd",port:"1-2",remembered:false,name:"USB disk",label:"USB disk"}')
    document=$(jq -c --argjson row "$row" '.usb.devices = [$row]' <<<"$document")
    status::validate_document <<<"$document"
    run status::validate_document <<<"$(jq '.usb.devices[0].token = "unbound"' <<<"$document")"
    [ "$status" -ne 0 ]
    run status::validate_document <<<"$(jq '.usb.devices[0].label = "USB\u202e disk"' <<<"$document")"
    [ "$status" -ne 0 ]
}

@test 'cache rejects symlink targets and unsafe directories' {
    fixture
    mv "$STATUS_DIRECTORY/status.json" "$STATUS_DIRECTORY/real.json"
    ln -s real.json "$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
    rm "$STATUS_DIRECTORY/status.json"
    mv "$STATUS_DIRECTORY/real.json" "$STATUS_DIRECTORY/status.json"
    chmod 0775 "$STATUS_DIRECTORY"
    run status::read
    [ "$status" -ne 0 ]
}

@test 'cache rejects writable, oversized, stale, and malformed documents' {
    fixture
    chmod 0664 "$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
    chmod 0644 "$STATUS_DIRECTORY/status.json"
    touch -d '3 minutes ago' "$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
    fixture
    head -c 262145 /dev/zero >"$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
    printf '{}\n' >"$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
}

@test 'fresh mtime cannot make stale observations current' {
    fixture
    local data
    data=$(jq '.checked_at = 1' "$STATUS_DIRECTORY/status.json")
    printf '%s\n' "$data" >"$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
}

@test 'future and noninteger observation timestamps are rejected' {
    fixture
    local data
    data=$(jq --argjson now "$(date +%s)" '.checked_at = $now + 3600' "$STATUS_DIRECTORY/status.json")
    printf '%s\n' "$data" >"$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
    data=$(jq '.checked_at = 1.5' "$STATUS_DIRECTORY/status.json")
    printf '%s\n' "$data" >"$STATUS_DIRECTORY/status.json"
    run status::read
    [ "$status" -ne 0 ]
}

@test 'reader rejects ownership from an untrusted writer' {
    fixture
    stat() { command stat "$@" | sed 's/^0:0:/1000:1000:/'; }
    run status::read
    [ "$status" -ne 0 ]
}

@test 'collector publishes atomically and preserves cache on failed validation' {
    ((EUID == 0)) || skip 'atomic root-owned publishing is exercised as root in package tests'
    status::refresh
    local original
    original=$(cat "$STATUS_DIRECTORY/status.json")
    status::collect() { printf '{}\n'; }
    run status::refresh
    [ "$status" -ne 0 ]
    [ "$(cat "$STATUS_DIRECTORY/status.json")" = "$original" ]
    [ "$(command stat -c %a "$STATUS_DIRECTORY/status.json")" = 644 ]
}

@test 'AppArmor loaded profiles retain honest partial coverage' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_SYS="$BATS_TEST_TMPDIR/sys"
    mkdir -p "$STATUS_SYS/module/apparmor/parameters"
    printf Y >"$STATUS_SYS/module/apparmor/parameters/enabled"
    aa-status() { :; }
    status::run() { printf '{"profiles":{"one":"enforce","two":"complain"}}\n'; }
    run status::apparmor
    [ "$status" -eq 0 ]
    jq -e '.state == "partial"' <<<"$output"
}

@test 'verified root encryption is positive without claiming whole disk coverage' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    status::run() {
        case "$1" in
            findmnt) printf '/dev/mapper/root\n' ;;
            lsblk) printf '%s\n' '{"blockdevices":[{"name":"root","type":"lvm","children":[{"name":"luks","type":"crypt","children":[{"name":"disk","type":"disk"}]}]}]}' ;;
            *) return 1 ;;
        esac
    }
    run status::disk_encryption
    [ "$status" -eq 0 ]
    jq -e '.state == "active" and (.summary | contains("not a whole-disk certification")) and .source == null' <<<"$output"
}

@test 'missing Thunderbolt DMA evidence never reports full protection' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_SYS="$BATS_TEST_TMPDIR/sys"
    mkdir -p "$STATUS_SYS/bus/thunderbolt/devices/domain0"
    printf 'user\n' >"$STATUS_SYS/bus/thunderbolt/devices/domain0/security"
    run status::thunderbolt
    [ "$status" -eq 0 ]
    jq -e '.state == "partial"' <<<"$output"
    printf '1\n' >"$STATUS_SYS/bus/thunderbolt/devices/domain0/iommu_dma_protection"
    run status::thunderbolt
    [ "$status" -eq 0 ]
    jq -e '.state == "active"' <<<"$output"
}

@test 'firewall needs actual IPv6 chain evidence as well as enabled configuration' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_ETC="$BATS_TEST_TMPDIR/etc"
    printf 'IPV6=yes\n' >"$STATUS_ETC/default/ufw"
    ufw() { :; }
    status::run() {
        [[ $2 == status ]] && printf 'Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n'
        return 0
    }
    run status::firewall
    [ "$status" -eq 0 ]
    jq -e '.state == "partial"' <<<"$output"
    status::run() {
        if [[ $2 == status ]]; then printf 'Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n'; else printf 'Chain ufw6-before-input\n'; fi
    }
    run status::firewall
    [ "$status" -eq 0 ]
    jq -e '.state == "active"' <<<"$output"
}

@test 'active monitor needs a recent valid heartbeat' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_DIRECTORY="$BATS_TEST_TMPDIR/run"
    status::unit() { printf 'active\n'; }
    run status::monitor
    [ "$status" -eq 0 ]
    jq -e '.state == "partial"' <<<"$output"
    printf 'v1 1-2-3 0 0 0\n' >"$STATUS_DIRECTORY/events"
    chmod 0644 "$STATUS_DIRECTORY/events"
    run status::monitor
    [ "$status" -eq 0 ]
    jq -e '.state == "active"' <<<"$output"
    touch -d '2 minutes ago' "$STATUS_DIRECTORY/events"
    run status::monitor
    [ "$status" -eq 0 ]
    jq -e '.state == "partial" and (.summary | contains("stale"))' <<<"$output"
}

@test 'disabled APT periodic processing does not count as active updates' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    status::unit() { printf 'active\n'; }
    status::run() { printf '%s\n' 'APT::Periodic::Enable "0";' 'APT::Periodic::Unattended-Upgrade "1";' 'APT::Periodic::Update-Package-Lists "1";'; }
    run status::updates
    [ "$status" -eq 0 ]
    jq -e '.state == "partial"' <<<"$output"
}

@test 'Wi-Fi connection changes alter only the public fingerprint even with unchanged carrier' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    STATUS_SYS="$BATS_TEST_TMPDIR/sys"
    mkdir -p "$STATUS_SYS/class/net/wlan0"
    printf '1\n' >"$STATUS_SYS/class/net/wlan0/carrier"
    nmcli() { :; }
    status::run() { printf 'private-connection-one:wifi:wlan0\n'; }
    local first second
    first=$(status::network_snapshot)
    status::run() { printf 'private-connection-two:wifi:wlan0\n'; }
    second=$(status::network_snapshot)
    [ "$(jq -r .fingerprint <<<"$first")" != "$(jq -r .fingerprint <<<"$second")" ]
    [ "$(jq -r .connected_count <<<"$second")" = 1 ]
    [[ $first != *private* && $second != *private* ]]
}

@test 'actual USB legacy approval scope is retained independently of global profile assignment' {
    status::control() {
        if [[ $1 == usb ]]; then
            printf '{"state":"active","summary":"Legacy policy","profile":"legacy","pending":0}\n'
        else status::result active 'Test'; fi
    }
    run status::collect
    [ "$status" -eq 0 ]
    jq -e '.usb.profile == "legacy" and .profiles.assignments.usb == "office"' <<<"$output"
}

usb_fixture() {
    status::usb() { printf '{"state":"active","summary":"Verified USB policy","profile":"office","pending":1}\n'; }
    usb::devices_json() {
        jq -cn --arg token "$(printf '%064d' 1)" '[{id:7,token:$token,state:"blocked",category:"storage",profile:"office",vendor_product:"1234:abcd",port:"1-2",remembered:false,name:"USB disk"}]'
    }
    status::collect_usb >"$STATUS_DIRECTORY/usb.json"
    chmod 0644 "$STATUS_DIRECTORY/usb.json"
}

@test 'fast USB cache is readable independently of the full inspection' {
    usb_fixture
    [ ! -e "$STATUS_DIRECTORY/status.json" ]
    run status::read_usb
    [ "$status" -eq 0 ]
    jq -e '.schema == 1 and .usb.available and .usb.state == "active" and .usb.profile == "office" and .usb.pending == 1 and .usb.devices[0].name == "USB disk"' <<<"$output"
}

@test 'fast USB collection reuses a single verified snapshot without another inventory read' {
    usb_fixture
    usb::profile_snapshot() {
        printf 'snapshot\n' >>"$BATS_TEST_TMPDIR/snapshot-calls"
        jq '{available:.usb.available,status:{state:.usb.state,summary:.usb.summary,profile:.usb.profile,pending:.usb.pending},devices:.usb.devices}' "$STATUS_DIRECTORY/usb.json"
    }
    usb::devices_json() {
        printf 'duplicate\n' >>"$BATS_TEST_TMPDIR/duplicate-calls"
        return 1
    }
    run status::collect_usb
    [ "$status" -eq 0 ]
    status::validate_usb_document <<<"$output"
    jq -e '.usb.available and .usb.state == "active" and .usb.pending == 1' <<<"$output"
    [ "$(cat "$BATS_TEST_TMPDIR/snapshot-calls")" = snapshot ]
    [ ! -e "$BATS_TEST_TMPDIR/duplicate-calls" ]
}

@test 'full inspection reuses the USB snapshot for status and public device rows' {
    usb_fixture
    usb::profile_snapshot() {
        printf 'snapshot\n' >>"$BATS_TEST_TMPDIR/snapshot-calls"
        jq '{available:.usb.available,status:{state:.usb.state,summary:.usb.summary,profile:.usb.profile,pending:.usb.pending},devices:.usb.devices}' "$STATUS_DIRECTORY/usb.json"
    }
    usb::devices_json() {
        printf 'duplicate\n' >>"$BATS_TEST_TMPDIR/duplicate-calls"
        return 1
    }
    run status::collect
    [ "$status" -eq 0 ]
    status::validate_document <<<"$output"
    jq -e '.controls.usb.state == "active" and .usb.profile == "office" and .usb.pending == 1 and .usb.devices[0].name == "USB disk"' <<<"$output"
    [ "$(cat "$BATS_TEST_TMPDIR/snapshot-calls")" = snapshot ]
    [ ! -e "$BATS_TEST_TMPDIR/duplicate-calls" ]
}

@test 'a failed verified USB snapshot never falls back to an unrelated actionable inventory' {
    usb_fixture
    usb::profile_snapshot() { return 1; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    status::validate_usb_document <<<"$output"
    jq -e '(.usb.available | not) and .usb.state == "unknown" and (.usb.devices | length == 0)' <<<"$output"
}

@test 'fast USB refresh never advances or replaces the full inspection' {
    usb_fixture
    fixture
    local original
    original=$(cat "$STATUS_DIRECTORY/status.json")
    # Collector tests also run unprivileged in CI; only ownership-changing
    # system calls are mocked, while paths and atomic replacement remain real.
    chown() { :; }
    if ((EUID == 0)); then status::refresh_usb; else
        run status::refresh_usb
        [ "$status" -ne 0 ]
    fi
    [ "$(cat "$STATUS_DIRECTORY/status.json")" = "$original" ]
}

@test 'fast USB cache distinguishes unavailable data from no devices' {
    usb_fixture
    usb::devices_json() { return 1; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    status::validate_usb_document <<<"$output"
    jq -e '.usb.available == false and .usb.state == "unknown" and .usb.pending == 0 and (.usb.devices | length == 0)' <<<"$output"
    usb::devices_json() { printf '[]\n'; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    jq -e '.usb.available and .usb.state == "active" and .usb.pending == 0 and (.usb.devices | length == 0)' <<<"$output"
}

@test 'inactive and unmanaged USB never expose actionable fast inventory' {
    usb_fixture
    status::usb() { status::result inactive 'USBGuard is not running.'; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    jq -e '.usb.available == false and .usb.state == "unknown" and (.usb.devices | length == 0)' <<<"$output"
    status::usb() { status::result unknown 'USBGuard is not enrolled.'; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    jq -e '.usb.available == false and (.usb.devices | length == 0)' <<<"$output"
}

@test 'fast USB collection refuses invalid and mixed-profile inventories' {
    usb_fixture
    usb::devices_json() { printf '[{"id":7,"state":"blocked"}]\n'; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    jq -e '.usb.available == false' <<<"$output"
    usb_fixture
    status::usb() { printf '{"state":"active","summary":"New profile","profile":"conference"}\n'; }
    run status::collect_usb
    [ "$status" -eq 0 ]
    jq -e '.usb.available == false and .usb.profile == "conference"' <<<"$output"
}

@test 'fast USB reader enforces its own short observation lifetime' {
    usb_fixture
    local document
    document=$(jq --argjson checked "$(($(date +%s) - 11))" '.checked_at = $checked' "$STATUS_DIRECTORY/usb.json")
    printf '%s\n' "$document" >"$STATUS_DIRECTORY/usb.json"
    run status::read_usb
    [ "$status" -ne 0 ]
    usb_fixture
    touch -d '20 seconds ago' "$STATUS_DIRECTORY/usb.json"
    run status::read_usb
    [ "$status" -ne 0 ]
}

@test 'fast USB reader refuses symlinks, writable files and malformed documents' {
    usb_fixture
    chmod 0664 "$STATUS_DIRECTORY/usb.json"
    run status::read_usb
    [ "$status" -ne 0 ]
    chmod 0644 "$STATUS_DIRECTORY/usb.json"
    mv "$STATUS_DIRECTORY/usb.json" "$STATUS_DIRECTORY/real-usb.json"
    ln -s real-usb.json "$STATUS_DIRECTORY/usb.json"
    run status::read_usb
    [ "$status" -ne 0 ]
    rm "$STATUS_DIRECTORY/usb.json"
    printf '{"schema":1}\n' >"$STATUS_DIRECTORY/usb.json"
    chmod 0644 "$STATUS_DIRECTORY/usb.json"
    run status::read_usb
    [ "$status" -ne 0 ]
}

@test 'fast USB validator refuses duplicate attachments and dishonest pending counts' {
    usb_fixture
    local document
    document=$(cat "$STATUS_DIRECTORY/usb.json")
    run status::validate_usb_document <<<"$(jq '.usb.devices += .usb.devices | .usb.pending = 2' <<<"$document")"
    [ "$status" -ne 0 ]
    run status::validate_usb_document <<<"$(jq '.usb.pending = 0' <<<"$document")"
    [ "$status" -ne 0 ]
    run status::validate_usb_document <<<"$(jq '.usb.available = false' <<<"$document")"
    [ "$status" -ne 0 ]
}
