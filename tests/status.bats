#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2030,SC2031,SC2317,SC2329
setup() {
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
    status::secure_boot() { status::result unknown 'Not verified'; }
    status::disk_encryption() { status::result unknown 'Not verified'; }
    status::thunderbolt() { status::result unsupported 'Not available'; }
    status::containers() { status::result unknown 'Not verified'; }
    status::forwarding() { status::result partial 'Forwarding enabled'; }
    status::network_snapshot() { printf '{"connected_count":1,"fingerprint":"%064d"}\n' 0; }
    usb::devices_json() { printf '[]\n'; }
}

@test 'background status uses the canonical CLI version without a second version constant' {
    unset OCTOSHIELD_VERSION
    run status::version
    [ "$status" -eq 0 ]
    [ "$output" = "$(bash "$BATS_TEST_DIRNAME/../scripts/version.sh")" ]
}

@test 'passive container inspection never activates a stopped Docker service' {
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

@test 'public pending USB devices never contain identifying descriptors' {
    usb::devices_json() {
        printf '%s\n' '[{"id":2,"state":"blocked","name":"PRIVATE","serial":"SECRET","hash":"HASH"},{"id":3,"state":"allowed","name":"HIDDEN"},{"id":4,"state":"rejected"},{"id":-5,"state":"blocked"}]'
    }
    run status::pending_devices
    [ "$status" -eq 0 ]
    [ "$output" = '[{"id":2,"state":"blocked","label":"USB device"},{"id":4,"state":"rejected","label":"USB device"}]' ]
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

@test 'disk encryption never claims full disk coverage from root mapper alone' {
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    status::run() {
        case "$1" in findmnt) printf '/dev/mapper/root\n' ;; lsblk) printf 'lvm\ncrypt\npart\ndisk\n' ;; *) return 1 ;; esac
    }
    run status::disk_encryption
    [ "$status" -eq 0 ]
    jq -e '.state == "partial" and (.summary | contains("Other disks"))' <<<"$output"
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
