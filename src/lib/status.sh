#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Read-only observations. The public cache contains summaries, never command
# output, connection names, addresses, USB descriptors, or authentication data.
STATUS_DIRECTORY=/run/octoshield
STATUS_MAX_AGE=90
STATUS_MAX_BYTES=262144
STATUS_ETC=/etc
STATUS_SYS=/sys
STATUS_PROC=/proc

status::run() { timeout --kill-after=1s 6s env LC_ALL=C "$@" 2>/dev/null; }

status::result() {
    jq -cn --arg state "$1" --arg summary "$2" '{state:$state,summary:$summary}'
}

status::unit() {
    local value
    value=$(status::run systemctl show --property=ActiveState --value "$1") || return 1
    case "$value" in active | inactive | failed | activating | deactivating) printf '%s\n' "$value" ;; *) return 1 ;; esac
}

status::firewall() {
    local observed raw defaults
    if ! command -v ufw >/dev/null 2>&1; then
        status::result inactive 'UFW is not installed.'
        return
    fi
    observed=$(status::run ufw status verbose) || {
        status::result unknown 'The current firewall policy could not be read.'
        return
    }
    if [[ $observed == *'Status: inactive'* ]]; then
        status::result inactive 'UFW is inactive; another firewall may have its own rules.'
        return
    fi
    [[ $observed == *'Status: active'* ]] || {
        status::result unknown 'UFW returned an unrecognized status.'
        return
    }
    defaults=$(awk -F= '/^[[:space:]]*IPV6[[:space:]]*=/ {gsub(/[[:space:]"\047]/,"",$2); value=$2} END {print value}' "$STATUS_ETC/default/ufw" 2>/dev/null) || defaults=
    raw=$(status::run ufw show raw) || raw=
    if [[ $observed != *'deny (incoming)'* || $observed != *'allow (outgoing)'* || $observed != *'deny (routed)'* || $defaults != yes || $raw != *'ufw6-before-input'* ]]; then
        status::result partial 'UFW is active, but incoming, forwarding, outgoing, and IPv6 baseline protections could not all be verified.'
    elif [[ $observed == *'ALLOW IN'* || $observed == *'ALLOW FWD'* || $observed == *'LIMIT IN'* ]]; then
        status::result partial 'UFW is active with incoming exceptions. Adopt a profile to manage and verify those exceptions.'
    else
        status::result active 'UFW blocks unsolicited incoming and forwarded traffic, permits outgoing traffic, and has IPv6 rules. No managed profile is selected.'
    fi
}

status::usb() {
    local observed count service
    if declare -F usb::profile_status >/dev/null; then
        usb::profile_status
        return
    fi
    if ! command -v usbguard >/dev/null 2>&1; then
        status::result inactive 'USBGuard is not installed.'
        return
    fi
    service=$(status::unit usbguard.service) || {
        status::result unknown 'USBGuard service status is unavailable.'
        return
    }
    [[ $service == active ]] || {
        status::result inactive 'USBGuard is not running.'
        return
    }
    observed=$(status::run usbguard list-devices) || {
        status::result unknown 'USBGuard device authorization could not be read.'
        return
    }
    count=$(awk '/^[0-9]+: (block|reject) / {n++} END {print n+0}' <<<"$observed")
    jq -cn --argjson pending "$count" '{state:"partial",summary:"USBGuard is running; its policy has not been verified against a managed profile.",pending:$pending}'
}

status::network() {
    local daemon config
    if ! command -v nmcli >/dev/null 2>&1; then
        status::result unsupported 'NetworkManager is unavailable; this network stack is not managed by OctoShield.'
        return
    fi
    daemon=$(status::run nmcli --terse --fields RUNNING general) || {
        status::result unknown 'NetworkManager status could not be read.'
        return
    }
    [[ $daemon == running ]] || {
        status::result inactive 'NetworkManager is not running.'
        return
    }
    config="$STATUS_ETC/NetworkManager/conf.d/90-octoshield.conf"
    if [[ -f $config ]]; then
        status::result partial 'Network privacy defaults exist, but effective connection settings are not verified against a profile.'
    else
        status::result inactive 'NetworkManager is running without a verified OctoShield privacy profile.'
    fi
}

status::services() {
    local unit load state masked=0 present=0 exposed=0 unknown=0
    local -a units=(ssh.service ssh.socket avahi-daemon.service avahi-daemon.socket cups.service cups.socket cups.path cups-browsed.service bluetooth.service smbd.service nmbd.service gnome-remote-desktop.service)
    for unit in "${units[@]}"; do
        load=$(status::run systemctl show --property=LoadState --value "$unit") || {
            unknown=1
            continue
        }
        [[ $load == not-found ]] && continue
        case "$load" in loaded | masked) ;; *)
            unknown=1
            continue
            ;;
        esac
        present=$((present + 1))
        state=$(status::unit "$unit") || {
            unknown=1
            continue
        }
        [[ $state == active || $state == activating ]] && exposed=$((exposed + 1))
        [[ $load == masked && $state == inactive ]] && masked=$((masked + 1))
    done
    if ((unknown)); then
        status::result unknown 'Some sharing service states could not be inspected.'
    elif ((exposed)); then
        status::result partial 'One or more sharing services are running. Firewall exceptions determine whether they are reachable.'
    elif ((present == masked)); then
        status::result active 'Known system sharing services are absent or masked and stopped. Per-user services require separate review.'
    else status::result partial 'Known system sharing services are stopped, but some can still be activated.'; fi
}

status::monitor() {
    local service metadata modified now line file="$STATUS_DIRECTORY/events"
    service=$(status::unit octoshield-monitor.service) || {
        status::result unknown 'Security event monitor status is unavailable.'
        return
    }
    if [[ $service != active ]]; then
        status::result inactive 'Security event monitoring is stopped; firewall and USB enforcement are independent.'
        return
    fi
    if [[ ! -f $file || -L $file || -L $STATUS_DIRECTORY ]]; then
        status::result partial 'The monitor service is running, but its heartbeat is unavailable.'
        return
    fi
    metadata=$(stat -c '%u:%g:%a:%s:%Y' -- "$file") || {
        status::result unknown 'The monitor heartbeat could not be inspected.'
        return
    }
    if [[ ! $metadata =~ ^0:0:644:([0-9]{1,3}):([0-9]{1,12})$ ]] || ((BASH_REMATCH[1] > 255)); then
        status::result partial 'The monitor service is running, but its heartbeat is unsafe or malformed.'
        return
    fi
    modified=${BASH_REMATCH[2]}
    now=$(date +%s) || return 1
    if ((now - modified > 45 || modified - now > 5)); then
        status::result partial 'The monitor service is running, but its heartbeat is stale.'
        return
    fi
    IFS= read -r line <"$file" || line=
    if [[ $line =~ ^v1\ [0-9]+-[0-9]+-[0-9]+\ [0-9]{1,20}\ [0-9]{1,20}\ [0-9]{1,20}$ ]]; then
        status::result active 'The security event monitor is running and its heartbeat is current.'
    else status::result partial 'The monitor service is running, but its heartbeat is malformed.'; fi
}

status::updates() {
    local config timer
    config=$(status::run apt-config dump) || {
        status::result unknown 'Automatic update configuration could not be read.'
        return
    }
    timer=$(status::unit apt-daily-upgrade.timer) || {
        status::result unknown 'Automatic update timer status is unavailable.'
        return
    }
    if [[ $config == *'APT::Periodic::Unattended-Upgrade "1";'* && $config != *'APT::Periodic::Enable "0";'* && $config == *'APT::Periodic::Update-Package-Lists "1";'* && $timer == active ]]; then
        status::result active 'Automatic upgrades are configured and their timer is active. This does not mean every update is installed.'
    elif [[ $timer == active ]]; then
        status::result partial 'The upgrade timer is active, but daily unattended upgrades are not verified.'
    else status::result inactive 'Daily automatic upgrades are not active.'; fi
}

status::apparmor() {
    local report enforce complain
    if ! command -v aa-status >/dev/null 2>&1; then
        status::result unsupported 'AppArmor inspection tools are unavailable.'
        return
    fi
    if [[ ! -r $STATUS_SYS/module/apparmor/parameters/enabled ]]; then
        status::result unsupported 'The running kernel does not expose AppArmor support.'
        return
    fi
    [[ $(<"$STATUS_SYS/module/apparmor/parameters/enabled") == Y ]] || {
        status::result inactive 'AppArmor is disabled in the running kernel.'
        return
    }
    report=$(status::run aa-status --json) || {
        status::result unknown 'AppArmor is enabled, but loaded policy could not be inspected.'
        return
    }
    enforce=$(jq -er '[.profiles[] | select(. == "enforce")] | length' <<<"$report" 2>/dev/null) || {
        status::result unknown 'AppArmor returned an unrecognized policy report.'
        return
    }
    complain=$(jq -er '[.profiles[] | select(. != "enforce")] | length' <<<"$report" 2>/dev/null) || complain=1
    if ((enforce == 0)); then
        status::result partial 'AppArmor is enabled but no enforcing profiles were found.'
    elif ((complain)); then
        status::result partial 'AppArmor has enforcing profiles and profiles in other modes. Coverage is not universal.'
    else status::result active 'Installed AppArmor profiles are enforcing; applications without a profile are not confined by this check.'; fi
}

status::sudo() {
    local config="$STATUS_ETC/sudoers.d/99-octoshield"
    if [[ -r $config ]] && grep -Eq '^[[:space:]]*Defaults[[:space:]]+timestamp_timeout=0[[:space:]]*$' "$config"; then
        status::result partial 'The zero-timeout sudo policy exists. User-specific overrides and passwordless grants still require review.'
    else status::result inactive 'OctoShield has not configured fresh authentication for each sudo command.'; fi
}

status::secure_boot() {
    local observed
    if [[ ! -d $STATUS_SYS/firmware/efi ]]; then
        status::result unsupported 'This boot does not expose UEFI Secure Boot.'
        return
    fi
    if ! command -v mokutil >/dev/null 2>&1; then
        status::result unknown 'Secure Boot verification requires mokutil.'
        return
    fi
    observed=$(status::run mokutil --sb-state) || {
        status::result unknown 'Secure Boot state could not be read.'
        return
    }
    if [[ $observed == *'SecureBoot enabled'* ]]; then
        status::result active 'UEFI Secure Boot is enabled for this boot.'
    elif [[ $observed == *'SecureBoot disabled'* ]]; then
        status::result inactive 'UEFI Secure Boot is disabled.'
    else status::result unknown 'Secure Boot returned an unrecognized state.'; fi
}

status::disk_encryption() {
    local source tree
    source=$(status::run findmnt --noheadings --output SOURCE /) || {
        status::result unknown 'The root filesystem storage source could not be inspected.'
        return
    }
    # Btrfs subvolumes add [subvolume]; discard it without evaluating any text.
    source=${source%%\[*}
    [[ $source == /dev/* && $source != *$'\n'* ]] || {
        status::result unknown 'The root filesystem uses a storage topology whose encryption cannot be verified here.'
        return
    }
    tree=$(status::run lsblk --inverse --noheadings --raw --output TYPE "$source") || {
        status::result unknown 'The root filesystem backing devices could not be inspected.'
        return
    }
    if grep -qx '[[:space:]]*crypt[[:space:]]*' <<<"$tree"; then
        status::result partial 'An encrypted block device backs the root filesystem. Other disks, home, swap, and unencrypted boot data are not verified.'
    else
        status::result unknown 'No encrypted block-device ancestor was verified for the root filesystem. Filesystem-level encryption and other storage need separate review.'
    fi
}

status::thunderbolt() {
    local domain device security iommu domains=0 unprotected=0 authorized=0 unreadable=0
    for domain in "$STATUS_SYS"/bus/thunderbolt/devices/domain*; do
        [[ -d $domain ]] || continue
        domains=$((domains + 1))
        security='' iommu=''
        [[ -r $domain/security ]] && read -r security <"$domain/security"
        [[ -r $domain/iommu_dma_protection ]] && read -r iommu <"$domain/iommu_dma_protection"
        [[ $iommu == 1 ]] || unprotected=$((unprotected + 1))
        [[ -n $security ]] || unreadable=1
    done
    for device in "$STATUS_SYS"/bus/thunderbolt/devices/*/authorized; do
        [[ -r $device ]] || continue
        read -r security <"$device"
        [[ $security == 1 || $security == 2 ]] && authorized=$((authorized + 1))
    done
    if ((domains == 0)); then
        status::result unsupported 'No Thunderbolt or USB4 domain is exposed by this kernel; hardware protection is not verified.'
    elif ((unreadable)); then
        status::result unknown 'Thunderbolt or USB4 authorization settings could not all be read.'
    elif ((unprotected)); then
        status::result partial 'Thunderbolt or USB4 is present, but IOMMU DMA protection is not confirmed for every domain. Device authorization needs separate review.'
    else
        jq -cn --argjson authorized "$authorized" '{state:"active",summary:"IOMMU DMA protection is reported for every detected Thunderbolt or USB4 domain. Ordinary USB approvals remain a separate policy.",authorized_devices:$authorized}'
    fi
}

status::containers() {
    local ports
    # Connecting to a socket-activated Docker daemon can start containers. A
    # passive inspection must not activate a stopped container service.
    if [[ $(status::unit docker.service) != active ]]; then
        status::result unknown 'The system Docker service is not running. Other container runtimes and rootless containers are not verified.'
        return
    fi
    if [[ ! -S /run/docker.sock && ! -S /var/run/docker.sock ]]; then
        status::result unknown 'No local system Docker socket was found. Rootless containers and other runtimes are not verified.'
        return
    fi
    if ! command -v docker >/dev/null 2>&1; then
        status::result unknown 'Docker is present, but its published ports cannot be inspected without the Docker client.'
        return
    fi
    ports=$(status::run env DOCKER_CONFIG=/var/empty docker --host=unix:///run/docker.sock ps --format '{{.Ports}}') || {
        status::result unknown 'Published Docker ports could not be inspected.'
        return
    }
    if [[ $ports == *'->'* ]]; then
        status::result partial 'Running Docker containers publish host ports. Their forwarding path can bypass UFW; review container exposure separately.'
    else
        status::result unknown 'No published ports were reported by the system Docker daemon. Host networking, other runtimes, and rootless containers remain unverified.'
    fi
}

status::forwarding() {
    local ipv4 ipv6
    if [[ ! -r $STATUS_PROC/sys/net/ipv4/ip_forward || ! -r $STATUS_PROC/sys/net/ipv6/conf/all/forwarding ]]; then
        status::result unknown 'Kernel forwarding settings could not be read.'
        return
    fi
    read -r ipv4 <"$STATUS_PROC/sys/net/ipv4/ip_forward"
    read -r ipv6 <"$STATUS_PROC/sys/net/ipv6/conf/all/forwarding"
    if [[ $ipv4 == 0 && $ipv6 == 0 ]]; then
        status::result active 'Kernel IPv4 and IPv6 routing are disabled. Bridged virtual machines still need separate review.'
    elif [[ $ipv4 =~ ^[01]$ && $ipv6 =~ ^[01]$ ]]; then
        status::result partial 'Kernel network forwarding is enabled. Virtual machines, containers, and bridged networks need separate firewall review.'
    else status::result unknown 'Kernel forwarding settings were not recognized.'; fi
}

status::network_snapshot() {
    local device state records='' count=0 fingerprint connections
    # Only the digest and count leave the root collector. Device names are never
    # published, and NetworkManager profile names/addresses are not collected.
    for device in "$STATUS_SYS"/class/net/*; do
        [[ -d $device && ${device##*/} != lo ]] || continue
        state=unknown
        [[ -r $device/carrier ]] && read -r state <"$device/carrier"
        [[ $state == 1 ]] && count=$((count + 1))
        records+="${device##*/}:$state;"
    done
    if command -v nmcli >/dev/null 2>&1; then
        connections=$(status::run nmcli --terse --fields UUID,TYPE,DEVICE connection show --active) || connections=unavailable
        records+="$connections"
    fi
    fingerprint=$(printf '%s' "$records" | sha256sum) || return 1
    fingerprint=${fingerprint%% *}
    jq -cn --arg fingerprint "$fingerprint" --argjson connected_count "$count" '{fingerprint:$fingerprint,connected_count:$connected_count}'
}

status::valid_result() {
    jq -e 'type == "object" and (.state | IN("active","inactive","partial","unknown","unsupported")) and (.summary | type == "string" and length <= 1024)' >/dev/null 2>&1
}

status::control() {
    local name=$1 profile='' observed
    if declare -F profiles::active >/dev/null; then profile=$(profiles::active "$name" 2>/dev/null) || profile=; fi
    case "$name" in
        firewall | network | services | monitor)
            if [[ -n $profile && $profile != unmanaged ]] && declare -F profiles::verify >/dev/null; then
                observed=$(profiles::verify "$name" 2>/dev/null) || observed=
                if [[ $name == monitor ]] && [[ $(jq -r '.state' <<<"$observed" 2>/dev/null) == active ]]; then observed=$(status::monitor) || observed=; fi
                if status::valid_result <<<"$observed"; then printf '%s\n' "$observed"; else status::result unknown 'The effective profile could not be verified.'; fi
                return
            fi
            ;;
    esac
    observed=$("status::$name" 2>/dev/null) || observed=
    if status::valid_result <<<"$observed"; then printf '%s\n' "$observed"; else status::result unknown 'This protection could not be inspected.'; fi
}

status::profile_snapshot() {
    local data='{}' available=false
    if declare -F profiles::public_status >/dev/null; then
        if data=$(profiles::public_status 2>/dev/null); then available=true; else data='{}'; fi
    fi
    # Explicit projection excludes any future private fields added by adapters.
    jq -ce --argjson available "$available" '
        def safeid: type == "string" and test("^[a-z][a-z0-9_-]{0,47}$");
        def mappings: if type == "object" then with_entries(select((.key | IN("firewall","usb","network","services","monitor","sudo","updates","apparmor")) and (.value | safeid))) else {} end;
        {available:$available,active:(if (.global | safeid) then .global else "unmanaged" end),
         global:(if (.global | safeid) then .global else "unmanaged" end),
         assignments:(.active | mappings), overrides:(.overrides | mappings),
         results:((.results // {}) | with_entries(select((.key | IN("firewall","usb","network","services","monitor")) and (.value.status | IN("applied","failed","unmanaged","pending","applying"))) | .value |= {status:.status})),
         catalog:[(.catalog // [])[] | select((.id | safeid) and (.name | type == "string")) | {id,name:(.name | gsub("[\u0000-\u001f\u007f]";"") | .[0:80])}]}
    ' <<<"$data" 2>/dev/null || printf '%s\n' '{"available":false,"active":"unmanaged","global":"unmanaged","assignments":{},"overrides":{},"results":{},"catalog":[]}'
}

status::pending_devices() {
    local devices='[]'
    if declare -F usb::devices_json >/dev/null; then devices=$(usb::devices_json 2>/dev/null) || devices='[]'; fi
    jq -ce '[.[] | select((.id | type == "number" and . >= 1 and . <= 4294967295 and floor == .) and (.state | IN("blocked","rejected"))) | {id,state,label:"USB device"}] | .[0:256]' <<<"$devices" 2>/dev/null || printf '[]\n'
}

status::version() {
    local version=${OCTOSHIELD_VERSION:-} source_file
    if [[ -z $version ]]; then
        source_file=${BASH_SOURCE[0]%/lib/status.sh}/octoshield
        version=$(sed -n 's/^readonly OCTOSHIELD_VERSION=//p' "$source_file") || return 1
    fi
    [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
    printf '%s\n' "$version"
}

status::collect() {
    local controls='{}' exposures='{}' name observed profiles network pending checked devices usb_profile version
    version=$(status::version) || return 1
    profiles=$(status::profile_snapshot) || return 1
    for name in firewall usb network services monitor updates apparmor sudo; do
        observed=$(status::control "$name") || return 1
        # Project the adapter result, so device descriptors cannot accidentally
        # leak into the public cache as adapters gain more private fields.
        observed=$(jq -c '{state,summary,pending:(.pending // 0),profile:(if (.profile | type == "string" and test("^[a-z][a-z0-9-]{0,31}$")) then .profile else "unmanaged" end)}' <<<"$observed") || return 1
        case "$name" in
            firewall | usb | network | services | monitor)
                observed=$(jq -cn --argjson profiles "$profiles" --argjson value "$observed" --arg name "$name" '
                    if $profiles.available != true then $value + {state:"unknown",summary:"Saved profile state could not be read; effective protection cannot be matched to your requested settings."}
                    elif ($profiles.results[$name].status | IN("failed","pending","applying")) then $value + {state:"partial",summary:("The requested profile change is " + $profiles.results[$name].status + ". " + $value.summary)}
                    else $value end') || return 1
                ;;
        esac
        controls=$(jq -cn --argjson current "$controls" --arg name "$name" --argjson value "$observed" '$current + {($name):$value}') || return 1
    done
    for name in secure_boot disk_encryption thunderbolt containers forwarding; do
        observed=$("status::$name" 2>/dev/null) || observed=
        status::valid_result <<<"$observed" || observed=$(status::result unknown 'This exposure could not be inspected.')
        exposures=$(jq -cn --argjson current "$exposures" --arg name "$name" --argjson value "$observed" '$current + {($name):($value | {state,summary})}') || return 1
    done
    network=$(status::network_snapshot) || return 1
    devices=$(status::pending_devices) || return 1
    pending=$(jq -er --argjson devices "$devices" '[($devices | length),(.usb.pending | if type == "number" and . >= 0 and . <= 65535 and floor == . then . else 0 end)] | max' <<<"$controls") || pending=0
    usb_profile=$(jq -er .usb.profile <<<"$controls") || return 1
    checked=$(date +%s) || return 1
    jq -cn --arg version "$version" --argjson checked "$checked" \
        --argjson controls "$controls" --argjson exposures "$exposures" --argjson profiles "$profiles" \
        --argjson network "$network" --argjson pending "$pending" --argjson devices "$devices" --arg usb_profile "$usb_profile" \
        '{schema:1,version:$version,checked_at:$checked,controls:$controls,exposures:$exposures,profiles:$profiles,network:$network,usb:{pending:$pending,devices:$devices,profile:$usb_profile}}'
}

status::validate_document() {
    jq -e '
        def state: IN("active","inactive","partial","unknown","unsupported");
        type == "object" and .schema == 1 and
        (.version | type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) and
        (.checked_at | type == "number" and . >= 0 and . <= 9007199254740991 and floor == .) and
        (.controls | type == "object") and
        (["firewall","usb","network","services","monitor","updates","apparmor","sudo"] - (.controls | keys) | length == 0) and
        (all(.controls[]; (.state | state) and (.summary | type == "string" and length <= 1024))) and
        (.exposures | type == "object") and
        (all(.exposures[]; (.state | state) and (.summary | type == "string" and length <= 1024))) and
        (.profiles.active | type == "string") and (.profiles.catalog | type == "array") and
        (.network.fingerprint | type == "string" and test("^[a-f0-9]{64}$")) and
        (.network.connected_count | type == "number" and . >= 0 and . <= 65535 and floor == .) and
        (.usb.pending | type == "number" and . >= 0 and . <= 65535 and floor == .) and
        (.usb.devices | type == "array" and length <= 256 and all(.[]; (.id | type == "number" and . >= 1 and . <= 4294967295 and floor == .) and (.state | IN("blocked","rejected")) and .label == "USB device"))
    ' >/dev/null 2>&1
}

status::refresh() (
    local data temporary metadata
    ((EUID == 0)) || return 1
    [[ ! -L $STATUS_DIRECTORY ]] || return 1
    if [[ -e $STATUS_DIRECTORY ]]; then
        [[ -d $STATUS_DIRECTORY ]] || return 1
        metadata=$(stat -c '%u:%g:%a' -- "$STATUS_DIRECTORY") || return 1
        [[ $metadata == 0:0:755 ]] || return 1
    else install -d -m 0755 -o root -g root -- "$STATUS_DIRECTORY" || return 1; fi
    [[ ! -L $STATUS_DIRECTORY/status.json ]] || return 1
    data=$(status::collect) || return 1
    ((${#data} <= STATUS_MAX_BYTES)) || return 1
    status::validate_document <<<"$data" || return 1
    temporary=$(mktemp "$STATUS_DIRECTORY/.status.XXXXXXXX") || return 1
    trap 'rm -f -- "$temporary"' EXIT
    printf '%s\n' "$data" >"$temporary" || return 1
    chmod 0644 "$temporary" && chown root:root "$temporary" || return 1
    mv -fT -- "$temporary" "$STATUS_DIRECTORY/status.json"
)

status::read() {
    local file="$STATUS_DIRECTORY/status.json" metadata size modified now document checked
    [[ -d $STATUS_DIRECTORY && ! -L $STATUS_DIRECTORY && -f $file && ! -L $file ]] || return 1
    metadata=$(stat -c '%u:%g:%a' -- "$STATUS_DIRECTORY") || return 1
    [[ $metadata == 0:0:755 ]] || return 1
    metadata=$(stat -c '%u:%g:%a:%s:%Y' -- "$file") || return 1
    [[ $metadata =~ ^0:0:644:([0-9]{1,7}):([0-9]{1,12})$ ]] || return 1
    size=${BASH_REMATCH[1]} modified=${BASH_REMATCH[2]}
    ((size > 0 && size <= STATUS_MAX_BYTES)) || return 1
    now=$(date +%s) || return 1
    ((now - modified <= STATUS_MAX_AGE && modified - now <= 5)) || return 1
    document=$(head -c "$((STATUS_MAX_BYTES + 1))" -- "$file") || return 1
    ((${#document} <= STATUS_MAX_BYTES)) || return 1
    status::validate_document <<<"$document" || return 1
    checked=$(jq -er .checked_at <<<"$document") || return 1
    ((now - checked <= STATUS_MAX_AGE && checked - now <= 5)) || return 1
    printf '%s\n' "$document"
}

status::text() {
    local document
    document=$(status::read) || {
        printf 'Live status is unavailable or stale. Run octoshield inspect as administrator to refresh it.\n' >&2
        return 1
    }
    jq -r '"Profile: " + .profiles.active, (.controls | to_entries[] | .key + ": " + .value.state + " — " + .value.summary), (.exposures | to_entries[] | .key + ": " + .value.state + " — " + .value.summary)' <<<"$document"
}
