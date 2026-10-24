#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Read-only observations. The public cache contains summaries, never command
# output, connection names, addresses, private USB identities, or authentication
# data. USB display names are deliberately sanitized for the local device UI.
STATUS_DIRECTORY=/run/octoshield
STATUS_MAX_AGE=90
STATUS_USB_MAX_AGE=10
STATUS_MAX_BYTES=262144
STATUS_ETC=/etc
STATUS_SYS=/sys
STATUS_PROC=/proc

# Native probes stay in their observer's supervised group and never inherit
# its locks. A probe descendant must not retain a lock after its observer exits.
status::run() { core::timeout --foreground --kill-after=1s 6s env LC_ALL=C "$@" 6>&- 8>&- 9>&- 2>/dev/null; }

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

status::storage_probe() {
    local target=$1 source
    source=$(status::run findmnt --noheadings --output SOURCE --target "$target") || {
        status::result unknown 'The filesystem storage source could not be inspected.'
        return
    }
    # Btrfs subvolumes add [subvolume]; discard it without evaluating any text.
    source=${source%%\[*}
    status::storage_source_probe "$source"
}

status::storage_source_probe() {
    local source=$1 tree coverage state=unknown detail
    [[ $source == /dev/* && $source != *$'\n'* ]] || {
        status::result unknown 'This filesystem uses a storage topology whose encryption cannot be verified by the block-device check.'
        return
    }
    tree=$(status::run lsblk --inverse --json --output NAME,TYPE "$source") || {
        status::result unknown 'The filesystem backing devices could not be inspected.'
        return
    }
    if ((${#tree} > 262144)); then
        status::result unknown 'The backing-device topology exceeded the inspection limit.'
        return
    fi
    if ! coverage=$(jq -er '
        def covered($encrypted):
            ($encrypted or .type == "crypt") as $next |
            if ((.children // []) | length) == 0 then $next
            else all(.children[]; covered($next)) end;
        if (.blockdevices | type) != "array" or (.blockdevices | length) == 0 then error("missing topology")
        elif all(.blockdevices[]; covered(false)) then "encrypted"
        elif any(.. | objects; .type? == "crypt") then "mixed"
        else "unverified" end' <<<"$tree" 2>/dev/null); then
        status::result unknown 'The backing-device inspection returned an incomplete or unrecognized topology.'
        return
    fi
    case "$coverage" in
        encrypted)
            state=active
            detail='Encryption was detected on every inspected backing-device path. Filesystem-native encryption and devices outside this topology are separate checks.'
            ;;
        mixed)
            state=partial
            detail='Encryption was detected, but at least one backing-device path has no verified encryption layer. Review this mixed storage topology.'
            ;;
        *) detail='No encrypted block-device ancestor was verified. Filesystem-native encryption and unsupported storage layouts remain unverified; this is not proof that the data is unencrypted.' ;;
    esac
    jq -c --arg state "$state" --arg summary "$detail" --arg source "$source" \
        '{state:$state,summary:$summary,source:$source,backing:([..|objects|select(has("name") and has("type"))|{name,type}][:32])}' <<<"$tree"
}

status::disk_encryption() {
    local observed state
    observed=$(status::storage_probe /) || {
        status::result unknown 'The root filesystem encryption check could not complete.'
        return
    }
    state=$(jq -r '.state // "unknown"' <<<"$observed") || return 1
    if [[ $state == active ]]; then
        status::result active 'Encryption detected for the inspected root filesystem backing storage. View details for home, swap and other coverage; this is not a whole-disk certification.'
    elif [[ $state == partial ]]; then
        status::result partial 'Root storage has mixed encryption coverage. View the backing-device details before making storage changes.'
    else
        status::result unknown 'Root filesystem encryption could not be verified. View storage details; an unavailable check does not mean the disk is unencrypted.'
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

status::_docker_ready() {
    # Connecting to a socket-activated Docker daemon can start containers. A
    # passive inspection must not activate a stopped container service.
    if [[ $(status::unit docker.service) != active ]]; then
        return 1
    fi
    if [[ ! -S /run/docker.sock && ! -S /var/run/docker.sock ]]; then
        return 1
    fi
    if ! command -v docker >/dev/null 2>&1; then
        return 1
    fi
}

status::docker_snapshot() {
    local ids report version networks network_report template
    local -a containers=() network_ids=()
    status::_docker_ready || return 1
    ids=$(status::run env DOCKER_CONFIG=/var/empty docker --host=unix:///run/docker.sock ps --quiet --no-trunc --filter status=running) || return 1
    if [[ -n $ids ]]; then
        mapfile -t containers <<<"$ids"
        ((${#containers[@]} <= 64)) || return 1
        for ids in "${containers[@]}"; do [[ $ids =~ ^[a-f0-9]{64}$ ]] || return 1; done
        # Only requested fields leave Docker. Environment, credentials, mounts,
        # command lines and unrelated application labels are never collected.
        template='{"id":{{json .Id}},"name":{{json .Name}},"ports":{{json .NetworkSettings.Ports}},"mode":{{json .HostConfig.NetworkMode}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}},"networks":{{json .NetworkSettings.Networks}}}'
        report=$(status::run env DOCKER_CONFIG=/var/empty docker --host=unix:///run/docker.sock inspect --type container --format "$template" "${containers[@]}") || return 1
        ((${#report} <= 262144)) || return 1
        jq -se '
            def bindings: .==null or (type=="array" and all(.[];
                (.HostIp|type=="string") and (.HostPort|type=="string" and test("^[0-9]{1,5}$"))));
            length <= 64 and all(.[];
            (.id | type == "string" and test("^[a-f0-9]{64}$")) and
            (.name | type == "string") and (.mode | type == "string") and
            all(.project,.service,.files; .==null or type=="string") and
            ((.ports//{}) | type=="object" and all(.[];bindings)))' <<<"$report" >/dev/null || return 1
        report=$(jq -sc '[.[] | {id,name,ports:(.ports//{}),mode,project:(.project//""),service:(.service//""),files:(.files//""),networks:([(.networks//{})[] | .NetworkID] | unique)}]' <<<"$report") || return 1
    else report='[]'; fi
    version=$(status::run env DOCKER_CONFIG=/var/empty docker --host=unix:///run/docker.sock version --format '{{.Server.Version}}') || version=unknown
    ((${#version} <= 128)) || version=unknown
    networks=$(jq -r '[.[].networks[] | select(type=="string" and test("^[a-f0-9]{64}$"))] | unique | .[]' <<<"$report") || return 1
    network_report='[]'
    if [[ -n $networks ]]; then
        mapfile -t network_ids <<<"$networks"
        ((${#network_ids[@]} <= 128)) || return 1
        template='{"id":{{json .Id}},"driver":{{json .Driver}},"options":{{json .Options}}}'
        if network_report=$(status::run env DOCKER_CONFIG=/var/empty docker --host=unix:///run/docker.sock network inspect --format "$template" "${network_ids[@]}"); then
            ((${#network_report} <= 262144)) || return 1
            network_report=$(jq -sc '[.[] | {id,driver,options:((.options//{}) | with_entries(select(.key | startswith("com.docker.network.bridge."))))}]' <<<"$network_report") || network_report='[]'
        else network_report='[]'; fi
    fi
    jq -cs --arg version "$version" '{version:$version,containers:.[0],networks:.[1]}' <<<"$report"$'\n'"$network_report"
}

status::docker_summary() {
    jq -c '
        def loopback: . == "::1" or test("^127\\.([0-9]{1,3}\\.){2}[0-9]{1,3}$");
        [.containers[].ports[]?[]? | .HostIp] as $bindings |
        [.containers[] | select(.mode == "host")] as $host |
        if any($bindings[]; (loopback | not)) then
            {state:"partial",summary:"Docker publishes ports beyond localhost. Review the containers, binding addresses and configuration sources before choosing local-only or LAN access. External reachability is not proven by this check."}
        elif ($host | length) > 0 then
            {state:"unknown",summary:"Docker host-network containers use the host network directly. Review their application listeners; published-port inspection does not cover them."}
        elif ($bindings | length) > 0 and (((.version | split(".")[0] | tonumber?) // 0) < 28) then
            {state:"unknown",summary:"Docker published ports bind to localhost, but the engine version is old or unverified. Versions before 28 can expose localhost publishing to nearby hosts; open details before relying on local-only access."}
        elif ($bindings | length) > 0 and ((.networks|length)==0 or any(.networks[]; .driver != "bridge" or ((.options["com.docker.network.bridge.gateway_mode_ipv4"]//"nat") != "nat") or ((.options["com.docker.network.bridge.gateway_mode_ipv6"]//"nat") != "nat") or ((.options["com.docker.network.bridge.trusted_host_interfaces"]//"") != ""))) then
            {state:"unknown",summary:"Docker published ports bind to localhost, but the network configuration needs a routing review. Open details; localhost bindings alone do not certify every container access path."}
        elif ($bindings | length) > 0 then
            {state:"active",summary:"Inspected Docker published ports bind only to localhost. Version and network-routing limitations are shown in details; other runtimes and virtual machines are not inspected."}
        else {state:"active",summary:"No host ports are published by the inspected running Docker containers. Other runtimes, virtual machines and direct container routing are separate checks."} end'
}

status::containers() {
    local observed
    if observed=$(status::docker_snapshot); then
        status::docker_summary <<<"$observed"
    else
        status::result unknown 'The local system Docker daemon could not be inspected without starting services. Open details for the check requirements; other runtimes and virtual machines are not inspected.'
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
        status::result unknown 'Network forwarding is enabled, as commonly required by Docker and virtual machines. This setting alone is not an exposure finding; view the interfaces and filtering details.'
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

status::_project_usb_devices() {
    # Project fields explicitly: never publish USBGuard hashes or serials.
    jq -ce '[.[] | select(
        (.id | type == "number" and . >= 1 and . <= 4294967294 and floor == .) and
        (.token | type == "string" and test("^[a-f0-9]{64}$")) and
        (.state | IN("allowed","blocked","rejected")) and
        (.category | IN("input","storage","network","hub","other")) and
        (.profile | type == "string" and test("^[a-z][a-z0-9-]{0,31}$")) and
        (.vendor_product | type == "string" and test("^[A-Fa-f0-9]{4}:[A-Fa-f0-9]{4}$")) and
        (.port | type == "string" and length <= 128 and test("^[0-9]+-[0-9]+(\\.[0-9]+)*$")) and
        (.remembered | type == "boolean")) |
        ((.name // "") | if type == "string" then gsub("[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]";"") | .[0:128] else "" end) as $name |
        {id,token,state,category,profile,vendor_product,port,remembered,name:$name,label:(if $name == "" then "USB device" else $name end)}] | .[0:256]' 2>/dev/null
}

status::pending_devices() {
    local devices='[]'
    if declare -F usb::devices_json >/dev/null; then devices=$(usb::devices_json 2>/dev/null) || devices='[]'; fi
    # Keep the historical entry-point name for collector compatibility, but
    # include allowed devices too so a refresh needs no privileged helper.
    status::_project_usb_devices <<<"$devices" || printf '[]\n'
}

# This independent, inexpensive snapshot never advances the full inspection's
# checked_at. A slow firewall/exposure inspection cannot keep a USB modal stale.
status::collect_usb() {
    local observed raw='' snapshot devices='[]' available=false profile=unmanaged checked
    if declare -F usb::profile_snapshot >/dev/null; then
        # Status and device rows must come from the same verified observation.
        # This fast path runs every two seconds: do not repeat the inventory
        # just to project its public fields and count pending decisions.
        snapshot=$(usb::profile_snapshot 2>/dev/null) || snapshot='{}'
        observed=$(jq -c '.status' <<<"$snapshot") || observed=
        raw=$(jq -ce 'select(.available == true) | .devices' <<<"$snapshot") || raw=
    else
        observed=$(status::usb 2>/dev/null) || observed=
        if [[ $(jq -r '.state' <<<"$observed" 2>/dev/null) =~ ^(active|partial)$ ]] && declare -F usb::devices_json >/dev/null; then
            raw=$(usb::devices_json 2>/dev/null) || raw=
        fi
    fi
    status::valid_result <<<"$observed" || observed=$(status::result unknown 'USB protection cannot be verified.')
    profile=$(jq -r '.profile // "unmanaged"' <<<"$observed") || return 1
    [[ $profile =~ ^[a-z][a-z0-9-]{0,31}$ ]] || profile=unmanaged
    if [[ $(jq -r .state <<<"$observed") =~ ^(active|partial)$ && -n $raw ]] && devices=$(status::_project_usb_devices <<<"$raw"); then
        # Treat omitted/invalid rows or mixed profiles as an unavailable read,
        # never as a successful empty list or an actionable partial inventory.
        if jq -e --argjson raw "$raw" --arg profile "$profile" '
            ($raw | type == "array" and length <= 256) and length == ($raw | length) and
            (map(.id) | unique | length) == length and (map(.token) | unique | length) == length and
            all(.[]; .profile == $profile)' <<<"$devices" >/dev/null 2>&1; then available=true; fi
    fi
    if [[ $available != true ]]; then
        devices='[]'
        observed=$(jq -c '{state:"unknown",summary:((.summary | .[0:800]) + " Connected USB devices could not be refreshed. No device approval is available until a fresh inspection succeeds.")}' <<<"$observed") || return 1
    fi
    checked=$(date +%s) || return 1
    jq -cn --argjson checked "$checked" --argjson available "$available" --argjson observed "$observed" --arg profile "$profile" --argjson devices "$devices" '
        {schema:1,checked_at:$checked,usb:{available:$available,state:$observed.state,summary:$observed.summary,profile:$profile,
          pending:($devices | map(select(.state == "blocked" or .state == "rejected")) | length),devices:$devices}}'
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
    local controls='{}' exposures='{}' name observed profiles network pending checked devices usb_profile version usb_snapshot=''
    version=$(status::version) || return 1
    profiles=$(status::profile_snapshot) || return 1
    for name in firewall usb network services monitor updates apparmor sudo; do
        if [[ $name == usb ]] && declare -F usb::profile_snapshot >/dev/null; then
            usb_snapshot=$(usb::profile_snapshot 2>/dev/null) || usb_snapshot='{}'
            observed=$(jq -c '.status' <<<"$usb_snapshot") || observed=
            status::valid_result <<<"$observed" || observed=$(status::result unknown 'USB protection cannot be verified.')
        else observed=$(status::control "$name") || return 1; fi
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
    if [[ -n $usb_snapshot ]]; then
        devices=$(jq -c 'if .available == true then .devices else [] end' <<<"$usb_snapshot" | status::_project_usb_devices) || return 1
    else devices=$(status::pending_devices) || return 1; fi
    pending=$(jq -er --argjson devices "$devices" '[($devices | map(select(.state == "blocked" or .state == "rejected")) | length),(.usb.pending | if type == "number" and . >= 0 and . <= 65535 and floor == . then . else 0 end)] | max' <<<"$controls") || pending=0
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
        (.usb.devices | type == "array" and length <= 256 and all(.[];
            (.id | type == "number" and . >= 1 and . <= 4294967294 and floor == .) and
            (.token | type == "string" and test("^[a-f0-9]{64}$")) and
            (.state | IN("allowed","blocked","rejected")) and
            (.category | IN("input","storage","network","hub","other")) and
            (.profile | type == "string" and test("^[a-z][a-z0-9-]{0,31}$")) and
            (.vendor_product | type == "string" and test("^[A-Fa-f0-9]{4}:[A-Fa-f0-9]{4}$")) and
            (.port | type == "string" and length <= 128 and test("^[0-9]+-[0-9]+(\\.[0-9]+)*$")) and
            (.remembered | type == "boolean") and
            (all(.name,.label; type == "string" and length <= 128 and (test("[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]") | not)))))
    ' >/dev/null 2>&1
}

status::validate_usb_document() {
    jq -e '
        def safe_name: type == "string" and length <= 128 and (test("[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]") | not);
        type == "object" and .schema == 1 and
        (.checked_at | type == "number" and . >= 0 and . <= 9007199254740991 and floor == .) and
        (.usb | type == "object") and
        (.usb.available | type == "boolean") and
        (.usb.state | IN("active","inactive","partial","unknown","unsupported")) and
        (.usb.summary | type == "string" and length <= 1024) and
        (.usb.profile | type == "string" and test("^[a-z][a-z0-9-]{0,31}$")) and
        (.usb.pending | type == "number" and . >= 0 and . <= 256 and floor == .) and
        (.usb.devices | type == "array" and length <= 256 and all(.[];
            (.id | type == "number" and . >= 1 and . <= 4294967294 and floor == .) and
            (.token | type == "string" and test("^[a-f0-9]{64}$")) and
            (.state | IN("allowed","blocked","rejected")) and
            (.category | IN("input","storage","network","hub","other")) and
            (.vendor_product | type == "string" and test("^[A-Fa-f0-9]{4}:[A-Fa-f0-9]{4}$")) and
            (.port | type == "string" and length <= 128 and test("^[0-9]+-[0-9]+(\\.[0-9]+)*$")) and
            (.remembered | type == "boolean") and (all(.name,.label; safe_name)))) and
        (.usb as $usb | all($usb.devices[]; .profile == $usb.profile)) and
        (.usb.devices | (map(.id) | unique | length) == length and (map(.token) | unique | length) == length) and
        .usb.pending == (.usb.devices | map(select(.state == "blocked" or .state == "rejected")) | length) and
        (if .usb.available then true else .usb.state == "unknown" and (.usb.devices | length == 0) end)
    ' >/dev/null 2>&1
}

# Caller holds the shared operation lock during collection (or already owns the
# exclusive mutation lock). Opening another lock here would deadlock refreshes
# made by an administrator operation that already holds the exclusive lock.
status::refresh_usb() (
    local data temporary metadata
    ((EUID == 0)) || return 1
    [[ ! -L $STATUS_DIRECTORY ]] || return 1
    if [[ -e $STATUS_DIRECTORY ]]; then
        [[ -d $STATUS_DIRECTORY ]] || return 1
        metadata=$(stat -c '%u:%g:%a' -- "$STATUS_DIRECTORY") || return 1
        [[ $metadata == 0:0:755 ]] || return 1
    else install -d -m 0755 -o root -g root -- "$STATUS_DIRECTORY" || return 1; fi
    [[ ! -L $STATUS_DIRECTORY/usb.json ]] || return 1
    data=$(status::collect_usb) || return 1
    ((${#data} <= STATUS_MAX_BYTES)) || return 1
    status::validate_usb_document <<<"$data" || return 1
    temporary=$(mktemp "$STATUS_DIRECTORY/.usb.XXXXXXXX") || return 1
    trap 'rm -f -- "$temporary"' EXIT
    printf '%s\n' "$data" >"$temporary" || return 1
    chmod 0644 "$temporary" && chown root:root "$temporary" || return 1
    mv -fT -- "$temporary" "$STATUS_DIRECTORY/usb.json"
)

status::read_usb() {
    local file="$STATUS_DIRECTORY/usb.json" metadata size modified now document checked
    [[ -d $STATUS_DIRECTORY && ! -L $STATUS_DIRECTORY && -f $file && ! -L $file ]] || return 1
    metadata=$(stat -c '%u:%g:%a' -- "$STATUS_DIRECTORY") || return 1
    [[ $metadata == 0:0:755 ]] || return 1
    metadata=$(stat -c '%u:%g:%a:%s:%Y' -- "$file") || return 1
    [[ $metadata =~ ^0:0:644:([0-9]{1,7}):([0-9]{1,12})$ ]] || return 1
    size=${BASH_REMATCH[1]} modified=${BASH_REMATCH[2]}
    ((size > 0 && size <= STATUS_MAX_BYTES)) || return 1
    now=$(date +%s) || return 1
    ((now - modified <= STATUS_USB_MAX_AGE && modified - now <= 5)) || return 1
    document=$(head -c "$((STATUS_MAX_BYTES + 1))" -- "$file") || return 1
    ((${#document} <= STATUS_MAX_BYTES)) || return 1
    status::validate_usb_document <<<"$document" || return 1
    checked=$(jq -er .checked_at <<<"$document") || return 1
    ((now - checked <= STATUS_USB_MAX_AGE && checked - now <= 5)) || return 1
    printf '%s\n' "$document"
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
