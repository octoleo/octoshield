#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Authenticated connection details and narrowly scoped NetworkManager changes.
# Never expose connection names, addresses or source paths through public status.
CONNECTIONS_SYS=/sys
CONNECTIONS_LIB=/usr/lib
CONNECTIONS_DEADLINE=0

connections::validate() {
    case "${1-}" in
        list | reconcile) [[ $# -eq 1 ]] ;;
        reconnect) [[ $# -eq 2 ]] && office::valid_uuid "$2" ;;
        set)
            [[ $# -eq 4 ]] && office::valid_uuid "$2" || return 1
            case "$3" in
                autoconnect | discovery) [[ $4 == true || $4 == false ]] ;;
                mac) [[ $4 == stable || $4 == permanent ]] ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}
connections::mutates() { [[ ${1-} != list ]]; }
connections::_run() {
    local seconds=6
    if ((CONNECTIONS_DEADLINE > 0)); then
        seconds=$((CONNECTIONS_DEADLINE - SECONDS))
        ((seconds > 0)) || return 124
        ((seconds <= 6)) || seconds=6
    fi
    core::timeout --foreground --kill-after=1s "${seconds}s" env LC_ALL=C "$@" 6>&- 8>&- 9>&- 2>/dev/null
}
connections::_get() { connections::_run nmcli --escape no -g "$2" connection show uuid "$1"; }
connections::_physical() {
    local interface=$1
    profiles::valid_interface "$interface" && [[ $interface != any && $interface != lo ]] || return 1
    [[ -e $CONNECTIONS_SYS/class/net/$interface/device && ! -d $CONNECTIONS_SYS/class/net/$interface/bridge ]]
}
connections::_active() {
    connections::_run nmcli --terse --escape no --fields UUID,DEVICE connection show --active
}
connections::_source_files() {
    local uuid=$1 file directory result='[]' examined=0 matches=0
    for directory in "$PROFILE_ETC/NetworkManager/system-connections" "$PROFILE_RUN/NetworkManager/system-connections" "$CONNECTIONS_LIB/NetworkManager/system-connections"; do
        [[ -d $directory && ! -L $directory ]] || continue
        for file in "$directory"/*; do
            ((CONNECTIONS_DEADLINE == 0 || SECONDS < CONNECTIONS_DEADLINE)) || return 124
            [[ -f $file && ! -L $file ]] || continue
            examined=$((examined + 1))
            ((examined <= 512 && ${#file} <= 1024)) || return 1
            [[ $(stat -c %s -- "$file") -le 1048576 ]] || continue
            if awk -v uuid="$uuid" '
                /^\[/ { connection=($0=="[connection]") }
                connection && /^[[:space:]]*uuid[[:space:]]*=/ {
                    value=$0; sub(/^[^=]*=/,"",value); gsub(/^[[:space:]]+|[[:space:]]+$/,"",value)
                    if (value==uuid) found=1
                }
                END {exit !found}' "$file"; then
                matches=$((matches + 1))
                ((matches <= 8)) || return 1
                result=$(jq -c --arg file "$file" '.+[$file]' <<<"$result") || return 1
            fi
        done
    done
    printf '%s\n' "$result"
}

# Hash only saved connection properties and private source contents. Neither
# credentials nor the inspected settings are emitted. Source hashes also bind
# secret changes, which nmcli deliberately hides from its regular display.
connections::_review_fingerprint() {
    local uuid=$1 settings sources file hash evidence
    settings=$(connections::_run nmcli --terse --fields connection,802-11-wireless,802-11-wireless-security,802-3-ethernet,802-1x,ipv4,ipv6,proxy connection show uuid "$uuid") || return 1
    ((${#settings} <= 262144)) || return 1
    settings=$(awk '!/^connection\.timestamp:/' <<<"$settings") || return 1
    sources=$(connections::_source_files "$uuid") || return 1
    evidence=$settings
    while IFS= read -r file; do
        hash=$(awk '/^\[/ {section=$0} section=="[connection]" && /^[[:space:]]*timestamp[[:space:]]*=/ {next} {print}' "$file" | sha256sum) || return 1
        evidence+=$'\n'"$file:${hash%% *}"
    done < <(jq -r '.[]' <<<"$sources")
    hash=$(printf '%s' "$evidence" | sha256sum) || return 1
    printf '%s\n' "${hash%% *}"
}
connections::_subnet() {
    local value=$1 address prefix mask number octet left right missing remaining field output=''
    local -a pieces=() suffix=()
    profiles::valid_source "$value" && [[ $value == */* ]] || return 1
    address=${value%/*} prefix=${value##*/}
    ((10#$prefix > 0)) || return 1
    if [[ $address == *:* ]]; then
        if [[ $address == *::* ]]; then
            left=${address%%::*} right=${address##*::}
            [[ -z $left ]] || IFS=: read -r -a pieces <<<"$left"
            [[ -z $right ]] || IFS=: read -r -a suffix <<<"$right"
            missing=$((8 - ${#pieces[@]} - ${#suffix[@]}))
            while ((missing > 0)); do
                pieces+=(0)
                missing=$((missing - 1))
            done
            pieces+=("${suffix[@]}")
        else IFS=: read -r -a pieces <<<"$address"; fi
        [[ ${#pieces[@]} -eq 8 ]] || return 1
        remaining=$((10#$prefix))
        for field in "${pieces[@]}"; do
            number=$((16#$field))
            if ((remaining >= 16)); then
                remaining=$((remaining - 16))
            elif ((remaining > 0)); then
                number=$((number & ((0xffff << (16 - remaining)) & 0xffff)))
                remaining=0
            else number=0; fi
            printf -v field '%x' "$number"
            output+="${output:+:}$field"
        done
        printf '%s/%d\n' "$output" "$((10#$prefix))"
        return
    fi
    IFS=. read -r -a pieces <<<"$address"
    number=0
    for octet in "${pieces[@]}"; do number=$(((number << 8) | 10#$octet)); done
    mask=$(((0xffffffff << (32 - 10#$prefix)) & 0xffffffff))
    number=$((number & mask))
    printf '%d.%d.%d.%d/%d\n' "$(((number >> 24) & 255))" "$(((number >> 16) & 255))" "$(((number >> 8) & 255))" "$((number & 255))" "$((10#$prefix))"
}
connections::_runtime() {
    local uuid=$1 interface=$2 expected=$3 device applied modes llmnr mdns mac desired_mac index property observed desired
    if [[ -z $interface ]]; then
        jq -cn '{state:"inactive",summary:"Saved settings will be used on the next connection."}'
        return
    fi
    profiles::valid_interface "$interface" && [[ $interface != any ]] || return 1
    device=$(connections::_run busctl --system --auto-start=no --json=short call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager GetDeviceByIpIface s "$interface") || device='{}'
    device=$(jq -er '.data[0]|select(type=="string" and test("^/org/freedesktop/NetworkManager/Devices/[0-9]+$"))' <<<"$device" 2>/dev/null) || device=
    if [[ -z $device ]]; then
        jq -cn '{state:"unknown",summary:"Saved settings are readable; active NetworkManager settings could not be inspected."}'
        return
    fi
    applied=$(connections::_run busctl --system --auto-start=no --json=short call org.freedesktop.NetworkManager "$device" org.freedesktop.NetworkManager.Device GetAppliedConnection u 0) || applied='{}'
    # Only selected non-secret properties are retained from GetAppliedConnection.
    modes=$(jq -ce '.data[0]|{uuid:.connection.uuid.data,llmnr:.connection.llmnr.data,mdns:.connection.mdns.data,mac:.["802-11-wireless"]["assigned-mac-address"].data}' <<<"$applied" 2>/dev/null) || modes='{}'
    if [[ $(jq -r '.uuid//""' <<<"$modes") != "$uuid" ]]; then
        jq -cn '{state:"unknown",summary:"The active connection changed or its applied settings are unavailable. Refresh before changing it."}'
        return
    fi
    llmnr=$(jq -r '.llmnr//""' <<<"$modes") mdns=$(jq -r '.mdns//""' <<<"$modes")
    if [[ ! $llmnr =~ ^(-1|[012])$ || ! $mdns =~ ^(-1|[012])$ ]]; then
        jq -cn '{state:"unknown",summary:"The active connection does not expose explicit discovery settings. Resolver defaults need separate review."}'
        return
    fi
    if [[ $llmnr != "$(jq -r .llmnr <<<"$expected")" || $mdns != "$(jq -r .mdns <<<"$expected")" ]]; then
        jq -cn '{state:"pending",summary:"Saved discovery settings differ from this active connection. Reconnect to activate them."}'
        return
    fi
    desired_mac=$(jq -r '.mac//""' <<<"$expected")
    if [[ -n $desired_mac ]]; then
        mac=$(jq -r '.mac//""' <<<"$modes")
        if [[ -z $mac ]]; then
            jq -cn '{state:"unknown",summary:"Discovery settings are applied; the active Wi-Fi address policy could not be verified."}'
            return
        elif [[ $mac != "$desired_mac" ]]; then
            jq -cn '{state:"pending",summary:"The saved Wi-Fi address policy differs from the active connection. Reconnect to activate it."}'
            return
        fi
    fi
    # NM applied options alone do not prove the DNS backend honors discovery.
    index=''
    [[ ! -r $CONNECTIONS_SYS/class/net/$interface/ifindex ]] || read -r index <"$CONNECTIONS_SYS/class/net/$interface/ifindex"
    if [[ ! $index =~ ^[1-9][0-9]{0,9}$ ]]; then
        jq -cn '{state:"unknown",summary:"NetworkManager has applied the saved settings; resolver enforcement is unverified."}'
        return
    fi
    for property in LLMNR MulticastDNS; do
        if [[ $property == LLMNR ]]; then desired=$llmnr; else desired=$mdns; fi
        case "$desired" in 0) desired=no ;; 1) desired=resolve ;; 2) desired=yes ;; *) desired=unknown ;; esac
        observed=$(connections::_run busctl --system --auto-start=no --json=short get-property org.freedesktop.resolve1 "/org/freedesktop/resolve1/link/_$index" org.freedesktop.resolve1.Link "$property") || observed='{}'
        observed=$(jq -r 'if .type=="s" and (.data|type)=="string" then .data else "unknown" end' <<<"$observed" 2>/dev/null) || observed=unknown
        if [[ $desired == unknown || $observed == unknown ]]; then
            jq -cn '{state:"unknown",summary:"NetworkManager has applied the saved settings; the DNS backend does not expose verifiable discovery state."}'
            return
        elif [[ $observed != "$desired" ]]; then
            jq -cn '{state:"pending",summary:"Resolver discovery differs from the saved policy. Review resolver settings or reconnect, then inspect again."}'
            return
        fi
    done
    jq -cn '{state:"verified",summary:"The active NetworkManager settings and resolver discovery match the saved connection policy."}'
}
connections::_connection() {
    local uuid=$1 active_listing=$2 name type autoconnect llmnr mdns mac='' interface='' active=false active_known=true lan=false addresses='[]' subnets='[]' sources runtime record observed address subnet row_uuid row_device
    name=$(connections::_get "$uuid" connection.id) || return 1
    type=$(connections::_get "$uuid" connection.type) || return 1
    case "$type" in wifi | 802-11-wireless | ethernet | 802-3-ethernet) ;; *) return 2 ;; esac
    autoconnect=$(connections::_get "$uuid" connection.autoconnect) || return 1
    llmnr=$(connections::_get "$uuid" connection.llmnr) || return 1
    mdns=$(connections::_get "$uuid" connection.mdns) || return 1
    llmnr=${llmnr%% *} mdns=${mdns%% *}
    [[ $autoconnect == yes || $autoconnect == no ]] && [[ $llmnr =~ ^-?[0-9]$ && $mdns =~ ^-?[0-9]$ ]] || return 1
    case "$type" in wifi | 802-11-wireless) mac=$(connections::_get "$uuid" 802-11-wireless.cloned-mac-address) || return 1 ;; esac
    while IFS=: read -r row_uuid row_device; do
        if [[ $row_uuid == "$uuid" ]] && profiles::valid_interface "$row_device" && [[ $row_device != any ]]; then
            interface=$row_device active=true
            break
        fi
    done <<<"$active_listing"
    if [[ $active == true ]]; then
        observed=$(connections::_run ip -j address show dev "$interface") || observed='[]'
        addresses=$(jq -c '[.[]?.addr_info[]?|select(.scope=="global")|(.local+"/"+(.prefixlen|tostring))]|unique' <<<"$observed") || addresses='[]'
        while IFS= read -r address; do
            subnet=$(connections::_subnet "$address") || continue
            subnets=$(jq -c --arg subnet "$subnet" '.+[$subnet]|unique' <<<"$subnets") || return 1
        done < <(jq -r '.[]' <<<"$addresses")
        if connections::_physical "$interface" && [[ $(jq length <<<"$subnets") -gt 0 ]]; then lan=true; fi
    fi
    sources=$(connections::_source_files "$uuid") || return 1
    record=$(jq -cn --arg uuid "$uuid" --arg name "$name" --arg type "$type" --arg interface "$interface" --argjson active "$active" --argjson addresses "$addresses" --argjson subnets "$subnets" --argjson lan "$lan" --arg autoconnect "$autoconnect" --arg llmnr "$llmnr" --arg mdns "$mdns" --arg mac "$mac" --argjson sources "$sources" '{uuid:$uuid,name:($name|gsub("[\u0000-\u001f\u007f]";" ")|.[0:256]),type:$type,interface:$interface,active:$active,addresses:$addresses,subnets:$subnets,lan_candidate:$lan,autoconnect:$autoconnect,llmnr:$llmnr,mdns:$mdns,mac:$mac,source_files:$sources}') || return 1
    if [[ $active_listing == unavailable ]]; then
        active_known=false
        runtime='{"state":"unknown","summary":"Saved settings are readable, but active connections could not be inspected."}'
    else runtime=$(connections::_runtime "$uuid" "$interface" "$record") || return 1; fi
    jq -c --argjson runtime "$runtime" --argjson active_known "$active_known" '.+{runtime:$runtime,active_known:$active_known}' <<<"$record"
}
connections::list() {
    local listing active uuid item candidate result='[]' count=0 incomplete=false profile bytes
    local CONNECTIONS_DEADLINE=$((SECONDS + 30))
    listing=$(connections::_run nmcli --terse --fields UUID connection show) || {
        core::die 'Saved connections could not be read. Check that NetworkManager is running.'
        return 1
    }
    active=$(connections::_active) || {
        active=unavailable
        incomplete=true
    }
    while IFS= read -r uuid; do
        [[ -n $uuid ]] || continue
        if ((SECONDS >= CONNECTIONS_DEADLINE)); then
            incomplete=true
            break
        fi
        office::valid_uuid "$uuid" || {
            incomplete=true
            continue
        }
        count=$((count + 1))
        if ((count > 128)); then
            incomplete=true
            break
        fi
        if item=$(connections::_connection "$uuid" "$active"); then
            candidate=$(jq -c --argjson item "$item" '.+[$item]' <<<"$result") || return 1
            bytes=$(jq 'tojson|tojson|utf8bytelength' <<<"$candidate") || return 1
            if ((bytes > 40000)); then
                incomplete=true
                break
            fi
            result=$candidate
        elif [[ $? != 2 ]]; then incomplete=true; fi
    done <<<"$listing"
    profile=$(profiles::active network) || profile=unmanaged
    jq -cn --arg profile "$profile" --argjson connections "$result" --argjson incomplete "$incomplete" --arg config "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" '{kind:"connections",profile:$profile,connections:$connections,incomplete:$incomplete,defaults_file:$config,notice:"A network name or subnet does not prove trust. Discovery and incoming firewall access are separate controls."}'
}
connections::verify_runtime() {
    local snapshot=$1 active uuid interface record runtime state checked=0 pending=0 unknown=0
    local CONNECTIONS_DEADLINE=$((SECONDS + 20))
    active=$(connections::_active) || {
        status::result unknown 'Saved privacy policy matches; active connections could not be inspected.'
        return
    }
    while IFS=: read -r uuid interface; do
        [[ -n $uuid ]] || continue
        if ! office::valid_uuid "$uuid" || ! profiles::valid_interface "$interface" || [[ $interface == any ]]; then
            unknown=$((unknown + 1))
            continue
        fi
        record=$(jq -c --arg uuid "$uuid" '[.connections[]|select(.uuid==$uuid)][0]//empty' <<<"$snapshot") || return 1
        [[ -n $record ]] || continue
        checked=$((checked + 1))
        runtime=$(connections::_runtime "$uuid" "$interface" "$record") || runtime='{"state":"unknown"}'
        state=$(jq -r '.state//"unknown"' <<<"$runtime") || state=unknown
        case "$state" in verified) ;; pending) pending=$((pending + 1)) ;; *) unknown=$((unknown + 1)) ;; esac
    done <<<"$active"
    if ((pending)); then
        status::result partial 'Saved privacy policy matches; an active connection needs a reconnect or resolver review. Open Connection privacy for details.'
    elif ((unknown)); then
        status::result unknown 'Saved privacy policy matches; some active settings could not be verified. Open Connection privacy for details.'
    elif ((checked)); then
        status::result active 'Saved privacy policy, active connections and resolver discovery settings match.'
    else status::result active 'Saved privacy policy matches. No active Wi-Fi or Ethernet connection currently needs verification.'; fi
}
# Update only the field this operation owns. In particular, an unrelated native
# edit must remain a conflict for a later whole-profile apply or restore.
connections::_record_setting() {
    local uuid=$1 key=$2 before=$3 after=$4 saved expected updated
    saved=$(profile_controls::_read network) || return 1
    expected=$(jq -c '.observed//.before' <<<"$saved") || return 1
    [[ $(profile_controls::_hash <<<"$expected") == "$(jq -r .expected <<<"$saved")" ]] || return 1
    updated=$(jq -c --arg uuid "$uuid" --arg key "$key" --argjson before "$before" --argjson after "$after" '
        ($before.connections|map(select(.uuid==$uuid))|first) as $original |
        ($after.connections|map(select(.uuid==$uuid))|first) as $actual |
        if $original==null or $actual==null then error("Selected connection disappeared") else
        if all(.before.connections[]; .uuid!=$uuid) then .before.connections+=[$original]|.before.connections|=sort_by(.uuid) else . end |
        .observed=(.observed//.before) |
        if all(.observed.connections[]; .uuid!=$uuid) then .observed.connections+=[$original] else . end |
        .observed.connections|= (map(if .uuid==$uuid then
            if $key=="autoconnect" then .autoconnect=$actual.autoconnect
            elif $key=="discovery" then .llmnr=$actual.llmnr|.mdns=$actual.mdns
            else .mac=$actual.mac end else . end)|sort_by(.uuid)) end' <<<"$saved") || return 1
    expected=$(jq -c .observed <<<"$updated" | profile_controls::_hash) || return 1
    updated=$(jq -c --arg expected "$expected" '.expected=$expected' <<<"$updated") || return 1
    profile_controls::_write network "$updated"
}

connections::reconcile() {
    local saved current reviewed updated profile
    core::require_root || return 1
    controls::local_console || return 1
    local CONNECTIONS_DEADLINE=$((SECONDS + 30))
    saved=$(profile_controls::_read network) || {
        core::die 'No saved network baseline is available. Save a connection setting or apply a network profile first.'
        return 1
    }
    current=$(profile_controls::_network_snapshot) || return 1
    reviewed=$(jq -c '.observed//.before' <<<"$saved") || return 1
    if [[ $(profile_controls::_hash <<<"$current") == "$(jq -r .expected <<<"$saved")" ]]; then
        core::log 'Saved NetworkManager settings already match the last recorded state.'
        return 0
    fi
    profile_controls::_network_changes "$reviewed" "$current" || return 1
    core::log 'Accepting records these current saved settings for future conflict checks. It does not apply a profile, reconnect, or replace the original recovery baseline. Restoring that baseline later can undo these external changes.'
    core::confirm 'Accept the displayed current network settings as reviewed?' || return 1
    CONNECTIONS_DEADLINE=$((SECONDS + 30))
    [[ $(profile_controls::_read network) == "$saved" && $(profile_controls::_network_snapshot) == "$current" ]] || {
        core::die 'Network settings changed during review. Review external changes again.'
        return 1
    }
    core::backup "$(profile_controls::_directory)/network.json" || return 1
    updated=$(jq -c --argjson observed "$current" --arg expected "$(profile_controls::_hash <<<"$current")" '.observed=$observed|.expected=$expected' <<<"$saved") || return 1
    profile_controls::_write network "$updated" || return 1
    profile=$(profiles::active network) || return 1
    if [[ $profile != unmanaged ]]; then profiles::_result network pending 'External saved settings accepted after review; inspect profile differences before applying.' || return 1; fi
    core::record 'CONNECTION reconcile reviewed native settings' || return 1
    core::log 'Current saved network settings accepted. Original recovery baseline retained; no connection was changed.'
}

connections::set() {
    local uuid=$1 key=$2 value=$3 active record profile document updated expected before after native fingerprint actual_selected expected_selected failed=0
    connections::validate set "$@" || return 2
    API_CHANGE_STARTED=false
    core::require_root || return 1
    controls::local_console || return 1
    local CONNECTIONS_DEADLINE=$((SECONDS + 30))
    active=$(connections::_active) || return 1
    record=$(connections::_connection "$uuid" "$active") || {
        core::die 'Select a saved Wi-Fi or Ethernet connection and refresh its details.'
        return 1
    }
    if [[ $key == mac ]] && [[ $(jq -r .type <<<"$record") != wifi && $(jq -r .type <<<"$record") != 802-11-wireless ]]; then
        core::die 'The private address setting applies to Wi-Fi connections only.'
        return 1
    fi
    profile=$(profiles::active network) || return 1
    document=$(profiles::_read) || return 1
    fingerprint=$(connections::_review_fingerprint "$uuid") || return 1
    before=$(profile_controls::_network_snapshot) || return 1
    core::log "Connection: $(jq -r .name <<<"$record"). Change $key to $value for this connection only."
    core::log "Current saved choices: $(jq -c '{autoconnect,llmnr,mdns,mac}' <<<"$record")."
    if [[ $key == autoconnect ]]; then
        core::log 'This saves the automatic-connection preference. It does not require a reconnect or connect a disconnected network now.'
    else
        core::log 'Saved discovery/address changes require a separate reconnect. No active connection will be disconnected by saving.'
    fi
    core::confirm 'Save this connection setting and retain its recovery baseline?' || return 1
    CONNECTIONS_DEADLINE=$((SECONDS + 30))
    [[ $(connections::_review_fingerprint "$uuid") == "$fingerprint" && $(profiles::_read) == "$document" ]] || {
        core::die 'Connection or profile settings changed during review. Refresh and try again.'
        return 1
    }
    # Read by the privileged API completion envelope.
    # shellcheck disable=SC2034
    API_CHANGE_STARTED=true
    profile_controls::_capture network || return 1
    core::backup "$PROFILE_ETC/NetworkManager/system-connections" || return 1
    core::backup "$PROFILE_RUN/NetworkManager/system-connections" || return 1
    if [[ $profile != unmanaged ]]; then
        if [[ $key == mac ]]; then
            updated=$(jq -c --arg profile "$profile" --arg uuid "$uuid" --arg key "$key" --arg value "$value" '.profiles[$profile].network.connections[$uuid][$key]=$value' <<<"$document") || return 1
        else
            updated=$(jq -c --arg profile "$profile" --arg uuid "$uuid" --arg key "$key" --argjson value "$value" '.profiles[$profile].network.connections[$uuid][$key]=$value' <<<"$document") || return 1
        fi
        profiles::_save "$updated" || return 1
        profiles::_result network applying 'Saving a connection-specific privacy setting.' || return 1
    fi
    case "$key" in
        autoconnect)
            native=no
            [[ $value != true ]] || native=yes
            nmcli connection modify uuid "$uuid" connection.autoconnect "$native" || failed=1
            ;;
        discovery)
            native=0
            [[ $value != true ]] || native=2
            nmcli connection modify uuid "$uuid" connection.llmnr "$native" connection.mdns "$native" || failed=1
            ;;
        mac) nmcli connection modify uuid "$uuid" 802-11-wireless.cloned-mac-address "$value" || failed=1 ;;
    esac
    # Record only this setting's partial effects; never absorb unrelated drift.
    after=$(profile_controls::_network_snapshot) || failed=1
    if [[ -n ${after:-} ]]; then connections::_record_setting "$uuid" "$key" "$before" "$after" || failed=1; fi
    expected=$(jq -c --arg uuid "$uuid" --arg key "$key" --arg value "$value" '.connections|=map(if .uuid==$uuid then
        if $key=="autoconnect" then .autoconnect=(if $value=="true" then "yes" else "no" end)
        elif $key=="discovery" then .llmnr=(if $value=="true" then "2" else "0" end)|.mdns=.llmnr
        else .mac=$value end else . end)' <<<"$before") || failed=1
    if ! actual_selected=$(jq -ce --arg uuid "$uuid" '[.connections[]|select(.uuid==$uuid)]|if length==1 then .[0] else error("Selected connection unavailable") end' <<<"$after") ||
        ! expected_selected=$(jq -ce --arg uuid "$uuid" '[.connections[]|select(.uuid==$uuid)]|if length==1 then .[0] else error("Selected connection unavailable") end' <<<"$expected") ||
        [[ $actual_selected != "$expected_selected" ]]; then failed=1; fi
    if ((failed)); then
        if [[ $profile != unmanaged ]]; then profiles::_result network failed 'Connection change did not verify; review its saved and active settings.' || :; fi
        core::die 'The connection change did not verify. No reconnect was attempted; inspect its settings and saved recovery baseline.'
        return 1
    fi
    if [[ $profile != unmanaged ]]; then
        # Other pending profile edits remain pending; never absorb unrelated work.
        if profile_controls::_satisfies network "$profile" "$after"; then
            profile_controls::remember_desired network "$profile" || return 1
            profiles::_result network applied 'Connection override saved; active settings are inspected separately.' || return 1
        else
            profiles::_result network pending 'Connection override saved. Other profile settings still need Apply.' || return 1
        fi
    fi
    core::record "CONNECTION $uuid $key $value" || return 1
    if [[ $key == autoconnect ]]; then
        core::log "Automatic connection saved and verified: $native. No reconnect is required."
    else core::log 'Connection setting saved and verified. Reconnect when convenient to activate discovery/address changes.'; fi
}
connections::reconnect() {
    local uuid=$1 active record before after interface
    connections::validate reconnect "$uuid" || return 2
    core::require_root || return 1
    controls::local_console || return 1
    local CONNECTIONS_DEADLINE=$((SECONDS + 30))
    active=$(connections::_active) || return 1
    record=$(connections::_connection "$uuid" "$active") || return 1
    interface=$(jq -r .interface <<<"$record") || return 1
    before=$(connections::_review_fingerprint "$uuid") || {
        core::die 'The saved connection could not be fully reviewed. Refresh before reconnecting.'
        return 1
    }
    core::log "Reconnect $(jq -r .name <<<"$record") to activate its saved settings. This may briefly interrupt downloads, calls and other network activity."
    core::confirm 'Activate this saved connection now?' || return 1
    CONNECTIONS_DEADLINE=$((SECONDS + 30))
    after=$(connections::_review_fingerprint "$uuid") || return 1
    [[ $before == "$after" ]] || {
        core::die 'The saved connection changed during review. Refresh and review its new settings before reconnecting.'
        return 1
    }
    if [[ -n $interface ]]; then
        nmcli --wait 30 connection up uuid "$uuid" ifname "$interface" || return 1
    else
        nmcli --wait 30 connection up uuid "$uuid" || return 1
    fi
    CONNECTIONS_DEADLINE=$((SECONDS + 15))
    after=$(connections::_active) || return 1
    grep -q "^$uuid:" <<<"$after" || {
        core::die 'The requested connection was not observed active. Refresh connection details before retrying.'
        return 1
    }
    core::record "CONNECTION reconnect $uuid" || return 1
    core::log 'The selected connection is active. Refresh Connection privacy to review its effective settings.'
}
connections::dispatch() {
    connections::validate "$@" || return 2
    case "$1" in
        list) connections::list ;;
        reconcile) connections::reconcile ;;
        set) connections::set "${@:2}" ;;
        reconnect) connections::reconnect "$2" ;;
    esac
}
