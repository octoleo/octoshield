#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Native adapters retain a first-adoption baseline and refuse to overwrite drift.
PROFILE_ETC=/etc
PROFILE_RUN=/run
PROFILE_SHARE=/usr/share/ufw

profile_controls::_directory() { printf '%s/profiles/controls\n' "$CORE_STATE"; }
profile_controls::_read() {
    local directory file
    directory=$(profile_controls::_directory) || return 1
    file="$directory/$1.json"
    profiles::_secure_file "$directory" directory && profiles::_secure_file "$file" || return 1
    jq -ce '.schema==1 and (.before|type=="object") and (.expected|type=="string") and (.desired|type=="string")' "$file" >/dev/null || return 1
    cat -- "$file"
}
profile_controls::_write() {
    local control=$1 document=$2 directory temporary
    directory=$(profile_controls::_directory) || return 1
    [[ ! -L $directory && ! -L $directory/$control.json ]] || return 1
    install -d -o root -g root -m 0700 "$CORE_STATE/profiles" "$directory" || return 1
    temporary=$(mktemp "$directory/.control.XXXXXX") || return 1
    if ! printf '%s\n' "$document" >"$temporary" || ! chmod 0600 "$temporary" || ! chown root:root "$temporary" || ! mv -fT "$temporary" "$directory/$control.json"; then
        rm -f -- "$temporary"
        return 1
    fi
}
profile_controls::_hash() { sha256sum | cut -d ' ' -f1; }
profile_controls::_tree_hash() {
    local path file
    for path in "$PROFILE_ETC/ufw" "$PROFILE_ETC/default/ufw"; do
        [[ ! -L $path ]] || return 1
        [[ -e $path ]] || {
            printf 'absent:%s\n' "$path"
            continue
        }
        stat -c '%n:%u:%g:%a:%F' -- "$path" || return 1
        if [[ -d $path ]]; then
            [[ -z $(find "$path" -type l -print -quit) ]] || return 1
            while IFS= read -r -d '' file; do
                stat -c '%n:%u:%g:%a:%F' -- "$file" || return 1
                sha256sum -- "$file" || return 1
            done < <(find "$path" -type f -print0 | sort -z)
        else sha256sum -- "$path" || return 1; fi
    done | profile_controls::_hash
}
profile_controls::_firewall_snapshot() {
    local config status ipv4 ipv6
    config=$(profile_controls::_tree_hash) || return 1
    status=$(LC_ALL=C ufw status verbose) || return 1
    # Strip packet counters: traffic must not look like a policy modification.
    ipv4=$(iptables-save | awk '/^:(INPUT|FORWARD|OUTPUT) / || /^:ufw/ || /^-A ufw/ || /^-A (INPUT|FORWARD|OUTPUT) / {gsub(/\[[0-9]+:[0-9]+\]/,"[counter]");print}') || return 1
    ipv6=$(ip6tables-save | awk '/^:(INPUT|FORWARD|OUTPUT) / || /^:ufw/ || /^-A ufw/ || /^-A (INPUT|FORWARD|OUTPUT) / {gsub(/\[[0-9]+:[0-9]+\]/,"[counter]");print}') || return 1
    jq -cn --arg config "$config" --arg status "$status" --arg ipv4 "$ipv4" --arg ipv6 "$ipv6" '{config:$config,status:$status,ipv4:$ipv4,ipv6:$ipv6}'
}
profile_controls::_network_read() {
    if declare -F connections::_run >/dev/null; then
        connections::_run nmcli "$@"
    else nmcli "$@"; fi
}
profile_controls::_network_snapshot() {
    local listing uuid type autoconnect llmnr mdns mac object config content mode result='[]'
    local CONNECTIONS_DEADLINE=${CONNECTIONS_DEADLINE:-0}
    ((CONNECTIONS_DEADLINE > 0)) || CONNECTIONS_DEADLINE=$((SECONDS + 30))
    listing=$(profile_controls::_network_read --terse --fields UUID,TYPE connection show) || return 1
    while IFS=: read -r uuid type; do
        [[ -n $uuid ]] || continue
        [[ $uuid =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ ]] || return 1
        case "$type" in wifi | 802-11-wireless | ethernet | 802-3-ethernet) ;; *) continue ;; esac
        autoconnect=$(profile_controls::_network_read -g connection.autoconnect connection show uuid "$uuid") || return 1
        llmnr=$(profile_controls::_network_read -g connection.llmnr connection show uuid "$uuid") || return 1
        mdns=$(profile_controls::_network_read -g connection.mdns connection show uuid "$uuid") || return 1
        llmnr=${llmnr%% *}
        mdns=${mdns%% *}
        [[ $autoconnect == yes || $autoconnect == no ]] && [[ $llmnr =~ ^-?[0-9]$ && $mdns =~ ^-?[0-9]$ ]] || return 1
        mac=
        case "$type" in wifi | 802-11-wireless) mac=$(profile_controls::_network_read -g 802-11-wireless.cloned-mac-address connection show uuid "$uuid") || return 1 ;; esac
        [[ $mac =~ ^[a-zA-Z0-9:-]*$ ]] || return 1
        object=$(jq -cn --arg uuid "$uuid" --arg type "$type" --arg autoconnect "$autoconnect" --arg llmnr "$llmnr" --arg mdns "$mdns" --arg mac "$mac" '{uuid:$uuid,type:$type,autoconnect:$autoconnect,llmnr:$llmnr,mdns:$mdns,mac:$mac}') || return 1
        result=$(jq -c --argjson item "$object" '.+[$item]|sort_by(.uuid)' <<<"$result") || return 1
    done <<<"$listing"
    config='{"exists":false,"content":"","mode":"644"}'
    if [[ -e $PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf || -L $PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf ]]; then
        [[ -f $PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf && ! -L $PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf ]] || return 1
        [[ $(stat -c %s "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf") -le 65536 ]] || return 1
        content=$(cat "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf") || return 1
        mode=$(stat -c %a "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf") || return 1
        config=$(jq -cn --arg content "$content" --arg mode "$mode" '{exists:true,content:$content,mode:$mode}') || return 1
    fi
    jq -cn --argjson connections "$result" --argjson config "$config" '{connections:$connections,config:$config}'
}
profile_controls::_units() {
    case "$1" in
        services) printf '%s\n' ssh.service ssh.socket avahi-daemon.service avahi-daemon.socket cups.service cups.socket cups.path cups-browsed.service bluetooth.service smbd.service nmbd.service gnome-remote-desktop.service ;;
        monitor) printf '%s\n' octoshield-monitor.service ;;
    esac
}
profile_controls::_services_snapshot() {
    local control=$1 unit load enabled active object result='[]'
    while IFS= read -r unit; do
        load=$(systemctl show --property=LoadState --value "$unit") || return 1
        [[ $load != not-found ]] || continue
        [[ $load == loaded || $load == masked ]] || return 1
        enabled=$(systemctl show --property=UnitFileState --value "$unit") || return 1
        active=$(systemctl show --property=ActiveState --value "$unit") || return 1
        case "$enabled" in enabled | enabled-runtime | disabled | masked | masked-runtime | static | indirect | alias) ;; *) return 1 ;; esac
        case "$active" in active | inactive | failed) ;; *) return 1 ;; esac
        object=$(jq -cn --arg unit "$unit" --arg enabled "$enabled" --arg active "$active" '{unit:$unit,enabled:$enabled,active:$active}') || return 1
        result=$(jq -c --argjson item "$object" '.+[$item]' <<<"$result") || return 1
    done < <(profile_controls::_units "$control")
    jq -cn --argjson units "$result" '{units:$units}'
}
profile_controls::snapshot() {
    case "$1" in
        firewall) profile_controls::_firewall_snapshot ;;
        network) profile_controls::_network_snapshot ;;
        services | monitor) profile_controls::_services_snapshot "$1" ;;
        *) return 1 ;;
    esac
}
profile_controls::conflict() {
    local control=$1 saved current expected file
    file="$(profile_controls::_directory)/$control.json"
    [[ -e $file || -L $file ]] || return 0
    saved=$(profile_controls::_read "$control") || return 1
    expected=$(jq -r .expected <<<"$saved") || return 1
    current=$(profile_controls::snapshot "$control") || return 1
    current=$(profile_controls::_hash <<<"$current") || return 1
    [[ $current == "$expected" ]] || {
        if [[ $control == firewall ]] && profile_controls::_runtime_narrowed "$saved"; then return 0; fi
        core::die "$control changed outside OctoShield, or a previous operation was interrupted. Review the current policy and saved baseline before continuing; no external changes were overwritten."
        return 1
    }
}
profile_controls::_capture() {
    local control=$1 directory before document
    directory=$(profile_controls::_directory) || return 1
    [[ ! -e $directory/$control.json && ! -L $directory/$control.json ]] || return 0
    before=$(profile_controls::snapshot "$control") || return 1
    if [[ $control == firewall ]]; then
        [[ ! -e $directory/firewall-baseline && ! -L $directory/firewall-baseline ]] || {
            core::die 'An incomplete firewall baseline already exists; inspect recovery files.'
            return 1
        }
        install -d -m 0700 -o root -g root "$CORE_STATE/profiles" "$directory" "$directory/firewall-baseline" || return 1
        cp -a -- "$PROFILE_ETC/ufw" "$directory/firewall-baseline/ufw" || return 1
        cp -a -- "$PROFILE_ETC/default/ufw" "$directory/firewall-baseline/default-ufw" || return 1
    fi
    document=$(jq -cn --argjson before "$before" --arg expected "$(profile_controls::_hash <<<"$before")" '{schema:1,before:$before,expected:$expected,desired:""}') || return 1
    profile_controls::_write "$control" "$document"
}
profile_controls::remember_desired() {
    local control=$1 profile=$2 saved desired policy
    saved=$(profile_controls::_read "$control") || return 1
    policy=$(profiles::get "$profile" "$control") || return 1
    desired=$(profile_controls::_hash <<<"$policy") || return 1
    saved=$(jq -c --arg desired "$desired" --argjson policy "$policy" '.desired=$desired|.policy=$policy' <<<"$saved") || return 1
    profile_controls::_write "$control" "$saved"
}
profile_controls::_record_actual() {
    local control=$1 saved current
    saved=$(profile_controls::_read "$control") || return 1
    current=$(profile_controls::snapshot "$control") || return 1
    saved=$(jq -c --arg expected "$(profile_controls::_hash <<<"$current")" --argjson observed "$current" '.expected=$expected|.observed=$observed' <<<"$saved") || return 1
    profile_controls::_write "$control" "$saved"
}
profile_controls::preflight() {
    local control=$1 profile=$2 config command value
    config=$(profiles::get "$profile" "$control") || return 1
    case "$control" in
        firewall)
            if ! command -v ufw >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1 || ! command -v ip6tables-save >/dev/null 2>&1; then
                core::confirm "Prepare firewall profiles by installing the missing UFW package? Policy changes require the next separate confirmation." || return 1
                core::install_packages ufw || return 1
            fi
            for command in ufw iptables ip6tables iptables-save ip6tables-save; do command -v "$command" >/dev/null 2>&1 || return 1; done
            [[ -f $PROFILE_ETC/default/ufw && -d $PROFILE_ETC/ufw ]] || return 1
            profile_controls::_standard_ufw_hooks || return 1
            profile_controls::_expiry_ready "$config" || return 1
            core::log 'Multicast discovery (mDNS/SSDP) requires explicit firewall exceptions in every profile; essential DHCP, ICMP and established connections remain available.'
            core::log 'Firewall: replace UFW exceptions with this profile, deny unsolicited incoming/forwarded traffic and allow outgoing IPv4/IPv6. The pre-profile UFW policy is saved for explicit restoration. Existing established connections are not terminated.'
            jq -r '.rules[]|"  Permit \(.protocol)/\(.port) from \(.source) on \(.interface), expiry epoch \(.expires_at) (0 means permanent)."' <<<"$config" >&2
            ;;
        network)
            command -v nmcli >/dev/null 2>&1 || {
                core::die 'NetworkManager is required for network profiles.'
                return 1
            }
            core::log 'Network: apply to saved Wi-Fi/Ethernet profiles. Discovery and MAC settings take effect after reconnecting; OctoShield does not reconnect or trust a network automatically.'
            ;;
        services)
            core::log 'Services: disabled policies stop/mask sharing, printing or Bluetooth units. A Bluetooth keyboard may disconnect; use a built-in or trusted wired keyboard. Baseline restores original states; enabled explicitly starts the selected service.'
            profile_controls::_required_services "$config" "$(profile_controls::_services_snapshot services)" || return 1
            ;;
        monitor)
            value=$(systemctl show --property=LoadState --value octoshield-monitor.service) || return 1
            [[ $value != not-found ]] || {
                core::die 'Install OctoShield system integration before enabling monitor profiles.'
                return 1
            }
            ;;
        *) return 1 ;;
    esac
    profile_controls::snapshot "$control" >/dev/null || return 1
    profile_controls::conflict "$control"
}
profile_controls::_firewall_apply() {
    local profile=$1 defaults listing count index config=${2-} mode=${3-} identifier port protocol source interface expiry
    [[ -n $config ]] || config=$(profiles::get "$profile" firewall) || return 1
    [[ $mode == expire ]] || profile_controls::_expiry_ready "$config" || return 1
    local -a args=()
    profile_controls::_restrict_discovery || return 1
    defaults=$(controls::ufw_defaults "$PROFILE_ETC/default/ufw") || return 1
    core::write_file "$PROFILE_ETC/default/ufw" 0644 <<<"$defaults" || return 1
    ufw default deny incoming || return 1
    ufw default deny routed || return 1
    ufw default allow outgoing || return 1
    # Reload an already active firewall to install IPv6 before rule switching.
    # There is deliberately no reset or disable: old grants are removed before
    # new grants are added, so the transition only narrows then expands.
    ufw --force enable || return 1
    # Timed rules deliberately exist only in the kernel. Reload the permanent
    # policy first so numbered UFW deletions refer to matching disk/kernel rules.
    ufw reload || return 1
    listing=$(LC_ALL=C ufw status numbered) || return 1
    count=$(awk '/^\[[[:space:]]*[0-9]+\]/ {n++} END {print n+0}' <<<"$listing") || return 1
    for ((index = count; index > 0; index--)); do ufw --force delete "$index" || return 1; done
    [[ -n $config ]] || config=$(profiles::get "$profile" firewall) || return 1
    while IFS=$'\t' read -r identifier port protocol source interface expiry; do
        [[ -n $port ]] || continue
        # Finite permissions are added directly to runtime chains after reload;
        # UFW's persistent files must never reopen an expired port at boot.
        ((expiry == 0)) || continue
        profiles::valid_port "$port" && profiles::valid_source "$source" && profiles::valid_interface "$interface" || return 1
        args=(allow in)
        [[ $interface == any ]] || args+=(on "$interface")
        args+=(proto "$protocol" from "$source" to any port "$port" comment "OctoShield:$profile:$identifier")
        ufw "${args[@]}" || return 1
    done < <(jq -r '.rules[]|[.id,.port,.protocol,.source,.interface,.expires_at]|@tsv' <<<"$config")
    ufw logging low || return 1
    ufw reload || return 1
    profile_firewall::temporary_apply "$config" || return 1
    if ! profile_controls::_firewall_verified "$config"; then
        # Finite grants must not survive a failed first application without an
        # active profile/expiry record. The disk policy contains permanent only.
        ufw reload || core::log 'Failed to remove temporary permissions after verification failure; inspect the native firewall immediately.'
        return 1
    fi
}
profile_controls::_network_apply() {
    local profile=$1 config before snapshot uuid type original_autoconnect autoconnect discovery override mac
    config=$(profiles::get "$profile" network) || return 1
    before=$(profile_controls::_read network) || return 1
    snapshot=$(profile_controls::_network_snapshot) || return 1
    autoconnect=$(jq -r .autoconnect <<<"$config") || return 1
    discovery=$(jq -r 'if .discovery then "2" else "0" end' <<<"$config") || return 1
    core::backup "$PROFILE_ETC/NetworkManager/system-connections" || return 1
    core::backup "$PROFILE_RUN/NetworkManager/system-connections" || return 1
    core::write_file "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" 0644 <<'CONFIG' || return 1
# Managed by OctoShield profiles. Individual profiles take precedence.
[device]
wifi.scan-rand-mac-address=yes
wifi.iwd.autoconnect=false
[connection]
wifi.cloned-mac-address=stable
connection.llmnr=0
connection.mdns=0
CONFIG
    while IFS=$'\t' read -r uuid type; do
        [[ -n $uuid ]] || continue
        override=$(jq -c --arg uuid "$uuid" '.connections[$uuid]//{}' <<<"$config") || return 1
        # jq's // treats false as absent; explicit false must override true.
        discovery=$(jq -r --argjson config "$config" 'if (if has("discovery") then .discovery else $config.discovery end) then "2" else "0" end' <<<"$override") || return 1
        nmcli connection modify uuid "$uuid" connection.llmnr "$discovery" connection.mdns "$discovery" || return 1
        case "$type" in
            wifi | 802-11-wireless)
                original_autoconnect=$(jq -r --arg uuid "$uuid" '[.before.connections[]|select(.uuid==$uuid)|.autoconnect][0]//"no"' <<<"$before") || return 1
                [[ $autoconnect == true ]] || original_autoconnect=no
                original_autoconnect=$(jq -r --arg original "$original_autoconnect" 'if has("autoconnect") then (if .autoconnect then "yes" else "no" end) else $original end' <<<"$override") || return 1
                mac=$(jq -r '.mac//"stable"' <<<"$override") || return 1
                nmcli connection modify uuid "$uuid" connection.autoconnect "$original_autoconnect" 802-11-wireless.cloned-mac-address "$mac" || return 1
                ;;
            *)
                if jq -e 'has("autoconnect")' <<<"$override" >/dev/null; then
                    original_autoconnect=$(jq -r 'if .autoconnect then "yes" else "no" end' <<<"$override") || return 1
                    nmcli connection modify uuid "$uuid" connection.autoconnect "$original_autoconnect" || return 1
                fi
                ;;
        esac
    done < <(jq -r '.connections[]|[.uuid,.type]|@tsv' <<<"$snapshot")
    nmcli general reload conf || return 1
    core::log 'Saved network settings changed. Reconnect manually to apply discovery/MAC settings to active connections.'
}
profile_controls::_unit_restore() {
    local unit=$1 enabled=$2 active=$3
    systemctl unmask "$unit" || return 1
    case "$enabled" in
        enabled) systemctl enable "$unit" || return 1 ;;
        enabled-runtime) systemctl enable --runtime "$unit" || return 1 ;;
        disabled) systemctl disable "$unit" || return 1 ;;
        masked)
            systemctl mask --now "$unit" || return 1
            return 0
            ;;
        masked-runtime)
            systemctl mask --runtime --now "$unit" || return 1
            return 0
            ;;
        static | indirect | alias) ;;
        *) return 1 ;;
    esac
    if [[ $active == active ]]; then systemctl start "$unit"; else systemctl stop "$unit"; fi
}
profile_controls::_services_apply() {
    local profile=$1 config baseline snapshot unit policy enabled active group
    config=$(profiles::get "$profile" services) || return 1
    baseline=$(profile_controls::_read services) || return 1
    snapshot=$(profile_controls::_services_snapshot services) || return 1
    profile_controls::_required_services "$config" "$snapshot" || return 1
    # Socket/path dependencies must be unmasked before any primary is started.
    while IFS= read -r unit; do
        case "$unit" in cups*) group=printing ;; bluetooth*) group=bluetooth ;; ssh.*) group=ssh ;; avahi-*) group=discovery ;;
        smbd.* | nmbd.*) group=samba ;;
        gnome-remote-desktop.*) group=remote_desktop ;; *) continue ;; esac
        policy=$(jq -r --arg key "$group" '.[$key]' <<<"$config") || return 1
        [[ $policy == disabled ]] || systemctl unmask "$unit" || return 1
    done < <(jq -r '.units[].unit' <<<"$snapshot")
    while IFS= read -r unit; do
        [[ -n $unit ]] || continue
        case "$unit" in
            cups*) group=printing ;;
            bluetooth*) group=bluetooth ;;
            ssh.*) group=ssh ;;
            avahi-*) group=discovery ;;
            smbd.* | nmbd.*) group=samba ;;
            gnome-remote-desktop.*) group=remote_desktop ;;
            *) group= ;;
        esac
        policy=disabled
        [[ -z $group ]] || policy=$(jq -r --arg key "$group" '.[$key]' <<<"$config") || return 1
        case "$policy" in
            disabled) systemctl mask --now "$unit" || return 1 ;;
            enabled)
                systemctl unmask "$unit" || return 1
                # Start the primary service, unmasking its socket/path partners;
                # do not broadly enable every activation unit or sharing daemon.
                case "$unit" in cups.service | bluetooth.service | ssh.service | avahi-daemon.service | smbd.service | nmbd.service | gnome-remote-desktop.service) systemctl enable --now "$unit" || return 1 ;; esac
                ;;
            baseline)
                enabled=$(jq -r --arg unit "$unit" '[.before.units[]|select(.unit==$unit)|.enabled][0]//"disabled"' <<<"$baseline") || return 1
                active=$(jq -r --arg unit "$unit" '[.before.units[]|select(.unit==$unit)|.active][0]//"inactive"' <<<"$baseline") || return 1
                profile_controls::_unit_restore "$unit" "$enabled" "$active" || return 1
                ;;
            *) return 1 ;;
        esac
    done < <(jq -r '.units[].unit' <<<"$snapshot")
}
profile_controls::apply() {
    local control=$1 profile=$2 success=0 value
    profile_controls::conflict "$control" || return 1
    profile_controls::_capture "$control" || return 1
    case "$control" in
        firewall) profile_controls::_firewall_apply "$profile" && success=1 ;;
        network) profile_controls::_network_apply "$profile" && success=1 ;;
        services) profile_controls::_services_apply "$profile" && success=1 ;;
        monitor)
            value=$(profiles::get "$profile" monitor.enabled) || return 1
            if [[ $value == true ]]; then
                systemctl enable --now octoshield-monitor.service && success=1
            else systemctl disable --now octoshield-monitor.service && success=1; fi
            ;;
        *) return 1 ;;
    esac
    # Record partial effects too, so an explicitly requested restore can recover
    # a failed first adoption. A crash before this record remains a conflict.
    profile_controls::_record_actual "$control" || return 1
    ((success == 1)) || return 1
    profile_controls::_satisfies "$control" "$profile" "$(profile_controls::snapshot "$control")" || return 1
    profile_controls::remember_desired "$control" "$profile"
}
profile_controls::_restore_native() {
    local control=$1 saved before directory temporary unit enabled active uuid autoconnect llmnr mdns mac type content mode
    directory=$(profile_controls::_directory) || return 1
    [[ -e $directory/$control.json ]] || return 0
    profile_controls::conflict "$control" || return 1
    saved=$(profile_controls::_read "$control") || return 1
    before=$(jq -c .before <<<"$saved") || return 1
    case "$control" in
        firewall)
            [[ -d $directory/firewall-baseline/ufw && -f $directory/firewall-baseline/default-ufw ]] || return 1
            core::backup "$PROFILE_ETC/ufw" || return 1
            core::backup "$PROFILE_ETC/default/ufw" || return 1
            temporary=$(mktemp -d "$PROFILE_ETC/.octoshield-ufw.XXXXXX") || return 1
            cp -a -- "$directory/firewall-baseline/ufw" "$temporary/ufw" || return 1
            mv -- "$PROFILE_ETC/ufw" "$temporary/replaced" || return 1
            if ! mv -- "$temporary/ufw" "$PROFILE_ETC/ufw"; then
                mv -- "$temporary/replaced" "$PROFILE_ETC/ufw" || :
                return 1
            fi
            core::write_file "$PROFILE_ETC/default/ufw" 0644 <"$directory/firewall-baseline/default-ufw" || return 1
            if [[ $(jq -r .status <<<"$before") == *'Status: active'* ]]; then
                ufw --force enable && ufw reload || return 1
            else ufw --force disable || return 1; fi
            rm -rf -- "$temporary" || return 1
            ;;
        network)
            if [[ $(jq -r .config.exists <<<"$before") == true ]]; then
                content=$(jq -r .config.content <<<"$before") || return 1
                mode=$(jq -r .config.mode <<<"$before") || return 1
                [[ $mode =~ ^[0-7]{3,4}$ ]] || return 1
                core::write_file "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" "$mode" <<<"$content" || return 1
            else
                core::backup "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" || return 1
                rm -f -- "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" || return 1
            fi
            while IFS=$'\t' read -r uuid type autoconnect llmnr mdns mac; do
                [[ -n $uuid ]] || continue
                nmcli connection modify uuid "$uuid" connection.autoconnect "$autoconnect" connection.llmnr "$llmnr" connection.mdns "$mdns" || return 1
                case "$type" in wifi | 802-11-wireless) nmcli connection modify uuid "$uuid" 802-11-wireless.cloned-mac-address "$mac" || return 1 ;; esac
            done < <(jq -r '.connections[]|[.uuid,.type,.autoconnect,.llmnr,.mdns,.mac]|@tsv' <<<"$before")
            nmcli general reload conf || return 1
            ;;
        services | monitor)
            # Restore all activation dependencies before starting any primary.
            while IFS=$'\t' read -r unit enabled; do
                [[ $enabled == masked || $enabled == masked-runtime ]] || systemctl unmask "$unit" || return 1
            done < <(jq -r '.units[]|[.unit,.enabled]|@tsv' <<<"$before")
            while IFS=$'\t' read -r unit enabled active; do profile_controls::_unit_restore "$unit" "$enabled" "$active" || return 1; done < <(jq -r '.units[]|[.unit,.enabled,.active]|@tsv' <<<"$before")
            ;;
        *) return 1 ;;
    esac
    rm -f -- "$directory/$control.json" || return 1
    [[ $control != firewall ]] || rm -rf -- "$directory/firewall-baseline" || return 1
    core::record "PROFILE restore $control"
}
profile_controls::restore() {
    local control=$1
    if profile_controls::_restore_native "$control"; then return 0; fi
    profile_controls::_record_actual "$control" || :
    return 1
}
profile_controls::verify() {
    local control=$1 profile saved current expected desired state summary document result
    profile=$(profiles::active "$control") || return 1
    document=$(profiles::state) || return 1
    result=$(jq -r --arg c "$control" '.results[$c].status//"unmanaged"' <<<"$document") || return 1
    if [[ $result == failed || $result == applying ]]; then
        state=partial
        summary='The previous profile change did not complete. Inspect and restore or retry.'
    elif [[ $profile == unmanaged ]]; then
        state=unknown
        summary='No profile controls this area; inspect its native state.'
    elif ! saved=$(profile_controls::_read "$control") || ! current=$(profile_controls::snapshot "$control"); then
        state=unknown
        summary='Native policy or saved verification data could not be read.'
    else
        expected=$(jq -r .expected <<<"$saved") || return 1
        desired=$(profiles::get "$profile" "$control" | profile_controls::_hash) || return 1
        if [[ $(profile_controls::_hash <<<"$current") != "$expected" ]]; then
            state=partial
            if [[ $control == firewall ]] && profile_controls::_runtime_narrowed "$saved"; then
                summary='Temporary permissions ended after a firewall reload or reboot. Permanent protection remains; Apply to reactivate unexpired exceptions.'
            else summary='Native policy differs from the last applied profile; review external changes.'; fi
        elif [[ $(jq -r .desired <<<"$saved") != "$desired" ]]; then
            state=partial
            summary='Profile settings were edited. Apply the profile to activate them.'
        elif ! profile_controls::_satisfies "$control" "$profile" "$current"; then
            state=partial
            summary='Native settings do not satisfy the selected profile.'
        elif [[ $control == monitor && $(profiles::get "$profile" monitor.enabled) == false ]]; then
            state=inactive
            summary="Monitoring is disabled as configured in $profile."
        elif [[ $control == network ]]; then
            if declare -F connections::verify_runtime >/dev/null; then
                connections::verify_runtime "$current"
                return
            fi
            state=unknown
            summary='Saved network policy matches. Active connection inspection is unavailable.'
        else
            state=active
            summary="Verified native policy matches $profile."
        fi
    fi
    jq -cn --arg state "$state" --arg summary "$summary" '{state:$state,summary:$summary}'
}

# A successful command is not proof of the requested state. Compare observed
# native settings to desired policy in addition to detecting later drift.
profile_controls::_satisfies() {
    local control=$1 profile=$2 current=$3 config baseline unit group policy enabled active original actual
    config=$(profiles::get "$profile" "$control") || return 1
    baseline=$(profile_controls::_read "$control") || return 1
    case "$control" in
        firewall) profile_firewall::verify "$config" && profile_controls::_expiry_ready "$config" ;;
        monitor)
            if [[ $(jq -r .enabled <<<"$config") == true ]]; then
                jq -e 'any(.units[]; .unit=="octoshield-monitor.service" and .enabled=="enabled" and .active=="active")' <<<"$current" >/dev/null
            else jq -e 'all(.units[]; .enabled!="enabled" and .enabled!="enabled-runtime" and .active!="active")' <<<"$current" >/dev/null; fi
            ;;
        network)
            jq -e --argjson config "$config" --argjson baseline "$baseline" '
              all(.connections[]; . as $connection|($config.connections[.uuid]//{}) as $override|
                (if $override|has("discovery") then $override.discovery else $config.discovery end) as $discovery|
                .llmnr==(if $discovery then "2" else "0" end) and .mdns==(if $discovery then "2" else "0" end)
                and (if .type=="wifi" or .type=="802-11-wireless" then
                  .mac==($override.mac//"stable") and .autoconnect==(if $override|has("autoconnect") then (if $override.autoconnect then "yes" else "no" end) elif $config.autoconnect then ([$baseline.before.connections[]|select(.uuid==$connection.uuid)|.autoconnect][0]//"no") else "no" end)
                elif $override|has("autoconnect") then .autoconnect==(if $override.autoconnect then "yes" else "no" end)
                else true end))' <<<"$current" >/dev/null
            ;;
        services)
            profile_controls::_required_services "$config" "$current" || return 1
            while IFS=$'\t' read -r unit enabled active; do
                case "$unit" in cups*) group=printing ;; bluetooth*) group=bluetooth ;; ssh.*) group=ssh ;; avahi-*) group=discovery ;;
                smbd.* | nmbd.*) group=samba ;;
                gnome-remote-desktop.*) group=remote_desktop ;; *) group= ;; esac
                policy=disabled
                [[ -z $group ]] || policy=$(jq -r --arg group "$group" '.[$group]' <<<"$config") || return 1
                case "$policy" in
                    disabled) [[ $enabled == masked && $active != active ]] || return 1 ;;
                    enabled)
                        [[ $enabled != masked && $enabled != masked-runtime ]] || return 1
                        case "$unit" in cups.service | bluetooth.service | ssh.service | avahi-daemon.service | smbd.service | nmbd.service | gnome-remote-desktop.service) [[ $active == active && $enabled == enabled ]] || return 1 ;; esac
                        ;;
                    baseline)
                        original=$(jq -c --arg unit "$unit" '[.before.units[]|select(.unit==$unit)|{enabled,active}][0]//{enabled:"disabled",active:"inactive"}' <<<"$baseline") || return 1
                        actual=$(jq -cn --arg enabled "$enabled" --arg active "$active" '{enabled:$enabled,active:$active}') || return 1
                        [[ $original == "$actual" ]] || return 1
                        ;;
                    *) return 1 ;;
                esac
            done < <(jq -r '.units[]|[.unit,.enabled,.active]|@tsv' <<<"$current")
            ;;
        *) return 1 ;;
    esac
}
profile_controls::expiry_due() {
    local saved now profile desired
    saved=$(profile_controls::_read firewall) || return 1
    now=$(date +%s) || return 1
    if jq -e --argjson now "$now" 'any(.policy.rules[]?; .expires_at>0 and .expires_at<=$now)' <<<"$saved" >/dev/null; then return 0; fi
    # A previous process may have committed adapter bookkeeping and then exited
    # before the profile document was saved. Retry that harmless reconciliation
    # without applying any pending edit or adding a native permission.
    profile=$(profiles::active firewall) || return 1
    [[ $profile != unmanaged ]] || return 1
    desired=$(profiles::get "$profile" firewall) || return 1
    jq -e --argjson now "$now" 'any(.rules[]; .expires_at>0 and .expires_at<=$now)' <<<"$desired" >/dev/null
}
profile_controls::expire() {
    local saved policy now current checked expected
    profiles::valid_name "${1-}" || return 1
    saved=$(profile_controls::_read firewall) || return 1
    policy=$(jq -ce .policy <<<"$saved") || return 1
    current=$(profile_controls::snapshot firewall) || return 1
    expected=$(jq -r .expected <<<"$saved") || return 1
    if [[ $(profile_controls::_hash <<<"$current") != "$expected" ]]; then
        if profile_controls::_runtime_narrowed "$saved" "$current"; then
            policy=$(jq -c '.rules|=map(select(.expires_at==0))' <<<"$policy") || return 1
        else
            core::die 'Firewall policy changed outside OctoShield; expiry metadata was preserved for review and retry.'
            return 1
        fi
    fi
    now=$(date +%s) || return 1
    policy=$(jq -c --argjson now "$now" '.rules|=map(select(.expires_at==0 or .expires_at>$now))' <<<"$policy") || return 1
    # The kernel time matcher already closes expired grants. Verify that effective
    # policy and update bookkeeping only: replaying hundreds of UFW rules here
    # could exceed the observer deadline and interrupt unrelated protection.
    # Inert expired kernel rules remain bounded by the 256-rule profile limit and
    # disappear at the next explicitly authorized Apply or native firewall reload.
    profile_firewall::verify "$policy" || return 1
    checked=$(profile_controls::snapshot firewall) || return 1
    [[ $(profile_controls::_hash <<<"$checked") == "$(profile_controls::_hash <<<"$current")" ]] || {
        core::die 'Firewall policy changed during expiry verification; retrying on the next observation.'
        return 1
    }
    saved=$(jq -c --arg expected "$(profile_controls::_hash <<<"$current")" --arg desired "$(profile_controls::_hash <<<"$policy")" --argjson observed "$current" --argjson policy "$policy" '.expected=$expected|.desired=$desired|.policy=$policy|.observed=$observed' <<<"$saved") || return 1
    profile_controls::_write firewall "$saved"
}

# UFW's user rules cannot constrain arbitrary administrator before/after hooks.
# Refuse adoption when package-owned base rules were changed instead of silently
# reporting that an earlier unconditional ACCEPT is protected by default-deny.
profile_controls::_standard_ufw_hooks() {
    local manifest name path vendor relative expected actual vendor_hash
    if [[ -e $(profile_controls::_directory)/firewall.json ]]; then
        # First adoption checked the vendor files before removing the four
        # discovery grants. Subsequent changes must match our recorded policy.
        profile_controls::conflict firewall
        return
    fi
    # UFW installs these hooks through ucf/postinst, not dpkg Conffiles. Verify
    # their package-owned templates against dpkg's payload checksums, then compare
    # installed hooks to those verified templates. A modified vendor template
    # must never make an equally modified hook look like a safe factory default.
    manifest=$(dpkg-query --control-show ufw md5sums) || return 1
    for name in before.rules before6.rules after.rules after6.rules before.init after.init; do
        path="$PROFILE_ETC/ufw/$name"
        [[ -e $path || -L $path ]] || continue
        [[ -f $path && ! -L $path ]] || return 1
        case "$name" in *.rules) relative="iptables/$name" ;; *) relative=$name ;; esac
        vendor="$PROFILE_SHARE/$relative"
        [[ -f $vendor && ! -L $vendor ]] || {
            core::die "The UFW vendor template for $name is missing or unsafe; reinstall ufw before profile adoption."
            return 1
        }
        expected=$(awk -v path="usr/share/ufw/$relative" '$2==path {print $1}' <<<"$manifest") || return 1
        [[ $expected =~ ^[a-f0-9]{32}$ ]] || {
            core::die "Package integrity data is missing for the UFW $name vendor template; reinstall ufw before profile adoption."
            return 1
        }
        vendor_hash=$(md5sum -- "$vendor") || return 1
        [[ ${vendor_hash%% *} == "$expected" ]] || {
            core::die "The UFW vendor template for $name differs from the installed package. Review it or reinstall ufw before profile adoption."
            return 1
        }
        actual=$(md5sum -- "$path") || return 1
        [[ ${actual%% *} == "$expected" ]] || {
            core::die "UFW $name contains administrator changes. Profile switching will not overwrite or claim coverage of those rules."
            return 1
        }
    done
}

profile_controls::_expiry_ready() {
    local config=$1 now loaded enabled active
    now=$(date +%s) || return 1
    jq -e --argjson now "$now" 'any(.rules[]; .expires_at>$now)' <<<"$config" >/dev/null || return 0
    loaded=$(systemctl show --property=LoadState --value octoshield-status.service) || return 1
    enabled=$(systemctl show --property=UnitFileState --value octoshield-status.service) || return 1
    active=$(systemctl show --property=ActiveState --value octoshield-status.service) || return 1
    [[ $loaded == loaded && $enabled == enabled && $active == active ]] || {
        core::die 'Timed firewall permissions require the enabled, running OctoShield status service for profile status and expiry bookkeeping. The kernel enforces their deadlines. Start the service before applying temporary exceptions.'
        return 1
    }
}

profile_controls::_restrict_discovery() {
    local name file content
    for name in before.rules before6.rules; do
        file="$PROFILE_ETC/ufw/$name"
        [[ -f $file && ! -L $file ]] || continue
        # Remove only exact package rules verified during first adoption. Do
        # not rewrite unrelated ICMP, DHCP, established, or loopback behavior.
        content=$(awk '
          $0=="-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT" {next}
          $0=="-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT" {next}
          $0=="-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT" {next}
          $0=="-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT" {next}
          {print}
        ' "$file") || return 1
        core::write_file "$file" 0640 <<<"$content" || return 1
    done
}

# A reload/reboot intentionally drops runtime-only timed grants. Accept only
# this exact narrowing, with untouched disk policy and every other captured
# native chain unchanged. An unrelated external change remains a conflict.
profile_controls::_runtime_narrowed() {
    local saved=$1 current=${2-} permanent before after family
    jq -e '.observed|type=="object"' <<<"$saved" >/dev/null || return 1
    jq -e 'any(.policy.rules[]?; .expires_at>0)' <<<"$saved" >/dev/null || return 1
    [[ -n $current ]] || current=$(profile_controls::_firewall_snapshot) || return 1
    [[ $(jq -r .observed.config <<<"$saved") == "$(jq -r .config <<<"$current")" ]] || return 1
    before=$(jq -r .observed.status <<<"$saved" | awk '/^(Status:|Logging:|Default:|New profiles:)/') || return 1
    after=$(jq -r .status <<<"$current" | awk '/^(Status:|Logging:|Default:|New profiles:)/') || return 1
    [[ $before == "$after" ]] || return 1
    for family in ipv4 ipv6; do
        before=$(jq -r --arg family "$family" '.observed[$family]' <<<"$saved" | awk '!/^-A ufw6?-user-input /') || return 1
        after=$(jq -r --arg family "$family" '.[$family]' <<<"$current" | awk '!/^-A ufw6?-user-input /') || return 1
        [[ $before == "$after" ]] || return 1
    done
    permanent=$(jq -c '.policy|.rules|=map(select(.expires_at==0))' <<<"$saved") || return 1
    profile_firewall::verify "$permanent"
}

profile_controls::_firewall_verified() {
    local config=$1 status
    status=$(LC_ALL=C ufw status verbose) || return 1
    [[ $status == *'Status: active'* && $status == *'deny (incoming)'* && $status == *'allow (outgoing)'* && $status == *'deny (routed)'* ]] || return 1
    profile_firewall::verify "$config" || return 1
    # A persisted IPv6=yes setting alone is not evidence of a live IPv6 filter.
    ip6tables-save | awk '/^-A INPUT .*ufw6-before-input/ {input=1} /^:ufw6-user-input / {user=1} END {exit !(input && user)}'
}

profile_controls::_required_services() {
    local config=$1 current=$2 group unit
    for group in printing bluetooth ssh discovery samba remote_desktop; do
        [[ $(jq -r --arg group "$group" '.[$group]' <<<"$config") == enabled ]] || continue
        case "$group" in printing) unit=cups.service ;; bluetooth) unit=bluetooth.service ;; ssh) unit=ssh.service ;; discovery) unit=avahi-daemon.service ;; samba) unit=smbd.service ;; remote_desktop) unit=gnome-remote-desktop.service ;; esac
        jq -e --arg unit "$unit" 'any(.units[];.unit==$unit)' <<<"$current" >/dev/null || {
            core::die "Cannot enable $group: its primary service is not installed."
            return 1
        }
    done
}
