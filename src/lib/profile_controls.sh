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
profile_controls::_tree_hash() (
    set -o pipefail
    local path file logical metadata digest index
    local -a sources=("${1:-$PROFILE_ETC/ufw}" "${2:-$PROFILE_ETC/default/ufw}")
    local -a targets=("$PROFILE_ETC/ufw" "$PROFILE_ETC/default/ufw")
    for index in 0 1; do
        path=${sources[index]}
        logical=${targets[index]}
        [[ ! -L $path ]] || return 1
        [[ -e $path ]] || {
            printf 'absent:%s\n' "$logical"
            continue
        }
        metadata=$(stat -c '%u:%g:%a:%F' -- "$path") || return 1
        printf '%s:%s\n' "$logical" "$metadata"
        if [[ -d $path ]]; then
            [[ -z $(find "$path" -type l -print -quit) ]] || return 1
            find "$path" -type f -print0 | sort -z | while IFS= read -r -d '' file; do
                metadata=$(stat -c '%u:%g:%a:%F' -- "$file") || return 1
                digest=$(sha256sum -- "$file") || return 1
                printf '%s:%s\n%s  %s\n' "$logical${file#"$path"}" "$metadata" "${digest%% *}" "$logical${file#"$path"}"
            done || return 1
        else
            digest=$(sha256sum -- "$path") || return 1
            printf '%s  %s\n' "${digest%% *}" "$logical"
        fi
    done | profile_controls::_hash
)
profile_controls::_firewall_snapshot() {
    local config status ipv4 ipv6
    config=$(profile_controls::_tree_hash) || return 1
    status=$(LC_ALL=C ufw status verbose) || return 1
    # Strip packet counters: traffic must not look like a policy modification.
    ipv4=$(iptables-save | awk '/^:(INPUT|FORWARD|OUTPUT) / || /^:ufw/ || /^-A ufw/ || /^-A (INPUT|FORWARD|OUTPUT) / {gsub(/\[[0-9]+:[0-9]+\]/,"[counter]");print}') || return 1
    ipv6=$(ip6tables-save | awk '/^:(INPUT|FORWARD|OUTPUT) / || /^:ufw/ || /^-A ufw/ || /^-A (INPUT|FORWARD|OUTPUT) / {gsub(/\[[0-9]+:[0-9]+\]/,"[counter]");print}') || return 1
    jq -cn --arg config "$config" --arg status "$status" --arg ipv4 "$ipv4" --arg ipv6 "$ipv6" '{config:$config,status:$status,ipv4:$ipv4,ipv6:$ipv6}'
}

profile_controls::_firewall_trusted_path() {
    local path=$1 kind=${2:-file} owner mode links size
    [[ ! -L $path ]] || return 1
    if [[ $kind == directory ]]; then [[ -d $path ]] || return 1; else [[ -f $path ]] || return 1; fi
    IFS=: read -r owner mode links size < <(stat -c '%u:%a:%h:%s' -- "$path")
    [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ && $links =~ ^[0-9]+$ && $size =~ ^[0-9]+$ ]] || return 1
    (((8#$mode & 0022) == 0)) || return 1
    [[ $kind == directory ]] || ((links == 1 && size <= 1048576))
}

profile_controls::_firewall_trusted_tree() (
    set -o pipefail
    local directory=$1 path count=0
    profile_controls::_firewall_trusted_path "$directory" directory || return 1
    find "$directory" -print0 | while IFS= read -r -d '' path; do
        # Retained tree names are data, but must be representable by the legacy
        # path-based fingerprint without newline or checksum escaping ambiguity.
        [[ $path != *[[:cntrl:]\\]* ]] || return 1
        count=$((count + 1))
        ((count <= 4096)) || return 1
        if [[ -d $path ]]; then
            profile_controls::_firewall_trusted_path "$path" directory || return 1
        else profile_controls::_firewall_trusted_path "$path" || return 1; fi
    done
)

# Availability means a trustworthy, complete original, not merely a directory
# with the expected name. The old fingerprint uses live absolute paths, so hash
# the retained copy under those same logical names without touching /etc.
profile_controls::firewall_baseline_available() {
    local directory saved baseline fingerprint
    directory=$(profile_controls::_directory) || return 1
    baseline="$directory/firewall-baseline"
    profiles::_secure_file "$CORE_STATE" directory && profiles::_secure_file "$CORE_STATE/profiles" directory &&
        profiles::_secure_file "$directory" directory && profiles::_secure_file "$baseline" directory || return 1
    profile_controls::_firewall_trusted_path "$directory/firewall.json" || return 1
    saved=$(profile_controls::_read firewall) || return 1
    jq -se 'length==1 and (.[0] | .schema==1 and
      (.expected|type=="string" and test("^[a-f0-9]{64}$")) and
      (.desired|type=="string" and (.=="" or test("^[a-f0-9]{64}$"))) and
      (.before|type=="object" and (.config|type=="string" and test("^[a-f0-9]{64}$")) and
        (.status|type=="string" and length<=262144 and (test("^Status: active(\\n|$)") or .=="Status: inactive")) and
        (.ipv4|type=="string" and length<=4194304) and (.ipv6|type=="string" and length<=4194304)))' <<<"$saved" >/dev/null || return 1
    profile_controls::_firewall_trusted_tree "$baseline/ufw" && profile_controls::_firewall_trusted_path "$baseline/default-ufw" || return 1
    fingerprint=$(profile_controls::_tree_hash "$baseline/ufw" "$baseline/default-ufw") || return 1
    [[ $fingerprint == "$(jq -r .before.config <<<"$saved")" ]]
}

profile_controls::firewall_reconcile_safe() {
    local observed ipv4 ipv6
    if ! profile_controls::_firewall_trusted_path "$PROFILE_ETC" directory ||
        ! profile_controls::_firewall_trusted_path "$PROFILE_ETC/default" directory ||
        ! profile_controls::_firewall_trusted_path "$PROFILE_ETC/default/ufw" ||
        ! profile_controls::_firewall_trusted_tree "$PROFILE_ETC/ufw"; then
        core::die 'UFW configuration paths, ownership or permissions are unsafe. Reconciliation was refused.'
        return 1
    fi
    profile_controls::_verified_ufw_hooks recognized || return 1
    if ! observed=$(LC_ALL=C ufw status verbose) || ! ipv4=$(LC_ALL=C iptables-save) || ! ipv6=$(LC_ALL=C ip6tables-save); then
        core::die 'The current UFW status and both address families must be readable before reconciliation.'
        return 1
    fi
    if [[ $observed == 'Status: inactive' ]]; then
        profile_firewall::_inactive 4 "$ipv4" >/dev/null && profile_firewall::_inactive 6 "$ipv6" >/dev/null
        return
    fi
    [[ $observed == 'Status: active'$'\n'* ]] || {
        core::die 'UFW returned an unrecognized active state.'
        return 1
    }
    profile_firewall::_native 4 "$ipv4" 0 reconcile >/dev/null && profile_firewall::_native 6 "$ipv6" 0 reconcile >/dev/null
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
profile_controls::_network_changes() {
    local previous=$1 current=$2 line changes
    changes=$(jq -nr --argjson previous "$previous" --argjson current "$current" '
        ($previous.connections|map({key:.uuid,value:.})|from_entries) as $old |
        ($current.connections|map({key:.uuid,value:.})|from_entries) as $new |
        (($old+$new)|keys[]) as $uuid |
        if $old[$uuid]==null then "Connection \($uuid): added"
        elif $new[$uuid]==null then "Connection \($uuid): removed"
        else ["type","autoconnect","llmnr","mdns","mac"][] as $key |
            select($old[$uuid][$key]!=$new[$uuid][$key]) |
            "Connection \($uuid): \($key) \($old[$uuid][$key]|tojson) -> \($new[$uuid][$key]|tojson)" end') || return 1
    while IFS= read -r line; do [[ -z $line ]] || core::log "$line" || return 1; done <<<"$changes"
    if [[ $(jq -c .config <<<"$previous") != "$(jq -c .config <<<"$current")" ]]; then
        core::log 'NetworkManager global OctoShield configuration changed (content, presence or permissions). Inspect /etc/NetworkManager/conf.d/90-octoshield.conf before accepting.' || return 1
    fi
}
profile_controls::conflict() {
    local control=$1 saved current expected file snapshot
    file="$(profile_controls::_directory)/$control.json"
    [[ -e $file || -L $file ]] || return 0
    saved=$(profile_controls::_read "$control") || return 1
    expected=$(jq -r .expected <<<"$saved") || return 1
    snapshot=$(profile_controls::snapshot "$control") || return 1
    current=$(profile_controls::_hash <<<"$snapshot") || return 1
    [[ $current == "$expected" ]] || {
        if [[ $control == firewall ]] && profile_controls::_runtime_narrowed "$saved"; then return 0; fi
        if [[ $control == network ]]; then
            profile_controls::_network_changes "$(jq -c '.observed//.before' <<<"$saved")" "$snapshot" || return 1
            core::die 'Saved network settings differ from the recorded state. Use Connection privacy > Review external changes, or octoshield connections reconcile. No native settings were overwritten.'
            return 1
        fi
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
    local control=$1 saved before directory temporary unit enabled active uuid autoconnect llmnr mdns mac type content mode current restore_expected preview
    directory=$(profile_controls::_directory) || return 1
    [[ -e $directory/$control.json ]] || return 0
    profile_controls::conflict "$control" || return 1
    saved=$(profile_controls::_read "$control") || return 1
    before=$(jq -c .before <<<"$saved") || return 1
    if [[ $control == network ]]; then
        current=$(profile_controls::_network_snapshot) || return 1
        restore_expected=$(jq -c --argjson baseline "$before" '
            .config=$baseline.config |
            .connections|=map(. as $connection | ([$baseline.connections[]|select(.uuid==$connection.uuid)][0]//$connection))' <<<"$current") || return 1
        profile_controls::_network_changes "$current" "$restore_expected" || return 1
        core::log 'Restore the displayed saved settings. Connections absent from the baseline are retained; deleted connections are not recreated. Active connections are not reconnected.'
        core::confirm 'Restore these saved NetworkManager settings?' || return 1
        [[ $(profile_controls::_network_snapshot) == "$current" ]] || {
            core::die 'Network settings changed during restore review. Refresh and review again.'
            return 1
        }
    fi
    [[ $control == firewall ]] || PROFILE_RESTORE_STARTED=true
    case "$control" in
        firewall)
            profile_controls::firewall_baseline_available || {
                core::die 'The original firewall baseline is missing, unsafe or differs from its saved fingerprint. Recovery evidence was retained.'
                return 1
            }
            if ! profile_controls::_firewall_trusted_path "$PROFILE_ETC" directory ||
                ! profile_controls::_firewall_trusted_path "$PROFILE_ETC/default" directory ||
                ! profile_controls::_firewall_trusted_path "$PROFILE_ETC/default/ufw" ||
                ! profile_controls::_firewall_trusted_tree "$PROFILE_ETC/ufw"; then
                core::die 'Current firewall paths are unsafe; the original baseline was not installed.'
                return 1
            fi
            current=$(profile_controls::snapshot firewall) || return 1
            preview=$(profile_controls::_firewall_restore_preview "$saved") || {
                core::die 'The complete original firewall policy cannot be previewed within the safe display limit. Inspect the retained baseline manually; nothing was restored.'
                return 1
            }
            preview=$(printf '%s\n' "$preview" | LC_ALL=C sed -n l) || return 1
            ((${#preview} <= 65536)) || {
                core::die 'The escaped original firewall policy exceeds the review limit. Inspect the retained baseline manually; nothing was restored.'
                return 1
            }
            core::log 'Review the original firewall state, recorded input rules and retained configuration below. Non-printing characters are escaped.' || return 1
            printf '%s\n' "$preview" || return 1
            core::log 'Restore reinstates these saved UFW settings and exceptions. If the original state was inactive, UFW will be disabled. Other protection areas and unrelated container forwarding rules are not restored.' || return 1
            # A declined review is distinct from a failed native restoration;
            # callers preserve the existing result for this no-change outcome.
            core::confirm 'Restore this displayed original firewall state and saved exceptions?' || return 3
            if [[ $(profile_controls::_read firewall) != "$saved" || $(profile_controls::snapshot firewall) != "$current" ]] ||
                ! profile_controls::firewall_baseline_available; then
                core::die 'The firewall or original recovery evidence changed during review. Nothing was restored; refresh and review again.'
                return 1
            fi
            # Retain the original evidence in this transaction as well as its
            # management location, so a later cleanup error cannot destroy it.
            core::backup "$directory/firewall.json" || return 1
            core::backup "$directory/firewall-baseline" || return 1
            core::backup "$PROFILE_ETC/ufw" || return 1
            core::backup "$PROFILE_ETC/default/ufw" || return 1
            temporary=$(mktemp -d "$PROFILE_ETC/.octoshield-ufw.XXXXXX") || return 1
            cp -a -- "$directory/firewall-baseline/ufw" "$temporary/ufw" || return 1
            cp -a -- "$directory/firewall-baseline/default-ufw" "$temporary/default-ufw" || return 1
            [[ $(profile_controls::_tree_hash "$temporary/ufw" "$temporary/default-ufw") == "$(jq -r .config <<<"$before")" ]] || {
                core::die 'The staged original firewall files did not match their saved fingerprint; nothing was restored.'
                return 1
            }
            # Staging and backup can take time. Preserve any native change that
            # appeared after the reviewed conflict check rather than replacing it.
            if [[ $(profile_controls::_read firewall) != "$saved" || $(profile_controls::snapshot firewall) != "$current" ]] ||
                ! profile_controls::firewall_baseline_available; then
                core::die 'The firewall or saved recovery evidence changed during staging; nothing was restored.'
                return 1
            fi
            profile_controls::conflict firewall || return 1
            PROFILE_RESTORE_STARTED=true
            mv -- "$PROFILE_ETC/ufw" "$temporary/replaced" || return 1
            if ! mv -- "$temporary/ufw" "$PROFILE_ETC/ufw"; then
                mv -- "$temporary/replaced" "$PROFILE_ETC/ufw" || :
                return 1
            fi
            mode=$(stat -c %a -- "$temporary/default-ufw") || return 1
            core::write_file "$PROFILE_ETC/default/ufw" "$mode" <"$temporary/default-ufw" || return 1
            chown --reference="$temporary/default-ufw" -- "$PROFILE_ETC/default/ufw" || return 1
            if [[ $(jq -r .status <<<"$before") == *'Status: active'* ]]; then
                ufw --force enable && ufw reload || return 1
            else ufw --force disable || return 1; fi
            profile_controls::_firewall_restore_verified "$before" || {
                core::die 'The original firewall files or effective UFW state did not verify after restoration. The baseline and transaction were retained for recovery.'
                return 1
            }
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
            done < <(jq -r --argjson baseline "$before" '.connections[]|select(.uuid as $uuid|any($baseline.connections[];.uuid==$uuid))|[.uuid,.type,.autoconnect,.llmnr,.mdns,.mac]|@tsv' <<<"$restore_expected")
            nmcli general reload conf || return 1
            [[ $(profile_controls::_network_snapshot) == "$restore_expected" ]] || {
                core::die 'Restored network settings did not verify. The recovery baseline has been retained.'
                return 1
            }
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
    core::record "PROFILE restore $control" || return 1
    if [[ $control == firewall ]] && ! rm -rf -- "$directory/firewall-baseline"; then
        core::die 'Firewall restoration verified, but baseline cleanup failed. The original evidence remains in the saved transaction.'
        return 1
    fi
    rm -f -- "$directory/$control.json" || {
        core::die 'Restoration verified, but its tracking record could not be removed. Inspect the saved recovery transaction.'
        return 1
    }
}

profile_controls::_firewall_restore_preview() {
    local saved=$1 directory baseline recorded family file label bytes total=0
    local LC_ALL=C
    directory=$(profile_controls::_directory) || return 1
    baseline="$directory/firewall-baseline"
    recorded=$(jq -er '.before.status' <<<"$saved") || return 1
    total=${#recorded}
    ((total <= 32768)) || return 1
    printf 'Original firewall state and listed exceptions:\n%s\n' "$recorded"
    for family in ipv4 ipv6; do
        recorded=$(jq -er --arg family "$family" '.before[$family]' <<<"$saved") || return 1
        recorded=$(profile_controls::_firewall_restore_rules <<<"$recorded") || return 1
        total=$((total + ${#recorded} + 256))
        ((total <= 65536)) || return 1
        printf '\nRecorded %s UFW/input rules and default policies:\n%s\n' "$family" "$recorded"
    done
    for label in default-ufw ufw.conf sysctl.conf before.init after.init before.rules before6.rules after.rules after6.rules user.rules user6.rules; do
        if [[ $label == default-ufw ]]; then file="$baseline/default-ufw"; else file="$baseline/ufw/$label"; fi
        if [[ ! -e $file && ! -L $file ]]; then
            printf '\nRetained %s: absent\n' "$label"
            continue
        fi
        profile_controls::_firewall_trusted_path "$file" || return 1
        bytes=$(stat -c %s -- "$file") || return 1
        total=$((total + bytes + 256))
        ((total <= 65536)) || return 1
        if [[ -s $file ]]; then LC_ALL=C grep -Iq . "$file" || return 1; fi
        printf '\nRetained %s:\n' "$label"
        # Bound a file that grows after stat as well. The caller checks the
        # complete escaped output and rechecks the baseline after consent.
        head -c 65537 -- "$file" || return 1
        printf '\n'
    done
}

profile_controls::_firewall_restore_rules() {
    # Empty filter tables are equivalent to their three ACCEPT policies. Ignore
    # unrelated Docker/output/forwarding jumps while checking UFW-owned chains,
    # INPUT rules and native defaults; restoring UFW must not undo those systems.
    awk '
      /^:(INPUT|FORWARD|OUTPUT) / {policy[$1]=$2; next}
      /^:ufw/ || /^-A ufw/ || /^-A INPUT / {rules=rules $0 "\n"}
      END {
        split(":INPUT :FORWARD :OUTPUT", names, " ")
        for (i=1;i<=3;i++) print names[i] " " (names[i] in policy ? policy[names[i]] : "ACCEPT")
        printf "%s", rules
      }'
}

profile_controls::_firewall_restore_verified() {
    local before=$1 current family previous_rules current_rules number inactive=false
    current=$(profile_controls::snapshot firewall) || return 1
    [[ $(jq -r .config <<<"$current") == "$(jq -r .config <<<"$before")" ]] || return 1
    [[ $(jq -r '.status|split("\n")[0]' <<<"$current") == "$(jq -r '.status|split("\n")[0]' <<<"$before")" ]] || return 1
    [[ $(jq -r .status <<<"$before") != 'Status: inactive' ]] || inactive=true
    for family in ipv4 ipv6; do
        previous_rules=$(jq -r --arg family "$family" '.[$family]' <<<"$before") || return 1
        current_rules=$(jq -r --arg family "$family" '.[$family]' <<<"$current") || return 1
        if [[ $inactive == true ]]; then
            number=${family#ipv}
            previous_rules=$(profile_firewall::_inactive "$number" "$previous_rules" snapshot) || return 1
            current_rules=$(profile_firewall::_inactive "$number" "$current_rules" snapshot) || return 1
        else
            previous_rules=$(profile_controls::_firewall_restore_rules <<<"$previous_rules") || return 1
            current_rules=$(profile_controls::_firewall_restore_rules <<<"$current_rules") || return 1
        fi
        [[ $previous_rules == "$current_rules" ]] || return 1
    done
}
profile_controls::restore() {
    local control=$1 result
    local PROFILE_RESTORE_STARTED=false
    if profile_controls::_restore_native "$control"; then return 0; else result=$?; fi
    # A rejected preflight must never accept external state as our own work.
    if [[ $PROFILE_RESTORE_STARTED == true ]]; then profile_controls::_record_actual "$control" || :; fi
    return "$result"
}
profile_controls::verify() {
    local control=$1 profile saved current expected desired state summary document result
    profile=$(profiles::active "$control") || return 1
    if [[ $control == firewall && $profile != unmanaged ]]; then
        profile_controls::firewall_observe "$profile"
        return
    fi
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
        firewall) profile_controls::_firewall_verified "$config" && profile_controls::_expiry_ready "$config" ;;
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
    if [[ -e $(profile_controls::_directory)/firewall.json ]]; then
        # First adoption checked the vendor files before removing the four
        # discovery grants. Subsequent changes must match our recorded policy.
        profile_controls::conflict firewall
        return
    fi
    profile_controls::_verified_ufw_hooks stock
}

profile_controls::_verified_ufw_hooks() {
    local mode=$1 manifest name path vendor relative expected actual vendor_hash filtered_hash filtered
    # UFW installs these hooks through ucf/postinst, not dpkg Conffiles. Verify
    # their package-owned templates against dpkg's payload checksums, then compare
    # installed hooks to those verified templates. A modified vendor template
    # must never make an equally modified hook look like a safe factory default.
    manifest=$(dpkg-query --control-show ufw md5sums) || return 1
    for name in before.rules before6.rules after.rules after6.rules before.init after.init; do
        path="$PROFILE_ETC/ufw/$name"
        if [[ ! -e $path && ! -L $path ]]; then
            case "$name" in *.init) continue ;; esac
            core::die "UFW $name is missing; restore the installed package rules before continuing."
            return 1
        fi
        profile_controls::_firewall_trusted_path "$path" || {
            core::die "UFW $name has unsafe ownership, permissions or file type."
            return 1
        }
        case "$name" in *.rules) relative="iptables/$name" ;; *) relative=$name ;; esac
        vendor="$PROFILE_SHARE/$relative"
        profile_controls::_firewall_trusted_path "$vendor" || {
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
        if [[ $mode == recognized && ($name == before.rules || $name == before6.rules) ]]; then
            filtered=$(profile_controls::_discovery_filter "$vendor") || return 1
            filtered_hash=$(md5sum <<<"$filtered") || return 1
            [[ ${actual%% *} != "${filtered_hash%% *}" ]] || continue
        fi
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

profile_controls::_discovery_filter() {
    awk '
      $0=="-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT" {next}
      $0=="-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT" {next}
      $0=="-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT" {next}
      $0=="-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT" {next}
      {print}
    ' "$1"
}

profile_controls::_restrict_discovery() {
    local name file content
    for name in before.rules before6.rules; do
        file="$PROFILE_ETC/ufw/$name"
        [[ -f $file && ! -L $file ]] || continue
        # Remove only exact package rules verified during first adoption. Do
        # not rewrite unrelated ICMP, DHCP, established, or loopback behavior.
        content=$(profile_controls::_discovery_filter "$file") || return 1
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
    profile_firewall::defaults "$PROFILE_ETC/default/ufw" || return 1
    status=$(LC_ALL=C ufw status verbose) || {
        core::die 'The current UFW status could not be read after the firewall change.'
        return 1
    }
    [[ $status == 'Status: active'$'\n'* && $status == *'deny (incoming)'* && $status == *'allow (outgoing)'* &&
        ($status == *'deny (routed)'* || $status == *'disabled (routed)'*) ]] || {
        core::die 'UFW is inactive or its reported default policies do not match the selected firewall protection.'
        return 1
    }
    # "disabled (routed)" is a display of forwarding sysctls, not its DROP
    # policy. Prove both kernel families and their actual INPUT hooks instead.
    profile_firewall::verify "$config"
}

# Live findings remain visible even when a previous operation failed. This is
# an observation, never consent to reconcile fingerprints or clear its result.
profile_controls::firewall_observe() {
    local profile=$1 config observed reason state summary
    profiles::valid_name "$profile" || return 1
    config=$(profiles::get "$profile" firewall) || return 1
    if ! observed=$(LC_ALL=C ufw status verbose); then
        state=unknown
        summary='The current UFW state could not be read. No firewall changes were made.'
    elif [[ $observed == 'Status: inactive' ]]; then
        state=inactive
        summary='UFW is inactive. The selected firewall profile is not currently enforced.'
    elif [[ $observed != 'Status: active'$'\n'* ]]; then
        state=unknown
        summary='UFW returned an unrecognized state; inspect the native firewall.'
    elif ! reason=$(profile_controls::_firewall_verified "$config" 2>&1); then
        state=partial
        reason=$(LC_ALL=C tr -d '\000-\037\177' <<<"$reason") || return 1
        summary="${reason:0:700}"
        [[ -n $summary ]] || summary='The running UFW policy does not satisfy the selected firewall profile.'
    elif ! reason=$(profile_controls::_expiry_ready "$config" 2>&1); then
        state=partial
        summary='The native firewall matches, but temporary-permission status bookkeeping is unavailable. Review the OctoShield status service.'
    else
        state=active
        summary="Live UFW host-input permissions and default policies match $profile. Container forwarding is inspected separately."
    fi
    jq -cn --arg state "$state" --arg summary "$summary" '{state:$state,summary:$summary}'
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
