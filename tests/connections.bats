#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2317,SC2329
setup() {
    bats_require_minimum_version 1.5.0
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profile_controls.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/office.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/connections.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    PROFILE_ETC="$BATS_TEST_TMPDIR/etc"
    PROFILE_RUN="$BATS_TEST_TMPDIR/run"
    CONNECTIONS_SYS="$BATS_TEST_TMPDIR/sys"
    CONNECTIONS_LIB="$BATS_TEST_TMPDIR/lib"
    mkdir -m700 "$CORE_STATE"
    mkdir -p "$PROFILE_ETC/NetworkManager/system-connections" "$PROFILE_RUN/NetworkManager/system-connections" "$CONNECTIONS_SYS/class/net/wlan0/device"
    printf '3\n' >"$CONNECTIONS_SYS/class/net/wlan0/ifindex"
    UUID=11111111-1111-1111-1111-111111111111
    SECOND=22222222-2222-2222-2222-222222222222
    NET="$BATS_TEST_TMPDIR/network.json"
    CALLS="$BATS_TEST_TMPDIR/calls"
    printf '[{"uuid":"%s","name":"Office Wi-Fi","type":"802-11-wireless","interface":"wlan0","autoconnect":"yes","llmnr":"0","mdns":"0","mac":"stable"},{"uuid":"%s","name":"Docker virtual cable","type":"802-3-ethernet","interface":"veth0","autoconnect":"yes","llmnr":"0","mdns":"0","mac":""}]\n' "$UUID" "$SECOND" >"$NET"
    printf '[connection]\nid=Office Wi-Fi\nuuid=%s\n[wifi-security]\npsk=DO-NOT-EXPOSE\n' "$UUID" >"$PROFILE_ETC/NetworkManager/system-connections/office.nmconnection"
    : >"$CALLS"
    FAIL='' APPLIED_LLMNR=0 RESOLVED_LLMNR=no APPROVE=yes
    core::require_root() { :; }
    controls::local_console() { :; }
    core::confirm() { [[ $APPROVE == yes ]]; }
    core::log() { :; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::record() { printf 'record %s\n' "$*" >>"$CALLS"; }
    core::backup() { printf 'backup %s\n' "$*" >>"$CALLS"; }
    core::write_file() {
        mkdir -p "${1%/*}"
        cat >"$1"
        chmod "$2" "$1"
    }
    connections::_run() { "$@"; }
    chown() { :; }
    install() {
        local -a args=()
        while (($#)); do case "$1" in -o | -g) shift 2 ;; *)
            args+=("$1")
            shift
            ;;
        esac done
        command install "${args[@]}"
    }
    profiles::_secure_file() {
        [[ ! -L $1 ]] || return 1
        if [[ ${2-} == directory ]]; then [[ -d $1 && $(stat -c %a "$1") == 700 ]]; else [[ -f $1 && $(stat -c %a "$1") == 600 ]]; fi
    }
    nmcli() {
        local field uuid property value temporary
        case "$*" in
            '--terse --fields UUID connection show') jq -r '.[].uuid' "$NET" ;;
            '--terse --fields UUID,TYPE connection show') jq -r '.[]|.uuid+":"+.type' "$NET" ;;
            '--terse --fields connection,802-11-wireless,802-11-wireless-security,802-3-ethernet,802-1x,ipv4,ipv6,proxy connection show uuid '*) jq -c --arg uuid "${*: -1}" '.[]|select(.uuid==$uuid)' "$NET" ;;
            '--terse --escape no --fields UUID,DEVICE connection show --active')
                [[ $FAIL != active ]] || return 1
                jq -r '.[]|select(.interface!="")|.uuid+":"+.interface' "$NET"
                ;;
            '--escape no -g '* | '-g '*)
                if [[ $1 == --escape ]]; then shift 2; fi
                field=$2 uuid=${*: -1}
                property=${field#connection.}
                [[ $field != 802-11-wireless.cloned-mac-address ]] || property=mac
                [[ $property != id ]] || property=name
                jq -r --arg uuid "$uuid" --arg property "$property" '.[]|select(.uuid==$uuid)|.[$property]' "$NET"
                ;;
            'connection modify uuid '*)
                printf 'nmcli %s\n' "$*" >>"$CALLS"
                [[ $FAIL != modify ]] || return 1
                uuid=$4
                shift 4
                while (($#)); do
                    property=${1#connection.} value=$2
                    [[ $1 != 802-11-wireless.cloned-mac-address ]] || property=mac
                    temporary="$NET.tmp"
                    jq --arg uuid "$uuid" --arg property "$property" --arg value "$value" 'map(if .uuid==$uuid then .[$property]=$value else . end)' "$NET" >"$temporary" && mv "$temporary" "$NET"
                    shift 2
                done
                ;;
            '--wait 30 connection up uuid '*) printf 'reconnect %s\n' "$*" >>"$CALLS" ;;
            'general reload conf') : ;;
            *)
                printf 'Unexpected nmcli: %s\n' "$*" >&2
                return 1
                ;;
        esac
    }
    ip() { printf '[{"addr_info":[{"family":"inet","local":"192.168.25.42","prefixlen":24,"scope":"global"}]}]\n'; }
    busctl() {
        [[ $FAIL != bus ]] || return 1
        case "$*" in
            *'GetDeviceByIpIface s '*) printf '{"type":"o","data":["/org/freedesktop/NetworkManager/Devices/3"]}\n' ;;
            *'GetAppliedConnection u 0') printf '{"type":"a{sa{sv}}t","data":[{"connection":{"uuid":{"type":"s","data":"%s"},"llmnr":{"type":"i","data":%s},"mdns":{"type":"i","data":0}},"802-11-wireless":{"assigned-mac-address":{"type":"s","data":"stable"}}},1]}\n' "$UUID" "$APPLIED_LLMNR" ;;
            *' LLMNR') printf '{"type":"s","data":"%s"}\n' "$RESOLVED_LLMNR" ;;
            *' MulticastDNS') printf '{"type":"s","data":"no"}\n' ;;
            *) return 1 ;;
        esac
    }
}

@test 'connection list provides names actual files and physical LAN scope without secrets' {
    run connections::list
    [ "$status" -eq 0 ]
    jq -e '.kind=="connections" and .profile=="unmanaged" and .connections[0].name=="Office Wi-Fi" and .connections[0].lan_candidate and .connections[0].subnets==["192.168.25.0/24"] and (.connections[0].source_files[0]|endswith("office.nmconnection")) and (.connections[1].lan_candidate|not)' <<<"$output"
    [[ $output != *DO-NOT-EXPOSE* ]]
}

@test 'validation permits only fixed per-connection settings and proper UUIDs' {
    connections::validate set "$UUID" discovery false
    connections::validate set "$UUID" mac permanent
    run ! connections::validate set "$UUID" connection.password secret
    run ! connections::validate set '--help' discovery false
    run ! connections::validate set "$UUID" mac 'stable;touch /tmp/no'
    run ! connections::validate reconnect "$UUID" extra
}

@test 'LAN scopes normalize both address families without broadening to every network' {
    [ "$(connections::_subnet 192.168.25.42/24)" = 192.168.25.0/24 ]
    [ "$(connections::_subnet 2001:db8::42/64)" = 2001:db8:0:0:0:0:0:0/64 ]
    [ "$(connections::_subnet fd12:1234:5678:9abc::1/56)" = fd12:1234:5678:9a00:0:0:0:0/56 ]
    run ! connections::_subnet 0.0.0.0/0
    run ! connections::_subnet ::/0
}

@test 'applied privacy and resolver verification differs from saved-only checks' {
    run connections::_connection "$UUID" "$UUID:wlan0"
    [ "$status" -eq 0 ]
    jq -e '.runtime.state=="verified"' <<<"$output"
    APPLIED_LLMNR=2
    run connections::_connection "$UUID" "$UUID:wlan0"
    jq -e '.runtime.state=="pending" and (.runtime.summary|contains("Reconnect"))' <<<"$output"
}

@test 'missing resolver evidence stays unknown and stale applied connection is not verified' {
    RESOLVED_LLMNR=unknown
    run connections::_connection "$UUID" "$UUID:wlan0"
    jq -e '.runtime.state=="unknown"' <<<"$output"
    run connections::_connection "$SECOND" "$SECOND:veth0"
    jq -e '.runtime.state=="unknown"' <<<"$output"
}

@test 'unavailable active inspection never labels saved connections as verified inactive' {
    FAIL=active
    run connections::list
    [ "$status" -eq 0 ]
    jq -e '.incomplete and all(.connections[]; (.active_known|not) and .runtime.state=="unknown" and (.lan_candidate|not))' <<<"$output"
}

@test 'unmanaged connection adjustment affects only selected connection and saves baseline' {
    connections::set "$UUID" autoconnect false >/dev/null
    jq -e '.[0].autoconnect=="no" and .[1].autoconnect=="yes"' "$NET"
    [ "$(profiles::active network)" = unmanaged ]
    baseline=$(profile_controls::_read network)
    jq -e '.before.connections[0].autoconnect=="yes" and .observed.connections[0].autoconnect=="no"' <<<"$baseline"
    run ! grep -q '^reconnect ' "$CALLS"
}

@test 'managed override survives profile apply without being reported as external drift' {
    document=$(profiles::_read)
    profiles::_save "$(jq '.active.network="home"|.results.network={status:"applied",message:"fixture"}' <<<"$document")"
    connections::set "$UUID" autoconnect false >/dev/null
    jq -e --arg uuid "$UUID" '.profiles.home.network.connections[$uuid].autoconnect==false and .results.network.status=="applied"' "$CORE_STATE/profiles/state.json"
    profile_controls::conflict network
    profile_controls::apply network home
    jq -e '.[0].autoconnect=="no" and .[1].autoconnect=="yes"' "$NET"
}

@test 'explicit discovery false overrides enabled profile default' {
    document=$(profiles::_read)
    profiles::_save "$(jq --arg uuid "$UUID" '.profiles.home.network.discovery=true|.profiles.home.network.connections[$uuid]={discovery:false}' <<<"$document")"
    profile_controls::apply network home
    jq -e '.[0].llmnr=="0" and .[0].mdns=="0" and .[1].llmnr=="2" and .[1].mdns=="2"' "$NET"
}

@test 'cancelled connection review changes neither native settings nor profile state' {
    APPROVE=no
    before=$(cat "$NET")
    run connections::set "$UUID" discovery true
    [ "$status" -ne 0 ]
    [ "$(cat "$NET")" = "$before" ]
    [ ! -e "$CORE_STATE/profiles/state.json" ]
    [ ! -s "$CALLS" ]
}

@test 'failed native changes remain failed and never reconnect automatically' {
    document=$(profiles::_read)
    profiles::_save "$(jq '.active.network="home"' <<<"$document")"
    FAIL=modify
    run connections::set "$UUID" discovery true
    [ "$status" -ne 0 ]
    jq -e '.results.network.status=="failed"' "$CORE_STATE/profiles/state.json"
    run ! grep -q '^reconnect ' "$CALLS"
}

@test 'a selected connection edit does not activate unrelated pending profile settings' {
    document=$(profiles::_read)
    profiles::_save "$(jq '.active.network="home"|.profiles.home.network.discovery=true' <<<"$document")"
    connections::set "$UUID" autoconnect false >/dev/null
    jq -e '.results.network.status=="pending"' "$CORE_STATE/profiles/state.json"
    jq -e 'all(.[];.mdns=="0" and .llmnr=="0")' "$NET"
}

@test 'native changes during review invalidate the operation before saving overrides' {
    core::confirm() {
        local temporary="$NET.tmp"
        jq '.[0].autoconnect="no"' "$NET" >"$temporary" && mv "$temporary" "$NET"
    }
    run connections::set "$UUID" discovery true
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    [ ! -e "$CORE_STATE/profiles/state.json" ]
    [ ! -s "$CALLS" ]
}

@test 'connection reconnect requires its own confirmation and checks observed activation' {
    APPROVE=no
    run connections::reconnect "$UUID"
    [ "$status" -ne 0 ]
    [ ! -s "$CALLS" ]
    APPROVE=yes
    connections::reconnect "$UUID" >/dev/null
    grep -q '^reconnect --wait 30 connection up uuid ' "$CALLS"
}

@test 'network override schema rejects arbitrary properties and invalid UUIDs' {
    document=$(profiles::_defaults)
    profiles::_validate_document <<<"$(jq --arg uuid "$UUID" '.profiles.home.network.connections[$uuid]={autoconnect:false,mac:"stable",discovery:true}' <<<"$document")"
    run ! profiles::_validate_document <<<"$(jq '.profiles.home.network.connections.bad={autoconnect:false}' <<<"$document")"
    run ! profiles::_validate_document <<<"$(jq --arg uuid "$UUID" '.profiles.home.network.connections[$uuid]={password:"no"}' <<<"$document")"
}

@test 'changed connection identity or secret source invalidates reconnect review' {
    core::confirm() { printf '\n# credentials changed\n' >>"$PROFILE_ETC/NetworkManager/system-connections/office.nmconnection"; }
    run connections::reconnect "$UUID"
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    run ! grep -q '^reconnect ' "$CALLS"
}

@test 'connection inventories retain a complete bounded subset instead of broken JSON' {
    connections::_run() { for index in {1..128}; do printf '%08d-1111-1111-1111-111111111111\n' "$index"; done; }
    connections::_active() { :; }
    connections::_connection() { jq -cn --arg uuid "$1" --arg large "$(printf '%1000s' '')" '{uuid:$uuid,name:$large}'; }
    run connections::list
    [ "$status" -eq 0 ]
    jq -e '.incomplete and (.connections|length)>0 and (.connections|length)<128 and (tojson|tojson|utf8bytelength)<42000' <<<"$output"
}
