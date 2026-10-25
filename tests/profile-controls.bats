#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2317,SC2329
setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profile_firewall_verify.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profile_controls.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    PROFILE_ETC="$BATS_TEST_TMPDIR/etc"
    PROFILE_RUN="$BATS_TEST_TMPDIR/run"
    mkdir -m700 "$CORE_STATE"
    mkdir -p "$PROFILE_ETC/ufw" "$PROFILE_ETC/default"
    printf 'IPV6=no\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n' >"$PROFILE_ETC/default/ufw"
    printf 'original\n' >"$PROFILE_ETC/ufw/user.rules"
    CALLS="$BATS_TEST_TMPDIR/calls"
    UNITS="$BATS_TEST_TMPDIR/units.json"
    FIREWALL="$BATS_TEST_TMPDIR/firewall"
    printf inactive >"$FIREWALL"
    printf '{}' >"$UNITS"
    : >"$CALLS"
    FAIL=''
    core::require_root() { :; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::log() { :; }
    core::record() { :; }
    core::confirm() { :; }
    core::backup() { printf 'backup %s\n' "$1" >>"$CALLS"; }
    core::write_file() {
        mkdir -p "${1%/*}"
        cat >"$1"
        chmod "$2" "$1"
    }
    chown() { :; }
    # Native root ownership is represented for nonroot developers; modes, file
    # types, link counts and fingerprints still come from real fixture files.
    stat() {
        local value
        value=$(command stat "$@") || return 1
        case "${2-}" in
            '%u:%a:%h:%s') value="0:${value#*:}" ;;
            '%u:%g:%a:%F') value="0:0:${value#*:*:}" ;;
        esac
        printf '%s\n' "$value"
    }
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
    controls::ufw_defaults() { printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n'; }
    profile_firewall::verify() { [[ $FAIL != verify ]]; }
    profile_firewall::temporary_apply() { :; }
    fixture_native_policy() {
        local prefix=ufw
        [[ $1 == 4 ]] || prefix=ufw6
        printf '*filter\n'
        if [[ $(cat "$FIREWALL") == active ]]; then
            printf ':INPUT DROP [99:20]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [10:30]\n:%s-user-input - [0:0]\n' "$prefix"
            printf '%s\n' "-A INPUT -j $prefix-before-input" "-A $prefix-before-input -j $prefix-user-input"
        else printf ':INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n'; fi
        printf 'COMMIT\n'
    }
    iptables-save() { fixture_native_policy 4; }
    ip6tables-save() { fixture_native_policy 6; }
    make_vendor_hooks() {
        local name relative hash
        PROFILE_SHARE="$BATS_TEST_TMPDIR/share/ufw"
        HOOK_MANIFEST="$BATS_TEST_TMPDIR/ufw.md5sums"
        mkdir -p "$PROFILE_SHARE/iptables"
        : >"$HOOK_MANIFEST"
        for name in before.rules before6.rules after.rules after6.rules before.init after.init; do
            case "$name" in *.rules) relative="iptables/$name" ;; *) relative=$name ;; esac
            printf 'vendor %s\n' "$name" >"$PROFILE_SHARE/$relative"
            case "$name" in
                before.rules) printf '%s\n' '-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT' >>"$PROFILE_SHARE/$relative" ;;
                before6.rules) printf '%s\n' '-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT' >>"$PROFILE_SHARE/$relative" ;;
            esac
            cp "$PROFILE_SHARE/$relative" "$PROFILE_ETC/ufw/$name"
            hash=$(md5sum "$PROFILE_SHARE/$relative")
            printf '%s  usr/share/ufw/%s\n' "${hash%% *}" "$relative" >>"$HOOK_MANIFEST"
        done
        dpkg-query() {
            [[ $* == '--control-show ufw md5sums' ]] || return 1
            cat "$HOOK_MANIFEST"
        }
    }
    ufw() {
        printf 'ufw %s\n' "$*" >>"$CALLS"
        [[ $FAIL != "ufw $*" ]] || return 1
        case "$*" in
            '--force enable') printf active >"$FIREWALL" ;;
            '--force disable') if [[ $FAIL != restore-noop ]]; then printf inactive >"$FIREWALL"; fi ;;
            'status verbose')
                if [[ $(cat "$FIREWALL") == active ]]; then printf 'Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n'; else printf 'Status: inactive\n'; fi
                ;;
            'status numbered') printf 'Status: active\n[ 1] 22 ALLOW Anywhere\n[ 2] 80 ALLOW Anywhere\n[ 3] 22(v6) ALLOW Anywhere(v6)\n' ;;
        esac
    }
    systemctl() {
        local unit=${*: -1} key value temporary enabled
        printf 'systemctl %s\n' "$*" >>"$CALLS"
        [[ $FAIL != "systemctl $*" ]] || return 1
        if [[ $1 == show ]]; then
            case "$2" in
                --property=LoadState) jq -r --arg u "$unit" 'if .[$u]==null then "not-found" elif .[$u].enabled=="masked" then "masked" else "loaded" end' "$UNITS" ;;
                --property=UnitFileState) jq -r --arg u "$unit" '.[$u].enabled' "$UNITS" ;;
                --property=ActiveState) jq -r --arg u "$unit" '.[$u].active' "$UNITS" ;;
            esac
            return
        fi
        case "$1" in
            mask)
                key=enabled
                value=masked
                ;;
            unmask)
                key=enabled
                value=disabled
                ;;
            enable)
                key=enabled
                value=enabled
                ;;
            disable)
                key=enabled
                value=disabled
                ;;
            start)
                key=active
                value=active
                ;;
            stop)
                key=active
                value=inactive
                ;;
            *) return 1 ;;
        esac
        if [[ $unit == cups.service && ($1 == start || "$*" == 'enable --now '*) ]]; then
            enabled=$(jq -r '."cups.socket".enabled//"disabled"' "$UNITS")
            [[ $enabled != masked ]] || return 1
        fi
        if [[ $FAIL == false-success ]]; then return 0; fi
        temporary="$UNITS.tmp"
        jq --arg u "$unit" --arg k "$key" --arg v "$value" --arg command "$*" '.[$u][$k]=$v|if ($command|startswith("mask")) then .[$u].active="inactive" elif ($command|startswith("enable --now")) then .[$u].active="active" elif ($command|startswith("disable --now")) then .[$u].active="inactive" else . end' "$UNITS" >"$temporary" && mv "$temporary" "$UNITS"
    }
}
@test 'firewall switch narrows before granting and never resets or disables UFW' {
    profiles::dispatch rule-add conference 443 tcp 192.0.2.0/24 wlan0 0 >/dev/null
    profile_controls::apply firewall conference
    run grep -E 'ufw --force (reset|disable)' "$CALLS"
    [ "$status" -eq 1 ]
    [ "$(grep 'ufw --force delete' "$CALLS")" = $'ufw --force delete 3\nufw --force delete 2\nufw --force delete 1' ]
    grep -q '^ufw allow in on wlan0 proto tcp from 192.0.2.0/24 to any port 443 comment OctoShield:conference:r[0-9]' "$CALLS"
    grep -qx IPV6=yes "$PROFILE_ETC/default/ufw"
    grep -qx IPV6=no "$CORE_STATE/profiles/controls/firewall-baseline/default-ufw"
}
@test 'firewall ignores expired rules while preserving permanent rules' {
    document=$(profiles::state | jq '.profiles.conference.firewall.rules=[{id:"r1-1-1",port:22,protocol:"tcp",source:"any",interface:"any",expires_at:1}]')
    profiles::_save "$document"
    profile_controls::apply firewall conference
    run grep '^ufw allow' "$CALLS"
    [ "$status" -eq 1 ]
}
@test 'external firewall edits are preserved and block both switching and restore' {
    profile_controls::apply firewall conference
    baseline=$(profile_controls::_read firewall)
    printf 'administrator change\n' >>"$PROFILE_ETC/ufw/user.rules"
    : >"$CALLS"
    run profile_controls::apply firewall office
    [ "$status" -ne 0 ]
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [ "$(profile_controls::_read firewall)" = "$baseline" ]
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [ "$(profile_controls::_read firewall)" = "$baseline" ]
    run grep -E '^ufw (default|--force|allow|reload)' "$CALLS"
    [ "$status" -eq 1 ]
    grep -q 'administrator change' "$PROFILE_ETC/ufw/user.rules"
}
@test 'explicit firewall restore recovers original policy and initial disabled state' {
    profile_controls::apply firewall conference
    profile_controls::restore firewall
    [ "$(cat "$FIREWALL")" = inactive ]
    grep -qx IPV6=no "$PROFILE_ETC/default/ufw"
    [ ! -e "$CORE_STATE/profiles/controls/firewall.json" ]
}
@test 'failed first firewall application still captures recoverable original baseline' {
    FAIL='ufw logging low'
    run profile_controls::apply firewall conference
    [ "$status" -ne 0 ]
    [ -e "$CORE_STATE/profiles/controls/firewall.json" ]
    FAIL=''
    profile_controls::restore firewall
    [ "$(cat "$FIREWALL")" = inactive ]
}
@test 'failed native rule verification cannot record desired policy as applied' {
    FAIL=verify
    run profile_controls::apply firewall conference
    [ "$status" -ne 0 ]
    [ "$(jq -r .desired "$CORE_STATE/profiles/controls/firewall.json")" = '' ]
}
@test 'printing activation unmasks socket dependencies before starting primary service' {
    printf '{"cups.service":{"enabled":"enabled","active":"active"},"cups.socket":{"enabled":"enabled","active":"active"},"cups.path":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profile_controls::apply services conference
    profiles::dispatch set office services.printing enabled
    profile_controls::apply services office
    jq -e '."cups.service".enabled=="enabled" and ."cups.service".active=="active" and ."cups.socket".enabled!="masked"' "$UNITS"
}
@test 'service baseline restores original enabled and active states' {
    printf '{"cups.service":{"enabled":"enabled","active":"active"},"cups.socket":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profile_controls::apply services conference
    profile_controls::apply services office
    jq -e '."cups.service".enabled=="enabled" and ."cups.service".active=="active" and ."cups.socket".enabled=="enabled"' "$UNITS"
}
@test 'successful service command with unchanged unsafe native state fails verification' {
    printf '{"cups.service":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    FAIL=false-success
    run profile_controls::apply services conference
    [ "$status" -ne 0 ]
    [ "$(jq -r .desired "$CORE_STATE/profiles/controls/services.json")" = '' ]
}
@test 'monitor command success does not disguise inactive or failed daemon' {
    printf '{"octoshield-monitor.service":{"enabled":"disabled","active":"failed"}}' >"$UNITS"
    FAIL=false-success
    run profile_controls::apply monitor conference
    [ "$status" -ne 0 ]
}
@test 'disabled monitor reports inactive instead of a misleading green active state' {
    printf '{"octoshield-monitor.service":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profiles::dispatch set home monitor.enabled false
    profile_controls::apply monitor home
    profiles::_result monitor applied verified home
    result=$(profile_controls::verify monitor)
    [ "$(jq -r .state <<<"$result")" = inactive ]
}
@test 'expiry uses last applied rules and never activates pending edited exceptions' {
    profiles::dispatch rule-add conference 443 tcp any any 0 >/dev/null
    profile_controls::apply firewall conference
    profiles::dispatch rule-add conference 88 tcp any any 0 >/dev/null
    : >"$CALLS"
    profile_controls::expire conference
    run grep -E '^ufw (allow|reload|default|--force)' "$CALLS"
    [ "$status" -eq 1 ]
    [ "$(jq '.policy.rules[0].port' "$CORE_STATE/profiles/controls/firewall.json")" -eq 443 ]
    profiles::_result firewall applied verified conference
    profile_firewall::verify() { jq -e 'all(.rules[];.port!=88)' <<<"$1" >/dev/null; }
    result=$(profile_controls::verify firewall)
    [ "$(jq -r .state <<<"$result")" = partial ]
}
@test 'nonstandard UFW before rules require review instead of false protection claim' {
    make_vendor_hooks
    printf 'modified rule\n' >"$PROFILE_ETC/ufw/before.rules"
    run profile_controls::_standard_ufw_hooks
    [ "$status" -ne 0 ]
    [[ $output == *'administrator changes'* ]]
}
@test 'network profile preserves private scan defaults and restores only baseline autoconnect choices' {
    NET="$BATS_TEST_TMPDIR/network.json"
    printf '{"uuid":"11111111-1111-1111-1111-111111111111","type":"802-11-wireless","autoconnect":"yes","llmnr":"-1","mdns":"-1","mac":"permanent"}' >"$NET"
    nmcli() {
        local property value temporary
        printf 'nmcli %s\n' "$*" >>"$CALLS"
        case "$1" in
            --terse) printf '11111111-1111-1111-1111-111111111111:802-11-wireless\n' ;;
            -g)
                property=${2#connection.}
                property=${property#802-11-wireless.}
                [[ $property != cloned-mac-address ]] || property=mac
                jq -r --arg key "$property" '.[$key]' "$NET"
                ;;
            connection)
                shift 4
                while (($#)); do
                    property=${1#connection.}
                    property=${property#802-11-wireless.}
                    [[ $property != cloned-mac-address ]] || property=mac
                    value=$2
                    shift 2
                    temporary="$NET.tmp"
                    jq --arg key "$property" --arg value "$value" '.[$key]=$value' "$NET" >"$temporary" && mv "$temporary" "$NET"
                done
                ;;
            general) return 0 ;;
            *) return 1 ;;
        esac
    }
    profile_controls::apply network conference
    jq -e '.autoconnect=="no" and .llmnr=="0" and .mdns=="0" and .mac=="stable"' "$NET"
    grep -qx 'wifi.scan-rand-mac-address=yes' "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf"
    grep -qx 'wifi.iwd.autoconnect=false' "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf"
    grep -qx "backup $PROFILE_RUN/NetworkManager/system-connections" "$CALLS"
    profile_controls::apply network office
    [ "$(jq -r .autoconnect "$NET")" = yes ]
    profile_controls::restore network
    jq -e '.autoconnect=="yes" and .llmnr=="-1" and .mdns=="-1" and .mac=="permanent"' "$NET"
    [ ! -e "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf" ]
}
@test 'network baseline preserves preexisting private config and restrictive file mode' {
    mkdir -p "$PROFILE_ETC/NetworkManager/conf.d"
    printf '[device]\nwifi.scan-rand-mac-address=no\n' >"$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf"
    chmod 0600 "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf"
    nmcli() { return 0; }
    profile_controls::apply network conference
    profile_controls::restore network
    grep -qx 'wifi.scan-rand-mac-address=no' "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf"
    [ "$(stat -c %a "$PROFILE_ETC/NetworkManager/conf.d/90-octoshield.conf")" = 600 ]
}
@test 'explicit services restoration unmasks socket dependencies before primaries' {
    printf '{"cups.service":{"enabled":"enabled","active":"active"},"cups.socket":{"enabled":"enabled","active":"active"},"cups.path":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profile_controls::apply services conference
    profile_controls::restore services
    jq -e '."cups.service".active=="active" and ."cups.socket".enabled=="enabled" and ."cups.path".enabled=="enabled"' "$UNITS"
}
@test 'finite firewall grants require a persistent running expiry coordinator' {
    profiles::dispatch rule-add conference 443 tcp any any 60 >/dev/null
    run profile_controls::apply firewall conference
    [ "$status" -ne 0 ]
    run grep '^ufw allow' "$CALLS"
    [ "$status" -eq 1 ]
    printf '{"octoshield-status.service":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profile_controls::apply firewall conference
    profiles::_result firewall applied verified conference
    printf '{"octoshield-status.service":{"enabled":"disabled","active":"inactive"}}' >"$UNITS"
    result=$(profile_controls::verify firewall)
    [ "$(jq -r .state <<<"$result")" = partial ]
}
@test 'vendor multicast discovery exceptions are removed narrowly and baseline restore recovers them' {
    cat >"$PROFILE_ETC/ufw/before.rules" <<'RULES'
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT
RULES
    cat >"$PROFILE_ETC/ufw/before6.rules" <<'RULES'
-A ufw6-before-input -i lo -j ACCEPT
-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT
-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT
RULES
    profile_controls::apply firewall conference
    [ "$(wc -l <"$PROFILE_ETC/ufw/before.rules")" -eq 2 ]
    [ "$(wc -l <"$PROFILE_ETC/ufw/before6.rules")" -eq 1 ]
    grep -q -- '--sport 67 --dport 68' "$PROFILE_ETC/ufw/before.rules"
    profile_controls::restore firewall
    [ "$(wc -l <"$PROFILE_ETC/ufw/before.rules")" -eq 4 ]
    [ "$(wc -l <"$PROFILE_ETC/ufw/before6.rules")" -eq 3 ]
}
@test 'finite permissions are sent only to the runtime helper and never persisted by UFW' {
    printf '{"octoshield-status.service":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profiles::dispatch rule-add conference 443 tcp any any 60 >/dev/null
    profile_firewall::temporary_apply() { jq -r '.rules[]|"temporary \(.port)"' <<<"$1" >>"$CALLS"; }
    profile_controls::apply firewall conference
    grep -qx 'temporary 443' "$CALLS"
    run grep '^ufw allow' "$CALLS"
    [ "$status" -eq 1 ]
}
@test 'reloaded permanent-only firewall is accepted only with every other native and persisted setting unchanged' {
    before=$(jq -cn '{config:"original",status:"Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n443 ALLOW Anywhere",ipv4:"-A INPUT -j ufw-before-input\n-A ufw-user-input -p tcp --dport 443 -j ACCEPT",ipv6:"-A INPUT -j ufw6-before-input"}')
    CURRENT=$(jq -c '.ipv4="-A INPUT -j ufw-before-input"|.status="Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)"' <<<"$before")
    saved=$(jq -cn --argjson observed "$before" '{observed:$observed,policy:{rules:[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:9999999999}]}}')
    profile_controls::_firewall_snapshot() { printf '%s\n' "$CURRENT"; }
    profile_firewall::verify() { jq -e 'all(.rules[]; .expires_at==0)' <<<"$1" >/dev/null; }
    profile_controls::_runtime_narrowed "$saved"
    original=$CURRENT
    CURRENT=$(jq -c '.config="externally-edited"' <<<"$original")
    run profile_controls::_runtime_narrowed "$saved"
    [ "$status" -ne 0 ]
    CURRENT=$(jq -c '.ipv4+="\n-A INPUT -j ACCEPT"' <<<"$original")
    run profile_controls::_runtime_narrowed "$saved"
    [ "$status" -ne 0 ]
}
@test 'expiry after reload never reopens still-future temporary grants' {
    printf '{"octoshield-status.service":{"enabled":"enabled","active":"active"}}' >"$UNITS"
    profiles::dispatch rule-add conference 443 tcp any any 60 >/dev/null
    profile_controls::apply firewall conference
    # Simulate the changed native snapshot after a reload removed timed grants.
    snapshot=$(profile_controls::snapshot firewall | jq -c '.status+="\nReloaded"')
    profile_controls::snapshot() { printf '%s\n' "$snapshot"; }
    profile_controls::_runtime_narrowed() { return 0; }
    : >"$CALLS"
    profile_controls::expire conference
    [ "$(jq '.policy.rules|length' "$CORE_STATE/profiles/controls/firewall.json")" -eq 0 ]
    [ ! -s "$CALLS" ]
}

@test 'missing primary service cannot be reported as enabled' {
    profiles::dispatch set office services.printing enabled
    run profile_controls::apply services office
    [ "$status" -ne 0 ]
    [[ $output == *'primary service is not installed'* ]]
}
@test 'expiry reconciles a full policy without rebuilding or adding native firewall rules' {
    # Exercise the full supported profile size, including a pending edit which
    # must not become an applied permission during expiry housekeeping.
    policy=$(jq -cn '{rules:[range(1;257)|{id:("r1-1-"+tostring),port:(10000+.),protocol:"tcp",source:"any",interface:"any",expires_at:(if .==1 then 1 else 0 end)}]}')
    profile_controls::_capture firewall
    snapshot=$(profile_controls::snapshot firewall)
    saved=$(profile_controls::_read firewall | jq -c --argjson policy "$policy" --argjson observed "$snapshot" '.policy=$policy|.observed=$observed')
    profile_controls::_write firewall "$saved"
    before=$(cat "$CORE_STATE/profiles/controls/firewall.json")
    profile_firewall::verify() {
        jq -e '.rules|length==255 and all(.[];.expires_at==0)' <<<"$1" >/dev/null
    }
    : >"$CALLS"
    profile_controls::expire conference
    [ "$(jq '.policy.rules|length' "$CORE_STATE/profiles/controls/firewall.json")" -eq 255 ]
    run grep -E '^ufw (allow|reload|default|--force)' "$CALLS"
    [ "$status" -eq 1 ]
    [ "$(jq -r .expected "$CORE_STATE/profiles/controls/firewall.json")" = "$(jq -r .expected <<<"$before")" ]
}
@test 'failed expiry verification or observation race keeps expired records retryable' {
    profile_controls::apply firewall conference
    saved=$(profile_controls::_read firewall | jq -c '.policy.rules=[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:1}]')
    profile_controls::_write firewall "$saved"
    original=$(cat "$CORE_STATE/profiles/controls/firewall.json")
    FAIL=verify
    run profile_controls::expire conference
    [ "$status" -ne 0 ]
    [ "$(cat "$CORE_STATE/profiles/controls/firewall.json")" = "$original" ]
    profile_controls::expiry_due
    FAIL=''
    profile_firewall::verify() {
        printf active >"$FIREWALL"
        printf 'external edit\n' >>"$PROFILE_ETC/ufw/user.rules"
    }
    run profile_controls::expire conference
    [ "$status" -ne 0 ]
    [ "$(cat "$CORE_STATE/profiles/controls/firewall.json")" = "$original" ]
    profile_controls::expiry_due
}
@test 'expiry resumes an interrupted profile-document save without activating future pending edits' {
    profile_controls::apply firewall conference
    profiles::_result firewall applied verified conference
    document=$(profiles::state | jq -c '.profiles.conference.firewall.rules=[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:1},{id:"r1-1-2",port:88,protocol:"tcp",source:"any",interface:"any",expires_at:0}]')
    profiles::_save "$document"
    # Adapter metadata is already reconciled while the editable document still
    # contains an expired row, as after interruption between atomic saves.
    profile_controls::expiry_due
    : >"$CALLS"
    profiles::expire
    [ "$(profiles::get conference firewall | jq '.rules|length')" -eq 1 ]
    [ "$(profiles::get conference firewall | jq '.rules[0].port')" -eq 88 ]
    [ "$(jq '.policy.rules|length' "$CORE_STATE/profiles/controls/firewall.json")" -eq 0 ]
    run profile_controls::expiry_due
    [ "$status" -ne 0 ]
    run grep -E '^ufw (allow|reload|default|--force)' "$CALLS"
    [ "$status" -eq 1 ]
}
@test 'stock ucf-managed UFW hooks validate through payload templates without Conffiles entries' {
    make_vendor_hooks
    profile_controls::_standard_ufw_hooks
    # Read-only adoption validation must not invoke UFW or rewrite factory files.
    [ ! -s "$CALLS" ]
    cmp "$PROFILE_SHARE/iptables/before.rules" "$PROFILE_ETC/ufw/before.rules"
}
@test 'matching administrator edits to both vendor template and hook fail package integrity verification' {
    make_vendor_hooks
    printf 'modified vendor rule\n' >"$PROFILE_SHARE/iptables/before.rules"
    cp "$PROFILE_SHARE/iptables/before.rules" "$PROFILE_ETC/ufw/before.rules"
    run profile_controls::_standard_ufw_hooks
    [ "$status" -ne 0 ]
    [[ $output == *'differs from the installed package'* ]]
    [ ! -s "$CALLS" ]
}
@test 'missing package checksum or symlink vendor templates fail closed' {
    make_vendor_hooks
    cp "$HOOK_MANIFEST" "$HOOK_MANIFEST.saved"
    : >"$HOOK_MANIFEST"
    run profile_controls::_standard_ufw_hooks
    [ "$status" -ne 0 ]
    [[ $output == *'integrity data is missing'* ]]
    cp "$HOOK_MANIFEST.saved" "$HOOK_MANIFEST"
    mv "$PROFILE_SHARE/iptables/before.rules" "$PROFILE_SHARE/iptables/before.saved"
    ln -s before.saved "$PROFILE_SHARE/iptables/before.rules"
    run profile_controls::_standard_ufw_hooks
    [ "$status" -ne 0 ]
    [[ $output == *'missing or unsafe'* ]]
}

@test 'nonrouting laptop verifies configured DROP despite disabled routed display' {
    controls::ufw_defaults >"$PROFILE_ETC/default/ufw"
    ufw() { printf 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n'; }
    profile_controls::_firewall_verified '{"rules":[]}'
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' "$PROFILE_ETC/default/ufw"
    run profile_controls::_firewall_verified '{"rules":[]}'
    [ "$status" -ne 0 ]
    [[ $output == *'DROP for incoming and forwarded'* ]]
}

@test 'live firewall observation ignores a historical failure without clearing its record' {
    profile_controls::apply firewall office
    profiles::_result firewall failed 'A previous verification failed.' office
    local document control
    document=$(profiles::state)
    control=$(profile_controls::_read firewall)
    : >"$CALLS"
    run profile_controls::firewall_observe office
    [ "$status" -eq 0 ]
    jq -e '.state=="active" and (.summary|contains("Live UFW"))' <<<"$output"
    run profile_controls::verify firewall
    [ "$status" -eq 0 ]
    jq -e '.state=="active"' <<<"$output"
    [ "$(profiles::state)" = "$document" ]
    [ "$(profile_controls::_read firewall)" = "$control" ]
    run grep -E '^ufw (default|--force|allow|reload)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'live firewall observation reports an actual mismatch and inactive state behind a failed marker' {
    profile_controls::apply firewall office
    profiles::_result firewall failed 'A previous verification failed.' office
    profile_firewall::verify() { core::die 'The running permission source is broader than selected.'; }
    run profile_controls::firewall_observe office
    [ "$status" -eq 0 ]
    jq -e '.state=="partial" and (.summary|contains("broader"))' <<<"$output"
    printf inactive >"$FIREWALL"
    run profile_controls::firewall_observe office
    [ "$status" -eq 0 ]
    jq -e '.state=="inactive"' <<<"$output"
    [ "$(profiles::state | jq -r .results.firewall.status)" = failed ]
}

@test 'baseline availability checks retained bytes and safe paths rather than directory existence' {
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
    profile_controls::apply firewall office
    profile_controls::firewall_baseline_available
    local baseline="$CORE_STATE/profiles/controls/firewall-baseline"
    printf 'changed baseline\n' >>"$baseline/ufw/user.rules"
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
    : >"$CALLS"
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'saved fingerprint'* ]]
    [ -f "$CORE_STATE/profiles/controls/firewall.json" ]
    [ -d "$baseline" ]
    run grep -E '^ufw (default|--force|allow|reload)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'linked writable and multi-document baseline evidence is not offered as recoverable' {
    profile_controls::apply firewall office
    local baseline="$CORE_STATE/profiles/controls/firewall-baseline" record original
    record="$CORE_STATE/profiles/controls/firewall.json"
    original=$(cat "$record")
    chmod 0666 "$baseline/default-ufw"
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
    chmod 0644 "$baseline/default-ufw"
    mv "$baseline/ufw/user.rules" "$baseline/original"
    ln -s ../original "$baseline/ufw/user.rules"
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
    rm "$baseline/ufw/user.rules"
    mv "$baseline/original" "$baseline/ufw/user.rules"
    printf '%s\n%s\n' "$original" "$original" >"$record"
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
}

@test 'successful disable command with unchanged live state retains failed restoration evidence' {
    profile_controls::apply firewall office
    FAIL=restore-noop
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'did not verify after restoration'* ]]
    [ -e "$CORE_STATE/profiles/controls/firewall.json" ]
    [ -d "$CORE_STATE/profiles/controls/firewall-baseline" ]
    [ "$(cat "$FIREWALL")" = active ]
    FAIL=''
    profile_controls::restore firewall
    [ "$(cat "$FIREWALL")" = inactive ]
    [ ! -e "$CORE_STATE/profiles/controls/firewall.json" ]
}

@test 'active baseline restoration preserves original defaults mode and verifies original kernel rules' {
    printf active >"$FIREWALL"
    chmod 0640 "$PROFILE_ETC/default/ufw"
    profile_controls::apply firewall office
    profile_controls::restore firewall
    [ "$(cat "$FIREWALL")" = active ]
    [ "$(stat -c %a "$PROFILE_ETC/default/ufw")" = 640 ]
    grep -qx IPV6=no "$PROFILE_ETC/default/ufw"
    [ ! -e "$CORE_STATE/profiles/controls/firewall-baseline" ]
}

@test 'kernel restore mismatch is retained even when UFW reports its original inactive state' {
    profile_controls::apply firewall office
    iptables-save() { fixture_native_policy 4 | sed '/COMMIT/i -A INPUT -j FOREIGN'; }
    profile_controls::_record_actual firewall
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'did not verify after restoration'* ]]
    [ -e "$CORE_STATE/profiles/controls/firewall.json" ]
    [ -d "$CORE_STATE/profiles/controls/firewall-baseline" ]
}

@test 'reconciliation accepts verified vendor hooks and exact discovery-filtered hooks without changing state' {
    make_vendor_hooks
    printf active >"$FIREWALL"
    profile_controls::firewall_reconcile_safe
    profile_controls::_restrict_discovery
    : >"$CALLS"
    profile_controls::firewall_reconcile_safe
    run grep -E '^ufw (default|--force|allow|reload)' "$CALLS"
    [ "$status" -eq 1 ]
    [ ! -e "$CORE_STATE/profiles/controls/firewall.json" ]
    printf '\n# Custom input policy\n' >>"$PROFILE_ETC/ufw/before.rules"
    run profile_controls::firewall_reconcile_safe
    [ "$status" -ne 0 ]
    [[ $output == *'administrator changes'* ]]
}

@test 'reconciliation refuses live custom input hooks and unsafe configuration paths' {
    make_vendor_hooks
    printf active >"$FIREWALL"
    iptables-save() { fixture_native_policy 4 | sed '/COMMIT/i -A ufw-before-input -j CUSTOM'; }
    run profile_controls::firewall_reconcile_safe
    [ "$status" -ne 0 ]
    [[ $output == *'unrecognized UFW input-chain jump'* ]]
    iptables-save() { fixture_native_policy 4; }
    mv "$PROFILE_ETC/ufw" "$PROFILE_ETC/elsewhere"
    ln -s elsewhere "$PROFILE_ETC/ufw"
    run profile_controls::firewall_reconcile_safe
    [ "$status" -ne 0 ]
    [[ $output == *'unsafe'* ]]
}

@test 'recovery evidence changed while staging is preserved before native restoration' {
    profile_controls::apply firewall office
    local baseline="$CORE_STATE/profiles/controls/firewall-baseline"
    cp() {
        command cp "$@" || return 1
        if [[ ${*: -2:1} == "$baseline/default-ufw" ]]; then
            printf '\n# Changed during review\n' >>"$baseline/default-ufw"
        fi
    }
    : >"$CALLS"
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'recovery evidence changed during staging'* ]]
    [ "$(cat "$FIREWALL")" = active ]
    [ -f "$CORE_STATE/profiles/controls/firewall.json" ]
    run grep -E '^ufw (--force|reload)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'discovery-filtered recognition matches legacy command-substitution newline handling' {
    make_vendor_hooks
    printf '\n\n' >>"$PROFILE_SHARE/iptables/before.rules"
    local hash
    hash=$(md5sum "$PROFILE_SHARE/iptables/before.rules")
    sed -i '/usr\/share\/ufw\/iptables\/before.rules$/d' "$HOOK_MANIFEST"
    printf '%s  usr/share/ufw/iptables/before.rules\n' "${hash%% *}" >>"$HOOK_MANIFEST"
    cp "$PROFILE_SHARE/iptables/before.rules" "$PROFILE_ETC/ufw/before.rules"
    profile_controls::_restrict_discovery
    printf active >"$FIREWALL"
    profile_controls::firewall_reconcile_safe
}

@test 'restoration log failure retains original baseline and retryable control record' {
    profile_controls::apply firewall office
    core::record() { return 1; }
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [ "$(cat "$FIREWALL")" = inactive ]
    [ -f "$CORE_STATE/profiles/controls/firewall.json" ]
    [ -d "$CORE_STATE/profiles/controls/firewall-baseline" ]
    core::record() { :; }
    profile_controls::restore firewall
    [ ! -e "$CORE_STATE/profiles/controls/firewall.json" ]
}

@test 'restore previews the actual active baseline and escaped exceptions before consent or staging' {
    printf active >"$FIREWALL"
    printf '%s\n' '-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 8443 -j ACCEPT' >"$PROFILE_ETC/ufw/user.rules"
    printf '# \033[31moriginal comment\n' >>"$PROFILE_ETC/ufw/user.rules"
    profile_controls::apply firewall office
    local record
    record=$(profile_controls::_read firewall)
    : >"$CALLS"
    core::confirm() {
        [[ $* == 'Restore this displayed original firewall state and saved exceptions?' ]] || return 99
        if grep -q '^backup ' "$CALLS"; then return 99; fi
        printf 'reviewed\n' >"$BATS_TEST_TMPDIR/reviewed"
        return 1
    }
    run profile_controls::restore firewall
    [ "$status" -eq 3 ]
    [[ $output == *'Original firewall state and listed exceptions:'* && $output == *'Status: active'* ]]
    [[ $output == *'192.0.2.0/24'* && $output == *'8443'* && $output == *'\033[31m'* ]]
    [[ $output != *$'\033'* ]]
    [ -f "$BATS_TEST_TMPDIR/reviewed" ]
    [ "$(profile_controls::_read firewall)" = "$record" ]
    [ "$(cat "$FIREWALL")" = active ]
    [ -z "$(find "$PROFILE_ETC" -maxdepth 1 -name '.octoshield-ufw.*' -print -quit)" ]
}

@test 'restore explicitly previews that the retained inactive baseline will disable UFW' {
    profile_controls::apply firewall office
    : >"$CALLS"
    core::log() { printf '%s\n' "$*"; }
    core::confirm() { return 1; }
    run profile_controls::restore firewall
    [ "$status" -eq 3 ]
    [[ $output == *'Status: inactive'* && $output == *'UFW will be disabled'* ]]
    [ "$(cat "$FIREWALL")" = active ]
    run grep -E '^(backup|ufw (--force|reload))' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'baseline changes during restore confirmation abort before backups or staging' {
    profile_controls::apply firewall office
    local record
    record=$(profile_controls::_read firewall)
    : >"$CALLS"
    core::confirm() { printf '\n# Changed during consent\n' >>"$CORE_STATE/profiles/controls/firewall-baseline/default-ufw"; }
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'recovery evidence changed during review'* ]]
    [ "$(profile_controls::_read firewall)" = "$record" ]
    [ "$(cat "$FIREWALL")" = active ]
    run grep -E '^(backup|ufw (--force|reload))' "$CALLS"
    [ "$status" -eq 1 ]
    [ -z "$(find "$PROFILE_ETC" -maxdepth 1 -name '.octoshield-ufw.*' -print -quit)" ]
}

@test 'native changes during restore confirmation remain untouched and unaccepted' {
    profile_controls::apply firewall office
    local record
    record=$(profile_controls::_read firewall)
    : >"$CALLS"
    core::confirm() { printf '\n# External native edit\n' >>"$PROFILE_ETC/ufw/user.rules"; }
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    grep -q 'External native edit' "$PROFILE_ETC/ufw/user.rules"
    [ "$(profile_controls::_read firewall)" = "$record" ]
    run grep -E '^(backup|ufw (--force|reload))' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'oversized baseline review is refused without a truncated approval' {
    printf '# ' >"$PROFILE_ETC/ufw/user.rules"
    head -c 70000 /dev/zero | tr '\000' x >>"$PROFILE_ETC/ufw/user.rules"
    printf '\n' >>"$PROFILE_ETC/ufw/user.rules"
    profile_controls::apply firewall office
    : >"$CALLS"
    core::confirm() { touch "$BATS_TEST_TMPDIR/confirmed"; }
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'cannot be previewed within the safe display limit'* ]]
    [ ! -e "$BATS_TEST_TMPDIR/confirmed" ]
    [ "$(cat "$FIREWALL")" = active ]
    run grep -E '^(backup|ufw (--force|reload))' "$CALLS"
    [ "$status" -eq 1 ]
}

# shellcheck disable=SC2031 # Bats run supplies status; the sourced core module stays in the backup subshell.
@test 'cleanup failure preserves original baseline and record in the real transaction backup' {
    profile_controls::apply firewall office
    local record baseline checkpoint original
    record="$(profile_controls::_directory)/firewall.json"
    baseline="$(profile_controls::_directory)/firewall-baseline"
    original=$(cat "$record")
    checkpoint="$CORE_STATE/backups/20261025T120000Z-123/original"
    core::backup() (
        local restore_test_state=$CORE_STATE
        source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
        CORE_STATE=$restore_test_state
        CORE_TRANSACTION=20261025T120000Z-123
        core::backup "$1"
    )
    rm() {
        [[ ${*: -1} != "$record" ]] || return 1
        command rm "$@"
    }
    run profile_controls::restore firewall
    [ "$status" -ne 0 ]
    [[ $output == *'tracking record could not be removed'* ]]
    [ "$(cat "$FIREWALL")" = inactive ]
    [ "$(cat "$checkpoint$record")" = "$original" ]
    [ -f "$checkpoint$baseline/default-ufw" ]
    grep -qx IPV6=no "$checkpoint$baseline/default-ufw"
    grep -qx original "$checkpoint$baseline/ufw/user.rules"
}

@test 'inactive restoration and reconciliation accept only empty standard UFW remnants' {
    make_vendor_hooks
    profile_controls::apply firewall office
    # Like ufw disable with MANAGE_BUILTINS=no, retain the empty primary chains
    # and their existing builtin hooks after the mock service becomes inactive.
    iptables-save() {
        fixture_native_policy 4 | sed '/COMMIT/i :ufw-after-input - [0:0]\n-A INPUT -j ufw-after-input'
    }
    ip6tables-save() {
        fixture_native_policy 6 | sed '/COMMIT/i :ufw6-after-input - [0:0]\n-A INPUT -j ufw6-after-input'
    }
    profile_controls::_record_actual firewall
    profile_controls::restore firewall
    [ "$(cat "$FIREWALL")" = inactive ]
    profile_controls::firewall_reconcile_safe
    iptables-save() {
        fixture_native_policy 4 | sed '/COMMIT/i :ufw-after-input - [0:0]\n-A INPUT -j ufw-after-input\n-A ufw-after-input -j ACCEPT'
    }
    run profile_controls::firewall_reconcile_safe
    [ "$status" -ne 0 ]
    [[ $output == *'nonempty, unknown or unsafe'* ]]
}

@test 'inactive normalization preserves stricter native defaults and restore rejects a real policy mismatch' {
    make_vendor_hooks
    iptables-save() { fixture_native_policy 4 | sed 's/:FORWARD ACCEPT/:FORWARD DROP/'; }
    profile_controls::firewall_reconcile_safe
    local original
    original=$(profile_controls::snapshot firewall)
    profile_controls::_firewall_restore_verified "$original"
    iptables-save() { fixture_native_policy 4; }
    run profile_controls::_firewall_restore_verified "$original"
    [ "$status" -ne 0 ]
}
