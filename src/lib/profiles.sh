#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Named policy documents are data, never shell input. Callers hold core::begin's
# operation lock for mutations; read paths do not create state or change policies.

profiles::valid_name() { [[ ${1-} =~ ^[a-z][a-z0-9-]{0,31}$ && $1 != unmanaged ]]; }
profiles::valid_control() { case "${1-}" in firewall | usb | network | services | monitor) return 0 ;; *) return 1 ;; esac }
profiles::valid_key() {
    case "${1-}" in network.autoconnect | network.discovery | services.printing | services.bluetooth | services.ssh | services.discovery | services.samba | services.remote_desktop | monitor.enabled) return 0 ;; *) return 1 ;; esac
}
profiles::valid_port() { [[ ${1-} =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535)); }
profiles::valid_source() {
    local value=${1-} address prefix part count=0 compressed=0
    local -a pieces=()
    [[ $value == any ]] && return 0
    address=${value%/*}
    prefix=${value##*/}
    if [[ $address == *:* ]]; then
        [[ $address =~ ^[a-fA-F0-9:]+$ && $address != *:::* ]] || return 1
        if [[ $value == */* ]]; then [[ $prefix =~ ^[0-9]{1,3}$ ]] && ((10#$prefix <= 128)) || return 1; fi
        if [[ $address == *::* ]]; then
            compressed=1
            [[ ${address#*::} != *::* ]] || return 1
        else
            [[ $address != :* && $address != *: ]] || return 1
        fi
        IFS=: read -r -a pieces <<<"$address"
        for part in "${pieces[@]}"; do
            [[ -z $part ]] && continue
            [[ $part =~ ^[a-fA-F0-9]{1,4}$ ]] || return 1
            count=$((count + 1))
        done
        ((compressed && count < 8 || !compressed && count == 8))
    else
        [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
        if [[ $value == */* ]]; then [[ $prefix =~ ^[0-9]{1,2}$ ]] && ((10#$prefix <= 32)) || return 1; fi
        IFS=. read -r -a pieces <<<"$address"
        for part in "${pieces[@]}"; do ((10#$part <= 255)) || return 1; done
    fi
}
profiles::valid_interface() { [[ ${1-} == any || ${1-} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$ ]]; }
profiles::validate() {
    case "${1-}" in
        list) [[ $# -eq 1 ]] ;;
        show | delete) [[ $# -eq 2 ]] && profiles::valid_name "$2" ;;
        create) [[ $# -eq 3 ]] && profiles::valid_name "$2" && profiles::valid_name "$3" ;;
        apply) [[ $# -eq 2 || $# -eq 3 ]] && profiles::valid_name "$2" && { [[ $# -eq 2 ]] || profiles::valid_control "$3"; } ;;
        restore) [[ $# -eq 1 || $# -eq 2 ]] && { [[ $# -eq 1 ]] || profiles::valid_control "$2"; } ;;
        set) [[ $# -eq 4 ]] && profiles::valid_name "$2" && profiles::valid_key "$3" && { if [[ $3 == services.* ]]; then [[ $4 == enabled || $4 == disabled || $4 == baseline ]]; else [[ $4 == true || $4 == false ]]; fi; } ;;
        rule-add) [[ $# -eq 7 ]] && profiles::valid_name "$2" && profiles::valid_port "$3" && [[ $4 == tcp || $4 == udp ]] && profiles::valid_source "$5" && profiles::valid_interface "$6" && [[ $7 =~ ^(0|[1-9][0-9]{0,4})$ ]] && ((10#$7 <= 10080)) ;;
        rule-remove) [[ $# -eq 3 ]] && profiles::valid_name "$2" && [[ $3 =~ ^r[0-9]{1,16}-[0-9]{1,10}-[0-9]{1,5}$ ]] ;;
        *) return 1 ;;
    esac
}
profiles::mutates() { case "${1-}" in list | show) return 1 ;; *) return 0 ;; esac }
profiles::_defaults() {
    jq -cn '
      def p($name;$comfortable): {name:$name,firewall:{rules:[]},usb:{},network:{autoconnect:$comfortable,discovery:false},services:{printing:(if $comfortable then "baseline" else "disabled" end),bluetooth:(if $comfortable then "baseline" else "disabled" end),ssh:"disabled",discovery:"disabled",samba:"disabled",remote_desktop:"disabled"},monitor:{enabled:true}};
      {schema:1,global:"unmanaged",active:{firewall:"unmanaged",usb:"unmanaged",network:"unmanaged",services:"unmanaged",monitor:"unmanaged"},results:{},profiles:{conference:p("Conference";false),public:p("Public";false),office:p("Office";true),home:p("Home";true)}}'
}
profiles::_validate_document() {
    jq -e '
      def slug: type=="string" and test("^[a-z][a-z0-9-]{0,31}$");
      def control: .=="firewall" or .=="usb" or .=="network" or .=="services" or .=="monitor";
      def booleans($keys): type=="object" and (keys|sort)==($keys|sort) and all(.[];type=="boolean");
      def rule: type=="object" and (keys|sort)==(["id","port","protocol","source","interface","expires_at"]|sort)
        and (.id|type=="string" and test("^r[0-9]{1,16}-[0-9]{1,10}-[0-9]{1,5}$"))
        and (.port|type=="number" and floor==. and .>=1 and .<=65535)
        and (.protocol=="tcp" or .protocol=="udp")
        and (.source|type=="string" and length<=64) and (.interface|type=="string" and length<=15)
        and (.expires_at|type=="number" and floor==. and .>=0 and .<=9007199254740991);
      .schema==1 and (.global|slug) and (.profiles|type=="object" and length>=1 and length<=64)
      and (.active|type=="object" and (keys|sort)==(["firewall","usb","network","services","monitor"]|sort) and all(.[];slug))
      and (.results|type=="object" and all(to_entries[];(.key|control) and (.value|type=="object") and (.value.status|IN("applied","failed","unmanaged","pending","applying")) and (.value.message|type=="string" and length<=512)))
      and all(.profiles|to_entries[];(.key|slug) and .key!="unmanaged" and (.value|
        type=="object" and (keys|sort)==(["name","firewall","usb","network","services","monitor"]|sort)
        and (.name|type=="string" and length>=1 and length<=64 and (test("[\u0000-\u001f\u007f]")|not))
        and (.firewall|type=="object" and keys==["rules"] and (.rules|type=="array" and length<=256 and all(.[];rule) and (map(.id)|unique|length)==length))
        and (.usb|type=="object" and length==0) and (.network|booleans(["autoconnect","discovery"]))
        and (.services|type=="object" and (keys|sort)==(["printing","bluetooth","ssh","discovery","samba","remote_desktop"]|sort) and all(.[];IN("enabled","disabled","baseline"))) and (.monitor|booleans(["enabled"]))))
      and (. as $root | all(.active[]; .=="unmanaged" or $root.profiles[.]!=null))
      and (.global=="unmanaged" or .profiles[.global]!=null)
    ' >/dev/null || return 1
}
profiles::_secure_file() {
    local path=$1 kind=${2:-file} metadata
    [[ ! -L $path ]] || return 1
    if [[ $kind == directory ]]; then [[ -d $path ]] || return 1; else [[ -f $path ]] || return 1; fi
    metadata=$(stat -c '%u:%a' -- "$path") || return 1
    if [[ $kind == directory ]]; then [[ $metadata == 0:700 ]]; else [[ $metadata == 0:600 ]]; fi
}
profiles::_read() {
    local file="$CORE_STATE/profiles/state.json" document source interface
    if [[ ! -e $file && ! -L $file ]]; then
        profiles::_defaults
        return
    fi
    if ! profiles::_secure_file "$CORE_STATE" directory || ! profiles::_secure_file "$CORE_STATE/profiles" directory || ! profiles::_secure_file "$file"; then
        core::die 'Profile state permissions or ownership are unsafe.'
        return 1
    fi
    [[ $(stat -c %s -- "$file") -le 1048576 ]] || return 1
    document=$(cat -- "$file") || return 1
    profiles::_validate_document <<<"$document" || {
        core::die 'Invalid profile state; nothing was changed.'
        return 1
    }
    while IFS=$'\t' read -r source interface; do
        profiles::valid_source "$source" && profiles::valid_interface "$interface" || return 1
    done < <(jq -r '.profiles[].firewall.rules[] | [.source,.interface]|@tsv' <<<"$document")
    printf '%s\n' "$document"
}
profiles::_save() {
    local document=$1 directory="$CORE_STATE/profiles" temporary
    profiles::_validate_document <<<"$document" || return 1
    [[ ! -L $directory && ! -L $directory/state.json ]] || return 1
    install -d -m 0700 -o root -g root "$directory" || return 1
    temporary=$(mktemp "$directory/.state.XXXXXX") || return 1
    if ! printf '%s\n' "$document" >"$temporary" || ! chmod 0600 "$temporary" || ! chown root:root "$temporary" || ! mv -fT -- "$temporary" "$directory/state.json"; then
        rm -f -- "$temporary"
        return 1
    fi
}
profiles::state() { profiles::_read; }
profiles::get() {
    local document
    profiles::valid_name "${1-}" || return 1
    document=$(profiles::_read) || return 1
    jq -c --arg id "$1" --arg path "${2-}" '.profiles[$id] // error("Unknown profile") | if $path=="" then . else getpath($path|split(".")) end' <<<"$document"
}
profiles::active() {
    local document
    profiles::valid_control "${1-}" || return 1
    document=$(profiles::_read) || return 1
    jq -r --arg control "$1" '.active[$control]' <<<"$document"
}
profiles::public_status() {
    local document
    document=$(profiles::_read) || return 1
    jq -c '{schema,global,active,results,catalog:(.profiles|to_entries|map({id:.key,name:.value.name})),overrides:(. as $root|.active|with_entries(select(.value!=$root.global)))}' <<<"$document"
}
profiles::_result() {
    local control=$1 status=$2 message=$3 active=${4-} document
    document=$(profiles::_read) || return 1
    document=$(jq -c --arg c "$control" --arg s "$status" --arg m "$message" --arg a "$active" '.results[$c]={status:$s,message:$m}|if $a!="" then .active[$c]=$a else . end' <<<"$document") || return 1
    profiles::_save "$document"
}
profiles::_hook() {
    local action=$1 control=$2 profile=${3-}
    if [[ $control == usb ]]; then
        declare -F "usb::profile_$action" >/dev/null || {
            core::die 'USB profile support is unavailable.'
            return 1
        }
        "usb::profile_$action" "$profile"
    else
        "profile_controls::$action" "$control" "$profile"
    fi
}
profiles::apply() {
    local profile=$1 control=${2-} document item failed=0
    local -a controls=(firewall usb network services monitor)
    [[ -z $control ]] || controls=("$control")
    profiles::get "$profile" >/dev/null || return 1
    controls::local_console || return 1
    core::log "Apply $profile to: ${controls[*]}. Existing permissions are replaced only for the selected controls. Other changes are preserved."
    for item in "${controls[@]}"; do profiles::_hook preflight "$item" "$profile" || return 1; done
    core::confirm "Apply the reviewed $profile profile settings? Individual controls can fail; verified results will show any incomplete switch." || return 1
    if [[ -z $control ]]; then
        document=$(profiles::_read) || return 1
        document=$(jq -c --arg p "$profile" '.global=$p' <<<"$document") || return 1
        profiles::_save "$document" || return 1
    fi
    for item in "${controls[@]}"; do
        profiles::_result "$item" applying 'Applying and verifying native policy.' || return 1
        if profiles::_hook apply "$item" "$profile"; then
            profiles::_result "$item" applied 'Native policy applied; current verification is shown separately.' "$profile" || return 1
            core::record "PROFILE $item $profile" || return 1
        else
            profiles::_result "$item" failed 'Application failed or was interrupted. Inspect the actual policy before retrying or restoring.' || return 1
            failed=1
            break
        fi
    done
    ((failed == 0))
}
profiles::restore() {
    local control=${1-} item document result failed=0
    local -a controls=(firewall usb network services monitor)
    [[ -z $control ]] || controls=("$control")
    controls::local_console || return 1
    core::confirm "Restore the pre-profile baseline for ${control:-all managed controls}? This can reduce protection. External changes cause a conflict instead of being overwritten." || return 1
    for item in "${controls[@]}"; do
        document=$(profiles::_read) || return 1
        result=$(jq -r --arg c "$item" '.results[$c].status//"unmanaged"' <<<"$document") || return 1
        [[ $(profiles::active "$item") != unmanaged || $result == failed || $result == applying ]] || continue
        if profiles::_hook restore "$item"; then
            profiles::_result "$item" unmanaged 'Restored the saved pre-profile baseline.' unmanaged || return 1
        else
            profiles::_result "$item" failed 'Baseline restoration failed or external changes require review.' || return 1
            failed=1
            break
        fi
    done
    if [[ -z $control && $failed == 0 ]]; then
        document=$(profiles::_read) || return 1
        document=$(jq -c '.global="unmanaged"' <<<"$document") || return 1
        profiles::_save "$document" || return 1
    fi
    ((failed == 0))
}
profiles::expiry_due() {
    [[ $(profiles::active firewall) != unmanaged ]] || return 1
    profile_controls::expiry_due
}
# The caller owns the mutation lock. Only the last-applied policy is reconciled:
# pending edits must never acquire privileges because a timer happened to fire.
profiles::expire() {
    local document profile now
    profiles::expiry_due || return 0
    document=$(profiles::_read) || return 1
    profile=$(jq -r '.active.firewall' <<<"$document") || return 1
    now=$(date +%s) || return 1
    if profile_controls::expire "$profile"; then
        document=$(jq -c --arg p "$profile" --argjson now "$now" '.profiles[$p].firewall.rules |= map(select(.expires_at==0 or .expires_at>$now))' <<<"$document") || return 1
        profiles::_save "$document" || return 1
        profiles::_result firewall applied 'Expired firewall exceptions were removed; pending edits still require Apply.' "$profile"
    else
        profiles::_result firewall failed 'An expired exception could not be removed. Inspect the firewall immediately.'
        return 1
    fi
}
profiles::verify() { profile_controls::verify "$@"; }
profiles::dispatch() {
    local command=${1-} document profile base key value identifier now minutes
    profiles::validate "$@" || {
        core::die 'Invalid profile command or argument.'
        return 1
    }
    core::require_root || return 1
    document=$(profiles::_read) || return 1
    shift
    case "$command" in
        list) jq -c '.profiles|to_entries|map(.value+{id:.key})' <<<"$document" ;;
        show) jq -ce --arg p "$1" '.profiles[$p] // error("Unknown profile")|.+{id:$p}' <<<"$document" ;;
        create)
            profile=$1
            base=$2
            jq -e --arg p "$profile" --arg b "$base" '.profiles[$p]==null and .profiles[$b]!=null and (.profiles|length)<64' <<<"$document" >/dev/null || {
                core::die 'Profile already exists, base is missing, or profile limit reached.'
                return 1
            }
            document=$(jq -c --arg p "$profile" --arg b "$base" '.profiles[$p]=.profiles[$b]|.profiles[$p].name=$p' <<<"$document") || return 1
            if declare -F usb::profile_clone >/dev/null; then usb::profile_clone "$profile" "$base" || return 1; fi
            profiles::_save "$document"
            ;;
        delete)
            profile=$1
            jq -e --arg p "$profile" '.profiles[$p]!=null and (.profiles|length)>1 and .global!=$p and all(.active[];. != $p)' <<<"$document" >/dev/null || {
                core::die 'Select a different profile before deleting an active or last profile.'
                return 1
            }
            if declare -F usb::profile_delete >/dev/null; then usb::profile_delete "$profile" || return 1; fi
            document=$(jq -c --arg p "$profile" 'del(.profiles[$p])' <<<"$document") || return 1
            profiles::_save "$document"
            ;;
        set)
            profile=$1
            key=$2
            value=$3
            profiles::get "$profile" >/dev/null || return 1
            [[ $key != services.* ]] || value=$(jq -cn --arg v "$value" '$v')
            document=$(jq -c --arg p "$profile" --arg k "$key" --argjson v "$value" '.profiles[$p] |= setpath($k|split(".");$v)' <<<"$document") || return 1
            profiles::_save "$document"
            ;;
        rule-add)
            profile=$1
            minutes=$6
            profiles::get "$profile" >/dev/null || return 1
            now=$(date +%s) || return 1
            identifier="r$now-$$-$RANDOM"
            ((minutes == 0)) || minutes=$((now + minutes * 60))
            document=$(jq -c --arg p "$profile" --arg id "$identifier" --argjson port "$2" --arg proto "$3" --arg source "$4" --arg interface "$5" --argjson expires "$minutes" '.profiles[$p].firewall.rules += [{id:$id,port:$port,protocol:$proto,source:$source,interface:$interface,expires_at:$expires}]' <<<"$document") || return 1
            profiles::_save "$document" || return 1
            printf '%s\n' "$identifier"
            ;;
        rule-remove)
            jq -e --arg p "$1" --arg id "$2" '.profiles[$p]!=null and any(.profiles[$p].firewall.rules[];.id==$id)' <<<"$document" >/dev/null || return 1
            document=$(jq -c --arg p "$1" --arg id "$2" '.profiles[$p].firewall.rules |= map(select(.id!=$id))' <<<"$document") || return 1
            profiles::_save "$document"
            ;;
        apply) profiles::apply "$@" ;;
        restore) profiles::restore "$@" ;;
    esac
}
