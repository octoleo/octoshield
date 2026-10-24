#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reviewed, grouped firewall permissions. Both frontends use this adapter and
# the existing profile engine; callers hold core::begin's mutation lock.

access::valid_id() { [[ ${1-} =~ ^[gr][0-9]{1,16}-[0-9]{1,10}-[0-9]{1,5}$ ]]; }
access::valid_ports() {
    local value=${1-} port
    local -a validated_ports=()
    [[ ${#value} -le 191 && $value =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
    IFS=, read -r -a validated_ports <<<"$value"
    ((${#validated_ports[@]} <= 32)) || return 1
    for port in "${validated_ports[@]}"; do profiles::valid_port "$port" || return 1; done
    [[ $(printf '%s\n' "${validated_ports[@]}" | sort -u | wc -l) -eq ${#validated_ports[@]} ]]
}
access::_valid_permission() {
    [[ $# -eq 5 ]] && access::valid_ports "$1" && [[ $2 == tcp || $2 == udp ]] &&
        profiles::valid_source "$3" && profiles::valid_interface "$4" &&
        [[ $5 =~ ^(0|[1-9][0-9]{0,4})$ ]] && ((10#$5 <= 10080))
}
access::validate() {
    case "${1-}" in
        list) [[ $# -eq 1 || $# -eq 2 ]] && { [[ $# -eq 1 ]] || profiles::valid_name "$2"; } ;;
        allow) [[ $# -eq 7 ]] && profiles::valid_name "$2" && access::_valid_permission "${@:3}" ;;
        update) [[ $# -eq 8 ]] && profiles::valid_name "$2" && access::valid_id "$3" && access::_valid_permission "${@:4}" ;;
        revoke) [[ $# -eq 3 ]] && profiles::valid_name "$2" && access::valid_id "$3" ;;
        *) return 1 ;;
    esac
}
access::mutates() { [[ ${1-} != list ]]; }

access::default_profile() {
    profiles::state | jq -er 'if .active.firewall!="unmanaged" then .active.firewall
      elif .global!="unmanaged" then .global elif .profiles.home!=null then "home"
      else (.profiles|keys|first) end'
}

access::list() {
    local profile=${1-} document active observation='{}' now
    document=$(profiles::state) || return 1
    active=$(jq -r .active.firewall <<<"$document") || return 1
    [[ -n $profile ]] || profile=$(jq -r 'if .active.firewall!="unmanaged" then .active.firewall
      elif .global!="unmanaged" then .global elif .profiles.home!=null then "home"
      else (.profiles|keys|first) end' <<<"$document") || return 1
    profiles::valid_name "$profile" || return 1
    jq -e --arg p "$profile" '.profiles[$p]!=null' <<<"$document" >/dev/null || {
        core::die 'The selected firewall profile no longer exists. Refresh permissions.'
        return 1
    }
    if [[ $active == "$profile" ]]; then
        observation=$(profile_controls::verify firewall) || observation='{}'
    fi
    now=$(date +%s) || return 1
    jq -cn --argjson doc "$document" --argjson observed "$observation" --arg p "$profile" --arg active "$active" --argjson now "$now" '
      ($doc.results.firewall.status//"unmanaged") as $result |
      (if $active!=$p then "pending" elif $result=="failed" or $result=="applying" then "failed"
       elif $observed.state=="active" then "active" elif $observed.state=="partial" then "pending" else "unknown" end) as $state |
      {kind:"access",profile:$p,managed:($active!="unmanaged"),state:$state,
       summary:(if $active=="unmanaged" then "Choose and review a profile before adopting the existing firewall. Current native exceptions will be shown before replacement."
                elif $active!=$p then "This is a saved profile. Select the active firewall profile to change live permissions."
                else ($observed.summary//"Current firewall policy could not be verified.") end),
       rules:($doc.profiles[$p].firewall.rules | group_by([(.group//.id),.protocol,.source,.interface,.expires_at]) |
         map(.[0] as $first | (map(.port)|sort|map(tostring)|join(",")) as $ports |
           {id:($first.group//$first.id),label:(if $ports=="80,443" and $first.protocol=="tcp" then "Web server (HTTP + HTTPS)"
              elif $ports=="22" and $first.protocol=="tcp" then "Incoming SSH" else (($first.protocol|ascii_upcase)+" "+$ports) end),
            ports:$ports,protocol:$first.protocol,source:$first.source,interface:$first.interface,expires_at:$first.expires_at,
            state:(if $first.expires_at>0 and $first.expires_at<=$now then "expired" else $state end)}))}'
}

access::_ready() {
    local profile=$1 active=$2 document=$3 saved desired result
    if [[ $active != unmanaged && $active != "$profile" ]]; then
        core::die "Firewall currently uses $active. Select that profile for a permission change, or explicitly switch profiles under Protections first."
        return 1
    fi
    jq -e --arg p "$profile" '.profiles[$p]!=null' <<<"$document" >/dev/null || return 1
    result=$(jq -r '.results.firewall.status//"unmanaged"' <<<"$document") || return 1
    if [[ $result == failed || $result == applying ]]; then
        core::die 'The previous firewall change did not complete. Review its result and retry or restore the firewall from Protections before changing permissions.'
        return 1
    fi
    if [[ $active != unmanaged ]]; then
        saved=$(profile_controls::_read firewall) || return 1
        desired=$(jq -c --arg p "$profile" '.profiles[$p].firewall' <<<"$document" | profile_controls::_hash) || return 1
        [[ $(jq -r .desired <<<"$saved") == "$desired" ]] || {
            core::die 'This firewall profile has saved changes awaiting Apply. Review and apply those changes under Protections before adding or revoking a live permission.'
            return 1
        }
    fi
    profile_controls::preflight firewall "$profile"
}

access::_candidate() {
    local document=$1 profile=$2 identifier=$3 ports=$4 protocol=$5 source=$6 interface=$7 expires=$8 now=$9 remove_id=${10:-$3} port id
    local -a values=()
    # Removing the selected group first makes an edit one saved transaction.
    document=$(jq -c --arg p "$profile" --arg id "$remove_id" '.profiles[$p].firewall.rules |= map(select((.group//.id)!=$id))' <<<"$document") || return 1
    [[ -n $ports ]] || {
        printf '%s\n' "$document"
        return
    }
    IFS=, read -r -a values <<<"$ports"
    for port in "${values[@]}"; do
        if jq -e --arg p "$profile" --argjson port "$port" --arg protocol "$protocol" --arg source "$source" --arg interface "$interface" --argjson now "$now" '
          any(.profiles[$p].firewall.rules[];.port==$port and .protocol==$protocol and .source==$source and .interface==$interface and (.expires_at==0 or .expires_at>$now))' <<<"$document" >/dev/null; then
            core::die "Port $port already has a permission with this source and interface. Edit that permission instead of adding a duplicate."
            return 1
        fi
        while :; do
            id="r$now-$$-$RANDOM"
            jq -e --arg p "$profile" --arg id "$id" 'all(.profiles[$p].firewall.rules[];.id!=$id)' <<<"$document" >/dev/null && break
        done
        document=$(jq -c --arg p "$profile" --arg id "$id" --arg group "$identifier" --argjson port "$port" --arg protocol "$protocol" --arg source "$source" --arg interface "$interface" --argjson expires "$expires" '
          .profiles[$p].firewall.rules += [{id:$id,port:$port,protocol:$protocol,source:$source,interface:$interface,expires_at:$expires}
            + (if ($group|startswith("g")) then {group:$group} else {} end)]' <<<"$document") || return 1
    done
    profiles::_validate_document <<<"$document" || {
        core::die 'This change would exceed the firewall permission limit.'
        return 1
    }
    printf '%s\n' "$document"
}

access::_rollback() {
    local before=$1 profile=$2 active=$3
    core::log 'The requested change failed. Restoring the previous reviewed firewall policy.'
    profiles::_save "$before" || return 1
    if [[ $active == unmanaged ]]; then
        profile_controls::restore firewall || return 1
    else
        profile_controls::apply firewall "$profile" || return 1
    fi
    profiles::_save "$before" || return 1
    core::record "ACCESS rollback $profile" || return 1
    core::log 'The previous firewall policy was restored. The requested permission change was not completed.'
}

access::change() {
    local operation=$1 profile=$2 identifier='' ports='' protocol='' source='' interface='' minutes=0
    local before active candidate snapshot current now expiry=0 observation native remove_id=''
    shift 2
    case "$operation" in
        allow) ports=$1 protocol=$2 source=$3 interface=$4 minutes=$5 ;;
        update) identifier=$1 ports=$2 protocol=$3 source=$4 interface=$5 minutes=$6 ;;
        revoke) identifier=$1 ;;
        *) return 1 ;;
    esac
    controls::local_console || return 1
    before=$(profiles::state) || return 1
    active=$(jq -r .active.firewall <<<"$before") || return 1
    access::_ready "$profile" "$active" "$before" || return 1
    if [[ $operation != allow ]]; then
        jq -e --arg p "$profile" --arg id "$identifier" 'any(.profiles[$p].firewall.rules[];(.group//.id)==$id)' <<<"$before" >/dev/null || {
            core::die 'That permission changed or was removed. Refresh permissions and review it again.'
            return 1
        }
        remove_id=$identifier
        # Old standalone rules gain a group when edited to several ports.
        [[ $operation != update || $identifier != r* ]] || identifier=''
    fi
    now=$(date +%s) || return 1
    if [[ -z $identifier ]]; then
        while :; do
            identifier="g$now-$$-$RANDOM"
            jq -e --arg p "$profile" --arg id "$identifier" 'all(.profiles[$p].firewall.rules[];(.group//.id)!=$id)' <<<"$before" >/dev/null && break
        done
    fi
    ((minutes == 0)) || expiry=$((now + minutes * 60))
    candidate=$(access::_candidate "$before" "$profile" "$identifier" "$ports" "$protocol" "$source" "$interface" "$expiry" "$now" "${remove_id:-$identifier}") || return 1
    profile_controls::_expiry_ready "$(jq -c --arg p "$profile" '.profiles[$p].firewall' <<<"$candidate")" || return 1
    snapshot=$(profile_controls::snapshot firewall) || return 1
    if [[ $active == unmanaged ]]; then
        native=$(LC_ALL=C ufw status numbered) || return 1
        [[ ${#native} -le 262144 ]] || return 1
        core::log 'Adopting this firewall replaces its current UFW exceptions with the reviewed profile. A private baseline is retained for Restore. Current native rules:'
        printf '%s\n' "$native"
    fi
    core::log "Review $operation in firewall profile $profile. The following complete permission set will be applied; unrelated profile settings are unchanged."
    jq -r --arg p "$profile" '.profiles[$p].firewall.rules[]|"  \(.protocol)/\(.port) from \(.source), interface \(.interface), " + (if .expires_at==0 then "permanent" else "temporary" end)' <<<"$candidate"
    if [[ $operation != revoke ]]; then
        core::log "Selected permission: $protocol ports $ports from $source on $interface, duration $minutes minutes (0 means permanent). This scopes host UFW input; Docker published ports need their own review."
        [[ $source != any ]] || core::log 'Any source allows incoming connections from every network that can reach this host.'
        core::log 'A subnet and interface do not authenticate a network. Another network can reuse the same subnet; revoke the permission before changing networks.'
    fi
    core::confirm "Apply this reviewed firewall permission change now? Existing connections are not forcibly disconnected. On failure OctoShield will attempt to restore the previous policy." || return 1
    current=$(profiles::state) || return 1
    if [[ $current != "$before" ]] || [[ $(profile_controls::snapshot firewall) != "$snapshot" ]]; then
        core::die 'The firewall or profile changed during review. Nothing was applied; refresh and review again.'
        return 1
    fi
    # Start the grant at activation, after the user has completed review.
    now=$(date +%s) || return 1
    expiry=0
    ((minutes == 0)) || expiry=$((now + minutes * 60))
    candidate=$(access::_candidate "$before" "$profile" "$identifier" "$ports" "$protocol" "$source" "$interface" "$expiry" "$now" "${remove_id:-$identifier}") || return 1
    profiles::_save "$candidate" || return 1
    if ! profiles::_result firewall applying 'Applying and verifying the reviewed permission change.'; then
        profiles::_save "$before" || core::die 'The saved permission could not be restored after a state-write failure. No native firewall change was started.'
        return 1
    fi
    if profile_controls::apply firewall "$profile" && profiles::_result firewall applied 'Reviewed firewall permissions applied.' "$profile"; then
        observation=$(profile_controls::verify firewall) || observation='{}'
        if jq -e '.state=="active"' <<<"$observation" >/dev/null; then
            core::record "ACCESS $operation $profile $identifier" || return 1
            access::list "$profile"
            return
        fi
    fi
    if ! access::_rollback "$before" "$profile" "$active"; then
        profiles::_result firewall failed 'Permission change and automatic restoration could not be completed. Inspect the actual firewall and use the saved baseline for recovery.' || :
        core::die 'Automatic restoration was incomplete. Some rules may have changed; inspect the firewall and the saved transaction before retrying.'
    fi
    return 1
}

access::dispatch() {
    access::validate "$@" || {
        core::die 'Invalid access command or arguments.'
        return 2
    }
    core::require_root || return 1
    case "$1" in
        list) access::list "${2-}" ;;
        allow | update | revoke) access::change "$@" ;;
    esac
}
