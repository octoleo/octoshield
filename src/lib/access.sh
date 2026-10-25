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
        recover | reconcile) [[ $# -eq 2 ]] && profiles::valid_name "$2" ;;
        restore) [[ $# -eq 1 ]] ;;
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

# Read-only assessment shared by the form and its mutation guard. A historical
# failure remains visible even when native inspection now finds matching rules.
# Only an explicitly reviewed Apply/Restore completes that failed operation.
access::_assessment() {
    local profile=$1 active=$2 document=$3 saved='' current='' desired result message transaction='' directory
    local ready=false can_apply=false can_restore=false can_reconcile=false matches=false narrowed=false
    local reason=unavailable summary='Firewall state or recovery evidence could not be read. Inspect the last change before retrying.' observed
    result=$(jq -r '.results.firewall.status//"unmanaged"' <<<"$document") || return 1
    message=$(jq -r '.results.firewall.message//"No previous firewall operation is recorded."' <<<"$document") || return 1
    transaction=$(jq -r '.results.firewall.transaction//""' <<<"$document") || return 1
    if ! profiles::valid_transaction "$transaction" ||
        ! profiles::_secure_file "$CORE_STATE/backups/$transaction" directory ||
        ! profiles::_secure_file "$CORE_STATE/backups/$transaction/actions.log"; then transaction=; fi
    observed=$(profile_controls::firewall_observe "$profile" 2>/dev/null) || observed='{}'
    observed=$(jq -ce 'select(type=="object" and (.state|IN("active","inactive","partial","unknown","unsupported")) and
        (.summary|type=="string" and length<=1024)) | {state,summary}' <<<"$observed" 2>/dev/null) ||
        observed='{"state":"unknown","summary":"Current native firewall policy could not be inspected."}'
    directory=$(profile_controls::_directory) || return 1
    if saved=$(profile_controls::_read firewall 2>/dev/null); then
        if profile_controls::firewall_baseline_available 2>/dev/null && current=$(profile_controls::snapshot firewall 2>/dev/null); then
            [[ $(profile_controls::_hash <<<"$current") != "$(jq -r .expected <<<"$saved")" ]] || matches=true
            if [[ $matches == false ]] && profile_controls::_runtime_narrowed "$saved" "$current" >/dev/null 2>&1; then narrowed=true; fi
            if [[ $matches == false && $narrowed == false ]]; then
                reason=drift
                summary='The native firewall differs from the recorded state. Review external changes here before applying a saved profile or restoring the original settings.'
                if profile_controls::firewall_reconcile_safe >/dev/null 2>&1; then can_reconcile=true; fi
                if [[ $can_reconcile == false ]]; then
                    summary='The native firewall differs from the recorded state and contains unsupported or unsafe configuration. Inspect its rules and the last change; automatic reconciliation is unavailable.'
                fi
            else
                can_apply=true can_restore=true
                desired=$(jq -c --arg p "$profile" '.profiles[$p].firewall' <<<"$document" | profile_controls::_hash) || return 1
                if [[ $active != unmanaged && $active != "$profile" ]]; then
                    reason=different-profile
                    summary="Firewall currently uses $active. Select that profile for a permission change, or review and apply the selected $profile firewall profile here."
                elif [[ $result == failed || $result == applying || $active == unmanaged ]]; then
                    reason=incomplete
                    summary='The previous firewall change did not complete. Review and apply the selected firewall profile here, or restore the original firewall settings. This is a saved result, not a running operation.'
                elif [[ $result == pending || $narrowed == true || $(jq -r .desired <<<"$saved") != "$desired" ]]; then
                    reason=pending
                    summary='This firewall profile has saved changes awaiting Apply, or needs reapplication after reviewed recovery. Review and apply it here before changing live permissions.'
                elif [[ $(jq -r .state <<<"$observed") != active ]]; then
                    reason=incomplete
                    summary='Current native rules do not verify against the selected firewall profile. Inspect the finding below, then review and apply the profile or restore its original settings.'
                else
                    reason=ready ready=true
                    summary='The selected firewall profile is verified. Review a permission to allow, update or revoke access.'
                fi
            fi
        fi
    elif [[ $active == unmanaged && $result != failed && $result != applying &&
        ! -e $directory/firewall.json && ! -L $directory/firewall.json &&
        ! -e $directory/firewall-baseline && ! -L $directory/firewall-baseline ]]; then
        reason=unmanaged ready=true can_apply=true
        summary='No profile controls the firewall. The next reviewed application will show and replace native UFW exceptions while retaining an original recovery baseline.'
    fi
    jq -cn --arg reason "$reason" --arg summary "$summary" --arg result "$result" --arg message "$message" --arg transaction "$transaction" \
        --argjson ready "$ready" --argjson apply "$can_apply" --argjson restore "$can_restore" --argjson reconcile "$can_reconcile" --argjson observed "$observed" \
        '{ready:$ready,summary:$summary,recovery:{reason:$reason,last_result:$result,message:$message,transaction:$transaction,
          can_apply:$apply,can_restore:$restore,can_reconcile:$reconcile,observed:$observed}}'
}

access::list() {
    local profile=${1-} document active assessment now
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
    assessment=$(access::_assessment "$profile" "$active" "$document") || return 1
    now=$(date +%s) || return 1
    jq -cn --argjson doc "$document" --argjson assessment "$assessment" --arg p "$profile" --arg active "$active" --argjson now "$now" '
      (if $assessment.recovery.reason=="ready" then "active" elif $assessment.recovery.reason=="incomplete" then "failed"
       elif $assessment.recovery.reason|IN("pending","unmanaged","different-profile") then "pending" else "unknown" end) as $state |
      {kind:"access",profile:$p,assigned_profile:$active,managed:($active!="unmanaged"),state:$state,
       ready:$assessment.ready,summary:$assessment.summary,recovery:$assessment.recovery,
       rules:($doc.profiles[$p].firewall.rules | group_by([(.group//.id),.protocol,.source,.interface,.expires_at]) |
         map(.[0] as $first | (map(.port)|sort|map(tostring)|join(",")) as $ports |
           {id:($first.group//$first.id),label:(if $ports=="80,443" and $first.protocol=="tcp" then "Web server (HTTP + HTTPS)"
              elif $ports=="22" and $first.protocol=="tcp" then "Incoming SSH" else (($first.protocol|ascii_upcase)+" "+$ports) end),
            ports:$ports,protocol:$first.protocol,source:$first.source,interface:$first.interface,expires_at:$first.expires_at,
            state:(if $first.expires_at>0 and $first.expires_at<=$now then "expired" else $state end)}))}'
}

access::_ready() {
    local profile=$1 active=$2 document=$3 assessment
    jq -e --arg p "$profile" '.profiles[$p]!=null' <<<"$document" >/dev/null || return 1
    assessment=$(access::_assessment "$profile" "$active" "$document") || return 1
    if ! jq -e '.ready==true' <<<"$assessment" >/dev/null; then
        core::die "$(jq -r .summary <<<"$assessment")"
        return 1
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

access::recover() {
    local profile=$1 document active assessment
    controls::local_console || return 1
    document=$(profiles::state) || return 1
    jq -e --arg p "$profile" '.profiles[$p]!=null' <<<"$document" >/dev/null || return 1
    active=$(jq -r .active.firewall <<<"$document") || return 1
    assessment=$(access::_assessment "$profile" "$active" "$document") || return 1
    jq -e '.recovery.can_apply==true' <<<"$assessment" >/dev/null || {
        core::die "$(jq -r .summary <<<"$assessment")"
        return 1
    }
    core::log "Review and apply the saved $profile firewall profile. Only its saved permissions are applied; other protection areas are unchanged."
    profiles::apply "$profile" firewall || return 1
    document=$(profiles::state) || return 1
    assessment=$(access::_assessment "$profile" "$profile" "$document") || return 1
    if ! jq -e '.ready==true' <<<"$assessment" >/dev/null; then
        profiles::_result firewall failed 'Firewall recovery did not pass the final native inspection. Review its current state before changing permissions.' || :
        core::die "$(jq -r .summary <<<"$assessment")"
        return 1
    fi
    core::record "ACCESS recover $profile" || return 1
    core::log "The saved $profile firewall profile is verified. Review your requested permission separately when ready."
}

access::restore() {
    local document active profile assessment
    controls::local_console || return 1
    document=$(profiles::state) || return 1
    active=$(jq -r .active.firewall <<<"$document") || return 1
    profile=$(access::default_profile) || return 1
    assessment=$(access::_assessment "$profile" "$active" "$document") || return 1
    jq -e '.recovery.can_restore==true' <<<"$assessment" >/dev/null || {
        core::die "No reviewed firewall restoration is available. $(jq -r .summary <<<"$assessment")"
        return 1
    }
    profiles::restore firewall || return 1
    core::record 'ACCESS restore original firewall' || return 1
    core::log 'The original firewall configuration was restored and verified. Other protection areas and saved profile permissions were retained.'
}

access::_review_file() {
    local file=$1 metadata
    [[ -f $file && ! -L $file ]] || return 1
    metadata=$(stat -c '%u:%a:%h:%s' -- "$file") || return 1
    [[ $metadata =~ ^0:([0-7]{3,4}):1:([0-9]+)$ ]] || return 1
    (((8#${BASH_REMATCH[1]} & 022) == 0 && BASH_REMATCH[2] <= 32768)) || return 1
    if [[ -s $file ]]; then LC_ALL=C grep -Iq . "$file" || return 1; fi
    printf '\nCurrent configuration file: %s\n' "$file"
    cat -- "$file" || return 1
    printf '\n'
}

# Old records contain file fingerprints, not previous file bodies. Show the
# real kernel difference and current configuration without inventing a diff.
access::_reconcile_preview() {
    local saved=$1 current=$2 previous field difference result file count=0 metadata
    previous=$(jq -ce '.observed//.before' <<<"$saved") || return 1
    jq -e --argjson current "$current" 'all([.,$current][]; type=="object" and
        (.config|type=="string" and test("^[a-f0-9]{64}$")) and
        (.status|type=="string" and length<=262144) and
        (.ipv4|type=="string" and length<=4194304) and (.ipv6|type=="string" and length<=4194304))' <<<"$previous" >/dev/null || return 1
    for field in status ipv4 ipv6; do
        result=0
        difference=$(diff -u --label "Recorded $field" --label "Current $field" \
            <(jq -er --arg field "$field" '.[$field] | select(type=="string")' <<<"$previous") \
            <(jq -er --arg field "$field" '.[$field] | select(type=="string")' <<<"$current")) || result=$?
        ((result <= 1)) || return 1
        [[ -z $difference ]] || printf '%s\n' "$difference"
    done
    if [[ $(jq -r .config <<<"$previous") != "$(jq -r .config <<<"$current")" ]]; then
        printf '\nThe on-disk configuration differs from its recorded fingerprint. The previous file contents are not available in that record. Review the current configuration below.\n'
    fi
    printf '\nUFW before/after hooks match supported, package-verified templates. Current configuration file inventory (ownership, mode and SHA-256):\n'
    while IFS= read -r -d '' file; do
        count=$((count + 1))
        ((count <= 64)) || return 1
        [[ -f $file && ! -L $file ]] || return 1
        metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$file") || return 1
        printf '%s %s\n' "$metadata" "$file"
        sha256sum -- "$file" || return 1
    done < <(find "$PROFILE_ETC/ufw" -type f -print0 | sort -z)
    for file in "$PROFILE_ETC/default/ufw" "$PROFILE_ETC/ufw/ufw.conf" "$PROFILE_ETC/ufw/sysctl.conf" \
        "$PROFILE_ETC/ufw/user.rules" "$PROFILE_ETC/ufw/user6.rules"; do
        [[ -e $file || -L $file ]] || continue
        access::_review_file "$file" || return 1
    done
}

access::reconcile() {
    local profile=$1 saved current document reviewed preview updated directory expected
    controls::local_console || return 1
    document=$(profiles::state) || return 1
    jq -e --arg p "$profile" '.profiles[$p]!=null' <<<"$document" >/dev/null || return 1
    saved=$(profile_controls::_read firewall) || {
        core::die 'No safe saved firewall record is available for reconciliation. Inspect the recovery history.'
        return 1
    }
    if ! profile_controls::firewall_baseline_available || ! profile_controls::firewall_reconcile_safe; then
        core::die 'The firewall contains unsupported hooks or unsafe recovery evidence. No native policy or tracking state was changed.'
        return 1
    fi
    current=$(profile_controls::snapshot firewall) || return 1
    expected=$(profile_controls::_hash <<<"$current") || return 1
    if [[ $expected == "$(jq -r .expected <<<"$saved")" ]]; then
        core::log 'Current firewall settings already match the recorded state. Review and apply the selected saved profile, or restore the original firewall settings.'
        return 0
    fi
    preview=$(access::_reconcile_preview "$saved" "$current") || {
        core::die 'The current firewall configuration cannot be fully previewed safely. Inspect it manually before recovery; nothing was changed.'
        return 1
    }
    ((${#preview} <= 65536)) || {
        core::die 'The firewall differences exceed the review limit. Inspect them manually; no tracking state or native rules were changed.'
        return 1
    }
    core::log "Review the current firewall before recovering the selected $profile profile. Non-printing characters in the evidence below are escaped."
    printf '%s\n' "$preview" | LC_ALL=C sed -n l || return 1
    core::log 'Accepting records this current state for conflict checks. It does not change firewall rules, apply a profile, or replace the original recovery baseline. A later Apply replaces UFW exceptions with the selected saved profile; Restore reinstates the original configuration.'
    core::confirm 'Accept this displayed current firewall state as reviewed, keeping recovery pending?' || return 1
    reviewed=$(profile_controls::snapshot firewall) || return 1
    if [[ $reviewed != "$current" || $(profile_controls::_read firewall) != "$saved" || $(profiles::state) != "$document" ]]; then
        core::die 'The firewall or saved profile changed during review. No reconciliation was applied; inspect and review again.'
        return 1
    fi
    profile_controls::firewall_baseline_available && profile_controls::firewall_reconcile_safe || return 1
    directory=$(profile_controls::_directory) || return 1
    core::backup "$directory/firewall.json" || return 1
    core::backup "$CORE_STATE/profiles/state.json" || return 1
    if [[ $(profile_controls::snapshot firewall) != "$current" || $(profile_controls::_read firewall) != "$saved" || $(profiles::state) != "$document" ]]; then
        core::die 'The firewall changed while preparing its recovery record. Nothing was accepted; review again.'
        return 1
    fi
    updated=$(jq -c --arg expected "$expected" --argjson observed "$current" '.expected=$expected|.observed=$observed' <<<"$saved") || return 1
    profile_controls::_write firewall "$updated" || return 1
    if ! profiles::_result firewall pending 'Current firewall settings were accepted after review. Apply a selected saved firewall profile or restore the original settings before changing permissions.'; then
        profile_controls::_write firewall "$saved" || core::die 'Could not restore the previous tracking record after a state-write failure. Inspect the saved transaction.'
        return 1
    fi
    core::record "ACCESS reconcile $profile reviewed native firewall" || return 1
    core::log 'Current firewall state accepted. Native rules and the original baseline are unchanged; review Apply or Restore to finish recovery.'
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
        recover) access::recover "$2" ;;
        restore) access::restore ;;
        reconcile) access::reconcile "$2" ;;
    esac
}
