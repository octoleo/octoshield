#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fixed, reviewed migrations for retired native configuration. Sourcing is inert.
# Reset trusted destinations instead of accepting paths from the environment.
REPAIR_ETC=/etc

repair::ids() { printf '%s\n' legacy-sudo-timeout-v1; }

repair::safe_directory() {
    local metadata
    [[ -d $1 && ! -L $1 ]] || return 1
    metadata=$(stat -c '%u:%a' -- "$1") || return 1
    [[ $metadata =~ ^0:([0-7]{3,4})$ ]] || return 1
    (((8#${BASH_REMATCH[1]} & 022) == 0))
}

repair::safe_file() {
    local metadata
    [[ -f $1 && ! -L $1 ]] || return 1
    metadata=$(stat -c '%u:%a:%h:%s' -- "$1") || return 1
    [[ $metadata =~ ^0:([0-7]{3,4}):1:([0-9]+)$ ]] || return 1
    (((8#${BASH_REMATCH[1]} & 022) == 0 && BASH_REMATCH[2] <= ${2:-1048576}))
}

# Verify every ancestor inside a trusted root before reading private snapshots.
repair::safe_relative_file() {
    local parent=$1 relative=$2 component
    repair::safe_directory "$parent" || return 1
    [[ $relative != /* && $relative != *'/../'* && $relative != ../* ]] || return 1
    while [[ $relative == */* ]]; do
        component=${relative%%/*}
        relative=${relative#*/}
        [[ -n $component && $component != . && $component != .. ]] || return 1
        parent+=/$component
        repair::safe_directory "$parent" || return 1
    done
    [[ -n $relative && $relative != . && $relative != .. ]] || return 1
    repair::safe_file "$parent/$relative" "${3:-1048576}"
}

repair::sudo_generated() {
    cmp -s -- "$1" <(printf '%s\n' \
        '# Managed by Octoshield; passwordless grants still bypass passwords.' \
        'Defaults timestamp_timeout=0')
}

repair::digest() {
    local digest
    digest=$(sha256sum -- "$1") || return 1
    digest=${digest%% *}
    [[ $digest =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

repair::sudo_receipt_matches() {
    local file=$1 receipt="$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" digest
    repair::safe_relative_file "$CORE_STATE" repairs/legacy-sudo-timeout-v1.json 4096 || return 1
    [[ $(stat -c '%a' -- "$receipt") == 600 ]] || return 1
    digest=$(repair::digest "$file") || return 1
    jq -se --arg path "$file" --arg digest "$digest" '
        length == 1 and (.[0] | type == "object" and .schema == 1 and
        .id == "legacy-sudo-timeout-v1" and .action == "restored" and
        .path == $path and .sha256 == $digest)
    ' "$receipt" >/dev/null 2>&1
}

# A receipt never hides a reintroduced generated policy. The passive observer
# recognizes only the restored original file, without scanning transaction logs.
repair::sudo_state() {
    local file="$REPAIR_ETC/sudoers.d/99-octoshield"
    REPAIR_SUDO_STATE=conflict
    REPAIR_SUDO_MESSAGE='The retired sudo policy path is unsafe or unreadable. Review it with an administrator.'
    repair::safe_directory "$REPAIR_ETC" || return 0
    if [[ ! -e $REPAIR_ETC/sudoers.d && ! -L $REPAIR_ETC/sudoers.d ]]; then
        REPAIR_SUDO_STATE=current
        return 0
    fi
    repair::safe_directory "$REPAIR_ETC/sudoers.d" || return 0
    if [[ ! -e $file && ! -L $file ]]; then
        REPAIR_SUDO_STATE=current
    elif repair::safe_file "$file"; then
        if repair::sudo_generated "$file"; then
            REPAIR_SUDO_STATE=pending
        elif repair::sudo_receipt_matches "$file"; then
            REPAIR_SUDO_STATE=current
        else
            REPAIR_SUDO_MESSAGE='The retired sudo policy file has administrator changes or unrecognized contents. Repair preserves it; review the recovery instructions.'
        fi
    fi
}

repair::status() {
    local state summary
    repair::sudo_state || return 1
    case "$REPAIR_SUDO_STATE" in
        current) state=active summary='No known retired OctoShield settings need repair.' ;;
        pending) state=partial summary='A retired OctoShield sudo timeout policy is still installed. Review Repair system to remove it or restore the earlier configuration.' ;;
        *) state=unknown summary=$REPAIR_SUDO_MESSAGE ;;
    esac
    jq -cn --arg state "$state" --arg summary "$summary" '{state:$state,summary:$summary}'
}

# Walk the latest activation backwards. Repeated Activate saved the generated
# policy; a genuine preimage or absence ends that activation's original chain.
repair::sudo_plan() {
    local file="$REPAIR_ETC/sudoers.d/99-octoshield" listing id transaction marker original log log_result selected_stamp='' digest
    REPAIR_PLAN_ACTION=remove
    REPAIR_PLAN_SOURCE=
    REPAIR_PLAN_BASELINE=
    REPAIR_PLAN_SOURCE_HASH=
    REPAIR_PLAN_CURRENT_HASH=$(repair::digest "$file") || return 1
    repair::safe_directory "$CORE_STATE/backups" || {
        core::die 'The private recovery directory is unsafe; no sudo policy was changed.'
        return 1
    }
    listing=$(find "$CORE_STATE/backups" -mindepth 1 -maxdepth 1 -printf '%f\n') || return 1
    listing=$(LC_ALL=C sort -t- -k1,1r -k2,2nr <<<"$listing") || return 1
    while IFS= read -r id; do
        [[ ${#id} -le 40 && $id =~ ^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$ ]] || continue
        if [[ -n $selected_stamp && ${id%-*} != "$selected_stamp" ]]; then return 0; fi
        [[ $id != "$CORE_TRANSACTION" ]] || continue
        transaction="$CORE_STATE/backups/$id"
        marker="$transaction/saved$file"
        [[ -e $marker || -L $marker ]] || continue
        log="$transaction/actions.log"
        repair::safe_relative_file "$CORE_STATE/backups" "$id/actions.log" || {
            core::die "Unsafe or missing recovery history for transaction $id; no sudo policy was changed."
            return 1
        }
        log_result=0
        grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z BEGIN (GUI )?apply sudo$' "$log" || log_result=$?
        case "$log_result" in
            0) ;;
            1) continue ;;
            *)
                core::die "Cannot read recovery history for transaction $id."
                return 1
                ;;
        esac
        repair::safe_relative_file "$transaction" "saved$file" 16 || {
            core::die "Unsafe sudo recovery marker in transaction $id; no sudo policy was changed."
            return 1
        }
        original="$transaction/original$file"
        if cmp -s -- "$marker" <(printf 'absent\n'); then
            if [[ -e $original || -L $original ]]; then
                core::die "Conflicting sudo recovery evidence in transaction $id; no sudo policy was changed."
                return 1
            fi
            if [[ -n $selected_stamp && $REPAIR_PLAN_ACTION != remove ]]; then
                core::die 'Different original sudo policies were recorded in the same second. Review the recovery history manually; no policy was changed.'
                return 1
            fi
            selected_stamp=${id%-*}
            REPAIR_PLAN_BASELINE=$id
            continue
        fi
        if ! cmp -s -- "$marker" <(printf 'existing\n') ||
            ! repair::safe_relative_file "$transaction" "original$file"; then
            core::die "Missing, invalid or unsafe original sudo policy in transaction $id; no sudo policy was changed."
            return 1
        fi
        repair::sudo_generated "$original" && continue
        digest=$(repair::digest "$original") || return 1
        if [[ -n $selected_stamp ]]; then
            if [[ $REPAIR_PLAN_ACTION != restore || $REPAIR_PLAN_SOURCE_HASH != "$digest" ]]; then
                core::die 'Different original sudo policies were recorded in the same second. Review the recovery history manually; no policy was changed.'
                return 1
            fi
            continue
        fi
        selected_stamp=${id%-*}
        REPAIR_PLAN_ACTION=restore
        REPAIR_PLAN_SOURCE=$original
        REPAIR_PLAN_BASELINE=$id
        REPAIR_PLAN_SOURCE_HASH=$digest
    done <<<"$listing"
}

repair::restore_file() {
    local source=$1 destination=$2 mode
    repair::safe_file "$source" || return 1
    mode=$(stat -c '%a' -- "$source") || return 1
    core::write_file "$destination" "$mode" <"$source" || return 1
    chown --reference="$source" -- "$destination" || return 1
    cmp -s -- "$source" "$destination"
}

repair::sudo_rollback() {
    local saved=$1 expected=${2-} file="$REPAIR_ETC/sudoers.d/99-octoshield" actual
    if ! repair::safe_relative_file "$CORE_STATE/backups" "$CORE_TRANSACTION/original$file" ||
        ! repair::sudo_generated "$saved"; then
        core::die 'The saved pre-repair sudo policy changed or is unsafe. It was not restored.'
        return 1
    fi
    repair::safe_directory "$REPAIR_ETC" && repair::safe_directory "$REPAIR_ETC/sudoers.d" || return 1
    if [[ -e $file || -L $file ]]; then
        repair::safe_file "$file" || return 1
        actual=$(repair::digest "$file") || return 1
        if ! repair::sudo_generated "$file" && [[ -z $expected || $actual != "$expected" ]]; then
            core::die 'The sudo policy changed outside this repair. It was preserved; use the saved transaction for administrator recovery.'
            return 1
        fi
    fi
    repair::restore_file "$saved" "$file" || return 1
    core::record 'REPAIR legacy-sudo-timeout-v1 rolled-back' || return 1
    core::log 'The pre-repair sudo policy was restored. The repair did not complete.'
    visudo --check
}

repair::sudo_timeout() {
    local file="$REPAIR_ETC/sudoers.d/99-octoshield" action source baseline current_hash source_hash saved receipt candidate preview result=0
    repair::sudo_state || return 1
    case "$REPAIR_SUDO_STATE" in
        current)
            core::log 'Sudo policy: no retired OctoShield setting needs repair.'
            core::record 'REPAIR legacy-sudo-timeout-v1 already-current'
            return $?
            ;;
        conflict)
            core::die "$REPAIR_SUDO_MESSAGE Path: $file"
            return 1
            ;;
    esac
    command -v visudo >/dev/null 2>&1 || {
        core::die 'Install or repair the system sudo package before running this repair.'
        return 1
    }
    visudo --check || return 1
    repair::sudo_plan || return 1
    action=$REPAIR_PLAN_ACTION source=$REPAIR_PLAN_SOURCE baseline=$REPAIR_PLAN_BASELINE
    current_hash=$REPAIR_PLAN_CURRENT_HASH source_hash=$REPAIR_PLAN_SOURCE_HASH
    # Review and publish the same verified private copy. Historical snapshots
    # remain administrator-owned files and may change while repair is open.
    if [[ $action == restore ]]; then
        candidate=$(mktemp "$CORE_STATE/backups/$CORE_TRANSACTION/.repair-sudo.XXXXXXXX") || return 1
        if ! cp -p -- "$source" "$candidate" || ! repair::safe_file "$candidate" ||
            [[ $(repair::digest "$candidate") != "$source_hash" ]]; then
            core::die 'The original sudo policy changed while preparing recovery. No sudo policy was changed.'
            return 1
        fi
        visudo --check --file "$candidate" || return 1
        preview=$(diff -u --label 'Current retired sudo policy' --label "Original policy from $baseline" -- "$file" "$candidate") || result=$?
        if ((result > 1)) || ((${#preview} > 16384)); then
            core::die 'The original sudo policy could not be previewed within the review limit. Use the manual recovery instructions.'
            return 1
        fi
        result=0
    fi
    core::log 'Repair available: remove the retired Fresh administrator authentication setting.'
    if [[ $action == restore ]]; then
        core::log "Restore $file from its original configuration in transaction $baseline."
        core::log 'The restored administrator configuration will determine sudo authentication; it can contain its own timeout or grants.'
        core::log 'Review the exact policy difference below; non-printing characters are escaped.'
        printf '%s\n' "$preview" | LC_ALL=C sed -n l || return 1
    else
        core::log "Remove only the unchanged generated file $file."
        if [[ -n $baseline ]]; then
            core::log "Transaction $baseline records that this file was originally absent."
        else
            core::log 'No pre-activation snapshot is available. The generated setting can be removed, but any overwritten earlier file cannot be reconstructed.'
        fi
        core::log 'The remaining system and administrator sudo policies will apply; no replacement timeout will be installed.'
    fi
    core::log 'A private recovery copy will be saved and the complete sudoers configuration will be checked.'
    core::confirm 'Apply this sudo repair?' || return 1
    repair::sudo_state || return 1
    if [[ $REPAIR_SUDO_STATE != pending ]] || ! repair::sudo_plan ||
        [[ $action != "$REPAIR_PLAN_ACTION" || $source != "$REPAIR_PLAN_SOURCE" ||
            $baseline != "$REPAIR_PLAN_BASELINE" || $current_hash != "$REPAIR_PLAN_CURRENT_HASH" ||
            $source_hash != "$REPAIR_PLAN_SOURCE_HASH" ]]; then
        core::die 'The sudo policy or its recovery evidence changed during review. No repair was applied; review again.'
        return 1
    fi
    visudo --check || return 1
    core::private_directory "$CORE_STATE/repairs" || {
        core::die 'The private repair record directory is unsafe.'
        return 1
    }
    receipt="$CORE_STATE/repairs/legacy-sudo-timeout-v1.json"
    if [[ -e $receipt || -L $receipt ]]; then
        repair::safe_file "$receipt" 4096 || {
            core::die 'The existing repair record is unsafe; no sudo policy was changed.'
            return 1
        }
    fi
    core::backup "$file" || return 1
    saved="$CORE_STATE/backups/$CORE_TRANSACTION/original$file"
    if ! repair::safe_relative_file "$CORE_STATE/backups" "$CORE_TRANSACTION/original$file" ||
        ! repair::sudo_generated "$saved"; then
        core::die 'The private pre-repair copy could not be verified. No sudo policy was changed.'
        return 1
    fi
    core::record "REPAIR legacy-sudo-timeout-v1 begin $action $file" || return 1
    repair::sudo_state || return 1
    if [[ $REPAIR_SUDO_STATE != pending || $(repair::digest "$file") != "$current_hash" ]]; then
        core::die 'The live sudo policy changed while preparing recovery. No repair was applied.'
        return 1
    fi
    if [[ $action == restore ]]; then
        repair::restore_file "$candidate" "$file" || result=1
    else
        rm -- "$file" && core::record "REMOVE $file" || result=1
    fi
    if ((result == 0)); then visudo --check || result=1; fi
    if ((result == 0)); then
        if [[ $action == restore ]]; then
            repair::safe_file "$file" && [[ $(repair::digest "$file") == "$source_hash" ]] || result=1
        elif [[ -e $file || -L $file ]]; then result=1; fi
    fi
    if ((result == 0)); then
        local record outcome=removed
        [[ $action != restore ]] || outcome=restored
        record=$(jq -cn --arg path "$file" --arg action "$outcome" --arg digest "$source_hash" --arg transaction "$CORE_TRANSACTION" \
            '{schema:1,id:"legacy-sudo-timeout-v1",path:$path,action:$action,sha256:$digest,transaction:$transaction}') || result=1
        if ((result == 0)); then core::write_file "$receipt" 0600 <<<"$record" || result=1; fi
        if ((result == 0)); then core::record "REPAIR legacy-sudo-timeout-v1 complete $outcome" || result=1; fi
    fi
    if ((result != 0)); then
        if ! repair::sudo_rollback "$saved" "$source_hash"; then
            core::die "Automatic recovery could not be fully verified. Keep administrator access and review transaction $CORE_TRANSACTION."
        fi
        return 1
    fi
    core::log 'Sudo repair completed and the full configuration passed validation. Existing system and administrator authentication rules now apply.'
}

repair::run() {
    local id result=0
    core::require_root || return 1
    [[ -n $CORE_TRANSACTION ]] || {
        core::die 'System repair requires a locked change transaction.'
        return 1
    }
    core::log 'Inspecting known retired OctoShield settings. Each available repair is reviewed before it changes the system.'
    while IFS= read -r id; do
        case "$id" in
            legacy-sudo-timeout-v1) repair::sudo_timeout || result=1 ;;
            *) core::die 'Unknown system repair migration.' || result=1 ;;
        esac
    done < <(repair::ids)
    if ((result == 0)); then core::log 'System repair finished. No known retired OctoShield settings remain pending.'; fi
    return "$result"
}
