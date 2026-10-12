#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compare the narrow rule language emitted by OctoShield with the running UFW
# user chains. Neither native output nor persisted policy is evaluated as code.

profile_firewall::_network() {
    local family=$1 source=$2 address prefix part value=0 index bits number
    local left right missing tail suffix
    local -a octets=() groups=() leading=() trailing=()
    if [[ $source == any ]]; then
        if [[ $family == 4 ]]; then printf '4:00000000/0\n'; else printf '6:00000000000000000000000000000000/0\n'; fi
        return
    fi
    # ip6tables-save may render the final 32 bits of an IPv4-mapped address in
    # dotted notation even when the configured source used hexadecimal groups.
    if [[ $family == 6 && $source == *:*.* ]]; then
        address=${source%/*}
        tail=${address##*:}
        profiles::valid_source "$tail" || return 1
        [[ $tail != */* && $tail != *:* ]] || return 1
        IFS=. read -r -a octets <<<"$tail"
        printf -v suffix '%x:%x' "$(((10#${octets[0]} << 8) | 10#${octets[1]}))" "$(((10#${octets[2]} << 8) | 10#${octets[3]}))"
        source="${address%:*}:$suffix${source#"$address"}"
    fi
    profiles::valid_source "$source" || return 1
    address=${source%/*}
    if [[ $family == 4 ]]; then
        [[ $address != *:* ]] || return 1
        prefix=32
        [[ $source != */* ]] || prefix=$((10#${source##*/}))
        IFS=. read -r -a octets <<<"$address"
        for part in "${octets[@]}"; do value=$(((value << 8) | 10#$part)); done
        if ((prefix == 0)); then value=0; else value=$((value & ((0xffffffff << (32 - prefix)) & 0xffffffff))); fi
        printf '4:%08x/%d\n' "$value" "$prefix"
    elif [[ $family == 6 ]]; then
        [[ $address == *:* ]] || return 1
        prefix=128
        [[ $source != */* ]] || prefix=$((10#${source##*/}))
        if [[ $address == *::* ]]; then
            left=${address%%::*} right=${address#*::}
            [[ -z $left ]] || IFS=: read -r -a leading <<<"$left"
            [[ -z $right ]] || IFS=: read -r -a trailing <<<"$right"
            missing=$((8 - ${#leading[@]} - ${#trailing[@]}))
            groups=("${leading[@]}")
            for ((index = 0; index < missing; index++)); do groups+=(0); done
            groups+=("${trailing[@]}")
        else IFS=: read -r -a groups <<<"$address"; fi
        ((${#groups[@]} == 8)) || return 1
        printf '6:'
        bits=$prefix
        for part in "${groups[@]}"; do
            number=$((16#$part))
            if ((bits <= 0)); then
                number=0
            elif ((bits < 16)); then number=$((number & ((0xffff << (16 - bits)) & 0xffff))); fi
            printf '%04x' "$number"
            bits=$((bits - 16))
        done
        printf '/%d\n' "$prefix"
    else return 1; fi
}

profile_firewall::_rule() {
    local family=$1 line=$2 protocol='' port='' source=any interface=any module='' jump='' destination=''
    local now=${3:-0} key value index=2 source_seen=0 interface_seen=0 destination_seen=0 canonical any time_module=0 stop='' expires=0
    local -a words=()
    IFS=' ' read -r -a words <<<"$line"
    # All accepted operands are single lexical tokens. Quoting, negation,
    # selectors, multiports, extra matches and additional targets fail closed.
    while ((index < ${#words[@]})); do
        key=${words[index]}
        index=$((index + 1))
        ((index < ${#words[@]})) || return 1
        value=${words[index]}
        index=$((index + 1))
        case "$key" in
            -s)
                ((source_seen == 0)) || return 1
                source=$value
                source_seen=1
                ;;
            -i)
                ((interface_seen == 0)) || return 1
                interface=$value
                interface_seen=1
                ;;
            -d)
                ((destination_seen == 0)) || return 1
                destination=$value
                destination_seen=1
                ;;
            -p)
                [[ -z $protocol && ($value == tcp || $value == udp) ]] || return 1
                protocol=$value
                ;;
            -m)
                if [[ $value == time ]]; then
                    ((time_module == 0)) || return 1
                    time_module=1
                else
                    [[ -z $module && ($value == tcp || $value == udp) ]] || return 1
                    module=$value
                fi
                ;;
            --datestop)
                [[ -z $stop && $value =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] || return 1
                stop=$value
                ;;
            --dport)
                [[ -z $port ]] && profiles::valid_port "$value" || return 1
                port=$value
                ;;
            -j)
                [[ -z $jump && $value == ACCEPT ]] || return 1
                jump=$value
                ;;
            *) return 1 ;;
        esac
    done
    [[ -n $protocol && -n $port && $jump == ACCEPT && (-z $module || $module == "$protocol") ]] || return 1
    profiles::valid_interface "$interface" || return 1
    canonical=$(profile_firewall::_network "$family" "$source") || return 1
    if [[ -n $destination ]]; then
        any=$(profile_firewall::_network "$family" any) || return 1
        [[ $(profile_firewall::_network "$family" "$destination") == "$any" ]] || return 1
    fi
    if ((time_module)); then
        [[ -n $stop ]] || return 1
        expires=$(date -u --date="$stop" +%s 2>/dev/null) || return 1
        ((expires >= 0 && expires < 2147483647)) || return 1
        [[ $(date -u --date="@$expires" +%Y-%m-%dT%H:%M:%S) == "$stop" ]] || return 1
        expires=$((expires + 1))
    else [[ -z $stop ]] || return 1; fi
    # A remaining expired rule grants no new traffic: the kernel time matcher
    # has already stopped matching even if userspace housekeeping is paused.
    ((expires == 0 || expires > now)) || return 0
    printf '%s|%s|%s|%s|%s|%s\n' "$family" "$protocol" "$port" "$canonical" "$interface" "$expires"
}

profile_firewall::_essential_input() {
    local family=$1 line=$2 prefix=ufw protocol='' source=any destination=any sport='' dport='' key value index=2
    local -a words=()
    [[ $family == 4 ]] || prefix=ufw6
    case "$line" in
        "-A $prefix-before-input -i lo -j ACCEPT" | \
            "-A $prefix-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" | \
            "-A $prefix-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") return 0 ;;
    esac
    IFS=' ' read -r -a words <<<"$line"
    while ((index < ${#words[@]})); do
        key=${words[index]}
        index=$((index + 1))
        ((index < ${#words[@]})) || return 1
        value=${words[index]}
        index=$((index + 1))
        case "$key" in
            -p)
                [[ -z $protocol ]] || return 1
                protocol=$value
                ;;
            -s)
                [[ $source == any ]] || return 1
                source=$value
                ;;
            -d)
                [[ $destination == any ]] || return 1
                destination=$value
                ;;
            --sport)
                [[ -z $sport ]] || return 1
                sport=$value
                ;;
            --dport)
                [[ -z $dport ]] || return 1
                dport=$value
                ;;
            -j) [[ $value == ACCEPT ]] || return 1 ;;
            -m) case "$value" in udp | icmp | icmp6 | ipv6-icmp | hl) ;; *) return 1 ;; esac ;;
            --icmp-type | --icmpv6-type | --hl-eq) ;;
            *) return 1 ;;
        esac
    done
    # ICMP/IPv6 neighbour discovery is not a listening TCP/UDP service. Keeping
    # the vendor control-message policy avoids breaking IPv6 and path MTU.
    if [[ $family == 4 && $protocol == icmp || $family == 6 && ($protocol == ipv6-icmp || $protocol == icmpv6) ]]; then
        [[ -z $sport && -z $dport ]]
    elif [[ $protocol == udp ]]; then
        if [[ $family == 4 ]]; then
            [[ $sport == 67 && $dport == 68 && $source == any && $destination == any ]]
        else
            [[ $sport == 547 && $dport == 546 ]] &&
                [[ $(profile_firewall::_network 6 "$source") == 6:fe800000000000000000000000000000/10 &&
                $(profile_firewall::_network 6 "$destination") == 6:fe800000000000000000000000000000/10 ]]
        fi
    else return 1; fi
}

profile_firewall::_native() {
    local family=$1 output=$2 now=${3:-0} prefix=ufw line table='' filters=0 input=0 forward=0 outgoing=0 user=0 user_hook=0 count=0 target
    [[ $family == 4 ]] || prefix=ufw6
    ((${#output} <= 4194304)) || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ ${#line} -le 16384 ]] || return 1
        case "$line" in
            \**)
                table=${line#\*}
                [[ $table != filter ]] || filters=$((filters + 1))
                continue
                ;;
            COMMIT)
                table=''
                continue
                ;;
        esac
        [[ $table == filter ]] || continue
        case "$line" in
            ':INPUT DROP ['*) input=1 ;;
            ':FORWARD DROP ['*) forward=1 ;;
            ':OUTPUT ACCEPT ['*) outgoing=1 ;;
            ":$prefix-user-input - ["*) user=1 ;;
            "-A $prefix-before-input -j $prefix-user-input") user_hook=1 ;;
            "-A $prefix-before-input"*' -j ACCEPT') profile_firewall::_essential_input "$family" "$line" || return 1 ;;
            "-A $prefix-after-input"*' -j ACCEPT' | \
                "-A $prefix-before-logging-input"*' -j ACCEPT' | \
                "-A $prefix-after-logging-input"*' -j ACCEPT' | \
                "-A $prefix-reject-input"*' -j ACCEPT' | \
                "-A $prefix-track-input"*' -j ACCEPT' | \
                "-A $prefix-not-local"*' -j ACCEPT' | \
                "-A $prefix-skip-to-policy-input"*' -j ACCEPT') return 1 ;;
            "-A $prefix-user-input "*)
                profile_firewall::_rule "$family" "$line" "$now" || return 1
                count=$((count + 1))
                ((count <= 256)) || return 1
                ;;
            "-A $prefix-user-output "* | "-A $prefix-user-forward "*) return 1 ;;
            '-A INPUT '*)
                # A direct ACCEPT or jump to another administrator's chain can
                # bypass UFW. Recognize only UFW's ordinary input hooks here.
                target=${line#"-A INPUT -j "}
                case "$target" in
                    "$prefix-before-logging-input" | "$prefix-before-input" | "$prefix-after-input" | "$prefix-after-logging-input" | "$prefix-reject-input" | "$prefix-track-input") ;;
                    *) return 1 ;;
                esac
                ;;
        esac
    done <<<"$output"
    ((filters == 1 && input && forward && outgoing && user && user_hook))
}

profile_firewall::_validate_config() {
    local config=$1 port source interface
    ((${#config} <= 1048576)) || return 1
    jq -e 'type == "object" and (.rules | type == "array" and length <= 256) and
        all(.rules[]; (.port|type=="number" and floor==. and .>=1 and .<=65535) and
        (.protocol=="tcp" or .protocol=="udp") and (.source|type=="string" and length<=64) and
        (.interface|type=="string" and length<=15) and
        (.expires_at|type=="number" and floor==. and .>=0 and .<=2147483647))' <<<"$config" >/dev/null || return 1
    while IFS=$'\t' read -r port source interface; do
        [[ -n $port ]] || continue
        profiles::valid_port "$port" && profiles::valid_source "$source" && profiles::valid_interface "$interface" || return 1
    done < <(jq -r '.rules[] | [.port,.source,.interface]|@tsv' <<<"$config")
}

# Finite grants never enter UFW's persistent rule files. Rebooting or reloading
# UFW therefore removes them even if the userspace expiry collector is absent.
# The kernel's UTC time match also ends new incoming permission at the deadline
# when the collector is stopped or the application has been uninstalled.
# The caller owns the operation lock and has just reloaded the permanent policy.
profile_firewall::temporary_apply() {
    local config=$1 port protocol source interface expires stop now family chain executable failed=0
    local -a args=()
    profile_firewall::_validate_config "$config" || return 1
    now=$(date +%s) || return 1
    while IFS=$'\t' read -r port protocol source interface expires; do
        [[ -n $port ]] || continue
        ((expires > now)) || continue
        # xt_time's stop is inclusive; subtract one second from our exclusive
        # deadline. Never use --kerneltz or fall back to an unbounded allowance.
        if ! stop=$(date -u --date="@$((expires - 1))" +%Y-%m-%dT%H:%M:%S); then
            failed=1
            break
        fi
        for family in 4 6; do
            if [[ $source != any ]]; then
                [[ $family != 4 || $source != *:* ]] || continue
                [[ $family != 6 || $source == *:* ]] || continue
            fi
            if [[ $family == 4 ]]; then
                executable=iptables
                chain=ufw-user-input
            else
                executable=ip6tables
                chain=ufw6-user-input
            fi
            args=(-w 5 -A "$chain")
            [[ $source == any ]] || args+=(-s "$source")
            [[ $interface == any ]] || args+=(-i "$interface")
            args+=(-p "$protocol" --dport "$port" -m time --datestop "$stop" -j ACCEPT)
            if ! "$executable" "${args[@]}"; then
                failed=1
                break 2
            fi
        done
    done < <(jq -r '.rules[] | [.port,.protocol,.source,.interface,.expires_at]|@tsv' <<<"$config")
    if ((failed)); then
        # Narrow back to permanent grants if one address family failed. Never
        # leave a successful first-family addition looking like a full success.
        if ! LC_ALL=C ufw reload; then
            printf 'OctoShield: temporary firewall rollback failed; inspect the active firewall immediately.\n' >&2
        fi
        return 1
    fi
}

profile_firewall::verify() {
    local config=$1 ipv4 ipv6 expected='' actual4 actual6 port protocol source interface expires now family network
    profile_firewall::_validate_config "$config" || return 1
    now=$(date +%s) || return 1
    while IFS=$'\t' read -r port protocol source interface expires; do
        [[ -n $port ]] || continue
        profiles::valid_port "$port" && profiles::valid_source "$source" && profiles::valid_interface "$interface" || return 1
        ((expires == 0 || expires > now)) || continue
        for family in 4 6; do
            if [[ $source != any ]]; then
                [[ $family != 4 || $source != *:* ]] || continue
                [[ $family != 6 || $source == *:* ]] || continue
            fi
            network=$(profile_firewall::_network "$family" "$source") || return 1
            expected+="$family|$protocol|$port|$network|$interface|$expires"$'\n'
        done
    done < <(jq -r '.rules[] | [.port,.protocol,.source,.interface,.expires_at]|@tsv' <<<"$config")
    ipv4=$(LC_ALL=C iptables-save) && ipv6=$(LC_ALL=C ip6tables-save) || return 1
    actual4=$(profile_firewall::_native 4 "$ipv4" "$now") && actual6=$(profile_firewall::_native 6 "$ipv6" "$now") || return 1
    [[ $(printf '%s\n' "$expected" | sed '/^$/d' | LC_ALL=C sort -u) == "$(printf '%s\n%s\n' "$actual4" "$actual6" | sed '/^$/d' | LC_ALL=C sort -u)" ]]
}
