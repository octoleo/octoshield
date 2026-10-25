#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compare the narrow rule language emitted by OctoShield with the running UFW
# user chains. Neither native output nor persisted policy is evaluated as code.

profile_firewall::_failure() {
    if declare -F core::die >/dev/null; then core::die "$1"; else printf '%s\n' "$1" >&2; fi
    return 1
}

# UFW reports "disabled (routed)" on a nonrouting laptop regardless of its
# configured forward policy. Read the data file without sourcing shell code;
# the kernel policies and input paths are checked independently below.
profile_firewall::defaults() {
    local file=$1
    [[ -f $file && ! -L $file ]] || {
        profile_firewall::_failure 'The UFW defaults file is missing or unsafe.'
        return 1
    }
    awk -F= '
      /^[[:space:]]*(IPV6|DEFAULT_INPUT_POLICY|DEFAULT_OUTPUT_POLICY|DEFAULT_FORWARD_POLICY)[[:space:]]*=/ {
        key=$1; gsub(/[[:space:]]/, "", key)
        expected=(key=="IPV6" ? "yes" : (key=="DEFAULT_OUTPUT_POLICY" ? "ACCEPT" : "DROP"))
        value=$0; sub(/^[^=]*=/, "", value)
        expression="^[[:space:]]*(" expected "|\"" expected "\"|\047" expected "\047)[[:space:]]*(#.*)?$"
        if (++seen[key] != 1 || value !~ expression) invalid=1
      }
      END { exit (invalid || seen["IPV6"]!=1 || seen["DEFAULT_INPUT_POLICY"]!=1 ||
        seen["DEFAULT_OUTPUT_POLICY"]!=1 || seen["DEFAULT_FORWARD_POLICY"]!=1) }
    ' "$file" || {
        profile_firewall::_failure 'UFW must configure IPv6, DROP for incoming and forwarded traffic, and ACCEPT for outgoing traffic.'
        return 1
    }
}

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
    local family=$1 line=$2 mode=${3:-profile} prefix=ufw protocol='' source=any destination=any sport='' dport='' key value index=2
    local -a words=()
    [[ $family == 4 ]] || prefix=ufw6
    case "$line" in
        "-A $prefix-before-input -i lo -j ACCEPT" | \
            "-A $prefix-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" | \
            "-A $prefix-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT") return 0 ;;
    esac
    if [[ $mode == reconcile ]]; then
        case "$line" in
            '-A ufw-before-input -d 224.0.0.251/32 -p udp -m udp --dport 5353 -j ACCEPT' | \
                '-A ufw-before-input -d 239.255.255.250/32 -p udp -m udp --dport 1900 -j ACCEPT' | \
                '-A ufw6-before-input -d ff02::fb/128 -p udp -m udp --dport 5353 -j ACCEPT' | \
                '-A ufw6-before-input -d ff02::f/128 -p udp -m udp --dport 1900 -j ACCEPT') return 0 ;;
        esac
    fi
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

profile_firewall::_input_jump() {
    local prefix=$1 line=$2 chain=${2#-A } target
    chain=${chain%% *}
    [[ $line == *' -j '* && $line != *' -g '* ]] || return 1
    target=${line#*' -j '}
    target=${target%% *}
    # Inspect only UFW's host-input graph. Docker and other forwarding/output
    # chains are outside this operation and must not be rewritten or certified.
    case "$chain:$target" in
        "$prefix-before-input:ACCEPT" | "$prefix-before-input:DROP" | \
            "$prefix-before-input:$prefix-logging-deny" | "$prefix-before-input:$prefix-not-local" | \
            "$prefix-before-input:$prefix-user-input" | \
            "$prefix-not-local:RETURN" | "$prefix-not-local:DROP" | "$prefix-not-local:$prefix-logging-deny" | \
            "$prefix-after-input:$prefix-skip-to-policy-input" | \
            "$prefix-reject-input:REJECT" | "$prefix-track-input:ACCEPT" | \
            "$prefix-skip-to-policy-input:DROP" | "$prefix-skip-to-policy-input:REJECT" | "$prefix-skip-to-policy-input:ACCEPT" | \
            "$prefix-before-logging-input:LOG" | "$prefix-before-logging-input:RETURN" | \
            "$prefix-after-logging-input:LOG" | "$prefix-after-logging-input:RETURN" | \
            "$prefix-user-logging-input:LOG" | "$prefix-user-logging-input:RETURN" | \
            "$prefix-logging-deny:LOG" | "$prefix-logging-deny:RETURN" | \
            "$prefix-logging-allow:LOG" | "$prefix-logging-allow:RETURN" | \
            "$prefix-user-input:ACCEPT" | "$prefix-user-input:DROP" | "$prefix-user-input:REJECT" | \
            "$prefix-user-input:$prefix-user-logging-input" | "$prefix-user-input:$prefix-user-limit" | \
            "$prefix-user-input:$prefix-user-limit-accept" | \
            "$prefix-user-limit:LOG" | "$prefix-user-limit:RETURN" | "$prefix-user-limit:REJECT" | \
            "$prefix-user-limit-accept:ACCEPT") return 0 ;;
        *) return 1 ;;
    esac
}

profile_firewall::_native() {
    local family=$1 output=$2 now=${3:-0} mode=${4:-profile} prefix=ufw line table='' filters=0 input=0 forward=0 outgoing=0 user=0 user_hook=0 input_hook=0 count=0 target chain
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
        if [[ $line == "-A $prefix-"* ]]; then
            chain=${line#-A }
            chain=${chain%% *}
            case "$chain" in
                "$prefix-before-input" | "$prefix-after-input" | "$prefix-before-logging-input" | \
                    "$prefix-after-logging-input" | "$prefix-reject-input" | "$prefix-track-input" | \
                    "$prefix-not-local" | "$prefix-skip-to-policy-input" | "$prefix-user-input" | \
                    "$prefix-user-logging-input" | "$prefix-logging-deny" | "$prefix-logging-allow" | \
                    "$prefix-user-limit" | "$prefix-user-limit-accept")
                    profile_firewall::_input_jump "$prefix" "$line" || {
                        profile_firewall::_failure "IPv$family has an unrecognized UFW input-chain jump. Review native firewall changes."
                        return 1
                    }
                    ;;
            esac
        fi
        case "$line" in
            ':INPUT DROP ['*) input=1 ;;
            ':FORWARD DROP ['*) forward=1 ;;
            ':OUTPUT ACCEPT ['*) outgoing=1 ;;
            ":$prefix-user-input - ["*) user=1 ;;
            "-A $prefix-before-input -j $prefix-user-input") user_hook=$((user_hook + 1)) ;;
            "-A $prefix-before-input"*' -j ACCEPT')
                profile_firewall::_essential_input "$family" "$line" "$mode" || {
                    profile_firewall::_failure "IPv$family has an unexpected UFW before-input allowance."
                    return 1
                }
                ;;
            "-A $prefix-after-input"*' -j ACCEPT' | \
                "-A $prefix-before-logging-input"*' -j ACCEPT' | \
                "-A $prefix-after-logging-input"*' -j ACCEPT' | \
                "-A $prefix-reject-input"*' -j ACCEPT' | \
                "-A $prefix-track-input"*' -j ACCEPT' | \
                "-A $prefix-not-local"*' -j ACCEPT' | \
                "-A $prefix-skip-to-policy-input"*' -j ACCEPT')
                [[ $mode == reconcile ]] || {
                    profile_firewall::_failure "IPv$family has an unexpected allowance outside the reviewed UFW user rules."
                    return 1
                }
                ;;
            "-A $prefix-user-input "*)
                [[ $mode == reconcile ]] || profile_firewall::_rule "$family" "$line" "$now" || {
                    profile_firewall::_failure "IPv$family contains an unsupported or unexpected UFW permission rule."
                    return 1
                }
                count=$((count + 1))
                ((count <= 256)) || return 1
                ;;
            "-A $prefix-user-output "* | "-A $prefix-user-forward "*)
                [[ $mode == reconcile ]] || {
                    profile_firewall::_failure "IPv$family contains UFW outgoing or forwarding exceptions outside the selected host-input profile."
                    return 1
                }
                ;;
            '-A INPUT '*)
                # A direct ACCEPT or jump to another administrator's chain can
                # bypass UFW. Recognize only UFW's ordinary input hooks here.
                target=${line#"-A INPUT -j "}
                case "$target" in
                    "$prefix-before-input") input_hook=$((input_hook + 1)) ;;
                    "$prefix-before-logging-input" | "$prefix-after-input" | "$prefix-after-logging-input" | "$prefix-reject-input" | "$prefix-track-input") ;;
                    *)
                        profile_firewall::_failure "IPv$family INPUT contains a rule outside the recognized UFW hooks."
                        return 1
                        ;;
                esac
                ;;
        esac
    done <<<"$output"
    if [[ $mode != reconcile ]] && ((!input || !forward || !outgoing)); then
        profile_firewall::_failure "IPv$family kernel defaults do not match DROP incoming/forwarded and ACCEPT outgoing."
        return 1
    fi
    ((filters == 1 && user && user_hook == 1 && input_hook == 1)) || {
        profile_firewall::_failure "IPv$family is missing a unique live INPUT-to-UFW-to-user-rule path."
        return 1
    }
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

# With MANAGE_BUILTINS=no, ufw disable intentionally leaves its empty primary
# chains and builtin jumps in place. Prove those exact remnants are inert before
# omitting them from comparisons. Preserve native ACCEPT/DROP defaults; only an
# absent filter table supplies the implicit three ACCEPT policies.
profile_firewall::_inactive() {
    local family=$1 output=$2 format=${3:-native}
    ((${#output} <= 4194304)) || return 1
    awk -v family="$family" -v format="$format" '
      function primary(name, direction, prefix, rest) {
        prefix=(family==4 ? "ufw-" : "ufw6-")
        if (index(name,prefix)!=1) return 0
        rest=substr(name,length(prefix)+1)
        return rest ~ /^(before-logging|before|after|after-logging|reject|track)-(input|output|forward)$/ &&
          (direction=="" || rest ~ ("-" direction "$"))
      }
      BEGIN { table=(format=="snapshot" ? "filter" : "") }
      /^\*/ {table=substr($0,2); if (table=="filter") filters++; next}
      /^COMMIT$/ {table=""; next}
      table=="" && $0 !~ /^[[:space:]]*(#|$)/ {invalid=1; next}
      table!="filter" {next}
      /^:(INPUT|FORWARD|OUTPUT) / {
        if (($2!="ACCEPT" && $2!="DROP") || NF!=3 || ($1 in policies && policies[$1]!=$2)) invalid=1
        policies[$1]=$2; next
      }
      /^:ufw/ {
        name=substr($1,2)
        if (!primary(name,"") || $2!="-" || NF!=3) invalid=1
        declared[name]=1; next
      }
      /^-A ufw/ {invalid=1; next}
      /^-A INPUT / {
        if (NF!=4 || $3!="-j" || !primary($4,"input")) invalid=1
        hooks[$4]++; next
      }
      /^-A (FORWARD|OUTPUT) / {
        if ($0 ~ /ufw6?-/) {
          direction=tolower($2)
          if (NF!=4 || $3!="-j" || !primary($4,direction)) invalid=1
          hooks[$4]++
        }
        next
      }
      /^:/ {if ($2!="-" || NF!=3) invalid=1; next}
      /^-A / || /^#/ || /^[[:space:]]*$/ {next}
      {invalid=1}
      END {
        for (name in hooks) if (!(name in declared) || hooks[name]!=1) invalid=1
        if (filters>1 || invalid) exit 1
        split(":INPUT :FORWARD :OUTPUT", names, " ")
        for (i=1;i<=3;i++) print names[i] " " (names[i] in policies ? policies[names[i]] : "ACCEPT")
      }' <<<"$output" || {
        profile_firewall::_failure "IPv$family is reported inactive but contains nonempty, unknown or unsafe firewall input remnants."
        return 1
    }
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
    profile_firewall::_validate_config "$config" || {
        profile_firewall::_failure 'The selected firewall permission configuration is invalid.'
        return 1
    }
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
    if ! ipv4=$(LC_ALL=C iptables-save) || ! ipv6=$(LC_ALL=C ip6tables-save); then
        profile_firewall::_failure 'The running IPv4 or IPv6 firewall rules could not be read.'
        return 1
    fi
    actual4=$(profile_firewall::_native 4 "$ipv4" "$now") && actual6=$(profile_firewall::_native 6 "$ipv6" "$now") || return 1
    [[ $(printf '%s\n' "$expected" | sed '/^$/d' | LC_ALL=C sort -u) == "$(printf '%s\n%s\n' "$actual4" "$actual6" | sed '/^$/d' | LC_ALL=C sort -u)" ]] || {
        profile_firewall::_failure 'The running UFW permissions differ from the selected ports, sources, interfaces or deadlines.'
        return 1
    }
}
