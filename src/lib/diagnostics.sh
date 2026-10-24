#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Authenticated evidence. Never publish these paths, addresses or names in the
# public status cache. Read-only probes share the status deadline.

diagnostics::validate() {
    [[ $# -eq 2 && $1 == show ]] || return 1
    case "$2" in disk_encryption | containers | forwarding | network) return 0 ;; *) return 1 ;; esac
}

diagnostics::mutates() { return 1; }

diagnostics::_finding() {
    jq -cn --arg title "$1" --arg state "$2" --arg detail "$3" --arg source "${4-}" --arg action "${5-}" \
        '{title:$title,state:$state,detail:$detail,source:$source,action:$action}'
}

diagnostics::_document() {
    local topic=$1 title=$2 summary=$3 findings=$4 document LC_ALL=C
    document=$(jq -c --arg topic "$topic" --arg title "$title" --arg summary "$summary" '
        def clean($size): tostring | gsub("[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f]"; " ") | .[0:$size];
        . as $findings |
        {kind:"diagnostics",topic:$topic,title:$title,summary:$summary,
         truncated:($findings|length > 20),
         findings:[$findings[:20][] | {title:(.title|clean(100)),state:.state,
             detail:(.detail|clean(480)),source:(.source|clean(300)),action:(.action|clean(480))}
             + (if (.container_id? | type)=="string" and (.container_id | test("^[a-f0-9]{64}$")) then {container_id:.container_id,fix:(.fix//"")} else {} end)]}' <<<"$findings") || return 1
    # Bound bytes, not Unicode characters, leaving room for protocol escaping.
    while ((${#document} > 24000)); do
        document=$(jq -c '.truncated=true | .findings=.findings[:-1]' <<<"$document") || return 1
    done
    printf '%s\n' "$document"
}

diagnostics::_storage_finding() {
    local target=$1 observed source state detail backing
    observed=$(status::storage_probe "$target") || observed='{"state":"unknown","summary":"Storage inspection failed."}'
    source=$(jq -r '.source//"Source unavailable"' <<<"$observed") || return 1
    state=$(jq -r '.state//"unknown"' <<<"$observed") || return 1
    detail=$(jq -r '.summary//"Unable to verify this storage."' <<<"$observed") || return 1
    backing=$(jq -r '[.backing[:8][]? | .name+" ("+.type+")"] | join(" → ")' <<<"$observed") || return 1
    [[ -z $backing ]] || detail="Observed ancestry: $backing. $detail"
    diagnostics::_finding "$target" "$state" "$detail" "$source" 'Review the mount and its backing-device chain. OctoShield does not convert, repartition or encrypt existing storage.'
}

diagnostics::disk_encryption() {
    local findings='[]' item target swaps name type observed source state detail
    for target in / /home; do
        item=$(diagnostics::_storage_finding "$target") || return 1
        findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
    done
    item=$(diagnostics::_finding 'Boot and other storage' unknown 'Boot/EFI partitions, additional disks, filesystem-native encryption and multi-device filesystem coverage need separate review. A boot password is not used as proof by this inspection.' '/boot; /boot/efi; /etc/crypttab; /etc/fstab' 'Check each mounted data volume. Keep the verified root result separate from unchecked coverage.') || return 1
    findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
    if swaps=$(status::run swapon --show --json --output NAME,TYPE) && jq -e '.swapdevices|type=="array"' <<<"$swaps" >/dev/null; then
        while IFS=$'\t' read -r name type; do
            [[ -n $name ]] || continue
            if [[ $type == file && $name == /* ]]; then
                observed=$(status::storage_probe "$name") || observed='{}'
            elif [[ $name == /dev/* ]]; then
                observed=$(status::storage_source_probe "$name") || observed='{}'
            else
                observed='{}'
            fi
            source=$(jq -r --arg name "$name" '.source//$name' <<<"$observed") || return 1
            state=$(jq -r '.state//"unknown"' <<<"$observed") || return 1
            detail=$(jq -r '.summary//"Swap backing storage could not be verified. The root result does not certify this device."' <<<"$observed") || return 1
            item=$(diagnostics::_finding 'Active swap' "$state" "$detail" "$source" 'Review swap and hibernation together before changing either. This inspection changes neither.') || return 1
            findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
        done < <(jq -r '.swapdevices[:12][] | [.name,.type] | @tsv' <<<"$swaps")
        if [[ $(jq '.swapdevices|length' <<<"$swaps") == 0 ]]; then
            item=$(diagnostics::_finding 'Swap' active 'No active swap devices were reported.' '' '') || return 1
            findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
        fi
    else
        item=$(diagnostics::_finding 'Swap' unknown 'Active swap could not be inspected.' '/etc/fstab; /etc/crypttab' 'Check the storage tools and permissions, then refresh this inspection.') || return 1
        findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
    fi
    diagnostics::_document disk_encryption 'Storage encryption evidence' 'Confirmed encryption and unchecked storage are shown separately. These checks do not change any disk.' "$findings"
}

diagnostics::containers() {
    local snapshot findings summary
    if ! snapshot=$(status::docker_snapshot); then
        findings=$(diagnostics::_finding 'System Docker inspection unavailable' unknown 'Only an already running local system Docker daemon is inspected. Passive checks never start Docker. Rootless Docker, other runtimes and virtual machines require their own inspection.' '/run/docker.sock; docker.service' 'Verify that your intended daemon is running and the Docker client is installed, then refresh. A missing inspection is not evidence of exposure.' | jq -sc .) || return 1
        diagnostics::_document containers 'Docker published ports' 'The system Docker inspection is unavailable.' "$findings"
        return
    fi
    summary=$(status::docker_summary <<<"$snapshot" | jq -r .summary) || return 1
    findings=$(jq -c '
        def loopback: . == "::1" or test("^127\\.([0-9]{1,3}\\.){2}[0-9]{1,3}$");
        def source($c): if $c.files != "" then "Compose files reported by Docker: " + $c.files + "; service: " + $c.service
            else "No Compose source was reported. Container: " + $c.id end;
        [ .containers[] as $c |
            if $c.mode == "host" then
                {title:($c.name|ltrimstr("/")),state:"unknown",detail:"Host networking uses host sockets directly; it has no isolated published-port boundary.",source:source($c),action:"Inspect the application listen address. Bind to loopback where supported, or use a reviewed bridge-network configuration. Do not disable host forwarding."}
            elif ([$c.ports[]?[]?]|length)==0 then
                {title:($c.name|ltrimstr("/")),state:"active",detail:"No host port mappings were reported. Other containers on the same network may still reach its services; direct routing is not certified.",source:source($c),action:"No published-port change is required. Review network mode and routing if stronger isolation is needed."}
            else $c.ports | to_entries[] as $port | ($port.value//[])[] as $binding |
                ($binding.HostIp//"") as $host |
                {title:(($c.name|ltrimstr("/")) + " · " + $binding.HostPort + " → " + $port.key),
                 container_id:$c.id,fix:(if ($host|loopback) then "" else "localize" end),
                 state:(if ($host|loopback) then "active" else "partial" end),
                 detail:("Binding: " + (if $host=="" then "all interfaces" else $host end) + ":" + $binding.HostPort + ". " +
                    (if ($host|loopback) then "Published on localhost. Direct-routing paths and old Docker versions still need review."
                    elif ($host=="0.0.0.0" or $host=="::" or $host=="") then "Published on all interfaces in this address family. External reachability also depends on routing and filtering."
                    else "Published on a specific address. This does not authenticate the network or enforce a source-subnet restriction." end)),
                 source:source($c),
                 action:(if ($host|loopback) then "Retain this binding for local development and review the engine/network findings."
                    elif $c.service!="" and $c.files!="" then
                       "Review local-only access for Compose service " + $c.service + ". Bind every effective published port to loopback, validate all overrides, then recreate only that service. A short interruption is required; retain volumes and outbound networking."
                    else "Recreate through the original launcher with explicit loopback publish addresses, retaining volumes and other settings. No source file was established, so OctoShield will not guess one." end)} end
        ] + [{title:("Docker Engine " + .version),state:(if (((.version|split(".")[0]|tonumber?)//0)>=28) then "active" else "unknown" end),
              detail:"Versions before 28 can allow nearby hosts to reach localhost-published ports. Rootless daemons, other runtimes and virtual machines are outside this inspection.",source:"Local Docker daemon version",action:"Use a supported current Docker Engine before relying on localhost publishing. No daemon upgrade or restart is performed here."}]
          + [.networks[] | {title:("Container network " + .id[0:12]),state:(if .driver=="bridge" and ((.options["com.docker.network.bridge.gateway_mode_ipv4"]//"nat")=="nat") and ((.options["com.docker.network.bridge.gateway_mode_ipv6"]//"nat")=="nat") and ((.options["com.docker.network.bridge.trusted_host_interfaces"]//"")=="") then "active" else "unknown" end),detail:("Driver: " + .driver + ". Options: " + (.options|tojson)),source:"Docker network inspect",action:"Review direct routing and gateway settings. Preserve Docker NAT, outbound connectivity and required forwarding. Do not turn Docker firewall management off."}]
          + [{title:"Discovery and incoming access",state:"unknown",detail:"Stopping discovery broadcasts does not close a listening port. Normal UFW host rules may not filter Docker forwarded traffic.",source:"Docker networks; service discovery configuration",action:"Use local bindings for local development. LAN sharing needs a separately verified forwarding policy; a UFW host allowance does not establish Docker protection."}]
        ' <<<"$snapshot") || return 1
    diagnostics::_document containers 'Docker published ports and sources' "$summary" "$findings"
}

diagnostics::forwarding() {
    local findings='[]' item ipv4=unknown ipv6=unknown links rules path line count=0
    [[ ! -r $STATUS_PROC/sys/net/ipv4/ip_forward ]] || read -r ipv4 <"$STATUS_PROC/sys/net/ipv4/ip_forward"
    [[ ! -r $STATUS_PROC/sys/net/ipv6/conf/all/forwarding ]] || read -r ipv6 <"$STATUS_PROC/sys/net/ipv6/conf/all/forwarding"
    item=$(diagnostics::_finding 'Kernel forwarding' unknown "IPv4: $ipv4; IPv6: $ipv6. Forwarding is normal for Docker and many virtual-machine networks; it does not establish an unwanted open path." '/proc/sys/net/ipv4/ip_forward; /proc/sys/net/ipv6/conf/all/forwarding' 'Review the runtime and packet-filtering policy. Do not disable forwarding merely to clear an indicator.') || return 1
    findings=$(jq -cn --argjson item "$item" '[$item]') || return 1
    if links=$(status::run ip -json -details link show) && jq -e 'type=="array"' <<<"$links" >/dev/null; then
        item=$(diagnostics::_finding 'Network interfaces' unknown "$(jq -r '[.[:20][] | .ifname + " (" + (.linkinfo.info_kind//.link_type//"unknown") + ")"] | join(", ")' <<<"$links")" 'Live kernel network interfaces' 'Bridges, virtual Ethernet and tunnels identify paths to inspect. Their existence alone is not a vulnerability.') || return 1
        findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
    fi
    # Only the relevant settings are read. Never display full configuration files.
    for path in "$STATUS_ETC/sysctl.conf" "$STATUS_ETC"/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do
        [[ -f $path && ! -L $path && -r $path ]] || continue
        line=$(awk '/^[[:space:]]*(-?net[.\/]ipv4[.\/]ip_forward|-?net[.\/]ipv6[.\/]conf[.\/]all[.\/]forwarding)[[:space:]]*=/ {print NR ": " $0}' "$path" | head -c 400) || continue
        [[ -n $line ]] || continue
        item=$(diagnostics::_finding 'Persistent forwarding setting' unknown "$line" "$path" 'A contributor, not proof that this file set the current value. Precedence and runtime changes still apply; review before editing.') || return 1
        findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
        count=$((count + 1))
        ((count < 10)) || break
    done
    if rules=$(status::run nft list ruleset); then
        item=$(diagnostics::_finding 'nftables forwarding structure' unknown "$(awk '/hook forward|policy (drop|accept)|chain (FORWARD|DOCKER-USER)/ {print}' <<<"$rules" | head -c 450)" 'Live nftables ruleset' 'Chain declarations are evidence, not complete reachability proof. Identify the actual Docker firewall backend before restricting it.') || return 1
    elif rules=$(status::run iptables -S FORWARD); then
        item=$(diagnostics::_finding 'IPv4 forwarding policy' unknown "${rules:0:450}" 'Live iptables FORWARD chain' 'Check IPv6 and other chains separately. Preserve established connections and container outbound traffic when restricting ingress.') || return 1
    else
        item=$(diagnostics::_finding 'Forwarding filters' unknown 'The active forwarding rules could not be inspected.' 'nftables / iptables' 'Check the active firewall inspection client and permissions, then refresh. Do not assume the path is blocked or exposed.') || return 1
    fi
    findings=$(jq -cn --argjson existing "$findings" --argjson item "$item" '$existing+[$item]') || return 1
    diagnostics::_document forwarding 'Forwarding paths and configuration' 'Exposure depends on interfaces, routes and filtering. The current forwarding value does not identify the process that set it.' "$findings"
}

diagnostics::network() {
    local findings
    findings=$(diagnostics::_finding 'Connection privacy' unknown 'Saved NetworkManager settings and the active connection are distinct. Some privacy changes require reconnecting; DNS discovery also depends on the resolver backend.' "$STATUS_ETC/NetworkManager/conf.d/90-octoshield.conf; $STATUS_ETC/NetworkManager/system-connections" 'Open Connection privacy to select a named connection, review its settings and reconnect explicitly when needed. Discovery and incoming service access are separate choices.' | jq -sc .) || return 1
    diagnostics::_document network 'Connection privacy configuration' 'Use the connection controls to inspect saved and active settings without entering a UUID.' "$findings"
}

diagnostics::dispatch() {
    diagnostics::validate "$@" || return 2
    core::require_root || return 1
    "diagnostics::$2"
}
