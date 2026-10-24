#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2030,SC2031,SC2317,SC2329
setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/diagnostics.sh"
    STATUS_ETC="$BATS_TEST_TMPDIR/etc"
    STATUS_PROC="$BATS_TEST_TMPDIR/proc"
    mkdir -p "$STATUS_ETC/sysctl.d" "$STATUS_PROC/sys/net/ipv4" "$STATUS_PROC/sys/net/ipv6/conf/all"
    printf '1\n' >"$STATUS_PROC/sys/net/ipv4/ip_forward"
    printf '0\n' >"$STATUS_PROC/sys/net/ipv6/conf/all/forwarding"
    CONTAINER_ID=$(printf '%064d' 1)
    NETWORK_ID=$(printf '%064d' 2)
}

docker_fixture() {
    jq -cn --arg id "$CONTAINER_ID" --arg network "$NETWORK_ID" --arg host "${1:-127.0.0.1}" --arg version "${2:-29.0.0}" \
        '{version:$version,containers:[{id:$id,name:"/web",mode:"bridge",ports:{"80/tcp":[{HostIp:$host,HostPort:"8080"}]},project:"demo",service:"web",files:"/home/developer/project/compose.yaml",networks:[$network]}],networks:[{id:$network,driver:"bridge",options:{}}]}'
}

@test 'diagnostics accept only fixed read topics' {
    diagnostics::validate show containers
    diagnostics::validate show disk_encryption
    run diagnostics::validate show /etc/shadow
    [ "$status" -ne 0 ]
    run diagnostics::validate show containers extra
    [ "$status" -ne 0 ]
    run diagnostics::validate delete containers
    [ "$status" -ne 0 ]
    run diagnostics::mutates show containers
    [ "$status" -ne 0 ]
}

@test 'localhost IPv4 and IPv6 are distinct from broad bindings' {
    for address in 127.0.0.1 127.0.1.2 ::1; do
        run status::docker_summary <<<"$(docker_fixture "$address")"
        [ "$status" -eq 0 ]
        jq -e '.state=="active" and (.summary|contains("localhost"))' <<<"$output"
    done
    for address in 0.0.0.0 :: 192.0.2.10; do
        run status::docker_summary <<<"$(docker_fixture "$address")"
        [ "$status" -eq 0 ]
        jq -e '.state=="partial" and (.summary|contains("not proven"))' <<<"$output"
    done
}

@test 'localhost on old Docker or unusual routing remains unverified' {
    run status::docker_summary <<<"$(docker_fixture 127.0.0.1 27.5.0)"
    jq -e '.state=="unknown" and (.summary|contains("before 28"))' <<<"$output"
    run status::docker_summary <<<"$(docker_fixture | jq '.networks[0].options["com.docker.network.bridge.gateway_mode_ipv6"]="routed"')"
    jq -e '.state=="unknown"' <<<"$output"
    run status::docker_summary <<<"$(docker_fixture | jq '.networks=[]')"
    jq -e '.state=="unknown"' <<<"$output"
}

@test 'one broad mapping is not hidden among localhost mappings' {
    run status::docker_summary <<<"$(docker_fixture | jq '.containers[0].ports["443/tcp"]=[{HostIp:"::",HostPort:"8443"}]')"
    jq -e '.state=="partial"' <<<"$output"
}

@test 'host networking is not hidden by an empty published-port list' {
    run status::docker_summary <<<"$(docker_fixture | jq '.containers[0].mode="host" | .containers[0].ports={}')"
    jq -e '.state=="unknown" and (.summary|contains("host-network"))' <<<"$output"
}

@test 'no host mappings is a scoped positive observation' {
    run status::docker_summary <<<"$(docker_fixture | jq '.containers[0].ports={"80/tcp":null}')"
    jq -e '.state=="active" and (.summary|contains("No host ports"))' <<<"$output"
}

@test 'private Docker findings include source and a bounded reviewable local-only action' {
    status::docker_snapshot() { docker_fixture 0.0.0.0; }
    run diagnostics::containers
    [ "$status" -eq 0 ]
    jq -e --arg id "$CONTAINER_ID" '.kind=="diagnostics" and .topic=="containers" and .findings[0].container_id==$id and .findings[0].fix=="localize" and (.findings[0].source|contains("compose.yaml"))' <<<"$output"
    run status::containers
    [ "$status" -eq 0 ]
    [[ $output != *'/home/developer'* && $output != *'compose.yaml'* && $output != *"$CONTAINER_ID"* ]]
}

@test 'unavailable Docker offers no guessed source or repair target' {
    status::docker_snapshot() { return 124; }
    run diagnostics::containers
    [ "$status" -eq 0 ]
    jq -e '.findings[0].state=="unknown" and .findings[0].container_id==null and (.findings[0].detail|contains("never start"))' <<<"$output"
}

@test 'Docker snapshot uses one bounded inspect and rejects malformed native data' {
    status::_docker_ready() { return 0; }
    status::run() {
        printf '%s\n' "$*" >>"$BATS_TEST_TMPDIR/probes"
        case "$*" in
            *' ps '*) printf '%s\n' "$CONTAINER_ID" ;;
            *' network inspect '*) docker_fixture | jq -c '.networks[0]' ;;
            *' inspect '*) docker_fixture | jq -c --arg network "$NETWORK_ID" '.containers[0] | .networks={"bridge":{NetworkID:$network}}' ;;
            *' version '*) printf '29.0.0\n' ;;
            *) return 1 ;;
        esac
    }
    run status::docker_snapshot
    [ "$status" -eq 0 ]
    jq -e '.version=="29.0.0" and (.containers|length)==1 and (.networks|length)==1' <<<"$output"
    [ "$(grep -c 'inspect --type container' "$BATS_TEST_TMPDIR/probes")" -eq 1 ]
    status::run() {
        case "$*" in *' ps '*) printf '%s\n' "$CONTAINER_ID" ;; *' inspect '*) printf '{"id":"invalid"}\n' ;; *) return 1 ;; esac
    }
    run status::docker_snapshot
    [ "$status" -ne 0 ]
}

@test 'Docker inspection timeout cannot become a positive empty inventory' {
    status::_docker_ready() { return 0; }
    status::run() { return 124; }
    run status::containers
    [ "$status" -eq 0 ]
    jq -e '.state=="unknown"' <<<"$output"
}

@test 'disk ancestry follows encryption through LVM and strips subvolume suffix' {
    status::run() {
        case "$1" in
            findmnt) printf '/dev/mapper/root[/@]\n' ;;
            lsblk)
                [[ ${*: -1} == /dev/mapper/root ]] || return 2
                printf '%s\n' '{"blockdevices":[{"name":"root","type":"lvm","children":[{"name":"luks","type":"crypt","children":[{"name":"disk","type":"disk"}]}]}]}'
                ;;
            *) return 1 ;;
        esac
    }
    run status::disk_encryption
    [ "$status" -eq 0 ]
    jq -e '.state=="active" and .source==null' <<<"$output"
}

@test 'a mixed encrypted and plain backing path is not certified encrypted' {
    status::run() {
        case "$1" in
            findmnt) printf '/dev/mapper/root\n' ;;
            lsblk) printf '%s\n' '{"blockdevices":[{"name":"root","type":"lvm","children":[{"name":"luks","type":"crypt"},{"name":"plain","type":"part"}]}]}' ;;
        esac
    }
    run status::disk_encryption
    jq -e '.state=="partial" and (.summary|contains("mixed"))' <<<"$output"
}

@test 'plain topology and unavailable probes stay unknown rather than unencrypted' {
    status::run() {
        case "$1" in findmnt) printf '/dev/sda1\n' ;; lsblk) printf '{"blockdevices":[{"name":"sda1","type":"part"}]}\n' ;; esac
    }
    run status::disk_encryption
    jq -e '.state=="unknown"' <<<"$output"
    status::run() { return 124; }
    run status::disk_encryption
    jq -e '.state=="unknown"' <<<"$output"
    status::run() { printf '{"unexpected":[]}\n'; }
    run status::disk_encryption
    jq -e '.state=="unknown"' <<<"$output"
}

@test 'storage details keep separate home and swap findings' {
    status::storage_probe() {
        if [[ $1 == / ]]; then
            printf '{"state":"active","summary":"Encrypted root","source":"/dev/mapper/root"}\n'
        else printf '{"state":"unknown","summary":"Home not verified","source":"/dev/sdb1"}\n'; fi
    }
    status::run() { printf '{"swapdevices":[{"name":"/dev/sdc1","type":"partition"}]}\n'; }
    run diagnostics::disk_encryption
    jq -e '.findings[0].state=="active" and .findings[1].state=="unknown" and .findings[3].source=="/dev/sdc1"' <<<"$output"
}

@test 'forwarding capability is informational with source evidence rather than a vulnerability' {
    printf 'net.ipv4.ip_forward=1\nSECRET=hidden\n' >"$STATUS_ETC/sysctl.d/90-router.conf"
    status::run() { return 1; }
    run status::forwarding
    jq -e '.state=="unknown" and (.summary|contains("not an exposure"))' <<<"$output"
    run diagnostics::forwarding
    [ "$status" -eq 0 ]
    jq -e 'any(.findings[]; (.source|endswith("90-router.conf"))) and all(.findings[]; .state=="unknown")' <<<"$output"
    [[ $output != *'SECRET'* && $output != *'hidden'* ]]
}

@test 'diagnostic response strips controls and caps encoded byte size explicitly' {
    local findings
    findings=$(jq -cn '[range(0;100) | {title:"\u202eUnsafe title",state:"unknown",detail:("😀"*800),source:("x"*1000),action:("x"*1000)}]')
    run diagnostics::_document containers 'Title' 'Summary' "$findings"
    [ "$status" -eq 0 ]
    [ "$(printf %s "$output" | wc -c)" -le 24000 ]
    jq -e '.truncated and (.findings|length)>0 and all(.findings[]; (.title|contains("\u202e")|not))' <<<"$output"
}
