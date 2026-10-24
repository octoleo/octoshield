#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2317,SC2329,SC2030,SC2031

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/containers.sh"
    containers::_require_user() { :; }
    containers::_daemon_running() { :; }
    containers::_daemon_policy() { printf 'verified-defaults\n'; }
    core::confirm() { :; }
    PROJECT="$BATS_TEST_TMPDIR/project"
    mkdir -m 0700 "$PROJECT"
    printf 'services: {}\n' >"$PROJECT/compose.yaml"
    chmod 0600 "$PROJECT/compose.yaml"
    ID=$(printf 'a%.0s' {1..64})
    NEXT_ID=$(printf 'e%.0s' {1..64})
    NETWORK_ID=$(printf 'b%.0s' {1..64})
    HASH=$(printf 'c%.0s' {1..64})
    IMAGE="sha256:$(printf 'd%.0s' {1..64})"
    jq -cn '{name:"app",services:{web:{image:"example/web:latest",environment:{PRIVATE:"secret-value"},volumes:[{type:"volume",source:"data",target:"/data"}],ports:[{target:80,published:"8080",protocol:"tcp",mode:"ingress"}],networks:{default:{}}}},networks:{default:{name:"app_default"}},volumes:{data:{name:"app_data"}}}' >"$BATS_TEST_TMPDIR/config.json"
    jq -cn --arg id "$ID" --arg image "$IMAGE" --arg network "$NETWORK_ID" --arg directory "$PROJECT" --arg hash "$HASH" '[{Id:$id,Name:"/app-web-1",Image:$image,State:{Running:true,StartedAt:"2026-10-24T00:00:00Z",Health:{Log:[]}},RestartCount:0,Config:{Env:["PRIVATE=secret-value"],Labels:{"com.docker.compose.project":"app","com.docker.compose.service":"web","com.docker.compose.project.working_dir":$directory,"com.docker.compose.project.config_files":($directory+"/compose.yaml"),"com.docker.compose.config-hash":$hash}},HostConfig:{NetworkMode:"app_default"},Mounts:[{Type:"volume",Name:"app_data",Destination:"/data"}],NetworkSettings:{Networks:{app_default:{NetworkID:$network,Aliases:["app-web-1","web"]}},Ports:{"80/tcp":[{HostIp:"0.0.0.0",HostPort:"8080"},{HostIp:"::",HostPort:"8080"}]}}}]' >"$BATS_TEST_TMPDIR/inspect.json"
    printf '%s\n' '[{"Driver":"bridge","Options":{}}]' >"$BATS_TEST_TMPDIR/network.json"
    containers::_docker() {
        case "$*" in
            'version --format {{.Server.Version}}') printf '28.5.0\n' ;;
            'compose version --short') printf '2.30.0\n' ;;
            "inspect --type container $ID") cat "$BATS_TEST_TMPDIR/inspect.json" ;;
            "inspect --type container $NEXT_ID")
                jq --arg id "$NEXT_ID" '.[0].Id=$id | .[0].NetworkSettings.Ports["80/tcp"]=[{HostIp:"127.0.0.1",HostPort:"8080"},{HostIp:"::1",HostPort:"8080"}]' "$BATS_TEST_TMPDIR/inspect.json"
                ;;
            "network inspect $NETWORK_ID") cat "$BATS_TEST_TMPDIR/network.json" ;;
            *)
                printf 'Unexpected Docker command: %s\n' "$*" >&2
                return 1
                ;;
        esac
    }
    containers::_compose() {
        local context=$1 source
        shift
        source=$(jq -r '.sources[0]' <<<"$context")
        case "$*" in
            'ps --all --quiet web') printf '%s\n' "$ID" ;;
            'config --format json')
                if [[ $source == "$PROJECT/.octoshield/"* && $source == *.json ]]; then
                    cat "$source"
                else cat "$BATS_TEST_TMPDIR/config.json"; fi
                ;;
            'config --hash web') printf 'web %s\n' "$HASH" ;;
            -f*' config --format json')
                jq --argjson ports "$(jq .ports <<<"$context")" --arg drift "${MERGE_DRIFT:-false}" '.services.web.ports=$ports | if $drift=="true" then .services.web.environment.PRIVATE="different" else . end' "$BATS_TEST_TMPDIR/config.json"
                ;;
            -f*' ps --all --quiet web') printf '%s\n' "$NEXT_ID" ;;
            *)
                printf 'Unexpected Compose command: %s\n' "$*" >&2
                return 1
                ;;
        esac
    }
    containers::_up() { printf 'web\n' >"$BATS_TEST_TMPDIR/recreated"; }
}

@test 'container actions accept only full identities and review tokens' {
    run containers::validate plan "$ID"
    [ "$status" -eq 0 ]
    run containers::validate localize "$ID" "$HASH"
    [ "$status" -eq 0 ]
    run containers::validate localize "$ID" '--privileged'
    [ "$status" -ne 0 ]
    run containers::validate plan '--all'
    [ "$status" -ne 0 ]
}

@test 'plans contain actual sources and localhost mappings without private environment values' {
    run containers::plan "$ID"
    [ "$status" -eq 0 ]
    jq -e --arg file "$PROJECT/compose.yaml" '.kind=="container-plan" and (.token|test("^[a-f0-9]{64}$")) and .sources==[$file] and ([.ports[].host_ip]|sort)==["127.0.0.1","::1"] and (.warning|contains("original files"))' <<<"$output"
    [[ $output != *secret-value* ]]
    [[ $output != *PRIVATE* ]]
    [ ! -e "$PROJECT/.octoshield" ]
}

@test 'Compose source drift prevents a repair plan' {
    HASH=$(printf 'f%.0s' {1..64})
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'does not match the running service'* ]]
    [ ! -e "$BATS_TEST_TMPDIR/recreated" ]
}

@test 'runtime network changes are refused before recreation' {
    jq --arg network "$NETWORK_ID" '.[0].NetworkSettings.Networks.extra={NetworkID:$network}' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
    mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'network attachments that differ'* ]]
}

@test 'routed bridge modes do not claim localhost isolation' {
    printf '%s\n' '[{"Driver":"bridge","Options":{"com.docker.network.bridge.gateway_mode_ipv6":"routed"}}]' >"$BATS_TEST_TMPDIR/network.json"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'direct routing or a nonstandard driver'* ]]
}

@test 'linked Compose source files are not followed' {
    mv "$PROJECT/compose.yaml" "$PROJECT/real.yaml"
    ln -s real.yaml "$PROJECT/compose.yaml"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'without symbolic links'* ]]
}

@test 'shared-writable Compose sources are refused' {
    chmod 0666 "$PROJECT/compose.yaml"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
}

@test 'cancelling a reviewed repair creates no override and recreates nothing' {
    plan=$(containers::plan "$ID")
    core::confirm() { return 1; }
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [ ! -e "$PROJECT/.octoshield" ]
    [ ! -e "$BATS_TEST_TMPDIR/recreated" ]
}

@test 'a stale review token refuses before any project write' {
    plan=$(containers::plan "$ID")
    printf '# new source edit\n' >>"$PROJECT/compose.yaml"
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'changed after review'* ]]
    [ ! -e "$PROJECT/.octoshield" ]
}

@test 'configuration changes while confirmation is open are refused' {
    plan=$(containers::plan "$ID")
    core::confirm() { printf '# changed\n' >>"$PROJECT/compose.yaml"; }
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'changed while confirmation was open'* ]]
    [ ! -e "$PROJECT/.octoshield" ]
}

@test 'a successful repair writes a narrow override and verifies the recreated service' {
    plan=$(containers::plan "$ID")
    original=$(sha256sum "$PROJECT/compose.yaml")
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -eq 0 ]
    jq -e '.kind=="container-result" and (.command|contains("--no-deps --no-build --pull never"))' <<<"$output"
    [ "$(cat "$BATS_TEST_TMPDIR/recreated")" = web ]
    [ "$(sha256sum "$PROJECT/compose.yaml")" = "$original" ]
    [ "$(stat -c %a "$PROJECT/.octoshield/web.local.yaml")" = 600 ]
    [ "$(stat -c %a "$PROJECT/.octoshield/web.reviewed.json")" = 600 ]
    jq -e --arg image "$IMAGE" '.services.web.image==$image' "$PROJECT/.octoshield/web.reviewed.json"
    [[ $(cat "$PROJECT/.octoshield/web.local.yaml") == *'ports: !override'* ]]
    [[ $(cat "$PROJECT/.octoshield/web.local.yaml") == *'127.0.0.1'* ]]
    [[ $(cat "$PROJECT/.octoshield/web.local.yaml") != *'image:'* ]]
    [[ $(cat "$PROJECT/.octoshield/web.local.yaml") != *secret-value* ]]
}

@test 'an existing override is never overwritten' {
    mkdir -m 0700 "$PROJECT/.octoshield"
    printf 'existing\n' >"$PROJECT/.octoshield/web.local.yaml"
    plan=$(containers::plan "$ID")
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [ "$(cat "$PROJECT/.octoshield/web.local.yaml")" = existing ]
    [ ! -e "$BATS_TEST_TMPDIR/recreated" ]
}

@test 'failed recreation retains the restrictive override without reopening ports' {
    plan=$(containers::plan "$ID")
    containers::_up() { return 1; }
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'will not automatically reopen'* ]]
    [[ $output != *'container-result'* ]]
    [ -f "$PROJECT/.octoshield/web.local.yaml" ]
}

@test 'unrelated merged model changes are refused before recreation' {
    plan=$(containers::plan "$ID")
    MERGE_DRIFT=true
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'contains other changes'* ]]
    [ ! -e "$BATS_TEST_TMPDIR/recreated" ]
    [ ! -e "$PROJECT/.octoshield/web.local.yaml" ]
}

@test 'version floors cover Docker localhost and Compose override support' {
    run containers::_version_at_least 27.9.9 28 0 0
    [ "$status" -ne 0 ]
    run containers::_version_at_least 28.0.0 28 0 0
    [ "$status" -eq 0 ]
    run containers::_version_at_least v2.24.3 2 24 4
    [ "$status" -ne 0 ]
    run containers::_version_at_least v2.24.4 2 24 4
    [ "$status" -eq 0 ]
}

@test 'disabled Docker firewall configuration is not mistaken for an omitted default' {
    run containers::_daemon_config_safe <<<'{}'
    [ "$status" -eq 0 ]
    run containers::_daemon_config_safe <<<'{"iptables":false}'
    [ "$status" -ne 0 ]
    run containers::_daemon_config_safe <<<'{"ip6tables":false}'
    [ "$status" -ne 0 ]
    run containers::_daemon_config_safe <<<'{"allow-direct-routing":true}'
    [ "$status" -ne 0 ]
}

@test 'resolved snapshot protects literal dollar values from a second interpolation' {
    jq '.services.web.environment.PRIVATE="$$VALUE and $${VALUE} and $$$$"' "$BATS_TEST_TMPDIR/config.json" >"$BATS_TEST_TMPDIR/new.json"
    mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/config.json"
    plan=$(containers::plan "$ID")
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -eq 0 ]
    jq -e '.services.web.environment.PRIVATE=="$$VALUE and $${VALUE} and $$$$"' "$PROJECT/.octoshield/web.reviewed.json"
    [[ $output != *'VALUE'* ]]
}

@test 'a recreated container with changed mounts is never reported successful' {
    plan=$(containers::plan "$ID")
    containers::_up() {
        jq '.[0].Mounts[0].Name="different-volume"' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
        mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    }
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'does not match its reviewed'* ]]
    [ -f "$PROJECT/.octoshield/web.local.yaml" ]
    [[ $output != *container-result* ]]
}

@test 'a recreated service with changed environment is never reported successful' {
    plan=$(containers::plan "$ID")
    containers::_up() {
        jq '.[0].Config.Env=["PRIVATE=changed"]' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
        mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    }
    run containers::localize "$ID" "$(jq -r .token <<<"$plan")"
    [ "$status" -ne 0 ]
    [[ $output == *'does not match its reviewed'* ]]
    [ -f "$PROJECT/.octoshield/web.local.yaml" ]
    [[ $output != *container-result* ]]
}

@test 'docker update resource changes are not silently reset by recreation' {
    jq '.[0].HostConfig.Memory=1073741824' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
    mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'will not reset runtime limits'* ]]
    [ ! -e "$BATS_TEST_TMPDIR/recreated" ]
}

@test 'docker update restart drift is refused even when Compose hash matches' {
    jq '.[0].HostConfig.RestartPolicy={Name:"always",MaximumRetryCount:0}' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
    mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'restart policy differs'* ]]
}

@test 'manually attached network aliases are not discarded by a port repair' {
    jq '.[0].NetworkSettings.Networks.app_default.Aliases += ["manual"]' "$BATS_TEST_TMPDIR/inspect.json" >"$BATS_TEST_TMPDIR/new.json"
    mv "$BATS_TEST_TMPDIR/new.json" "$BATS_TEST_TMPDIR/inspect.json"
    run containers::plan "$ID"
    [ "$status" -ne 0 ]
    [[ $output == *'network aliases differ'* ]]
}

@test 'real Compose renderer preserves dollar literals mounts and replaces ports' {
    [[ -n ${OCTOSHIELD_TEST_COMPOSE:-} && -x $OCTOSHIELD_TEST_COMPOSE ]] || skip 'Set OCTOSHIELD_TEST_COMPOSE to a Compose plugin executable for daemon-free rendering validation.'
    mkdir "$PROJECT/data"
    cat >"$PROJECT/compose.yaml" <<'YAML'
services:
  web:
    image: example/web:latest
    command: ["sh", "-c", "printf '$$VALUE'"]
    environment:
      LITERAL: '$$VALUE and $${VALUE} and $$$$'
    volumes:
      - ./data:/data
    ports:
      - '8080:80'
      - '[::]:8443:443'
YAML
    before=$("$OCTOSHIELD_TEST_COMPOSE" --project-name app --project-directory "$PROJECT" -f "$PROJECT/compose.yaml" config --format json)
    context=$(jq -cn --argjson config "$before" --arg image "$IMAGE" '{service:"web",image:$image,ports:[$config.services.web.ports[] | .host_ip=(if (.host_ip//""|contains(":")) then "::1" else "127.0.0.1" end)]}')
    containers::_write_override "$context" "$PROJECT/local.yaml"
    merged=$("$OCTOSHIELD_TEST_COMPOSE" --project-name app --project-directory "$PROJECT" -f "$PROJECT/compose.yaml" -f "$PROJECT/local.yaml" config --format json)
    jq -e --argjson before "$before" --argjson ports "$(jq .ports <<<"$context")" '(.services.web.ports==$ports) and (del(.services.web.image,.services.web.ports)==($before|del(.services.web.image,.services.web.ports)))' <<<"$merged"
    merged=$(jq -c --arg image "$IMAGE" '.services.web.image=$image' <<<"$merged")
    printf '%s\n' "$merged" >"$PROJECT/reviewed.json"
    checked=$("$OCTOSHIELD_TEST_COMPOSE" --project-name app --project-directory "$PROJECT" -f "$PROJECT/reviewed.json" -f "$PROJECT/local.yaml" config --format json)
    [ "$(jq -cS . <<<"$merged")" = "$(jq -cS . <<<"$checked")" ]
    original_hash=$("$OCTOSHIELD_TEST_COMPOSE" --project-name app --project-directory "$PROJECT" -f "$PROJECT/compose.yaml" config --hash web)
    resolved_hash=$("$OCTOSHIELD_TEST_COMPOSE" --project-name app --project-directory "$PROJECT" -f - config --hash web <<<"$before")
    [ "$original_hash" = "$resolved_hash" ]
}
