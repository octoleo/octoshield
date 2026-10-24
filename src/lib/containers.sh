#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Deliberately unprivileged. Compose sources never run through the root helper.

containers::validate() {
    case "${1-}" in
        plan) [[ $# -eq 2 && $2 =~ ^[a-f0-9]{64}$ ]] ;;
        localize) [[ $# -eq 3 && $2 =~ ^[a-f0-9]{64}$ && $3 =~ ^[a-f0-9]{64}$ ]] ;;
        *) return 1 ;;
    esac
}

containers::_require_user() {
    if ((EUID == 0)) || [[ -n ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]]; then
        core::die 'Open this action as your normal local desktop user. OctoShield never executes project Compose files as root.'
        return 1
    fi
}

containers::_docker() {
    core::timeout --foreground --kill-after=2s 30s env -u DOCKER_CONTEXT -u DOCKER_HOST \
        DOCKER_CONFIG=/var/empty LC_ALL=C docker --host=unix:///run/docker.sock "$@"
}

containers::_daemon_running() {
    [[ $(status::unit docker.service) == active && -S /run/docker.sock ]] || {
        core::die 'Start Docker deliberately before reviewing its containers. This inspection does not activate a stopped Docker service.'
        return 1
    }
}

containers::_daemon_config_safe() {
    jq -e 'type == "object" and (."allow-direct-routing" // false) == false and ((has("iptables")|not) or .iptables == true) and ((has("ip6tables")|not) or .ip6tables == true) and (."ip-forward-no-drop" // false) == false' >/dev/null
}

containers::_daemon_policy() {
    local pid argument config='{}' digest
    local -a arguments
    pid=$(status::run systemctl show --property=MainPID --value docker.service) || return 1
    [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]] || {
        core::die 'Docker daemon startup options could not be checked. Review direct routing and firewall options before treating localhost bindings as isolated.'
        return 1
    }
    mapfile -d '' -t arguments <"/proc/$pid/cmdline" || return 1
    [[ ${#arguments[@]} -gt 0 && ${arguments[0]##*/} == dockerd ]] || {
        core::die 'Docker uses an unrecognized service wrapper. Review its effective daemon configuration before automatic local-only repair.'
        return 1
    }
    for argument in "${arguments[@]}"; do
        case "$argument" in
            --config-file* | --allow-direct-routing* | --iptables* | --ip6tables* | --ip-forward-no-drop*)
                core::die 'Docker has custom routing, firewall or configuration-file startup options. Review those options before restricting published host bindings.'
                return 1
                ;;
        esac
    done
    if [[ -e /etc/docker/daemon.json || -L /etc/docker/daemon.json ]]; then
        [[ -f /etc/docker/daemon.json && ! -L /etc/docker/daemon.json && -r /etc/docker/daemon.json && $(stat -c %s /etc/docker/daemon.json) -le 65536 ]] || return 1
        config=$(cat /etc/docker/daemon.json) || return 1
        containers::_daemon_config_safe <<<"$config" || {
            core::die 'Review /etc/docker/daemon.json: direct routing or disabled Docker filtering can expose container addresses independently of published host bindings.'
            return 1
        }
    fi
    digest=$({
        printf '%s\n' "${arguments[@]}"
        jq -cS . <<<"$config"
    } | sha256sum) || return 1
    printf '%s\n' "${digest%% *}"
}

containers::_version_at_least() {
    local value=${1#v} major=$2 minor=$3 patch=$4
    [[ $value =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-+].*)?$ ]] || return 1
    ((10#${BASH_REMATCH[1]} > major || (\
    10#${BASH_REMATCH[1]} == major && 10#${BASH_REMATCH[2]} > minor) || (\
    10#${BASH_REMATCH[1]} == major && 10#${BASH_REMATCH[2]} == minor && 10#${BASH_REMATCH[3]} >= patch)))
}

# Labels are discovery hints. Refuse links, shared-writable sources, excessive
# sizes and paths whose ancestors another account can replace.
containers::_safe_path() {
    local path=$1 canonical current owner mode
    [[ $path == /* && ${#path} -le 512 && ! $path =~ [[:cntrl:]] ]] || return 1
    canonical=$(realpath -e -- "$path") || return 1
    [[ $canonical == "$path" ]] || return 1
    current=$path
    while [[ $current != / ]]; do
        [[ ! -L $current ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$current") || return 1
        [[ $owner == "$EUID" || $owner == 0 ]] || return 1
        [[ $mode =~ ^[0-7]{3,4}$ ]] || return 1
        if (((8#$mode & 022) != 0)); then
            [[ $owner == 0 && -d $current ]] && (((8#$mode & 01000) != 0)) || return 1
        fi
        current=${current%/*}
        [[ -n $current ]] || current=/
    done
}

containers::_safe_file() {
    local owner size
    [[ -f $1 && ! -L $1 ]] && containers::_safe_path "$1" || return 1
    read -r owner size < <(stat -c '%u %s' -- "$1") || return 1
    [[ $owner == "$EUID" && $size =~ ^[0-9]+$ ]] && ((size <= 1048576))
}

containers::_compose() {
    local context=$1 file
    shift
    local -a args=(compose --ansi never --project-name "$(jq -r .project <<<"$context")" --project-directory "$(jq -r .directory <<<"$context")")
    while IFS= read -r file; do args+=(-f "$file"); done < <(jq -r '.sources[]' <<<"$context")
    containers::_docker "${args[@]}" "$@"
}

containers::_runtime_matches() {
    local config=$1 inspect=$2 service=$3 expected actual restart name retries=0
    # docker update does not refresh Compose's config-hash label. Refuse resource
    # managed services until their running limits can be reproduced completely.
    if ! jq -e --arg service "$service" '.services[$service] | [.cpu_count,.cpu_percent,.cpu_period,.cpu_quota,.cpu_rt_period,.cpu_rt_runtime,.cpu_shares,.cpus,.cpuset,.mem_limit,.mem_reservation,.mem_swappiness,.memswap_limit,.pids_limit,.blkio_config,.deploy.resources,.deploy.restart_policy] | all(.[]; . == null)' <<<"$config" >/dev/null ||
        ! jq -e '.HostConfig | [.CpuShares,.Memory,.NanoCpus,.CgroupParent,.BlkioWeight,.BlkioWeightDevice,.BlkioDeviceReadBps,.BlkioDeviceWriteBps,.BlkioDeviceReadIOps,.BlkioDeviceWriteIOps,.CpuPeriod,.CpuQuota,.CpuRealtimePeriod,.CpuRealtimeRuntime,.CpusetCpus,.CpusetMems,.MemoryReservation,.MemorySwap,.MemorySwappiness,.OomKillDisable,.PidsLimit,.CpuCount,.CpuPercent,.IOMaximumIOps,.IOMaximumBandwidth] | all(.[]; . == null or . == 0 or . == false or . == "" or . == [] or . == {})' <<<"$inspect" >/dev/null; then
        core::die 'This service has resource limits or deployment policy that require a manual Compose change. OctoShield will not reset runtime limits while restricting ports.'
        return 1
    fi
    restart=$(jq -r --arg service "$service" '.services[$service].restart // "no"' <<<"$config") || return 1
    name=$restart
    if [[ $restart == on-failure:* ]]; then
        name=on-failure
        retries=${restart#*:}
        [[ $retries =~ ^[0-9]{1,6}$ ]] || return 1
    fi
    case "$name" in no | always | unless-stopped | on-failure) ;; *) return 1 ;; esac
    jq -e --arg name "$name" --argjson retries "$retries" '(.HostConfig.RestartPolicy.Name // "no") == $name and (.HostConfig.RestartPolicy.MaximumRetryCount // 0) == $retries' <<<"$inspect" >/dev/null || {
        core::die 'The running restart policy differs from Compose, possibly after docker update. Align that policy before restricting ports.'
        return 1
    }
    if ! jq -e --arg service "$service" '.services[$service].networks | all(.[]; (.ipv4_address // "") == "" and (.ipv6_address // "") == "" and (.link_local_ips // []) == [] and (.driver_opts // {}) == {} and (.gw_priority // 0) == 0 and (.interface_name // "") == "")' <<<"$config" >/dev/null ||
        ! jq -e '.NetworkSettings.Networks | all(.[]; (.IPAMConfig // {}) == {} and (.Links // []) == [] and (.DriverOpts // {}) == {} and (.GwPriority // 0) == 0)' <<<"$inspect" >/dev/null; then
        core::die 'This service has explicit network endpoint settings. Review them manually so a port change cannot discard custom addressing or routing.'
        return 1
    fi
    expected=$(jq -cS --arg service "$service" --arg name "$(jq -r '.Name | ltrimstr("/")' <<<"$inspect")" '. as $config | [.services[$service].networks | to_entries[] | {name:$config.networks[.key].name,aliases:([$name,$service]+(.value.aliases//[])|unique|sort)}] | sort_by(.name)' <<<"$config") || return 1
    actual=$(jq -cS '[.NetworkSettings.Networks | to_entries[] | {name:.key,aliases:(.value.Aliases//[]|unique|sort)}] | sort_by(.name)' <<<"$inspect") || return 1
    [[ $actual == "$expected" ]] || {
        core::die 'The running network aliases differ from Compose. Review those aliases before recreating the service.'
        return 1
    }
}

containers::_context() {
    local id=$1 inspect project service directory sources source files='[]' hashes='[]' config hash engine compose replicas network network_data expected actual ports image context daemon_policy
    containers::_require_user || return 1
    containers::_daemon_running || return 1
    daemon_policy=$(containers::_daemon_policy) || return 1
    engine=$(containers::_docker version --format '{{.Server.Version}}' 2>/dev/null) || {
        core::die 'Your desktop account cannot inspect the running local Docker daemon. Use the configuration guidance; this action never adds Docker permissions or starts a daemon.'
        return 1
    }
    containers::_version_at_least "$engine" 28 0 0 || {
        core::die 'Verified local-only publishing requires Docker Engine 28 or newer. Update Docker before using this repair.'
        return 1
    }
    compose=$(containers::_docker compose version --short 2>/dev/null) || return 1
    containers::_version_at_least "$compose" 2 24 4 || {
        core::die 'This repair requires Docker Compose 2.24.4 or newer for explicit port replacement.'
        return 1
    }
    inspect=$(containers::_docker inspect --type container "$id" 2>/dev/null) || return 1
    if ((${#inspect} > 1048576)) || ! jq -e --arg id "$id" 'length == 1 and .[0].Id == $id and .[0].State.Running == true and .[0].HostConfig.NetworkMode != "host"' <<<"$inspect" >/dev/null; then
        core::die 'The selected container changed, stopped, or uses host networking. Refresh its details before continuing.'
        return 1
    fi
    inspect=$(jq -c '.[0] | {Id,Name,Image,Config,HostConfig,Mounts,NetworkSettings:{Networks:.NetworkSettings.Networks,Ports:.NetworkSettings.Ports},State:{Running:.State.Running,StartedAt:.State.StartedAt},RestartCount}' <<<"$inspect") || return 1
    project=$(jq -er '.Config.Labels["com.docker.compose.project"]' <<<"$inspect") || return 1
    service=$(jq -er '.Config.Labels["com.docker.compose.service"]' <<<"$inspect") || return 1
    directory=$(jq -er '.Config.Labels["com.docker.compose.project.working_dir"]' <<<"$inspect") || return 1
    sources=$(jq -er '.Config.Labels["com.docker.compose.project.config_files"]' <<<"$inspect") || return 1
    if [[ ! $project =~ ^[a-z0-9][a-z0-9_-]{0,63}$ || ! $service =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$ || ! -d $directory ]] || ! containers::_safe_path "$directory"; then
        core::die 'The Compose project metadata or source directory is not safe to use. Review the source files manually.'
        return 1
    fi
    [[ $(stat -c %u -- "$directory") == "$EUID" && ${#sources} -le 2048 ]] || return 1
    local -a paths
    IFS=',' read -r -a paths <<<"$sources"
    ((${#paths[@]} >= 1 && ${#paths[@]} <= 4)) || return 1
    for source in "${paths[@]}"; do
        containers::_safe_file "$source" || {
            core::die 'Compose sources must be existing regular files owned by your desktop account, without symbolic links or shared write access.'
            return 1
        }
        files=$(jq -cn --argjson files "$files" --arg path "$source" '$files + [$path]') || return 1
        hash=$(sha256sum -- "$source") || return 1
        hashes=$(jq -cn --argjson hashes "$hashes" --arg hash "${hash%% *}" '$hashes + [$hash]') || return 1
    done
    context=$(jq -cn --arg id "$id" --arg project "$project" --arg service "$service" --arg directory "$directory" --argjson sources "$files" --argjson hashes "$hashes" --arg daemon_policy "$daemon_policy" '{id:$id,project:$project,service:$service,directory:$directory,sources:$sources,source_hashes:$hashes,daemon_policy:$daemon_policy}') || return 1
    replicas=$(containers::_compose "$context" ps --all --quiet "$service") || return 1
    [[ $replicas == "$id" ]] || {
        core::die 'Automatic repair supports one running container per service. Review scaled or stopped replicas in Compose.'
        return 1
    }
    config=$(containers::_compose "$context" config --format json) || return 1
    ((${#config} <= 1048576)) && jq -e --arg service "$service" '.services[$service] != null and (.services[$service].network_mode // "") == "" and (.services[$service].scale // 1) == 1 and (.services[$service].deploy.replicas // 1) == 1' <<<"$config" >/dev/null || return 1
    # Hash the resolved model through stdin. Several Compose releases omit
    # env_file resolution in config --hash; hashing original files can falsely
    # report drift, while container creation hashes the resolved environment.
    hash=$(containers::_compose "$(jq -c '.sources=["-"]' <<<"$context")" config --hash "$service" <<<"$config") || return 1
    hash=${hash##* }
    [[ $hash =~ ^[a-f0-9]{64}$ && $hash == "$(jq -r '.Config.Labels["com.docker.compose.config-hash"]' <<<"$inspect")" ]] || {
        core::die 'The Compose configuration does not match the running service. Apply or resolve those changes yourself before restricting its ports; OctoShield will not deploy unrelated edits.'
        return 1
    }
    expected=$(jq -cS --arg service "$service" '[.services[$service].networks | keys[] as $key | $key] as $keys | [.networks | to_entries[] | select(.key as $key | $keys | index($key)) | .value.name] | sort' <<<"$config") || return 1
    actual=$(jq -cS '.NetworkSettings.Networks | keys | sort' <<<"$inspect") || return 1
    [[ $expected == "$actual" && $actual != '[]' ]] || {
        core::die 'The running service has network attachments that differ from Compose. Review those attachments before recreating it.'
        return 1
    }
    containers::_runtime_matches "$config" "$inspect" "$service" || return 1
    while IFS= read -r network; do
        [[ $network =~ ^[a-f0-9]{64}$ ]] || return 1
        network_data=$(containers::_docker network inspect "$network") || return 1
        jq -e 'length == 1 and .[0].Driver == "bridge" and (.[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] // "nat") == "nat" and (.[0].Options["com.docker.network.bridge.gateway_mode_ipv6"] // "nat") == "nat" and (.[0].Options["com.docker.network.bridge.trusted_host_interfaces"] // "") == ""' <<<"$network_data" >/dev/null || {
            core::die 'This network uses direct routing or a nonstandard driver. Loopback publishing alone is insufficient; review its Docker network configuration.'
            return 1
        }
    done < <(jq -r '.NetworkSettings.Networks[].NetworkID' <<<"$inspect")
    ports=$(jq -ce --arg service "$service" '.services[$service].ports | select(type == "array" and length > 0 and length <= 32) | map(select((.target | type == "number") and (.target >= 1 and .target <= 65535) and (.published | tostring | test("^[1-9][0-9]{0,4}$")) and ((.published | tonumber) <= 65535) and ((.protocol // "tcp") | IN("tcp","udp"))))' <<<"$config") || return 1
    [[ $(jq length <<<"$ports") == "$(jq --arg service "$service" '.services[$service].ports | length' <<<"$config")" ]] || {
        core::die 'Automatic repair requires fixed individual TCP/UDP ports; ranges and dynamic ports need a manual Compose edit.'
        return 1
    }
    expected=$(jq -cS '[.[] | {target:(.target|tostring),protocol:(.protocol//"tcp"),published:(.published|tostring)}] | unique | sort_by(.target,.protocol,.published)' <<<"$ports") || return 1
    actual=$(jq -cS '[.NetworkSettings.Ports | to_entries[] | .key as $port | (.value//[])[] | {target:($port|split("/")[0]),protocol:($port|split("/")[1]),published:.HostPort}] | unique | sort_by(.target,.protocol,.published)' <<<"$inspect") || return 1
    [[ $expected == "$actual" ]] || {
        core::die 'Published ports differ from the saved Compose model. Review the actual bindings before recreating this service.'
        return 1
    }
    image=$(jq -er '.Image | select(test("^sha256:[a-f0-9]{64}$"))' <<<"$inspect") || return 1
    # Retain the address families actually published by Docker. An implicit
    # wildcard commonly creates both IPv4 and IPv6 bindings; keep both usable
    # locally rather than silently dropping existing ::1 access.
    ports=$(jq -c --argjson inspect "$inspect" '[.[] as $port | ($inspect.NetworkSettings.Ports[($port.target|tostring)+"/"+($port.protocol//"tcp")] | map(if (.HostIp|contains(":")) then "::1" else "127.0.0.1" end) | unique)[] as $host | $port + {host_ip:$host}] | unique' <<<"$ports") || return 1
    jq -cn --argjson context "$context" --argjson config "$config" --argjson ports "$ports" --arg image "$image" --argjson inspect "$inspect" '$context + {config:$config,ports:$ports,image:$image,inspect:$inspect,override_path:($context.directory+"/.octoshield/"+$context.service+".local.yaml"),snapshot_path:($context.directory+"/.octoshield/"+$context.service+".reviewed.json")}'
}

containers::_token() {
    local digest
    digest=$(jq -cS . <<<"$1" | sha256sum) || return 1
    printf '%s\n' "${digest%% *}"
}

containers::_command() {
    local context=$1 file
    local -a args=(docker --host=unix:///run/docker.sock compose --project-name "$(jq -r .project <<<"$context")" --project-directory "$(jq -r .directory <<<"$context")")
    while IFS= read -r file; do args+=(-f "$file"); done < <(jq -r '.sources[]' <<<"$context")
    args+=(-f "$(jq -r .override_path <<<"$context")" up --no-deps --no-build --pull never -d "$(jq -r .service <<<"$context")")
    printf '%q ' "${args[@]}"
}

containers::plan() {
    local context token command result
    context=$(containers::_context "$1") || return 1
    token=$(containers::_token "$context") || return 1
    command=$(containers::_command "$context") || return 1
    result=$(jq -cn --argjson context "$context" --arg token "$token" --arg command "$command" '{kind:"container-plan",id:$context.id,token:$token,title:("Bind "+$context.service+" ports to localhost"),summary:"Recreate only this service with its current image and ports bound to localhost. Mounted volumes are retained; active connections stop briefly and unmounted container-layer changes are replaced.",project:$context.project,service:$context.service,sources:$context.sources,ports:$context.ports,override_path:$context.override_path,snapshot_path:$context.snapshot_path,command:$command,warning:"Include the generated override in future deployments; original files alone can expose ports again. A private resolved snapshot may contain environment values. This verifies published host bindings; custom firewall/routing paths remain outside this check."}') || return 1
    ((${#result} <= 4000)) || {
        core::die 'This project has too much configuration detail for a safe interactive repair. Use the displayed source guidance instead.'
        return 1
    }
    printf '%s\n' "$result"
}

containers::_write_override() {
    local context=$1 path=$2 service
    service=$(jq -r .service <<<"$context") || return 1
    {
        printf '# Generated by OctoShield. Include this file after the original Compose files.\nservices:\n  %s:\n    ports: !override\n' "$service"
        jq -r '.ports[] | "      - " + tojson' <<<"$context"
    } >"$path"
}

containers::_up() {
    local context=$1 file
    local -a args=(compose --ansi never --project-name "$(jq -r .project <<<"$context")" --project-directory "$(jq -r .directory <<<"$context")")
    while IFS= read -r file; do args+=(-f "$file"); done < <(jq -r '.sources[]' <<<"$context")
    args+=(-f "$(jq -r .override_path <<<"$context")" up --no-deps --no-build --pull never --force-recreate --scale "$(jq -r .service <<<"$context")=1" -d "$(jq -r .service <<<"$context")")
    core::timeout --foreground --kill-after=5s 120s env -u DOCKER_CONTEXT -u DOCKER_HOST \
        DOCKER_CONFIG=/var/empty LC_ALL=C docker --host=unix:///run/docker.sock "${args[@]}"
}

containers::localize() (
    local id=$1 token=$2 context current directory destination temporary merged service actual new_id command snapshot snapshot_temporary snapshot_context checked expected_ports actual_ports before after
    containers::_require_user || return 1
    context=$(containers::_context "$id") || return 1
    [[ $(containers::_token "$context") == "$token" ]] || {
        core::die 'The container or its source configuration changed after review. Refresh the plan; no repair was started.'
        return 1
    }
    destination=$(jq -r .override_path <<<"$context") || return 1
    snapshot=$(jq -r .snapshot_path <<<"$context") || return 1
    service=$(jq -r .service <<<"$context") || return 1
    [[ ! -e $destination && ! -L $destination && ! -e $snapshot && ! -L $snapshot ]] || {
        core::die 'A local override already exists. Review it in your Compose project instead of overwriting it.'
        return 1
    }
    core::confirm "Restrict $service to this computer? This briefly recreates only that service, retains mounted volumes and pins its current image. Unmounted container-layer changes are replaced. Include $destination in future deployments; original files can expose ports again. A private resolved snapshot is retained at $snapshot. No other service will be restarted." || return 1
    current=$(containers::_context "$id") || return 1
    [[ $(containers::_token "$current") == "$token" ]] || {
        core::die 'The service changed while confirmation was open. Refresh the plan before retrying.'
        return 1
    }
    directory=${destination%/*}
    if [[ ! -e $directory ]]; then mkdir -m 0700 -- "$directory" || return 1; fi
    [[ -d $directory && $(stat -c '%u:%a' -- "$directory") == "$EUID:700" ]] && containers::_safe_path "$directory" || return 1
    [[ ! -L $directory/lock ]] || return 1
    exec 5>"$directory/lock" || return 1
    flock -n 5 || {
        core::die 'Another local container repair is running for this project.'
        return 1
    }
    temporary=$(mktemp "$directory/.local.XXXXXXXX.yaml") || return 1
    snapshot_temporary=$(mktemp "$directory/.reviewed.XXXXXXXX.json") || return 1
    trap 'rm -f -- "$temporary" "$snapshot_temporary"' EXIT
    containers::_write_override "$context" "$temporary" || return 1
    merged=$(containers::_compose "$context" -f "$temporary" config --format json) || return 1
    jq -e --arg service "$service" --argjson before "$(jq .config <<<"$context")" --argjson ports "$(jq .ports <<<"$context")" '(.services[$service].ports == $ports) and (del(.services[$service].ports) == ($before | del(.services[$service].ports)))' <<<"$merged" >/dev/null || {
        core::die 'The merged Compose model contains other changes. No container was recreated.'
        return 1
    }
    # Pin only this execution snapshot. Keeping the permanent override limited
    # to ports allows the project's normal image upgrades on future deployments.
    merged=$(jq -c --arg service "$service" --arg image "$(jq -r .image <<<"$context")" '.services[$service].image=$image' <<<"$merged") || return 1
    # Execute exactly the reviewed resolved model, so edits to an original
    # Compose file cannot silently join the operation after confirmation.
    # `compose config` already serializes dollar escapes for a round trip.
    # Preserve that serialization, then verify the rendered snapshot exactly;
    # applying another escaping pass would change environment/command values.
    printf '%s\n' "$merged" >"$snapshot_temporary" || return 1
    snapshot_context=$(jq -c --arg source "$snapshot_temporary" '.sources=[$source]' <<<"$context") || return 1
    checked=$(containers::_compose "$snapshot_context" config --format json) || return 1
    [[ $(jq -cS . <<<"$checked") == "$(jq -cS . <<<"$merged")" ]] || {
        core::die 'The resolved configuration could not be reproduced exactly. No container was recreated.'
        return 1
    }
    ln -- "$snapshot_temporary" "$snapshot" || return 1
    if ! ln -- "$temporary" "$destination"; then
        rm -f -- "$snapshot"
        return 1
    fi
    rm -f -- "$temporary" "$snapshot_temporary" || return 1
    snapshot_context=$(jq -c --arg source "$snapshot" '.sources=[$source]' <<<"$context") || return 1
    if ! containers::_up "$snapshot_context"; then
        core::die "Compose could not finish the local-only change. The restrictive override remains at $destination. Review the service and retry its deployment; OctoShield will not automatically reopen its ports."
        return 1
    fi
    new_id=$(containers::_compose "$snapshot_context" -f "$destination" ps --all --quiet "$service") || return 1
    [[ $new_id =~ ^[a-f0-9]{64}$ ]] || return 1
    actual=$(containers::_docker inspect --type container "$new_id") || return 1
    jq -e --arg image "$(jq -r .image <<<"$context")" 'length == 1 and .[0].State.Running and .[0].Image == $image and ([.[0].NetworkSettings.Ports | .[]? // [] | .[] | .HostIp] as $binds | ($binds | length > 0) and all($binds[]; . == "127.0.0.1" or . == "::1"))' <<<"$actual" >/dev/null || {
        core::die "The recreated service did not verify as running with localhost-only bindings. Inspect it with $destination before assuming it is restricted."
        return 1
    }
    expected_ports=$(jq -cS '[.ports[] | {target:(.target|tostring),protocol:(.protocol//"tcp"),published:(.published|tostring),host_ip}] | unique | sort_by(.target,.protocol,.published,.host_ip)' <<<"$context") || return 1
    actual_ports=$(jq -cS '[.[0].NetworkSettings.Ports | to_entries[] | .key as $port | (.value//[])[] | {target:($port|split("/")[0]),protocol:($port|split("/")[1]),published:.HostPort,host_ip:.HostIp}] | unique | sort_by(.target,.protocol,.published,.host_ip)' <<<"$actual") || return 1
    before=$(jq -cS '.inspect | {image:.Image,env:(.Config.Env|sort),cmd:.Config.Cmd,entrypoint:.Config.Entrypoint,user:.Config.User,directory:.Config.WorkingDir,host:(.HostConfig|del(.PortBindings)),mounts:([.Mounts[]? | {Type,Name,Source,Destination,RW,Propagation}]|sort_by(.Destination)),networks:(.NetworkSettings.Networks|keys|sort)}' <<<"$context") || return 1
    after=$(jq -cS '.[0] | {image:.Image,env:(.Config.Env|sort),cmd:.Config.Cmd,entrypoint:.Config.Entrypoint,user:.Config.User,directory:.Config.WorkingDir,host:(.HostConfig|del(.PortBindings)),mounts:([.Mounts[]? | {Type,Name,Source,Destination,RW,Propagation}]|sort_by(.Destination)),networks:(.NetworkSettings.Networks|keys|sort)}' <<<"$actual") || return 1
    [[ $expected_ports == "$actual_ports" && $before == "$after" ]] || {
        core::die 'The recreated service does not match its reviewed ports, image, mounts or process configuration. Its restrictive override remains; inspect the service before using it.'
        return 1
    }
    command=$(containers::_command "$context") || return 1
    jq -cn --arg source "$destination" --arg snapshot "$snapshot" --arg command "$command" '{kind:"container-result",summary:"The service is running with its reviewed host ports bound to localhost and its image, mounts and process configuration retained. Keep the override in future deployments. Custom firewall/routing paths are not verified.",source:$source,snapshot:$snapshot,command:$command}'
)

containers::dispatch() {
    containers::validate "$@" || return 2
    case "$1" in plan) containers::plan "$2" ;; localize) containers::localize "$2" "$3" ;; esac
}
