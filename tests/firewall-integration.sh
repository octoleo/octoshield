#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real UFW and TCP integration. All native changes run in private mount, PID
# and network namespaces, with no connection to the invoking host's network.
set -Eeuo pipefail

firewall_test::fail() {
    printf 'Firewall integration (%s): %s\n' "${FIREWALL_TEST_CASE:-setup}" "$*" >&2
    exit 1
}

firewall_test::change() {
    local result=0
    core::begin "Native firewall integration: $*" || return 1
    "$@" || result=$?
    core::end
    return "$result"
}

firewall_test::expect_failure() {
    if "$@"; then firewall_test::fail "Unexpected success: $*"; fi
}

firewall_test::probe() {
    local expected=$1 peer=$2 family=$3 source=$4 destination=$5 port=$6 output result=0
    output=$(printf 'OctoShield native TCP fixture\n' |
        ip netns exec "$peer" nc "-$family" -n -w 1 -N -s "$source" "$destination" "$port" 2>"$temporary/probe.log") || result=$?
    if [[ $expected == allowed ]]; then
        [[ $result == 0 && $output == 'OctoShield native TCP fixture' ]] || {
            cat "$temporary/probe.log" >&2
            firewall_test::fail "TCP $source -> $destination:$port did not pass through the real listener."
        }
    else
        [[ $result != 0 && -z $output ]] || firewall_test::fail "TCP $source -> $destination:$port was not blocked."
    fi
}

firewall_test::web_scope() {
    local expected=$1 port
    for port in 80 443; do
        firewall_test::probe "$expected" octolan 4 192.168.77.2 192.168.77.1 "$port"
        # A different source on the same interface must remain blocked.
        firewall_test::probe blocked octolan 4 198.51.100.2 192.168.77.1 "$port"
        # The permitted source subnet on a different interface is also blocked.
        firewall_test::probe blocked octoother 4 192.168.77.3 192.0.2.1 "$port"
        # An IPv4-only permission must not create an IPv6 allowance.
        firewall_test::probe blocked octolan 6 fd42:77::2 fd42:77::1 "$port"
    done
}

firewall_test::assert_ready() {
    access::list office | jq --exit-status '.ready == true and .state == "active" and .assigned_profile == "office" and .recovery.last_result == "applied"' >/dev/null ||
        firewall_test::fail 'Access did not report the verified office profile ready.'
    profile_controls::verify firewall | jq --exit-status '.state == "active"' >/dev/null ||
        firewall_test::fail 'Production verification did not accept the actual kernel policy.'
}

firewall_test::baseline_hash() {
    local directory
    directory="$(profile_controls::_directory)/firewall-baseline"
    find "$directory" -type f -exec sha256sum {} + | LC_ALL=C sort | sha256sum
}

firewall_test::isolated() {
    local root=$1 temporary=$2 parent_mount=$3 parent_network=$4 directory program selected port _attempt native_before saved_before document_before baseline_before web_group
    local -a listener_pids=()
    [[ $EUID == 0 && $$ == 1 && $(readlink /proc/self/ns/mnt) != "$parent_mount" && $(readlink /proc/self/ns/net) != "$parent_network" ]] ||
        firewall_test::fail 'Refusing native changes outside fresh mount, PID and network namespaces.'
    mount --make-rprivate /

    # Preserve installed vendor policy and executable selections, never host
    # account/password databases. The entire /etc is private because production
    # baseline restoration renames /etc/ufw rather than editing a mount point.
    install -d -m 0755 "$temporary/etc" "$temporary/etc/default" "$temporary/etc/alternatives"
    cp -a /etc/ufw "$temporary/etc/ufw"
    cp -a /etc/default/ufw "$temporary/etc/default/ufw"
    for program in services protocols os-release; do
        [[ ! -f /etc/$program ]] || cp -L /etc/"$program" "$temporary/etc/$program"
    done
    # awk, nc and iptables (and coreutils on some Ubuntu versions) use these
    # links. Copy links only; their package-owned targets stay in /usr or /bin.
    while IFS= read -r -d '' selected; do cp -a -- "$selected" "$temporary/etc/alternatives/"; done < <(find /etc/alternatives -maxdepth 1 -type l -print0)
    for directory in /etc /run /var/log; do
        mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$directory"
        [[ $(findmnt --noheadings --output FSTYPE --target "$directory") == tmpfs ]] || firewall_test::fail "Private $directory mount is missing."
    done
    cp -a "$temporary/etc/." /etc/
    printf 'root:x:0:0:root:/root:/bin/bash\n' >/etc/passwd
    printf 'root:x:0:\n' >/etc/group
    printf 'passwd: files\ngroup: files\nhosts: files\n' >/etc/nsswitch.conf
    printf '127.0.0.1 localhost\n::1 localhost\n' >/etc/hosts
    install -d -m 0755 /run/netns
    export LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1
    unset SSH_CONNECTION SSH_CLIENT SSH_TTY

    # Real production transactions, private snapshots, native adapters and
    # verification are all retained. Only operator consent is automated.
    for program in core controls profiles profile_controls profile_firewall_verify access status; do
        # shellcheck source=/dev/null
        source "$root/src/lib/$program.sh"
    done
    CORE_STATE="$temporary/state-inactive"
    # shellcheck disable=SC2317,SC2329 # Called by the sourced production backend.
    core::confirm() {
        printf 'Integration consent (%s): %s\n' "$FIREWALL_TEST_CONSENT" "$*"
        [[ $FIREWALL_TEST_CONSENT == yes ]]
    }
    # The one failure injection happens after a REAL native mutation succeeds.
    # It models an interrupted action without substituting its policy, status,
    # snapshots or verification. All UFW invocations still execute the package.
    # shellcheck disable=SC2317,SC2329
    ufw() {
        command ufw "$@" || return "$?"
        if [[ $* == 'logging low' && $FIREWALL_TEST_FAIL_AFTER_LOGGING == yes ]]; then
            FIREWALL_TEST_FAIL_AFTER_LOGGING=no
            printf 'Injected interruption after actual ufw logging low.\n' >&2
            return 1
        fi
    }
    FIREWALL_TEST_CONSENT=yes
    FIREWALL_TEST_FAIL_AFTER_LOGGING=no
    FIREWALL_TEST_CASE=setup
    # shellcheck disable=SC2317,SC2329 # Invoked by the EXIT trap while locals remain in scope.
    cleanup() {
        local result=$?
        trap - EXIT
        set +e
        if ((result)); then
            printf '\nNative firewall diagnostics (%s)\n' "$FIREWALL_TEST_CASE" >&2
            command ufw status verbose >&2 || :
            iptables-save >&2 || :
            ip6tables-save >&2 || :
            profiles::state >&2 || :
            profile_controls::_read firewall >&2 || :
            for directory in "$temporary"/listener-*.log; do [[ ! -f $directory ]] || cat "$directory" >&2; done
        fi
        core::end
        if ((${#listener_pids[@]})); then kill "${listener_pids[@]}" 2>/dev/null || :; fi
        ip netns delete octolan 2>/dev/null || :
        ip netns delete octoother 2>/dev/null || :
        exit "$result"
    }
    trap cleanup EXIT

    ufw --version
    iptables --version
    ip6tables --version
    [[ $(ufw status) == 'Status: inactive' ]] || firewall_test::fail 'The fresh disposable UFW package must start inactive.'
    profile_controls::_standard_ufw_hooks || firewall_test::fail 'Installed vendor hooks failed production preflight.'
    ip link set lo up
    sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 net.ipv6.conf.default.forwarding=0 net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
    ip netns add octolan
    ip netns add octoother
    ip netns exec octolan sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
    ip link add octolan0 type veth peer name peerlan
    ip link add octoother0 type veth peer name peerother
    ip link set peerlan netns octolan
    ip link set peerother netns octoother
    ip address add 192.168.77.1/24 dev octolan0
    ip address add 192.0.2.1/24 dev octoother0
    ip -6 address add fd42:77::1/64 dev octolan0 nodad
    ip link set octolan0 up
    ip link set octoother0 up
    ip netns exec octolan ip link set lo up
    ip netns exec octolan ip link set peerlan up
    ip netns exec octolan ip address add 192.168.77.2/24 dev peerlan
    ip netns exec octolan ip address add 198.51.100.2/32 dev peerlan
    ip netns exec octolan ip -6 address add fd42:77::2/64 dev peerlan nodad
    ip netns exec octoother ip link set lo up
    ip netns exec octoother ip link set peerother up
    ip netns exec octoother ip address add 192.0.2.2/24 dev peerother
    ip netns exec octoother ip address add 192.168.77.3/32 dev peerother
    # These explicit return routes make both negative scope probes reachable
    # before UFW is enabled, including with reverse-path filtering in use.
    ip netns exec octolan ip address add 172.24.0.4/32 dev peerlan
    ip route add 172.24.0.4/32 dev octolan0
    ip route add 198.51.100.2/32 dev octolan0
    ip route add 192.168.77.3/32 dev octoother0

    for port in 80 443 9000 9003; do
        socat "TCP4-LISTEN:$port,reuseaddr,fork" EXEC:/bin/cat >"$temporary/listener-4-$port.log" 2>&1 &
        listener_pids+=("$!")
        socat "TCP6-LISTEN:$port,ipv6only=1,reuseaddr,fork" EXEC:/bin/cat >"$temporary/listener-6-$port.log" 2>&1 &
        listener_pids+=("$!")
    done
    for _attempt in {1..30}; do
        [[ $(ss -H -ltn '( sport = :80 or sport = :443 or sport = :9000 or sport = :9003 )' | wc -l) == 8 ]] && break
        sleep 0.1
    done
    [[ $(ss -H -ltn '( sport = :80 or sport = :443 or sport = :9000 or sport = :9003 )' | wc -l) == 8 ]] || firewall_test::fail 'Native TCP listeners did not start.'
    for port in 80 443 9000 9003; do
        firewall_test::probe allowed octolan 4 192.168.77.2 192.168.77.1 "$port"
        firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 "$port"
        firewall_test::probe allowed octoother 4 192.168.77.3 192.0.2.1 "$port"
        firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 "$port"
    done
    printf 'PASS: every positive and negative probe can reach its actual listener before policy application\n'

    FIREWALL_TEST_CASE='failed first adoption and reviewed retry with forwarding disabled'
    CORE_STATE="$temporary/state-inactive"
    native_before=$(profile_controls::_tree_hash)
    FIREWALL_TEST_FAIL_AFTER_LOGGING=yes
    firewall_test::expect_failure firewall_test::change profiles::apply office firewall
    [[ $FIREWALL_TEST_FAIL_AFTER_LOGGING == no ]] || firewall_test::fail 'The first adoption failed before reaching the intended native mutation.'
    [[ -d $CORE_STATE/profiles/controls/firewall-baseline ]] || firewall_test::fail 'Failed adoption lost its original baseline.'
    baseline_before=$(firewall_test::baseline_hash)
    [[ $(ufw status verbose) == *'disabled (routed)'* ]] || firewall_test::fail 'The laptop case did not exercise disabled routing.'
    profiles::state | jq --exit-status '.results.firewall.status == "failed" and .active.firewall == "unmanaged"' >/dev/null
    access::list office | jq --exit-status '.ready == false and .recovery.last_result == "failed" and .recovery.can_apply and .recovery.can_restore' >/dev/null
    saved_before=$(profile_controls::snapshot firewall)
    document_before=$(profiles::state)
    firewall_test::expect_failure firewall_test::change access::dispatch allow office 80,443 tcp 192.168.77.0/24 octolan0 0
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Rejected Access changed the failed policy.'
    FIREWALL_TEST_CONSENT=no
    firewall_test::expect_failure firewall_test::change access::dispatch recover office
    FIREWALL_TEST_CONSENT=yes
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Cancelled retry changed policy or profile state.'
    firewall_test::change access::dispatch recover office
    firewall_test::assert_ready
    status::firewall | jq --exit-status '.state == "active"' >/dev/null || firewall_test::fail 'The native dashboard probe rejected a closed firewall with routing disabled.'
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'Retry replaced the original baseline.'
    firewall_test::web_scope blocked
    printf 'PASS: real partial application is failed, Access is blocked, cancellation is read-only, and reviewed retry succeeds with forwarding off\n'

    FIREWALL_TEST_CASE='verified Office permits scoped TCP 9003 without its original restore point'
    directory=$(profile_controls::_directory)
    mv "$directory/firewall-baseline" "$directory/retained-baseline-test"
    saved_before=$(profile_controls::snapshot firewall)
    document_before=$(profiles::state)
    firewall_test::assert_ready
    access::list office | jq --exit-status '.recovery.can_restore == false and .recovery.can_apply' >/dev/null
    firewall_test::expect_failure firewall_test::change access::dispatch restore
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Unavailable original restoration changed policy.'
    FIREWALL_TEST_CONSENT=no
    firewall_test::expect_failure firewall_test::change access::dispatch allow office 9003 tcp 172.24.0.4 any 0
    FIREWALL_TEST_CONSENT=yes
    [[ $(profile_controls::snapshot firewall) == "$saved_before" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Cancelled TCP 9003 review changed policy.'
    firewall_test::change access::dispatch allow office 9003 tcp 172.24.0.4 any 0
    firewall_test::assert_ready
    firewall_test::probe allowed octolan 4 172.24.0.4 192.168.77.1 9003
    firewall_test::probe blocked octolan 4 192.168.77.2 192.168.77.1 9003
    firewall_test::probe blocked octolan 6 fd42:77::2 fd42:77::1 9003
    web_group=$(access::list office | jq --exit-status --raw-output '.rules[] | select(.ports == "9003") | .id')
    firewall_test::change access::dispatch revoke office "$web_group"
    firewall_test::probe blocked octolan 4 172.24.0.4 192.168.77.1 9003
    [[ ! -e $directory/firewall-baseline ]] || firewall_test::fail 'Access fabricated an original restore point.'
    mv "$directory/retained-baseline-test" "$directory/firewall-baseline"
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'TCP 9003 management changed retained original evidence.'
    firewall_test::assert_ready
    access::list office | jq --exit-status '.recovery.can_restore' >/dev/null
    printf 'PASS: verified Office allows and revokes exact TCP 9003 source without an original restore point; cancellation and scope are enforced\n'

    FIREWALL_TEST_CASE='permanent scoped web access, reload and grouped revocation'
    firewall_test::change access::dispatch allow office 9000 tcp 192.168.77.0/24 octolan0 0
    firewall_test::change access::dispatch allow office 80,443 tcp 192.168.77.0/24 octolan0 0
    firewall_test::assert_ready
    profiles::get office firewall | jq --exit-status '[.rules[] | select(.port == 80 or .port == 443)] | length == 2 and (map(.group) | unique | length) == 1 and all(.[]; .expires_at == 0 and .source == "192.168.77.0/24" and .interface == "octolan0")' >/dev/null
    web_group=$(access::list office | jq --exit-status --raw-output '.rules[] | select(.ports == "80,443") | .id')
    firewall_test::web_scope allowed
    firewall_test::probe allowed octolan 4 192.168.77.2 192.168.77.1 9000
    ufw reload
    firewall_test::assert_ready
    firewall_test::web_scope allowed
    firewall_test::change access::dispatch revoke office "$web_group"
    firewall_test::assert_ready
    firewall_test::web_scope blocked
    firewall_test::probe allowed octolan 4 192.168.77.2 192.168.77.1 9000
    profiles::get office firewall | jq --exit-status '.rules | length == 1 and .[0].port == 9000' >/dev/null

    FIREWALL_TEST_CASE='external disable with retained empty native chains'
    # Stock UFW keeps its empty primary chains and built-in hooks after disable.
    # These real remnants must be reviewable without silently applying policy.
    firewall_test::change ufw disable
    local disabled_snapshot
    disabled_snapshot=$(profile_controls::snapshot firewall)
    jq --exit-status '.status == "Status: inactive" and
      (.ipv4 | contains("-A INPUT -j ufw-before-input")) and
      (.ipv6 | contains("-A INPUT -j ufw6-before-input"))' <<<"$disabled_snapshot" >/dev/null ||
        firewall_test::fail 'External disable did not exercise the normal retained UFW input hooks.'
    saved_before=$(profile_controls::_read firewall)
    document_before=$(profiles::state)
    access::list office | jq --exit-status '.ready == false and .recovery.reason == "drift" and .recovery.can_reconcile == true' >/dev/null
    firewall_test::expect_failure firewall_test::change access::dispatch allow office 80,443 tcp 192.168.77.0/24 octolan0 0
    [[ $(profile_controls::snapshot firewall) == "$disabled_snapshot" && $(profiles::state) == "$document_before" && $(profile_controls::_read firewall) == "$saved_before" ]] || firewall_test::fail 'Blocked Access changed the externally disabled firewall or its saved intent.'
    firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 80
    firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 443
    firewall_test::change access::dispatch reconcile office
    [[ $(ufw status) == 'Status: inactive' && $(profile_controls::snapshot firewall) == "$disabled_snapshot" ]] || firewall_test::fail 'Reconciliation enabled or changed the externally disabled firewall.'
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'Inactive reconciliation replaced the original baseline.'
    [[ $(profile_controls::_read firewall | jq -c '{before,desired,policy}') == "$(jq -c '{before,desired,policy}' <<<"$saved_before")" ]] || firewall_test::fail 'Inactive reconciliation changed saved intent or the original baseline.'
    profiles::state | jq --exit-status '.results.firewall.status == "pending"' >/dev/null
    access::list office | jq --exit-status '.ready == false and .recovery.reason == "pending" and .recovery.observed.state == "inactive"' >/dev/null
    firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 80
    firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 443
    firewall_test::change access::dispatch recover office
    firewall_test::assert_ready
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'Recovery from external disable replaced the original baseline.'
    firewall_test::web_scope blocked
    firewall_test::probe allowed octolan 4 192.168.77.2 192.168.77.1 9000
    firewall_test::probe blocked octolan 4 198.51.100.2 192.168.77.1 9000
    firewall_test::probe blocked octoother 4 192.168.77.3 192.0.2.1 9000
    firewall_test::probe blocked octolan 6 fd42:77::2 fd42:77::1 9000
    printf 'PASS: ordinary external disable retains inert hooks, blocks Access, reconciles without native changes, and explicit recovery restores the saved scoped policy\n'

    FIREWALL_TEST_CASE='restore the initially inactive baseline'
    firewall_test::change access::dispatch restore
    [[ $(ufw status) == 'Status: inactive' ]] || firewall_test::fail 'Restore did not retain the initially disabled firewall.'
    [[ $(profile_controls::_tree_hash) == "$native_before" ]] || firewall_test::fail 'Restore did not restore the original inactive configuration.'
    [[ ! -e $CORE_STATE/profiles/controls/firewall.json && ! -e $CORE_STATE/profiles/controls/firewall-baseline ]] || firewall_test::fail 'Verified restore left stale control tracking.'
    profiles::state | jq --exit-status '.active.firewall == "unmanaged" and .results.firewall.status == "unmanaged"' >/dev/null
    firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 80
    firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 443
    printf 'PASS: actual packets follow permanent subnet/interface web permissions, reload preserves them, grouped revoke retains unrelated access, and Restore returns the inactive baseline\n'

    FIREWALL_TEST_CASE='active baseline, external changes and reviewed reconciliation'
    # The second adoption covers real forwarding enabled as well as retention
    # of an administrator's active, pre-existing exception in both IP families.
    CORE_STATE="$temporary/state-active"
    sysctl -q -w net.ipv4.ip_forward=1
    ufw allow 9000/tcp comment 'Original administrator permission'
    ufw --force enable
    [[ $(ufw status verbose) == *'deny (routed)'* ]] || firewall_test::fail 'The routing case did not exercise the configured default deny policy.'
    native_before=$(profile_controls::_tree_hash)
    firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 9000
    firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 9000
    firewall_test::probe blocked octolan 4 192.168.77.2 192.168.77.1 80
    firewall_test::change access::dispatch recover office
    firewall_test::assert_ready
    status::firewall | jq --exit-status '.state == "active"' >/dev/null || firewall_test::fail 'The native dashboard probe rejected a closed firewall with routing enabled.'
    baseline_before=$(firewall_test::baseline_hash)
    firewall_test::probe blocked octolan 4 192.168.77.2 192.168.77.1 9000
    firewall_test::change access::dispatch allow office 80,443 tcp 192.168.77.0/24 octolan0 0
    ufw allow in on octolan0 proto tcp from 192.168.77.0/24 to any port 9000 comment 'External administrator change'
    saved_before=$(profile_controls::_read firewall)
    document_before=$(profiles::state)
    local external_snapshot
    external_snapshot=$(profile_controls::snapshot firewall)
    access::list office | jq --exit-status '.ready == false and .recovery.can_reconcile == true' >/dev/null
    firewall_test::expect_failure firewall_test::change access::dispatch allow office 8080 tcp 192.168.77.0/24 octolan0 0
    firewall_test::expect_failure firewall_test::change access::dispatch recover office
    FIREWALL_TEST_CONSENT=no
    firewall_test::expect_failure firewall_test::change access::dispatch reconcile office
    FIREWALL_TEST_CONSENT=yes
    [[ $(profile_controls::snapshot firewall) == "$external_snapshot" && $(profiles::state) == "$document_before" && $(profile_controls::_read firewall) == "$saved_before" ]] || firewall_test::fail 'Refused actions overwrote external rules or accepted tracking.'
    firewall_test::change access::dispatch reconcile office
    [[ $(profile_controls::snapshot firewall) == "$external_snapshot" ]] || firewall_test::fail 'Reconciliation changed native firewall rules.'
    [[ $(firewall_test::baseline_hash) == "$baseline_before" ]] || firewall_test::fail 'Reconciliation replaced the original baseline.'
    [[ $(profile_controls::_read firewall | jq -c '{before,desired,policy}') == "$(jq -c '{before,desired,policy}' <<<"$saved_before")" ]] || firewall_test::fail 'Reconciliation changed saved intent or the original baseline.'
    profiles::state | jq --exit-status '.results.firewall.status == "pending"' >/dev/null
    access::list office | jq --exit-status '.ready == false' >/dev/null
    firewall_test::probe allowed octolan 4 192.168.77.2 192.168.77.1 9000
    firewall_test::change access::dispatch recover office
    firewall_test::assert_ready
    firewall_test::web_scope allowed
    firewall_test::probe blocked octolan 4 192.168.77.2 192.168.77.1 9000
    document_before=$(profiles::state)
    external_snapshot=$(profile_controls::snapshot firewall)
    FIREWALL_TEST_CONSENT=no
    firewall_test::expect_failure firewall_test::change access::dispatch restore
    FIREWALL_TEST_CONSENT=yes
    [[ $(profile_controls::snapshot firewall) == "$external_snapshot" && $(profiles::state) == "$document_before" ]] || firewall_test::fail 'Cancelled baseline restoration changed policy or state.'
    firewall_test::change access::dispatch restore
    [[ $(ufw status) == 'Status: active'* ]] || firewall_test::fail 'Restore disabled an originally active firewall.'
    [[ $(profile_controls::_tree_hash) == "$native_before" ]] || firewall_test::fail 'Restore did not recover the original active configuration.'
    [[ ! -e $CORE_STATE/profiles/controls/firewall.json && ! -e $CORE_STATE/profiles/controls/firewall-baseline ]] || firewall_test::fail 'Active baseline restore left stale tracking.'
    firewall_test::probe allowed octolan 4 198.51.100.2 192.168.77.1 9000
    firewall_test::probe allowed octolan 6 fd42:77::2 fd42:77::1 9000
    firewall_test::web_scope blocked
    printf 'PASS: real external changes require reviewed reconciliation, reconciliation grants nothing and retains intent, explicit retry applies intent, and Restore recovers the original active IPv4/IPv6 policy\n'
    # Run the EXIT cleanup before leaving this function's dynamic local scope.
    exit 0
}

if [[ ${1-} == --isolated ]]; then
    [[ $# == 5 ]] || firewall_test::fail 'Invalid isolated invocation.'
    firewall_test::isolated "$2" "$3" "$4" "$5"
fi

[[ $# == 0 && $EUID == 0 ]] || firewall_test::fail 'Run as root in a disposable integration runner; no arguments are accepted.'
for program in unshare mount findmnt ip ufw iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore jq sysctl nc socat ss timeout; do
    command -v "$program" >/dev/null || firewall_test::fail "Missing native dependency: $program"
done
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
unshare --mount --net --pid --fork --mount-proc bash "$0" --isolated "$root" "$temporary" "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/net)"
