#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Tests use an isolated fake prefix; they never install packages or alter the host.
# Bats recreates setup variables for every test; assignments are intentionally local.
# shellcheck disable=SC1091,SC2317,SC2329,SC2030,SC2031

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/install.sh"
    export CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$CALLS"
    export OCTOSHIELD_ROOT="$BATS_TEST_TMPDIR/source"
    INSTALL_LIBRARY="$BATS_TEST_TMPDIR/lib"
    INSTALL_EXECUTABLES="$BATS_TEST_TMPDIR/bin"
    export CORE_TRANSACTION=test
    export FAIL=
    mkdir -p "$OCTOSHIELD_ROOT" "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES"
    local file
    while IFS= read -r file; do
        mkdir -p "$(dirname "$OCTOSHIELD_ROOT/$file")"
        printf '# fixture\n' >"$OCTOSHIELD_ROOT/$file"
    done < <(install::files)
    core::require_root() { [[ $FAIL != root ]]; }
    core::begin() { printf 'begin\n' >>"$CALLS"; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::log() { printf '%s\n' "$*"; }
    core::record() { printf 'record %s\n' "$*" >>"$CALLS"; }
    core::install_packages() {
        printf 'packages %s\n' "$*" >>"$CALLS"
        [[ $FAIL != packages ]]
    }
}

mock_install_environment() {
    install::safe_directory() { [[ -d $1 && ! -L $1 ]]; }
    install::stage() {
        printf 'stage\n' >>"$CALLS"
        [[ $FAIL != stage ]] || return 1
        printf 'new program\n' >"$2/new-program"
    }
    chown() { :; }
    mv() {
        if [[ $FAIL == promote && ${*: -1} == "$INSTALL_LIBRARY/octoshield" && $* == *'.octoshield-install.'* && $* != *'.previous'* ]]; then
            return 1
        fi
        if [[ $FAIL == launcher && ${*: -1} == "$INSTALL_EXECUTABLES/octoshield" ]]; then return 1; fi
        command mv "$@"
    }
}

mock_bootstrap_download() {
    export BOOTSTRAP_SOURCE="$BATS_TEST_DIRNAME/../src/octoshield"
    export BOOTSTRAP_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    export TMPDIR="$BATS_TEST_TMPDIR/downloads"
    mkdir "$TMPDIR"
    cp "$BOOTSTRAP_SOURCE" "$BATS_TEST_TMPDIR/standalone"
    curl() {
        local url='' destination='' relative
        while (($#)); do
            case "$1" in
                https://*)
                    url=$1
                    shift
                    ;;
                --output)
                    destination=$2
                    shift 2
                    ;;
                *) shift ;;
            esac
        done
        printf 'curl %s\n' "$url" >>"$CALLS"
        if [[ $url == https://api.github.com/* ]]; then
            [[ $FAIL != resolve ]] || return 22
            printf '%s\n' "$BOOTSTRAP_SHA"
            return
        fi
        [[ $FAIL != download ]] || return 22
        relative=${url#https://raw.githubusercontent.com/octoleo/octoshield/*/}
        case "$relative" in
            src/octoshield) cp "$BOOTSTRAP_SOURCE" "$destination" ;;
            src/lib/cli.sh)
                # shellcheck disable=SC2016 # Expand only when the downloaded fixture is run.
                printf '%s\n' 'cli::main() { printf "executed %s\\n" "$*" >>"$CALLS"; }' >"$destination"
                ;;
            *) printf '# fixture\n' >"$destination" ;;
        esac
    }
    export -f curl
}

@test 'source initialization ignores inherited install destination overrides' {
    INSTALL_LIBRARY=/unsafe
    INSTALL_EXECUTABLES=/unsafe
    source "$BATS_TEST_DIRNAME/../src/lib/install.sh"
    [ "$INSTALL_LIBRARY" = /usr/local/lib ]
    [ "$INSTALL_EXECUTABLES" = /usr/local/bin ]
    [ ! -s "$CALLS" ]
}

@test 'complete source manifest validates' {
    run install::validate_source "$OCTOSHIELD_ROOT"
    [ "$status" -eq 0 ]
}

@test 'missing runtime module rejects installation before any package changes' {
    rm "$OCTOSHIELD_ROOT/src/lib/usb.sh"
    run install::run
    [ "$status" -ne 0 ]
    [ ! -s "$CALLS" ]
    [[ $output == *'Missing or linked source file'* ]]
}

@test 'a symlink source file is rejected' {
    rm "$OCTOSHIELD_ROOT/src/monitor.c"
    ln -s "$OCTOSHIELD_ROOT/LICENSE" "$OCTOSHIELD_ROOT/src/monitor.c"
    run install::validate_source "$OCTOSHIELD_ROOT"
    [ "$status" -ne 0 ]
}

@test 'a symlink source ancestor is rejected even for regular leaf files' {
    mv "$OCTOSHIELD_ROOT/src/lib" "$OCTOSHIELD_ROOT/modules"
    ln -s "$OCTOSHIELD_ROOT/modules" "$OCTOSHIELD_ROOT/src/lib"
    run install::validate_source "$OCTOSHIELD_ROOT"
    [ "$status" -ne 0 ]
    [[ $output == *'Linked source directory'* ]]
}

@test 'source root must not itself be a symlink' {
    ln -s "$OCTOSHIELD_ROOT" "$BATS_TEST_TMPDIR/linked-source"
    run install::validate_source "$BATS_TEST_TMPDIR/linked-source"
    [ "$status" -ne 0 ]
}

@test 'directory safety rejects writable directories and non-root owners' {
    export TEST_OWNER=0 TEST_MODE=755
    stat() { if [[ $2 == %u ]]; then printf '%s\n' "$TEST_OWNER"; else printf '%s\n' "$TEST_MODE"; fi; }
    run install::safe_directory "$INSTALL_LIBRARY"
    [ "$status" -eq 0 ]
    TEST_MODE=775
    run install::safe_directory "$INSTALL_LIBRARY"
    [ "$status" -ne 0 ]
    TEST_MODE=755 TEST_OWNER=1000
    run install::safe_directory "$INSTALL_LIBRARY"
    [ "$status" -ne 0 ]
}

@test 'insufficient privilege makes no changes' {
    FAIL=root
    run install::run
    [ "$status" -ne 0 ]
    [ ! -s "$CALLS" ]
}

@test 'unsafe destination symlink is rejected before package installation' {
    mock_install_environment
    ln -s "$OCTOSHIELD_ROOT" "$INSTALL_LIBRARY/octoshield"
    run install::run
    [ "$status" -ne 0 ]
    [ ! -s "$CALLS" ]
}

@test 'package installation failure leaves the old installation untouched' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    FAIL=packages
    run install::run
    [ "$status" -ne 0 ]
    [ "$(cat "$INSTALL_LIBRARY/octoshield/old-program")" = original ]
    [ "$(find "$INSTALL_LIBRARY" -maxdepth 1 -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'failed compilation cleans staging and preserves the previous installation' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    FAIL=stage
    run install::run
    [ "$status" -ne 0 ]
    [ "$(cat "$INSTALL_LIBRARY/octoshield/old-program")" = original ]
    [ "$(find "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES" -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'directory promotion failure restores the old tree' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    FAIL=promote
    run install::run
    [ "$status" -ne 0 ]
    [ "$(cat "$INSTALL_LIBRARY/octoshield/old-program")" = original ]
    [ "$(find "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES" -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'launcher promotion failure rolls the library back and preserves the old launcher' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    printf 'old launcher\n' >"$INSTALL_EXECUTABLES/octoshield"
    FAIL=launcher
    run install::run
    [ "$status" -ne 0 ]
    [ "$(cat "$INSTALL_LIBRARY/octoshield/old-program")" = original ]
    [ "$(cat "$INSTALL_EXECUTABLES/octoshield")" = 'old launcher' ]
    [ "$(find "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES" -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'launcher write failure propagates with errexit suppressed and preserves the previous program' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    printf 'old launcher\n' >"$INSTALL_EXECUTABLES/octoshield"
    cat() { return 1; }
    conditional_install() {
        if install::run; then return 0; else return 1; fi
    }
    run conditional_install
    [ "$status" -ne 0 ]
    [ "$(command cat "$INSTALL_LIBRARY/octoshield/old-program")" = original ]
    [ "$(command cat "$INSTALL_EXECUTABLES/octoshield")" = 'old launcher' ]
    [ "$(find "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES" -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'a failed first installation does not leave a partially installed program' {
    mock_install_environment
    FAIL=launcher
    run install::run
    [ "$status" -ne 0 ]
    [ ! -e "$INSTALL_LIBRARY/octoshield" ]
    [ ! -e "$INSTALL_EXECUTABLES/octoshield" ]
}

@test 'successful upgrade installs a fixed launcher and removes the previous tree' {
    mock_install_environment
    mkdir "$INSTALL_LIBRARY/octoshield"
    printf 'original\n' >"$INSTALL_LIBRARY/octoshield/old-program"
    run install::run
    [ "$status" -eq 0 ]
    [ -f "$INSTALL_LIBRARY/octoshield/new-program" ]
    [ ! -e "$INSTALL_LIBRARY/octoshield/old-program" ]
    [ -x "$INSTALL_EXECUTABLES/octoshield" ]
    # shellcheck disable=SC2016 # This is the launcher's literal argv forwarding.
    grep -Fx 'exec /usr/bin/bash /usr/local/lib/octoshield/src/octoshield "$@"' "$INSTALL_EXECUTABLES/octoshield"
    [ "$(find "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES" -name '.octoshield*' | wc -l)" -eq 0 ]
}

@test 'standalone bootstrap help and version do not require modules or the network' {
    cp "$BATS_TEST_DIRNAME/../src/octoshield" "$BATS_TEST_TMPDIR/standalone"
    run bash "$BATS_TEST_TMPDIR/standalone" --help
    [ "$status" -eq 0 ]
    [[ $output == *'Usage: octoshield'* ]]
    run bash "$BATS_TEST_TMPDIR/standalone" --version
    [ "$status" -eq 0 ]
    [ "$output" = 'Octoshield 0.1.0' ]
}

@test 'standalone bootstrap rejects unsupported arguments without network activity' {
    cp "$BATS_TEST_DIRNAME/../src/octoshield" "$BATS_TEST_TMPDIR/standalone"
    run bash "$BATS_TEST_TMPDIR/standalone" unsupported
    [ "$status" -eq 2 ]
    [[ $output == *'install it first'* ]]
}

@test 'staging clears compiler environment and uses fixed hardened compiler arguments' {
    local stage="$BATS_TEST_TMPDIR/stage"
    mkdir "$stage"
    install() {
        local -a args=()
        while (($#)); do
            case "$1" in
                -o | -g) shift 2 ;;
                *)
                    args+=("$1")
                    shift
                    ;;
            esac
        done
        command install "${args[@]}"
    }
    env() {
        printf '%s\n' "$*" >>"$CALLS"
        : >"${*: -1}"
    }
    export CC=/hostile/compiler CFLAGS='-include /hostile/header'
    run install::stage "$OCTOSHIELD_ROOT" "$stage"
    [ "$status" -eq 0 ]
    grep -F -- '-i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now' "$CALLS"
    [ -x "$stage/src/octoshield" ]
    [ -x "$stage/src/notify.sh" ]
    [ -x "$stage/bin/octoshield-monitor" ]
    [ -r "$stage/src/lib/usb.sh" ]
}

@test 'bootstrap pins every downloaded file to one commit and cleans its temporary checkout' {
    mock_bootstrap_download
    run bash "$BATS_TEST_TMPDIR/standalone"
    [ "$status" -eq 0 ]
    [ "$(grep -c "^curl https://raw.githubusercontent.com/octoleo/octoshield/$BOOTSTRAP_SHA/" "$CALLS")" -eq "$(install::files | wc -l)" ]
    grep -Fx 'executed install' "$CALLS"
    [ "$(find "$TMPDIR" -mindepth 1 | wc -l)" -eq 0 ]
}

@test 'bootstrap rejects invalid commit responses before downloading or executing source' {
    mock_bootstrap_download
    BOOTSTRAP_SHA=not-a-commit
    run bash "$BATS_TEST_TMPDIR/standalone"
    [ "$status" -ne 0 ]
    [ "$(wc -l <"$CALLS")" -eq 1 ]
    [[ $output == *'valid immutable commit'* ]]
}

@test 'bootstrap failure offers authenticated checkout instructions for a private repository' {
    mock_bootstrap_download
    FAIL=resolve
    run bash "$BATS_TEST_TMPDIR/standalone"
    [ "$status" -ne 0 ]
    [[ $output == *'gh repo clone octoleo/octoshield'* ]]
    [ "$(wc -l <"$CALLS")" -eq 1 ]
}

@test 'bootstrap never executes an incomplete download and removes temporary files' {
    mock_bootstrap_download
    FAIL=download
    run bash "$BATS_TEST_TMPDIR/standalone"
    [ "$status" -ne 0 ]
    run grep -q '^executed' "$CALLS"
    [ "$status" -eq 1 ]
    [ "$(find "$TMPDIR" -mindepth 1 | wc -l)" -eq 0 ]
}
