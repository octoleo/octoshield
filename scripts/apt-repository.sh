#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build public repository files only; never configure or install into this host.
# Disable tracing before reading secret environment values, including under bash -x.
set +x +a
set -Eeuo pipefail
IFS=$' \t\n'
umask 077

aptrepo::error() {
    printf 'APT repository: %s\n' "$*" >&2
    return 1
}

aptrepo::usage() {
    cat <<'HELP'
Usage: bash scripts/apt-repository.sh --input DIR --assets DIR --output NEW_DIR

Input must contain the two matching OctoShield Ubuntu 24.04/26.04 amd64 release
packages. Assets must be the matching scripts/release-assets.sh output.

Without signing credentials, output is marked UNSIGNED-TEST-ONLY and must not be
published as an installable repository. Signed publication requires:
  APT_SIGNING_KEY              ASCII-armored private signing key (secret)
  APT_SIGNING_PASSPHRASE       Optional private-key passphrase (secret)
  APT_SIGNING_KEY_FINGERPRINT  Expected full uppercase primary fingerprint
  APT_REPOSITORY_URL           Public HTTPS repository base URL
No key is generated, no repository is uploaded, and no system settings change.
HELP
}

aptrepo::inputs() {
    local input=$1 file name version ubuntu suite actual
    local -a packages
    shopt -s nullglob
    packages=("$input"/*.deb)
    shopt -u nullglob
    ((${#packages[@]} == 2)) || {
        aptrepo::error 'Exactly two release .deb files are required.'
        return 1
    }
    for file in "${packages[@]}"; do
        [[ -f $file && ! -L $file ]] || {
            aptrepo::error 'Package inputs must be regular, unlinked files.'
            return 1
        }
        name=${file##*/}
        [[ $name =~ ^octoshield_([0-9]+\.[0-9]+\.[0-9]+)_ubuntu(24\.04|26\.04)_amd64\.deb$ ]] || {
            aptrepo::error "Unexpected release package filename: $name"
            return 1
        }
        version=${BASH_REMATCH[1]} ubuntu=${BASH_REMATCH[2]}
        [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
        if [[ $ubuntu == 24.04 ]]; then suite=noble; else suite=resolute; fi
        [[ -z ${APT_PACKAGES[$suite]:-} ]] || {
            aptrepo::error "Duplicate $suite package."
            return 1
        }
        actual=$(dpkg-deb --field "$file" Package)
        [[ $actual == octoshield ]] || {
            aptrepo::error "Unexpected binary package in $name."
            return 1
        }
        actual=$(dpkg-deb --field "$file" Architecture)
        [[ $actual == amd64 ]] || {
            aptrepo::error "Unexpected architecture in $name."
            return 1
        }
        actual=$(dpkg-deb --field "$file" Version)
        [[ $actual == "$version" ]] || {
            aptrepo::error "Filename/control version mismatch: $name"
            return 1
        }
        [[ -z $APT_VERSION || $APT_VERSION == "$version" ]] || {
            aptrepo::error 'Ubuntu packages must have the same version.'
            return 1
        }
        APT_VERSION=$version
        APT_PACKAGES[$suite]=$file
    done
    [[ -n ${APT_PACKAGES[noble]:-} && -n ${APT_PACKAGES[resolute]:-} ]] || {
        aptrepo::error 'Both supported Ubuntu releases are required.'
        return 1
    }
}

aptrepo::indices() (
    local repository=$1 assets=$2 url=$3 script_root=$4 suite file
    cd -- "$repository"
    for suite in noble resolute; do
        file=${APT_PACKAGES[$suite]}
        install -D -m 0644 -- "$file" "pool/$suite/main/o/octoshield/${file##*/}"
        mkdir -p "dists/$suite/main/binary-amd64"
        apt-ftparchive --md5=false --sha1=false packages "pool/$suite" >"dists/$suite/main/binary-amd64/Packages"
        gzip -n -9 -c "dists/$suite/main/binary-amd64/Packages" >"dists/$suite/main/binary-amd64/Packages.gz"
        bash "$script_root/apt-catalog.sh" "$repository" "$assets" "$suite" "$url" "$APT_VERSION"
        [[ -s dists/$suite/main/dep11/Components-amd64.yml.gz ]] || {
            aptrepo::error "Missing application catalog for $suite."
            return 1
        }
        # Generate outside dists to avoid including a partial Release in itself.
        apt-ftparchive --md5=false --sha1=false \
            -o APT::FTPArchive::Release::Origin=OctoShield \
            -o 'APT::FTPArchive::Release::Label=Vast Development Method' \
            -o "APT::FTPArchive::Release::Suite=$suite" \
            -o "APT::FTPArchive::Release::Codename=$suite" \
            -o APT::FTPArchive::Release::Architectures=amd64 \
            -o APT::FTPArchive::Release::Components=main \
            -o 'APT::FTPArchive::Release::Description=OctoShield native packages and application metadata' \
            release "dists/$suite" >"release-$suite.tmp"
        mv -- "release-$suite.tmp" "dists/$suite/Release"
        grep -Fq 'main/dep11/Components-amd64.yml.gz' "dists/$suite/Release" || {
            aptrepo::error "Application catalog is absent from $suite release hashes."
            return 1
        }
    done
)

aptrepo::sign() {
    local repository=$1 keyhome=$2 fingerprint=$3 passphrase=$4 suite actual
    local -a primary_keys public_keys
    mapfile -t primary_keys < <(gpg --no-options --batch --homedir "$keyhome" --with-colons --fingerprint --list-secret-keys 2>/dev/null |
        awk -F: '$1=="sec" {primary=1; next} primary && $1=="fpr" {print $10; primary=0}')
    mapfile -t public_keys < <(gpg --no-options --batch --homedir "$keyhome" --with-colons --fingerprint --list-keys 2>/dev/null |
        awk -F: '$1=="pub" {primary=1; next} primary && $1=="fpr" {print $10; primary=0}')
    [[ ${#primary_keys[@]} == 1 && ${#public_keys[@]} == 1 && ${primary_keys[0]} == "$fingerprint" && ${public_keys[0]} == "$fingerprint" ]] || {
        aptrepo::error 'Signing material must contain exactly the expected private primary key and no other primary keys.'
        return 1
    }
    gpg --no-options --batch --homedir "$keyhome" --export "$fingerprint" >"$repository/octoshield-archive-keyring.gpg"
    gpg --no-options --batch --homedir "$keyhome" --armor --export "$fingerprint" >"$repository/octoshield-archive-keyring.asc"
    [[ -s $repository/octoshield-archive-keyring.gpg && -s $repository/octoshield-archive-keyring.asc ]] || return 1
    printf '%s\n' "$fingerprint" >"$repository/octoshield-archive-keyring.fingerprint"
    for suite in noble resolute; do
        for actual in clearsign detach-sign; do
            local destination="$repository/dists/$suite/InRelease"
            if [[ $actual == detach-sign ]]; then destination="$repository/dists/$suite/Release.gpg"; fi
            # The passphrase travels on stdin, never on the command line.
            if ! printf '%s\n' "$passphrase" | gpg --no-options --batch --no-tty --homedir "$keyhome" \
                --pinentry-mode loopback --passphrase-fd 0 --local-user "$fingerprint" \
                --armor --digest-algo SHA256 --output "$destination" "--$actual" "$repository/dists/$suite/Release" \
                2>"$keyhome/signing.log"; then
                aptrepo::error 'Signing failed; check the private key, passphrase, expiry, and signing capability.'
                return 1
            fi
        done
        gpgv --homedir "$keyhome" --keyring "$repository/octoshield-archive-keyring.gpg" \
            "$repository/dists/$suite/InRelease" >/dev/null 2>"$keyhome/verify.log" || return 1
        gpgv --homedir "$keyhome" --keyring "$repository/octoshield-archive-keyring.gpg" \
            "$repository/dists/$suite/Release.gpg" "$repository/dists/$suite/Release" >/dev/null 2>"$keyhome/verify.log" || return 1
    done
}

aptrepo::main() (
    local signing_key=${APT_SIGNING_KEY:-} passphrase=${APT_SIGNING_PASSPHRASE:-}
    export -n signing_key passphrase
    unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE
    local fingerprint=${APT_SIGNING_KEY_FINGERPRINT:-} url=${APT_REPOSITORY_URL:-}
    local input='' assets='' output='' work='' keyhome='' script_root tool signed=false suite
    local APT_VERSION=''
    local -A APT_PACKAGES=()
    while (($#)); do
        case $1 in
            --input | --assets | --output)
                [[ $# -ge 2 && -n ${2:-} ]] || {
                    aptrepo::usage >&2
                    return 2
                }
                case $1 in
                    --input)
                        [[ -z $input ]] || return 2
                        input=$2
                        ;;
                    --assets)
                        [[ -z $assets ]] || return 2
                        assets=$2
                        ;;
                    --output)
                        [[ -z $output ]] || return 2
                        output=$2
                        ;;
                esac
                shift 2
                ;;
            --help)
                aptrepo::usage
                return
                ;;
            *)
                aptrepo::usage >&2
                return 2
                ;;
        esac
    done
    [[ -n $input && -n $assets && -n $output ]] || {
        aptrepo::usage >&2
        return 2
    }
    if [[ -n $signing_key || -n $passphrase || -n $fingerprint ]]; then
        [[ -n $signing_key && $fingerprint =~ ^[A-F0-9]{40}$ && -n $url ]] || {
            aptrepo::error 'Signing requires a private key, full uppercase primary fingerprint, and HTTPS repository URL.'
            return 1
        }
        [[ $passphrase != *$'\n'* && $passphrase != *$'\r'* ]] || {
            aptrepo::error 'Passphrases must be a single line.'
            return 1
        }
        signed=true
    fi
    if [[ -n $url ]]; then
        [[ $url =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] || {
            aptrepo::error 'Repository URL must be HTTPS without credentials, query, fragment, or whitespace.'
            return 1
        }
        url=${url%/}
    else
        url=https://example.invalid/octoshield
    fi
    for tool in apt-ftparchive dpkg-deb gzip install realpath sha256sum; do
        command -v "$tool" >/dev/null || {
            aptrepo::error "Missing build tool: $tool"
            return 1
        }
    done
    [[ -d $input && -d $assets && ! -L $input && ! -L $assets ]] || {
        aptrepo::error 'Input and assets must be regular directories.'
        return 1
    }
    [[ ! -e $output && ! -L $output ]] || {
        aptrepo::error 'Output already exists; choose a new directory.'
        return 1
    }
    input=$(realpath -e -- "$input")
    assets=$(realpath -e -- "$assets")
    output=$(realpath -m -- "$output")
    [[ -d ${output%/*} && ! -e $output && ! -L $output ]] || {
        aptrepo::error 'Output parent must exist; output must be new.'
        return 1
    }
    script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    [[ -f $script_root/apt-catalog.sh && ! -L $script_root/apt-catalog.sh ]] || {
        aptrepo::error 'Missing catalog builder.'
        return 1
    }
    aptrepo::inputs "$input" || return 1
    work=$(mktemp -d "${output%/*}/.octoshield-apt.XXXXXXXX")
    # Only our own freshly created staging directory is removed on failure.
    # shellcheck disable=SC2317,SC2329
    aptrepo::cleanup() {
        local result=$?
        if [[ -n $keyhome ]]; then gpgconf --homedir "$keyhome" --kill gpg-agent >/dev/null 2>&1 || :; fi
        rm -rf -- "$work"
        exit "$result"
    }
    trap aptrepo::cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir "$work/repository"
    aptrepo::indices "$work/repository" "$assets" "$url" "$script_root"
    if [[ $signed == true ]]; then
        for tool in gpg gpgv gpgconf; do command -v "$tool" >/dev/null || {
            aptrepo::error "Missing signing tool: $tool"
            return 1
        }; done
        keyhome="$work/gnupg"
        mkdir -m 0700 "$keyhome"
        if ! printf '%s\n' "$signing_key" | gpg --no-options --batch --no-tty --homedir "$keyhome" --quiet --import \
            >/dev/null 2>"$keyhome/import.log"; then
            aptrepo::error 'Cannot import the supplied signing key.'
            return 1
        fi
        signing_key=''
        aptrepo::sign "$work/repository" "$keyhome" "$fingerprint" "$passphrase"
        passphrase=''
        for suite in noble resolute; do
            printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/octoshield-archive-keyring.gpg\n' \
                "$url" "$suite" >"$work/repository/octoshield-$suite.sources"
        done
    else
        printf 'UNSIGNED TEST ARTIFACT. Do not publish or configure APT to trust this repository.\n' >"$work/repository/UNSIGNED-TEST-ONLY"
    fi
    printf 'OctoShield %s native APT repository\nPublisher: Vast Development Method (https://www.vdm.io)\nSuites: noble (Ubuntu 24.04), resolute (Ubuntu 26.04); architecture: amd64\nSigned: %s\nRepository URL: %s\n\nUse the documented Signed-By keyring enrollment after independently checking the signing fingerprint.\nNever use trusted=yes or disable signature checks. Installing this repository does not apply security controls.\n' \
        "$APT_VERSION" "$signed" "$url" >"$work/repository/README.txt"
    cat >"$work/repository/index.html" <<HTML
<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OctoShield native APT repository</title>
<style>body{font:18px/1.6 system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem}code{overflow-wrap:anywhere}</style>
<main><h1>OctoShield $APT_VERSION</h1>
<p>Native GNOME laptop security controls and a terminal interface, maintained by
<a href="https://www.vdm.io">Vast Development Method</a> as part of Octoleo.</p>
<p>This repository supplies application packages and metadata for Ubuntu 24.04 (noble)
and Ubuntu 26.04 (resolute), on amd64. Installing the application does not apply protections.</p>
<ul><li><a href="pool/noble/main/o/octoshield/${APT_PACKAGES[noble]##*/}">Ubuntu 24.04 package</a></li>
<li><a href="pool/resolute/main/o/octoshield/${APT_PACKAGES[resolute]##*/}">Ubuntu 26.04 package</a></li>
<li><a href="https://github.com/octoleo/octoshield/blob/main/docs/distribution.md">Installation, updates, and removal</a></li>
<li><a href="README.txt">Repository details</a></li></ul>
HTML
    if [[ $signed == true ]]; then
        cat >>"$work/repository/index.html" <<HTML
<h2>Repository authentication</h2><p>Verify this signing-key fingerprint against the publisher's independently trusted documentation before adding the repository:</p>
<p><code>$fingerprint</code></p>
<p><a href="octoshield-archive-keyring.asc">Public key (armored)</a> · <a href="octoshield-archive-keyring.gpg">Public key (binary)</a></p>
<p>After verification and key installation, select the matching source configuration:
<a href="octoshield-noble.sources">Ubuntu 24.04</a> or <a href="octoshield-resolute.sources">Ubuntu 26.04</a>.</p>
HTML
    else
        printf '<h2>Unsigned test artifact</h2><p>This build is for inspection only. It is not an authenticated installable repository.</p>\n' >>"$work/repository/index.html"
    fi
    printf '</main></html>\n' >>"$work/repository/index.html"
    (
        cd "$work/repository"
        # shellcheck disable=SC2094
        find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
    )
    find "$work/repository" -type d -exec chmod 0755 {} +
    find "$work/repository" -type f -exec chmod 0644 {} +
    mv -T --no-clobber -- "$work/repository" "$output"
    [[ ! -d $work/repository ]] || {
        aptrepo::error 'Output appeared during build; it was not overwritten.'
        return 1
    }
    printf 'Created OctoShield %s APT repository (signed=%s): %s\n' "$APT_VERSION" "$signed" "$output"
)

aptrepo::main "$@"
