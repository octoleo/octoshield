#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Release maintenance only. The embedded CLI version remains bootstrap-safe.
set -Eeuo pipefail

version::error() {
    printf 'Version error: %s\n' "$*" >&2
    return 1
}

version::valid() {
    [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

version::one() {
    local file=$1 expression=$2
    local -a matches
    mapfile -t matches < <(sed -nE "$expression" "$file")
    ((${#matches[@]} == 1)) || {
        version::error "Expected exactly one version declaration in $file."
        return 1
    }
    printf '%s\n' "${matches[0]}"
}

version::check() {
    local root=$1 file actual url
    local -a releases images cli_versions
    for file in "${VERSION_FILES[@]}"; do
        [[ -f $root/$file && ! -L $root/$file ]] || {
            version::error "Missing or linked file: $file"
            return 1
        }
    done
    VERSION_CURRENT=$(version::one "$root/src/octoshield" 's/^readonly OCTOSHIELD_VERSION=(.*)$/\1/p') || return 1
    version::valid "$VERSION_CURRENT" || {
        version::error 'CLI version must be X.Y.Z without leading zeros.'
        return 1
    }
    actual=$(version::one "$root/src/octoshield" 's/^OctoShield ([^ ]+) — Ubuntu laptop protection$/\1/p') || return 1
    [[ $actual == "$VERSION_CURRENT" ]] || {
        version::error 'Bootstrap banner version differs from CLI.'
        return 1
    }
    mapfile -t cli_versions < <(sed -nE 's/.*OctoShield ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' "$root/src/lib/cli.sh")
    ((${#cli_versions[@]} == 3)) || {
        version::error 'Expected three CLI display versions.'
        return 1
    }
    for actual in "${cli_versions[@]}"; do
        [[ $actual == "$VERSION_CURRENT" ]] || {
            version::error 'CLI display version differs from bootstrap.'
            return 1
        }
    done
    actual=$(version::one "$root/src/ui/octoshield-gtk.c" 's/^#define OCTOSHIELD_VERSION "([^"]+)"$/\1/p') || return 1
    [[ $actual == "$VERSION_CURRENT" ]] || {
        version::error 'GUI version differs from CLI.'
        return 1
    }
    actual=$(sed -nE '1s/^octoshield \(([^)]+)\) .*$/\1/p' "$root/debian/changelog")
    [[ $actual == "$VERSION_CURRENT" ]] || {
        version::error 'Debian changelog version differs from CLI.'
        return 1
    }
    mapfile -t releases < <(sed -nE 's/^ *<release version="([^"]+)" date="[0-9]{4}-[0-9]{2}-[0-9]{2}">$/\1/p' "$root/data/io.vdm.OctoShield.metainfo.xml")
    [[ ${releases[0]:-} == "$VERSION_CURRENT" ]] || {
        version::error 'Newest AppStream release differs from CLI or has an invalid date.'
        return 1
    }
    mapfile -t images < <(sed -nE 's@^ *<image type="source">([^<]+)</image>$@\1@p' "$root/data/io.vdm.OctoShield.metainfo.xml")
    ((${#images[@]} > 0)) || {
        version::error 'AppStream screenshots are missing.'
        return 1
    }
    for url in "${images[@]}"; do
        [[ $url == "https://github.com/octoleo/octoshield/releases/download/v$VERSION_CURRENT/OctoShield-"*.png ]] || {
            version::error "Screenshot URL does not use v$VERSION_CURRENT: $url"
            return 1
        }
    done
}

version::set() (
    local root=$1 next=$2 previous=$VERSION_CURRENT temporary file identity suffix stamp release_date promoted=0
    version::valid "$next" || {
        version::error 'Expected X.Y.Z without leading zeros, prefixes, or suffixes.'
        return 1
    }
    if [[ $next == "$previous" ]]; then
        printf 'Version already %s; no files changed.\n' "$next"
        return
    fi
    [[ $(printf '%s\n' "$previous" "$next" | sort -V | tail -n 1) == "$next" ]] || {
        version::error 'The new release must be newer than the current release.'
        return 1
    }
    identity=$(awk '/^ -- / { sub(/  .*/, ""); print; exit }' "$root/debian/changelog")
    [[ $identity =~ ^\ --\ .+\ \<[^\<\>]+\>$ ]] || {
        version::error 'Cannot preserve the changelog maintainer identity.'
        return 1
    }
    IFS= read -r suffix <"$root/debian/changelog"
    suffix=${suffix#*)}
    stamp=$(LC_ALL=C date -u -R)
    release_date=$(date -u +%F)
    temporary=$(mktemp -d "$root/.octoshield-version.XXXXXXXX") || return 1
    # All output is prepared and checked before promotion. Restore originals if
    # a promotion fails or this process receives an ordinary interrupt.
    # Invoked indirectly through the EXIT trap below.
    # shellcheck disable=SC2317,SC2329
    version::cleanup() {
        local result=$? restored=1 file
        if ((result != 0 && promoted)); then
            for file in "${VERSION_FILES[@]}"; do
                if ! cp -p -- "$temporary/original/$file" "$root/$file"; then
                    restored=0
                    printf 'Could not restore %s; retained backup: %s\n' "$file" "$temporary" >&2
                fi
            done
        fi
        if ((restored)); then rm -rf -- "$temporary"; fi
        exit "$result"
    }
    trap version::cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for file in "${VERSION_FILES[@]}"; do
        mkdir -p "$temporary/original/${file%/*}" "$temporary/new/${file%/*}"
        cp -p -- "$root/$file" "$temporary/original/$file"
        cp -p -- "$root/$file" "$temporary/new/$file"
    done
    sed -E "s/^readonly OCTOSHIELD_VERSION=.*/readonly OCTOSHIELD_VERSION=$next/; s/^OctoShield [^ ]+ — Ubuntu laptop protection$/OctoShield $next — Ubuntu laptop protection/" \
        "$root/src/octoshield" >"$temporary/new/src/octoshield"
    sed -E "s/^#define OCTOSHIELD_VERSION \"[^\"]+\"$/#define OCTOSHIELD_VERSION \"$next\"/" \
        "$root/src/ui/octoshield-gtk.c" >"$temporary/new/src/ui/octoshield-gtk.c"
    sed -E "s/(OctoShield )[0-9]+\\.[0-9]+\\.[0-9]+/\\1$next/g" \
        "$root/src/lib/cli.sh" >"$temporary/new/src/lib/cli.sh"
    {
        printf 'octoshield (%s)%s\n\n  * Prepare release %s; review release notes before tagging.\n\n%s  %s\n\n' "$next" "$suffix" "$next" "$identity" "$stamp"
        cat "$root/debian/changelog"
    } >"$temporary/new/debian/changelog"
    awk -v next_version="$next" -v release_date="$release_date" '
        /<release version=/ && !inserted {
            print "    <release version=\"" next_version "\" date=\"" release_date "\">"
            print "      <description><p>Release preparation; review the release notes before publication.</p></description>"
            print "    </release>"
            inserted=1
        }
        /Captured application images are attached by/ {
            sub(/v[0-9]+\.[0-9]+\.[0-9]+/, "v" next_version)
        }
        /<image type="source">/ {
            sub(/\/releases\/download\/v[0-9]+\.[0-9]+\.[0-9]+\//, "/releases/download/v" next_version "/")
        }
        { print }
    ' "$root/data/io.vdm.OctoShield.metainfo.xml" >"$temporary/new/data/io.vdm.OctoShield.metainfo.xml"
    version::check "$temporary/new" || return 1
    for file in "${VERSION_FILES[@]}"; do
        cmp -s "$root/$file" "$temporary/original/$file" || {
            version::error "File changed during preparation; refusing to overwrite: $file"
            return 1
        }
    done
    promoted=1
    for file in "${VERSION_FILES[@]}"; do
        mv -- "$temporary/new/$file" "$root/$file" || return 1
    done
    printf 'Updated version to %s. Review the new Debian and AppStream release notes before tagging.\n' "$next"
)

version::main() {
    local root
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
    local -a VERSION_FILES=(src/octoshield src/lib/cli.sh src/ui/octoshield-gtk.c debian/changelog data/io.vdm.OctoShield.metainfo.xml)
    local VERSION_CURRENT
    case "${1:-}" in
        '') (($# == 0)) || return 2 ;;
        --check) (($# <= 2)) || return 2 ;;
        --set) (($# == 2)) || {
            version::error 'Usage: scripts/version.sh --set X.Y.Z'
            return 2
        } ;;
        *)
            version::error 'Usage: scripts/version.sh [--check [vX.Y.Z] | --set X.Y.Z]'
            return 2
            ;;
    esac
    version::check "$root" || return 1
    case "${1:-}" in
        '') printf '%s\n' "$VERSION_CURRENT" ;;
        --check)
            if (($# == 2)) && [[ $2 != "v$VERSION_CURRENT" ]]; then
                version::error "Release tag must be v$VERSION_CURRENT."
                return 1
            fi
            printf 'Version %s is consistent.\n' "$VERSION_CURRENT"
            ;;
        --set) version::set "$root" "$2" ;;
    esac
}

version::main "$@"
