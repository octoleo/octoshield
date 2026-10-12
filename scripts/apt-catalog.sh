#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build native APT catalog metadata; the caller hashes/signs it in Release.
set -Eeuo pipefail
IFS=$' \t\n'
umask 022

# Reuse the release assembler's read-only PNG header validation.
# shellcheck source=release-assets.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/release-assets.sh"

apt_catalog::error() {
    printf 'APT catalog: %s\n' "$*" >&2
    return 1
}

apt_catalog::directory() {
    if [[ -e $1 || -L $1 ]]; then
        [[ -d $1 && ! -L $1 ]] || {
            apt_catalog::error "Refusing non-directory or symlink: $1"
            return 1
        }
    else
        mkdir -m 0755 -- "$1" || return 1
    fi
}

# Suites share versioned media. A second suite may reuse exactly the same bytes,
# but an existing release's media must never silently change or follow symlinks.
apt_catalog::media() {
    local source=$1 destination=$2
    if [[ -e $destination || -L $destination ]]; then
        if [[ ! -f $destination || -L $destination ]] || ! cmp -s -- "$source" "$destination"; then
            apt_catalog::error "Existing media differs or is not a regular file: $destination"
            return 1
        fi
    else
        install -m 0644 -- "$source" "$destination" || return 1
    fi
}

apt_catalog::xml() {
    local assets=$1 suite=$2 url=$3 version=$4 dimensions=$5 output=$6
    # XML is parsed and serialized, never edited with shell substitution. Python
    # is a release-build dependency only; the installed application does not use it.
    python3 - "$assets" "$suite" "$url" "$version" "$dimensions" "$output" <<'PY'
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

assets, suite, url, version, dimensions_path, output = sys.argv[1:]
try:
    raw = (Path(assets) / "data/io.vdm.OctoShield.metainfo.xml").read_bytes()
    if len(raw) > 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("oversized metadata or document type/entity declarations")
    component = ET.fromstring(raw)
    if (component.tag != "component" or component.get("type") != "desktop-application"
            or component.findtext("id") != "io.vdm.OctoShield"):
        raise ValueError("metadata does not describe the OctoShield desktop application")
    release = component.find("releases/release")
    if release is None or release.get("version") != version:
        raise ValueError("latest metadata release differs from the package version")
    dimensions = json.loads(Path(dimensions_path).read_text())
    # Installation source and icon belong to this repository's catalog, not to
    # the upstream metainfo. Other upstream content remains unchanged.
    for tag in ("pkgname", "source_pkgname", "bundle", "icon"):
        for child in component.findall(tag):
            component.remove(child)
    ET.SubElement(component, "pkgname").text = "octoshield"
    icon_name = "OctoShield-light.png"
    width, height = dimensions[icon_name]
    ET.SubElement(component, "icon", {
        "type": "remote", "width": str(width), "height": str(height)
    }).text = f"{url}/media/v{version}/{icon_name}"
    images = component.findall("screenshots/screenshot/image")
    if not images:
        raise ValueError("metadata has no screenshots")
    for image in images:
        name = (image.text or "").rsplit("/", 1)[-1]
        if name not in dimensions or name in ("OctoShield-light.png", "OctoShield-dark.png"):
            raise ValueError("screenshot is not one of the bundled application captures")
        width, height = dimensions[name]
        image.text = f"{url}/media/v{version}/{name}"
        image.set("width", str(width))
        image.set("height", str(height))
    catalog = ET.Element("components", {
        "version": "1.0", "origin": f"octoshield-{suite}-main", "architecture": "amd64"
    })
    catalog.append(component)
    ET.indent(catalog, space="  ")
    ET.ElementTree(catalog).write(output, encoding="utf-8", xml_declaration=True)
except (OSError, ValueError, ET.ParseError, KeyError) as error:
    print(f"APT catalog: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

apt_catalog::main() (
    [[ $# -eq 5 ]] || {
        apt_catalog::error 'Usage: scripts/apt-catalog.sh REPOSITORY_DIR ASSETS_DIR SUITE HTTPS_URL VERSION'
        return 2
    }
    local repository=$1 assets=$2 suite=$3 url=${4%/} version=$5
    local tool file page theme name measured width height stage directory record
    local -a names=() records=()
    local -A sources=()
    [[ $suite == noble || $suite == resolute ]] || {
        apt_catalog::error 'Unsupported Ubuntu suite'
        return 1
    }
    [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
        apt_catalog::error 'Expected a release version in X.Y.Z form'
        return 1
    }
    # Public media must be addressable without credentials, query strings or
    # fragments. example.invalid is reserved for the caller's unsigned tests.
    if [[ ! $url =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$ ]] ||
        [[ $url == */../* || $url == */.. || $url == */./* || $url == */. ]]; then
        apt_catalog::error 'Expected an HTTPS repository URL without credentials or unsafe path segments'
        return 1
    fi
    for tool in appstreamcli python3 jq gzip od cmp install mktemp realpath; do
        command -v "$tool" >/dev/null || {
            apt_catalog::error "Required tool unavailable: $tool"
            return 1
        }
    done
    [[ -d $repository && ! -L $repository && -d $assets && ! -L $assets ]] || {
        apt_catalog::error 'Repository and assets must be existing non-symlink directories'
        return 1
    }
    repository=$(realpath -e -- "$repository") || return 1
    assets=$(realpath -e -- "$assets") || return 1
    for file in manifest.json data/io.vdm.OctoShield.metainfo.xml; do
        release_assets::require_file "$assets/$file" || return 1
    done
    jq -e --arg version "$version" '.application_id == "io.vdm.OctoShield" and .version == $version' \
        "$assets/manifest.json" >/dev/null || {
        apt_catalog::error 'Assets do not match the package version/application'
        return 1
    }
    for page in overview protections usb office monitoring recovery; do
        for theme in light dark; do
            name="OctoShield-$page-$theme.png"
            names+=("$name")
            sources[$name]="$assets/gallery/$name"
        done
    done
    for theme in light dark; do
        name="OctoShield-$theme.png"
        names+=("$name")
        sources[$name]="$assets/branding/$name"
    done
    for name in "${names[@]}"; do
        measured=$(release_assets::png_dimensions "${sources[$name]}") || return 1
        read -r width height <<<"$measured"
        record=$(jq -cn --arg name "$name" --argjson width "$width" --argjson height "$height" \
            '{key:$name,value:[$width,$height]}') || return 1
        records+=("$record")
    done
    stage=$(mktemp -d "$repository/.octoshield-catalog.XXXXXXXX") || return 1
    # Only remove the private directory returned by mktemp, never a caller path.
    trap 'rm -rf -- "$stage"' EXIT
    printf '%s\n' "${records[@]}" | jq -s from_entries >"$stage/dimensions.json" || return 1
    apt_catalog::xml "$assets" "$suite" "$url" "$version" "$stage/dimensions.json" "$stage/Components-amd64.xml" || return 1
    appstreamcli validate --no-net "$stage/Components-amd64.xml" >&2 || return 1
    appstreamcli convert "$stage/Components-amd64.xml" "$stage/Components-amd64.yml" >&2 || return 1
    # Read the emitted DEP-11 back through the official parser before signing.
    appstreamcli convert "$stage/Components-amd64.yml" "$stage/roundtrip.xml" >&2 || return 1
    appstreamcli validate --no-net "$stage/roundtrip.xml" >&2 || return 1
    gzip -n -9 -c "$stage/Components-amd64.yml" >"$stage/Components-amd64.yml.gz" || return 1
    for directory in "$repository/dists" "$repository/dists/$suite" "$repository/dists/$suite/main" \
        "$repository/dists/$suite/main/dep11" "$repository/media" "$repository/media/v$version"; do
        apt_catalog::directory "$directory" || return 1
    done
    directory="$repository/dists/$suite/main/dep11"
    for file in Components-amd64.xml Components-amd64.yml Components-amd64.yml.gz; do
        [[ ! -e $directory/$file && ! -L $directory/$file ]] || {
            apt_catalog::error "Catalog already exists: $directory/$file"
            return 1
        }
    done
    for name in "${names[@]}"; do
        apt_catalog::media "${sources[$name]}" "$repository/media/v$version/$name" || return 1
    done
    for file in Components-amd64.xml Components-amd64.yml Components-amd64.yml.gz; do
        install -m 0644 -- "$stage/$file" "$directory/$file" || return 1
    done
    printf 'Created OctoShield %s %s AppStream catalog and unchanged release media.\n' "$version" "$suite"
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then apt_catalog::main "$@"; fi
