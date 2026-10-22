#!/usr/bin/env bash
# Installs the tools agent-guard runs but does not ship, at the versions in
# plugin/mise.toml. mise installs them. A copy already on PATH does not win:
# mise installs the pin anyway.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MISE_CONFIG="${PLUGIN_ROOT}/mise.toml"

say() { printf 'agent-guard: %s\n' "$*"; }
die() {
	say "$*" >&2
	exit 1
}

if ! command -v mise >/dev/null 2>&1; then
	die "mise is not on PATH; install mise, then run this script again"
fi
if [ ! -f "$MISE_CONFIG" ]; then
	die "mise config missing: ${MISE_CONFIG}"
fi

# An older mise fails each locked pin as "not in the lockfile", which hides
# the cause.
required=$(sed -n 's/^min_version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$MISE_CONFIG")
found=$(mise --version 2>/dev/null | awk 'NR == 1 { print $1 }')
if [ -n "$required" ] && [ "$(printf '%s\n%s\n' "$required" "$found" | sort -V | head -1)" != "$required" ]; then
	die "the plugin needs mise ${required} or newer, found ${found:-an unknown version}; run \`mise self-update\`, then run this script again"
fi

export MISE_TRUSTED_CONFIG_PATHS="${MISE_TRUSTED_CONFIG_PATHS:+${MISE_TRUSTED_CONFIG_PATHS}:}${PLUGIN_ROOT}"

# The [settings] of mise.toml win over the machine's config files, but not
# over its MISE_* variables. These win over both.
export MISE_GITHUB_ATTESTATIONS=true MISE_GITHUB_GITHUB_ATTESTATIONS=true
export MISE_AQUA_GITHUB_ATTESTATIONS=true
export MISE_LOCKFILE=true MISE_LOCKED_VERIFY_PROVENANCE=true
# Locked mode fails a pin with no lock entry.
export MISE_LOCKED=true MISE_LOCKED_SCOPES=project

# A bare `mise install` also installs the tools of every other config mise
# loads, such as the user's global one. Name this config's tools instead.
mapfile -t tools < <(mise -C "$PLUGIN_ROOT" ls --local | awk '{ print $1 }')
if [ "${#tools[@]}" -eq 0 ]; then
	die "mise lists no tools in ${MISE_CONFIG}"
fi

say "installing tools from ${MISE_CONFIG}"
mise -C "$PLUGIN_ROOT" install "${tools[@]}"
say "installed $(mise -C "$PLUGIN_ROOT" which fallow)"
