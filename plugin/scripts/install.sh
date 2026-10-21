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

say "installing tools from ${MISE_CONFIG}"
mise -C "$PLUGIN_ROOT" install
say "installed $(mise -C "$PLUGIN_ROOT" which fallow)"
