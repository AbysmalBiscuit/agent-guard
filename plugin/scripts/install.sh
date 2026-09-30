#!/usr/bin/env bash
# Installs the tools agent-guard runs but does not ship: uv, and fallow for the
# changeset audit. A tool already on PATH is left alone.
set -euo pipefail

BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
FALLOW_RELEASES="https://github.com/fallow-rs/fallow/releases/latest/download"
# fallow's release signing key, as published in its SECURITY.md (raw key
# 834e6fd77333e6eedf779347c710acb403d2d8234d559f5ed7c87e552ade0bd1).
FALLOW_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAg05v13Mz5u7fd5NHxxCstAPS2CNNVZ9e18h+VSreC9E=
-----END PUBLIC KEY-----"

say() { printf 'agent-guard: %s\n' "$*"; }
die() {
	say "$*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null || die "$1 is required to install ${2}"
}

install_uv() {
	if command -v uv >/dev/null; then
		say "uv found at $(command -v uv)"
		return
	fi
	need curl uv
	say "installing uv"
	curl -LsSf https://astral.sh/uv/install.sh | sh
}

fallow_asset() {
	local os arch libc=gnu
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "no fallow build for $(uname -s); see https://github.com/fallow-rs/fallow" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=x64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "no fallow build for $(uname -m)" ;;
	esac
	if [[ $os == darwin ]]; then
		printf 'fallow-darwin-%s\n' "$arch"
		return
	fi
	if ldd --version 2>&1 | grep -qi musl; then
		libc=musl
	fi
	printf 'fallow-linux-%s-%s\n' "$arch" "$libc"
}

install_fallow() {
	if command -v fallow >/dev/null; then
		say "fallow found at $(command -v fallow)"
		return
	fi
	need curl fallow
	need openssl "fallow's signed binary"
	local asset tmp
	asset="$(fallow_asset)"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN

	say "installing fallow ($asset) to $BIN_DIR"
	curl -fsSL -o "$tmp/$asset" "$FALLOW_RELEASES/$asset"
	curl -fsSL -o "$tmp/$asset.sig" "$FALLOW_RELEASES/$asset.sig"
	printf '%s\n' "$FALLOW_PUBLIC_KEY" >"$tmp/key.pem"
	openssl pkeyutl -verify -pubin -inkey "$tmp/key.pem" -rawin \
		-in "$tmp/$asset" -sigfile "$tmp/$asset.sig" >/dev/null 2>&1 ||
		die "signature check failed for $asset; this needs OpenSSL 3, or install fallow with: npm install -g fallow"

	mkdir -p "$BIN_DIR"
	install -m 755 "$tmp/$asset" "$BIN_DIR/fallow"
	case ":$PATH:" in
	*":$BIN_DIR:"*) ;;
	*) say "add $BIN_DIR to PATH so the hooks can find fallow" ;;
	esac
}

install_uv
install_fallow
