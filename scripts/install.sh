#!/bin/sh
# tg-exec installer: picks the package for this system (deb/rpm/apk or a plain
# binary), verifies its SHA-256 against the release SHA256SUMS and installs it.
#
#   curl -fsSL https://github.com/WithoutCowards/tg_exec/releases/latest/download/install.sh | sudo sh
#
# Environment:
#   TG_EXEC_VERSION=2.0.0   install a specific version (default: latest)
#   TG_EXEC_METHOD=binary   skip the package manager, install /usr/local/bin/tg-exec
#   TG_EXEC_PREFIX=/opt/bin where the binary goes in binary mode
# Proxies: the usual HTTPS_PROXY / ALL_PROXY variables are honoured by curl/wget.
set -eu

REPO="WithoutCowards/tg_exec"
say() { printf '%s\n' "tg-exec: $*" >&2; }
die() { say "$*"; exit 1; }

if [ -n "${TG_EXEC_VERSION:-}" ]; then
	BASE="https://github.com/${REPO}/releases/download/v${TG_EXEC_VERSION#v}"
else
	BASE="https://github.com/${REPO}/releases/latest/download"
fi

fetch() { # url file
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "need curl or wget"
	fi
}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 deb=amd64 rpm=x86_64 apk=x86_64 ;;
	aarch64 | arm64) arch=arm64 deb=arm64 rpm=aarch64 apk=aarch64 ;;
	armv7* | armv8l) arch=armv7 deb=armhf rpm=armv7hl apk=armv7 ;;
	i?86) arch=386 deb="" rpm="" apk="" ;;
	*) die "unsupported CPU: $(uname -m)" ;;
esac
case "$os" in
	linux | darwin) ;;
	*) die "unsupported OS: $os" ;;
esac

uid=$(id -u)
bindir=/usr/bin
method="${TG_EXEC_METHOD:-auto}"
asset=""
if [ "$method" = auto ] && [ "$os" = linux ] && [ "$uid" -eq 0 ]; then
	if command -v dpkg >/dev/null 2>&1 && [ -n "$deb" ]; then
		method=deb asset="tg-exec_${deb}.deb"
	elif command -v rpm >/dev/null 2>&1 && [ -n "$rpm" ]; then
		method=rpm asset="tg-exec.${rpm}.rpm"
	elif command -v apk >/dev/null 2>&1 && [ -n "$apk" ]; then
		method=apk asset="tg-exec_${apk}.apk"
	fi
fi
if [ -z "$asset" ]; then
	method=binary
	asset="tg-exec_${os}_${arch}.tar.gz"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading ${asset}"
fetch "${BASE}/${asset}" "$tmp/${asset}" || die "download failed: ${BASE}/${asset}"
fetch "${BASE}/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: SHA256SUMS"

want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "${asset} is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
	got=$(sha256sum "$tmp/${asset}" | awk '{print $1}')
else
	got=$(shasum -a 256 "$tmp/${asset}" | awk '{print $1}')
fi
[ "$want" = "$got" ] || die "checksum mismatch for ${asset}"
say "checksum OK"

case "$method" in
	deb) dpkg -i "$tmp/${asset}" >/dev/null ;;
	rpm) rpm -U --replacepkgs "$tmp/${asset}" ;;
	apk) apk add --no-network --allow-untrusted "$tmp/${asset}" >/dev/null ;;
	binary)
		tar -xzf "$tmp/${asset}" -C "$tmp"
		dir="$tmp/${asset%.tar.gz}"
		if [ -n "${TG_EXEC_PREFIX:-}" ]; then
			bindir="$TG_EXEC_PREFIX"
		elif [ "$uid" -eq 0 ]; then
			bindir=/usr/local/bin
		else
			bindir="$HOME/.local/bin"
		fi
		mkdir -p "$bindir"
		install -m 0755 "$dir/tg-exec" "$bindir/tg-exec"
		if [ "$uid" -eq 0 ] && [ "$os" = linux ]; then
			mkdir -p /etc/tg-exec
			if [ ! -f /etc/tg-exec/config.conf ]; then
				install -m 0600 "$dir/config.conf.example" /etc/tg-exec/config.conf
			fi
			if [ -d /usr/local/share/man/man1 ] || mkdir -p /usr/local/share/man/man1 2>/dev/null; then
				install -m 0644 "$dir/tg-exec.1" /usr/local/share/man/man1/tg-exec.1 || true
			fi
		fi
		case ":$PATH:" in
			*":$bindir:"*) ;;
			*) say "add $bindir to PATH" ;;
		esac
		;;
esac

say "installed: $(command -v tg-exec 2>/dev/null || echo "$bindir/tg-exec") ($(tg-exec --version 2>/dev/null || "$bindir/tg-exec" --version))"
if [ "$uid" -eq 0 ]; then
	say "next: tg-exec --setup"
else
	say "next: tg-exec --setup   (per-user config in ~/.config/tg-exec/)"
fi
