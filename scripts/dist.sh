#!/usr/bin/env bash
# Build release artifacts into dist/: tarballs, deb/rpm/apk packages, SHA256SUMS.
# Asset names carry no version, so .../releases/latest/download/<name> stays stable.
#
#   VERSION=2.0.0 scripts/dist.sh        (nfpm must be in PATH for packages)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-dev}"
NFPM="${NFPM:-nfpm}"
LDFLAGS="-s -w -X main.version=${VERSION}"

rm -rf dist build
mkdir -p dist build
gzip -9n -c man/tg-exec.1 > build/tg-exec.1.gz

# goos goarch goarm  name  deb   rpm      apk
TARGETS=(
	"linux amd64 -  linux_amd64  amd64 x86_64  x86_64"
	"linux arm64 -  linux_arm64  arm64 aarch64 aarch64"
	"linux arm   7  linux_armv7  armhf armv7hl armv7"
	"linux 386   -  linux_386    -     -       -"
	"darwin amd64 - darwin_amd64 -     -       -"
	"darwin arm64 - darwin_arm64 -     -       -"
)

for t in "${TARGETS[@]}"; do
	read -r goos goarch goarm name deb rpm apk <<<"$t"
	out="build/${name}"
	mkdir -p "$out"
	echo "==> ${name}"
	env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="${goarm/-/}" \
		go build -trimpath -ldflags "$LDFLAGS" -o "$out/tg-exec" ./cmd/tg-exec

	pkgdir="build/pkg/tg-exec_${name}"
	mkdir -p "$pkgdir"
	cp "$out/tg-exec" README.md CHANGELOG.md LICENSE "$pkgdir/"
	cp man/tg-exec.1 "$pkgdir/"
	cp internal/config/default.conf "$pkgdir/config.conf.example"
	tar -C build/pkg -czf "dist/tg-exec_${name}.tar.gz" --owner=0 --group=0 "tg-exec_${name}"

	[ "$goos" = linux ] && [ "$deb" != - ] || continue
	nfarch="$goarch"
	[ "$goarch" = arm ] && nfarch="arm7"
	cp "$out/tg-exec" build/tg-exec
	export VERSION ARCH="$nfarch"
	"$NFPM" pkg -f packaging/nfpm.yaml -p deb -t "dist/tg-exec_${deb}.deb" >/dev/null
	"$NFPM" pkg -f packaging/nfpm.yaml -p rpm -t "dist/tg-exec.${rpm}.rpm" >/dev/null
	"$NFPM" pkg -f packaging/nfpm.yaml -p apk -t "dist/tg-exec_${apk}.apk" >/dev/null
done

cp scripts/install.sh dist/install.sh
(cd dist && sha256sum -- * > SHA256SUMS)
echo "==> dist/"
ls -l dist
