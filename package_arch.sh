#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="$(git describe --tags --match "0.09.*" --abbrev=0 2>/dev/null || echo 0.09.12)"
BUILDDATE=$(date +%s)
DIST_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

echo "=== 正在构建 xdns-bpf (${VERSION}) ==="
cmake -B build -S .
cmake --build build -j$(nproc)

PKGDIR="/tmp/arch_xdns_bpf"
rm -rf "$PKGDIR"
mkdir -p "$PKGDIR/usr/bin"
mkdir -p "$PKGDIR/usr/lib/bpf"
mkdir -p "$PKGDIR/etc/xdns"

cp build/xdns-ctl "$PKGDIR/usr/bin/"
cp build/xdns_bpf.o "$PKGDIR/usr/lib/bpf/"

cat << 'DOM' > "$PKGDIR/etc/xdns/domains.conf"
# xdns-bpf 加速域名列表 (支持子域名自动泛解析与动态 IP 学习)
github.com
githubusercontent.com
anthropic.com
claude.ai
openai.com
oaistatic.com
x.ai
grok.com
DOM

cat << PKGINFO > "$PKGDIR/.PKGINFO"
pkgname = xdns-bpf
pkgbase = xdns-bpf
pkgver = ${VERSION}-1
pkgdesc = eBPF transparent socket DNS and TCP acceleration for Omarchy/Arch
url = https://github.com/liudf0716/xdns-bpf
builddate = ${BUILDDATE}
packager = liudf0716 <liudf0716@gmail.com>
size = 230000
arch = x86_64
license = GPL2
depend = bpftool
backup = etc/xdns/domains.conf
PKGINFO

cd "$PKGDIR"
tar --zstd -cf "$DIST_DIR/xdns-bpf-${VERSION}-1-x86_64.pkg.tar.zst" .PKGINFO etc usr
rm -rf "$PKGDIR"
echo "已生成 Omarchy/Arch 安装包: $DIST_DIR/xdns-bpf-${VERSION}-1-x86_64.pkg.tar.zst"
