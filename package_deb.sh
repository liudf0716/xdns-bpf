#!/bin/bash
set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="$(git describe --tags --match "0.09.*" --abbrev=0 2>/dev/null || echo 0.09.12)"
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

echo "=== 正在构建 xdns-bpf (${VERSION}) ==="
cmake -B build -S .
cmake --build build -j$(nproc)

DIST_DIR="$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

echo "=== 打包 xdns-bpf ==="
PKG_DIR="/tmp/pkg_xdns_bpf"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/local/bin"
mkdir -p "$PKG_DIR/usr/lib/bpf"
mkdir -p "$PKG_DIR/etc/xdns"

# 安装可执行文件与 eBPF 对象
cp build/xdns-ctl "$PKG_DIR/usr/local/bin/"
cp build/xdns_bpf.o "$PKG_DIR/usr/lib/bpf/"

# 预设常用 AI / 开发加速域名清单模板
cat << 'DOMAINS' > "$PKG_DIR/etc/xdns/domains.conf"
# xdns-bpf 常用加速域名列表 (每行一个，支持子域名自动加速)
github.com
githubusercontent.com
anthropic.com
claude.ai
openai.com
oaistatic.com
x.ai
grok.com
DOMAINS

# deb control 信息
cat << CTRL > "$PKG_DIR/DEBIAN/control"
Package: xdns-bpf
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: liudf0716 <liudf0716@gmail.com>
Depends: libc6, bpftool
Description: eBPF transparent socket DNS and TCP acceleration for Linux/Omarchy
CTRL

# 标记配置文件
echo "/etc/xdns/domains.conf" > "$PKG_DIR/DEBIAN/conffiles"

# 构建 deb
DEB_FILE="$DIST_DIR/xdns-bpf_${VERSION}_${ARCH}.deb"
dpkg-deb --build "$PKG_DIR" "$DEB_FILE"
echo "已生成 xdns-bpf 安装包: $DEB_FILE"

# 清理临时目录
rm -rf "$PKG_DIR"
echo "=== xdns-bpf deb 安装包生成完毕 ==="
