include $(TOPDIR)/rules.mk

PKG_NAME:=xdns-bpf
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Dengfeng Liu <liudf0716@gmail.com>
PKG_LICENSE:=GPL-2.0-or-later

PKG_BUILD_DEPENDS:=bpf-headers

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/xdns-bpf
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=eBPF DNS Interception and Transparent Traffic Redirection
  DEPENDS:=+libbpf +tc-full $(BPF_DEPENDS)
  URL:=https://github.com/liudf0716/xdns-bpf
endef

define Package/xdns-bpf/description
  xdns-bpf provides kernel-level DNS interception, dynamic IP learning, and transparent
  TCP redirection using eBPF TC classifier for high-speed encrypted tunnels.
endef

define Build/Compile
	$(call Build/Compile/Default)
	$(call CompileBPF,$(PKG_BUILD_DIR)/src/xdns_bpf.c)
endef

define Package/xdns-bpf/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xdns-ctl $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/usr/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/xdns_bpf.o $(1)/usr/lib/bpf/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/xdns.conf $(1)/etc/config/xdns

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/xdns.init $(1)/etc/init.d/xdns

	$(INSTALL_DIR) $(1)/etc/xdns
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/whitelist.txt $(1)/etc/xdns/
endef

$(eval $(call BuildPackage,xdns-bpf))
