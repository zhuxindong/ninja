# Copyright (C) 2023 gngpp <gngppz@gmail.com>

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ninja
PKG_VERSION:=1.1.0

PKG_MAINTAINER:=gngpp <gngppz@gmail.com>

LUCI_TITLE:=LuCI support for Ninja
LUCI_DEPENDS:=+ninja
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] || {
	( . /etc/uci-defaults/luci-ninja ) && rm -f /etc/uci-defaults/luci-ninja
	exit 0
}
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature