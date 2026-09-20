include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for NetQMon Agent
LUCI_DEPENDS:=+netqmon-agent +rpcd +jsonfilter

PKG_NAME:=luci-app-netqmon
PKG_VERSION:=0.1.0-beta.10
PKG_RELEASE:=1
PKG_MAINTAINER:=netqmon Authors
PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
