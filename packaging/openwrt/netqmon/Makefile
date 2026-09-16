include $(TOPDIR)/rules.mk

PKG_NAME:=netqmon-agent
PKG_VERSION:=0.1.0-beta.9
PKG_RELEASE:=1

PKG_MAINTAINER:=netqmon Authors
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/netqmon-agent
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NetQMon eBPF network telemetry agent
  URL:=https://github.com/jarvis2f/netqmon
  DEPENDS:=+kmod-sched-core +kmod-sched-bpf +libelf +zlib
endef

define Package/netqmon-agent/description
  High-performance OpenWrt eBPF network telemetry agent for traffic analysis,
  device discovery, flow metrics, and DNS observation.
endef

define Package/netqmon-agent/conffiles
/etc/config/netqmon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	@agent_bin=""; \
	case "$(ARCH)" in \
		x86_64) \
			agent_bin="netqmon-agent_x86_64" ;; \
		aarch64*) \
			agent_bin="netqmon-agent_aarch64" ;; \
		riscv64*) \
			agent_bin="netqmon-agent_riscv64" ;; \
		mipsel*|mipsel_24kc|mipsel_74kc|mipsel_24kc_24kf) \
			agent_bin="netqmon-agent_mipsel32r2" ;; \
		arm*) \
			if [ "$(CONFIG_HAS_FPU)" = "y" ] || [ "$(CONFIG_SOFT_FLOAT)" != "y" ] || echo "$(TARGET_CROSS)" | grep -q "hf"; then \
				agent_bin="netqmon-agent_armv7hf"; \
			else \
				agent_bin="netqmon-agent_armv7"; \
			fi ;; \
		*) \
			agent_bin="netqmon-agent_$(ARCH)" ;; \
	esac; \
	copied=0; \
	for candidate in \
		"$(TOPDIR)/feeds/action/netqmon/bin/$$$${agent_bin}" \
		"/feed/netqmon/bin/$$$${agent_bin}" \
		"/feed/bin/$$$${agent_bin}" \
		"$(PKG_BUILD_DIR)/bin/$$$${agent_bin}" \
		"./bin/$$$${agent_bin}" \
		"./bin/netqmon-agent" \
		"$(TOPDIR)/feeds/action/bin/$$$${agent_bin}" \
		"$(TOPDIR)/bin/$$$${agent_bin}"; do \
		if [ -f "$$$$candidate" ]; then \
			cp "$$$$candidate" $(PKG_BUILD_DIR)/netqmon-agent; \
			chmod 0755 $(PKG_BUILD_DIR)/netqmon-agent; \
			copied=1; \
			echo "Found prebuilt agent binary ($$$${agent_bin}) at $$$$candidate"; \
			break; \
		fi; \
	done; \
	if [ "$$$$copied" -ne 1 ]; then \
		echo "Error: Precompiled binary for $(ARCH) ($$$${agent_bin}) not found" >&2; \
		exit 1; \
	fi
endef

define Build/Compile
	# precompiled binary
endef

define Package/netqmon-agent/install

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/netqmon-agent $(1)/usr/bin/netqmon-agent
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/netqmon $(1)/etc/config/netqmon
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/netqmon $(1)/etc/init.d/netqmon
endef

define Package/netqmon-agent/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/netqmon enable
	/etc/init.d/netqmon start
}
exit 0
endef

define Package/netqmon-agent/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/netqmon stop
	/etc/init.d/netqmon disable
}
exit 0
endef

$(eval $(call BuildPackage,netqmon-agent))
