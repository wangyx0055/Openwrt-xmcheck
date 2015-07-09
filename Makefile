include $(TOPDIR)/rules.mk

PKG_NAME:=xmcheck
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/xmcheck
	SECTION:=base
	CATEGORY:=xmcheck
	TITLE:= xmcheck
endef

define Package/xmcheck/description
	wan type
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Package/xmcheck/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xmcheck $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,xmcheck))
