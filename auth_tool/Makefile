include $(TOPDIR)/rules.mk

PKG_NAME:=auth_tool
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=
PKG_MAINTAINER:=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
SRC_DIR=src
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=Applications
	CATEGORY:=Puppies
	TITLE:=auth_tool
endef

define Package/$(PKG_NAME)/description
	auth_tool
endef

define Build/Compile
	$(MAKE) -C $(SRC_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/$(PKG_NAME)/install  
	$(INSTALL_DIR) $(1)/usr/sbin 
	$(INSTALL_BIN) $(SRC_DIR)/src/auth_tool $(1)/usr/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
