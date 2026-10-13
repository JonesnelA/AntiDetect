TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AntiDetect
AntiDetect_FILES = AntiDetect.m fishhook-lite.c
AntiDetect_FRAMEWORKS = Foundation UIKit CoreFoundation
AntiDetect_CFLAGS = -fobjc-arc -Wno-unused-variable
# 关键：禁用 chained fixups，保证 classic bind 可被 fishhook-lite 重绑定；
# 不链接 substrate（无 Logos）
AntiDetect_LDFLAGS = -Wl,-no_fixup_chains

include $(THEOS_MAKE_PATH)/tweak.mk
