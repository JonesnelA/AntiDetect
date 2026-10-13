TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AntiDetect
AntiDetect_FILES = AntiDetect.m fishhook-lite.c
AntiDetect_FRAMEWORKS = Foundation UIKit CoreFoundation
AntiDetect_CFLAGS = -fobjc-arc -Wno-unused-variable
# 不链接 substrate（无 Logos）；工具链默认 classic bind（无 chained fixups）
AntiDetect_LDFLAGS =

include $(THEOS_MAKE_PATH)/tweak.mk
