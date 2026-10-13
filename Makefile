TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AntiDetect
# v7: JnZ1Hub 隐身三件套复刻（fishhook 3 fns + 隐藏自身，无 ObjC hook）
AntiDetect_FILES = AntiDetect.m fishhook-lite.c
AntiDetect_FRAMEWORKS = Foundation
AntiDetect_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
