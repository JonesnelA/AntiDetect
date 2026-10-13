TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AntiDetect
# v3: 仅 ObjC swizzle，无 fishhook（消除 GOT 审计痕迹）
AntiDetect_FILES = AntiDetect.m
AntiDetect_FRAMEWORKS = Foundation UIKit CoreFoundation
AntiDetect_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
