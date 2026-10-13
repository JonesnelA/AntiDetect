TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = UnlockHelper
UnlockHelper_FILES = UnlockHelper.m
UnlockHelper_FRAMEWORKS = Foundation
UnlockHelper_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
