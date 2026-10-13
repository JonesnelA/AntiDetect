TARGET := iphone:clang:latest:12.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AntiDetect
AntiDetect_FILES = AntiDetect.x
AntiDetect_FRAMEWORKS = Foundation UIKit
AntiDetect_CFLAGS = -fobjc-arc
# 非 bundle hook（Reachability 等）运行时解析，链接不做强校验
AntiDetect_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS_MAKE_PATH)/tweak.mk
