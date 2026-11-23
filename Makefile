# InstaProxy.dylib — Jailed iOS arm64 Makefile (no CydiaSubstrate required)
# Compatible with GitHub Actions macos-15-intel / macos-15 (Xcode CLT) and Sideloadly injection.

TARGET_NAME        := InstaProxy
OUTPUT_DIR         := build
OBJ_DIR            := $(OUTPUT_DIR)/obj
DYLIB              := $(OUTPUT_DIR)/$(TARGET_NAME).dylib

SDK_PATH           := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC                 := $(shell xcrun --sdk iphoneos --find clang)
CXX                := $(shell xcrun --sdk iphoneos --find clang++)

FISHHOOK_DIR       ?= third_party/fishhook
LIBBOX_XCFRAMEWORK ?= third_party/Libbox.xcframework
LIBBOX_FW_DIR      ?= $(shell find $(LIBBOX_XCFRAMEWORK) -maxdepth 2 -type d -name "ios-arm64*" ! -name "*simulator*" 2>/dev/null | head -n 1)

MIN_IOS_VERSION    := 15.0

COMMON_FLAGS       := -arch arm64 \
                      -isysroot $(SDK_PATH) \
                      -miphoneos-version-min=$(MIN_IOS_VERSION) \
                      -O2 -fPIC -fvisibility=hidden \
                      -Isrc \
                      -I$(FISHHOOK_DIR) \
                      -F$(LIBBOX_FW_DIR)

CFLAGS             := $(COMMON_FLAGS) -std=c11

# Pure Objective-C (.m): enables Clang modules (-fmodules) so gomobile's
# "@import Foundation;" inside Libbox.objc.h / Universe.objc.h compiles cleanly.
OBJCFLAGS          := $(COMMON_FLAGS) \
                      -fobjc-arc \
                      -fmodules \
                      -Wno-protocol \
                      -Wno-incomplete-implementation \
                      -Wno-deprecated-declarations \
                      -Wno-method-signatures \
                      -Wno-nullability-completeness

# Objective-C++ (.mm): standard C++17 without C++ modules.
OBJCXXFLAGS        := $(COMMON_FLAGS) \
                      -std=c++17 \
                      -fobjc-arc \
                      -Wno-protocol \
                      -Wno-incomplete-implementation \
                      -Wno-deprecated-declarations

LDFLAGS            := -arch arm64 \
                      -isysroot $(SDK_PATH) \
                      -miphoneos-version-min=$(MIN_IOS_VERSION) \
                      -dynamiclib \
                      -ObjC \
                      -install_name @rpath/$(TARGET_NAME).dylib \
                      -Wl,-rpath,@executable_path/Frameworks \
                      -Wl,-rpath,@loader_path \
                      -Wl,-rpath,@loader_path/Frameworks \
                      -F$(LIBBOX_FW_DIR) \
                      -framework Libbox \
                      -framework Foundation \
                      -framework UIKit \
                      -framework CFNetwork \
                      -framework CoreFoundation \
                      -framework CoreTelephony \
                      -framework Security \
                      -framework Network \
                      -framework NetworkExtension \
                      -framework SystemConfiguration \
                      -lresolv \
                      -lz \
                      -lc++

C_SRCS             := $(FISHHOOK_DIR)/fishhook.c
M_SRCS             := src/SingBoxController.m
MM_SRCS            := src/ProxyInterceptor.mm \
                      src/SubscriptionManager.mm \
                      src/ProxySettingsUI.mm \
                      src/Tweak.mm

OBJS               := $(OBJ_DIR)/fishhook.o \
                      $(patsubst src/%.m,$(OBJ_DIR)/%.o,$(M_SRCS)) \
                      $(patsubst src/%.mm,$(OBJ_DIR)/%.o,$(MM_SRCS))

.PHONY: all clean verify

all: $(DYLIB)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/fishhook.o: $(FISHHOOK_DIR)/fishhook.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: src/%.m | $(OBJ_DIR)
	$(CC) $(OBJCFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: src/%.mm | $(OBJ_DIR)
	$(CXX) $(OBJCXXFLAGS) -c $< -o $@

$(DYLIB): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@
	codesign --force --sign - $@

verify: $(DYLIB)
	lipo -info $(DYLIB)
	otool -L $(DYLIB)

clean:
	rm -rf $(OUTPUT_DIR)
