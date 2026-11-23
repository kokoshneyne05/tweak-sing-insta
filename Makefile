# InstaProxy.dylib — Jailed iOS arm64 Makefile (no CydiaSubstrate required)
# Compatible with GitHub Actions macos-latest (Xcode CLT) and Sideloadly injection.

TARGET_NAME       := InstaProxy
OUTPUT_DIR        := build
OBJ_DIR           := $(OUTPUT_DIR)/obj
DYLIB             := $(OUTPUT_DIR)/$(TARGET_NAME).dylib

SDK_PATH          := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC                := $(shell xcrun --sdk iphoneos --find clang)
CXX               := $(shell xcrun --sdk iphoneos --find clang++)

FISHHOOK_DIR      ?= third_party/fishhook
LIBBOX_XCFRAMEWORK ?= third_party/Libbox.xcframework
LIBBOX_FW_DIR     := $(LIBBOX_XCFRAMEWORK)/ios-arm64

MIN_IOS_VERSION   := 15.0

COMMON_FLAGS      := -arch arm64 \
                     -isysroot $(SDK_PATH) \
                     -miphoneos-version-min=$(MIN_IOS_VERSION) \
                     -O2 -fPIC -fvisibility=hidden \
                     -Isrc \
                     -I$(FISHHOOK_DIR) \
                     -F$(LIBBOX_FW_DIR)

CFLAGS            := $(COMMON_FLAGS) -std=c11
OBJCXXFLAGS       := $(COMMON_FLAGS) \
                     -std=c++17 \
                     -fobjc-arc \
                     -fmodules \
                     -Wno-protocol \
                     -Wno-incomplete-implementation

LDFLAGS           := -arch arm64 \
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
                     -framework Security \
                     -framework Network \
                     -framework NetworkExtension \
                     -framework SystemConfiguration \
                     -lresolv \
                     -lc++

C_SRCS            := $(FISHHOOK_DIR)/fishhook.c
MM_SRCS           := src/ProxyInterceptor.mm \
                     src/SubscriptionManager.mm \
                     src/SingBoxController.mm \
                     src/ProxySettingsUI.mm \
                     src/Tweak.mm

OBJS              := $(OBJ_DIR)/fishhook.o \
                     $(patsubst src/%.mm,$(OBJ_DIR)/%.o,$(MM_SRCS))

.PHONY: all clean verify

all: $(DYLIB)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/fishhook.o: $(FISHHOOK_DIR)/fishhook.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

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
