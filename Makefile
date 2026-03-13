CC = musl-gcc
TARGET_NAME = nmesh
BUILD_DIR = build

SRCS = $(wildcard src/*.c) ext/monocypher/src/monocypher.c
vpath %.c src ext/monocypher/src

CFLAGS_COMMON = -std=gnu11 -Wall -Wextra -Iext/monocypher/src -Iext/uthash/src
LDFLAGS_COMMON = -static

CFLAGS_RELEASE = -Os -flto -ffunction-sections -fdata-sections \
                 -fno-asynchronous-unwind-tables -fno-stack-protector \
                 -fno-ident -fmerge-all-constants
LDFLAGS_RELEASE = -flto -Wl,--gc-sections -s -Wl,--build-id=none \
                  -Wl,-z,norelro -Wl,--no-export-dynamic

CFLAGS_DEBUG = -g -O0 -DDEBUG
LDFLAGS_DEBUG = 

OBJS_REL = $(patsubst %.c,$(BUILD_DIR)/release/%.o,$(notdir $(SRCS)))
OBJS_DBG = $(patsubst %.c,$(BUILD_DIR)/debug/%.o,$(notdir $(SRCS)))

all: release

release: $(BUILD_DIR)/release/$(TARGET_NAME)

debug: $(BUILD_DIR)/debug/$(TARGET_NAME)

$(BUILD_DIR)/release/$(TARGET_NAME): $(OBJS_REL)
	$(CC) $(OBJS_REL) -o $@ $(LDFLAGS_COMMON) $(LDFLAGS_RELEASE)

$(BUILD_DIR)/debug/$(TARGET_NAME): $(OBJS_DBG)
	$(CC) $(OBJS_DBG) -o $@ $(LDFLAGS_COMMON) $(LDFLAGS_DEBUG)

$(BUILD_DIR)/release/%.o: %.c | $(BUILD_DIR)/release
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_RELEASE) -c $< -o $@

$(BUILD_DIR)/debug/%.o: %.c | $(BUILD_DIR)/debug
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) -c $< -o $@

$(BUILD_DIR)/release $(BUILD_DIR)/debug:
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean debug release