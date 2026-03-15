CC = musl-gcc
TARGET_NAME = nmesh
BUILD_DIR = build

LIBSODIUM_DIR = ext/libsodium/src/libsodium
LIBSODIUM_INC = $(LIBSODIUM_DIR)/include
LIBSODIUM_SRCS = $(shell find $(LIBSODIUM_DIR) -name "*.c" \
                -not -path "*/armcrypto/*" \
                -not -path "*/sandy2x/fe51_ns.c" \
                -not -path "*/wasm32/*")

SRCS = $(wildcard src/*.c) $(LIBSODIUM_SRCS)
vpath %.c src $(shell find $(LIBSODIUM_DIR) -type d)

CFLAGS_COMMON = -std=gnu11 -Wall -Wextra -Isrc -I$(LIBSODIUM_INC) -I$(LIBSODIUM_INC)/sodium -Iext/uthash/src \
                -DSODIUM_STATIC -DCONFIG_H_IS_NOT_HERE -D_GNU_SOURCE \
                -march=x86-64 -DMODERN_CHACHA20 -DNATIVE_LITTLE_ENDIAN \
                -DHAVE_CPUID -DHAVE_MMINTRIN_H -DHAVE_EMMINTRIN_H -DHAVE_PMMINTRIN_H \
                -DHAVE_TMMINTRIN_H -DHAVE_SMMINTRIN_H -DHAVE_AVXINTRIN_H -DHAVE_AVX2INTRIN_H \
                -DHAVE_WMMINTRIN_H -DHAVE_IMMINTRIN_H -DHAVE_TI_MODE -DHAVE_GETXBV \
                -DHAVE_PCLMUL_INTRIN -DHAVE_AVX_INTRIN -DHAVE_ADXINTRIN_H -DHAVE_RDRAND
LDFLAGS_COMMON = -static

CFLAGS_RELEASE = -O3 -flto -ffunction-sections -fdata-sections \
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