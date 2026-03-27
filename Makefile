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

CFLAGS_BASE = -std=gnu11 -Wall -Wextra -Iext/uthash/src \
		-DSODIUM_STATIC -DCONFIG_H_IS_NOT_HERE -D_GNU_SOURCE \
		-march=x86-64 -DMODERN_CHACHA20 -DNATIVE_LITTLE_ENDIAN \
		-DHAVE_CPUID -DHAVE_MMINTRIN_H -DHAVE_EMMINTRIN_H -DHAVE_PMMINTRIN_H \
		-DHAVE_TMMINTRIN_H -DHAVE_SMMINTRIN_H -DHAVE_AVXINTRIN_H -DHAVE_AVX2INTRIN_H \
		-DHAVE_WMMINTRIN_H -DHAVE_IMMINTRIN_H -DHAVE_TI_MODE -DHAVE_GETXBV \
		-DHAVE_PCLMUL_INTRIN -DHAVE_AVX_INTRIN -DHAVE_ADXINTRIN_H -DHAVE_RDRAND

CFLAGS_APP = $(CFLAGS_BASE) -Isrc -I$(LIBSODIUM_INC) -I$(LIBSODIUM_INC)/sodium
CFLAGS_LIB = $(CFLAGS_BASE) -I$(LIBSODIUM_INC) -I$(LIBSODIUM_INC)/sodium

LDFLAGS_COMMON = -static

CFLAGS_RELEASE = -O3 -flto -ffunction-sections -fdata-sections \
		 -fomit-frame-pointer -fno-asynchronous-unwind-tables \
		 -fno-stack-protector -fno-ident -fmerge-all-constants
LDFLAGS_RELEASE = -flto -s -Wl,--gc-sections -Wl,--build-id=none \
		  -Wl,-z,norelro -Wl,--no-export-dynamic

CFLAGS_DEBUG = -g -O0 -DDEBUG
LDFLAGS_DEBUG =

OBJS_REL = $(patsubst %.c,$(BUILD_DIR)/release/%.o,$(SRCS))
OBJS_DBG = $(patsubst %.c,$(BUILD_DIR)/debug/%.o,$(SRCS))

all: release

release: $(BUILD_DIR)/release/$(TARGET_NAME)

debug: $(BUILD_DIR)/debug/$(TARGET_NAME)

$(BUILD_DIR)/release/$(TARGET_NAME): $(OBJS_REL)
	$(CC) $(OBJS_REL) -o $@ $(LDFLAGS_COMMON) $(LDFLAGS_RELEASE)

$(BUILD_DIR)/debug/$(TARGET_NAME): $(OBJS_DBG)
	$(CC) $(OBJS_DBG) -o $@ $(LDFLAGS_COMMON) $(LDFLAGS_DEBUG)

$(BUILD_DIR)/release/src/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_APP) $(CFLAGS_RELEASE) -c $< -o $@

$(BUILD_DIR)/debug/src/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_APP) $(CFLAGS_DEBUG) -c $< -o $@

$(BUILD_DIR)/release/ext/%.o: ext/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_LIB) $(CFLAGS_RELEASE) -c $< -o $@

$(BUILD_DIR)/debug/ext/%.o: ext/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_LIB) $(CFLAGS_DEBUG) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean debug release