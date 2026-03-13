CC = musl-gcc
CFLAGS = -O3 -std=gnu11 -Wall -Wextra -ffunction-sections -fdata-sections -Iext/monocypher/src -Iext/uthash/src
LDFLAGS = -static -Wl,--gc-sections -s -Wl,--build-id=none

BUILD_DIR = build
TARGET = $(BUILD_DIR)/nmesh

SRCS = $(wildcard src/*.c) ext/monocypher/src/monocypher.c
OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SRCS)))

vpath %.c src ext/monocypher/src

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean