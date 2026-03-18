#pragma once
#include <stddef.h>
#include <stdint.h>

void gro_fls_all(int tap_fd);
void gro_fed(int tap_fd, const uint8_t *vnet_frm, size_t vnet_len);