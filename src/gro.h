#pragma once
#include <stddef.h>
#include <stdint.h>

void gro_fls_all (int tap_fd);
uint64_t gro_drop_get (void);
void gro_fed (int tap_fd, const uint8_t *vnet_frm, size_t vnet_len);