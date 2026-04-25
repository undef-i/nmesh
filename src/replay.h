#pragma once
#include "packet.h"
#include "route.h"
#include <stdbool.h>
#include <stdint.h>

bool rx_rp_chk (const uint8_t nonce[PKT_NONCE_SZ]);
void rx_rp_rst_ep (const uint8_t ip[16], uint16_t port);
void rx_rp_rst_lla (Rt *rt, const uint8_t lla[16]);
