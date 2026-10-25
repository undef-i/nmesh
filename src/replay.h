#pragma once
#include "packet.h"
#include "route.h"
#include <stdbool.h>
#include <stdint.h>

bool rx_rp_chk (const uint8_t nonce[PKT_NONCE_SZ]);
bool rx_rp_cmt (const uint8_t nonce[PKT_NONCE_SZ]);
