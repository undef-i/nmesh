#pragma once
#include "udp.h"
#include "crypto.h"
#include "route.h"
#include "config.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool rel_fwd_dat(Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                 const uint8_t dest_lla[16], const uint8_t *vnet_frame,
                 size_t vnet_len, uint8_t hop_c, uint64_t ts,
                 const uint8_t src_ip[16], uint16_t src_port);

bool relay_fwd_frag(Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                    const uint8_t dest_lla[16], uint32_t mid, uint16_t frag_off,
                    bool mf_in, const uint8_t *chunk, size_t chunk_len,
                    uint8_t hop_c, uint64_t ts, const uint8_t s_ip[16],
                    uint16_t s_port);