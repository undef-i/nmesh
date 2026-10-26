#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <stddef.h>
#include <stdint.h>
#define IBS_PING_PL_SZ (PING_PL_SZ + CRY_KX_PUB_SZ + 16 + IBS_CKIE_SZ)
#define IBS_PONG_PL_SZ (PONG_PL_SZ + CRY_KX_PUB_SZ + 16)
#define IBS_CKIE_PL_SZ (IBS_CKIE_SZ + IBS_CKIE_SZ)
#define IBS_PING_CKIE_OFF (IBS_PING_PL_SZ - IBS_CKIE_SZ)
uint8_t *ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                   uint64_t ts, uint64_t sid, uint64_t prb_tok, uint8_t *buf,
                   size_t *out_len);
uint8_t *pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                   uint64_t o_ts, uint64_t sid, uint64_t rx_ts,
                   uint64_t prb_tok, uint8_t *buf, size_t *out_len);
uint8_t *ibs_ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                       uint64_t ts, uint64_t sid, uint64_t prb_tok,
                       const uint8_t our_ip[16],
                       const uint8_t ckie[IBS_CKIE_SZ], uint8_t *buf,
                       size_t *out_len);
size_t ibs_ping_pl_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                        uint64_t ts, uint64_t sid, uint64_t prb_tok,
                        const uint8_t our_ip[16],
                        const uint8_t ckie[IBS_CKIE_SZ], uint8_t *pl);
void ibs_pl_hash (const uint8_t *pl, uint8_t out[IBS_CKIE_SZ]);
void ibs_ckie_calc (const uint8_t key[IBS_CKIE_SZ], const uint8_t lla[16],
                    const uint8_t ip[16], uint16_t port,
                    const uint8_t pl_hash[IBS_CKIE_SZ], uint64_t bucket,
                    uint8_t out[IBS_CKIE_SZ]);
uint8_t *ibs_pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                       uint64_t o_ts, uint64_t sid, uint64_t rx_ts,
                       uint64_t prb_tok, const uint8_t our_ip[16],
                       uint8_t *buf, size_t *out_len);
uint8_t *hp_bld (Cry *s, const uint8_t req_lla[16], const uint8_t tgt_lla[16],
                 const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len);
uint8_t *mtu_prb_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu,
                      size_t t_pl_len, const uint8_t dst_lla[16],
                      uint8_t *buf, size_t *out_len);
uint8_t *mtu_ack_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu,
                      const uint8_t dst_lla[16], uint8_t *buf,
                      size_t *out_len);
int nbr_prs_mtu_prb (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                     uint16_t *probe_mtu);
int on_ping (const uint8_t *pt, size_t pt_len, uint64_t *o_ts, uint64_t *sid,
             uint8_t *lla, uint16_t *port, uint64_t *prb_tok);
int on_pong (const uint8_t *pt, size_t pt_len, uint64_t *o_ts, uint64_t *sid,
             uint8_t *lla, uint16_t *port, uint64_t *rx_ts,
             uint64_t *prb_tok);
const uint8_t *on_ping_kx (const uint8_t *pt, size_t pt_len);
const uint8_t *on_pong_kx (const uint8_t *pt, size_t pt_len);
bool lla_inf_s (Rt *rt, const uint8_t src_ip[16], uint16_t src_port,
                uint8_t out_lla[16]);
int on_hp (const uint8_t *pt, size_t pt_len, Cry *s, Udp *udp, Rt *rt,
           const Cfg *cfg, const uint8_t our_lla[16], uint64_t sid,
           uint64_t sys_ts);
