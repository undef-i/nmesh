#pragma once
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <stddef.h>
#include <stdint.h>
#define GSP_MAX 20
uint8_t *ping_bld (Cry *s, const uint8_t our_lla[16], uint64_t ts,
                   uint64_t sid, uint8_t *buf, size_t *out_len);
uint8_t *pong_bld (Cry *s, const uint8_t our_lla[16], uint64_t o_ts,
                   uint64_t sid, uint8_t *buf, size_t *out_len);
uint8_t *gsp_bld (Cry *s, const Re *rt_arr, int rt_cnt, int s_off,
                  const uint8_t our_lla[16], uint8_t *buf, size_t *out_len);
uint8_t *gsp_dt_bld (Cry *s, const Re *rt_arr, int rt_cnt,
                     const uint8_t tgt_lla[16], const uint8_t our_lla[16],
                     uint8_t *buf, size_t *out_len);
uint8_t *hp_bld (Cry *s, const uint8_t req_lla[16], const uint8_t tgt_lla[16],
                 uint8_t *buf, size_t *out_len);
uint8_t *data_bld_zc (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len,
                      uint8_t rel_f, uint8_t hop_c, size_t *out_len);
uint8_t *frag_bld_zc (Cry *s, uint8_t *chunk_ptr, size_t chunk_len,
                      uint32_t msg_id, uint16_t off, bool mf, uint8_t rel_f,
                      const uint8_t dest_tail[4], uint8_t hop_c,
                      size_t *out_len);
uint8_t *keep_bld (Cry *s, uint8_t *buf, size_t *out_len);
uint8_t *mtu_prb_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu,
                      size_t t_pl_len, uint8_t *buf, size_t *out_len);
uint8_t *mtu_ack_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu,
                      uint8_t *buf, size_t *out_len);
int pkt_dec (Cry *s, const uint8_t *raw, size_t raw_len, uint8_t *pt_buf,
             size_t pt_len, PktHdr *hdr_out, uint8_t **pt_out,
             size_t *pt_len_out);
int gsp_prs_mtu_prb (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                     uint16_t *probe_mtu);
int gsp_prs_mtu_ack (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                     uint16_t *probe_mtu);
int on_ping (const uint8_t *pt, size_t pt_len, uint64_t *o_ts, uint64_t *sid,
             uint8_t *lla);
int on_gsp (const uint8_t *pt, size_t pt_len, const uint8_t src_ip[16],
            uint16_t src_port, const uint8_t our_lla[16], Rt *rt, PPool *pool,
            uint64_t sys_ts, bool *is_mod, bool *req_seq, uint8_t seq_tgt[16]);
uint8_t *seq_req_bld (Cry *s, const uint8_t tgt_lla[16], uint8_t *buf,
                      size_t *out_len);
int on_seq_req (const uint8_t *pt, size_t pt_len, uint8_t tgt_lla[16]);
bool is_ip_bgn (const uint8_t ip[16]);
int on_hp (const uint8_t *pt, size_t pt_len, Cry *s, Udp *udp, Rt *rt,
           const uint8_t our_lla[16], uint64_t sid, uint64_t sys_ts);
