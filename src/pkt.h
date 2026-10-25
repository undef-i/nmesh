#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <stddef.h>
#include <stdint.h>
uint8_t *pkt_enc_psk (Cry *s, const uint8_t hdr[PKT_CH_SZ],
                      const uint8_t *payload, size_t pl_len, uint8_t *buf,
                      size_t *out_len);
uint8_t *pkt_enc_to (Cry *s, const uint8_t dst_lla[16],
                     const uint8_t hdr[PKT_CH_SZ], const uint8_t *payload,
                     size_t pl_len, uint8_t *buf, size_t *out_len);
void hdr_bld (uint8_t pkt_type, uint8_t rel_f, uint8_t hop_c,
              uint8_t hdr[PKT_CH_SZ]);
uint8_t *data_bld_zc_cnt (Cry *s, uint8_t *ipv6_ptr_start,
                          size_t ipv6_len, uint8_t rel_f, uint8_t hop_c,
                          uint64_t cnt, const uint8_t dst_lla[16],
                          size_t *out_len);
uint8_t *data_bld_zc (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len,
                      uint8_t rel_f, uint8_t hop_c,
                      const uint8_t dst_lla[16], size_t *out_len);
uint8_t *frag_bld_zc (Cry *s, uint8_t *chunk_ptr, size_t chunk_len,
                      uint32_t msg_id, size_t off, bool mf, uint8_t rel_f,
                      const uint8_t dest_tail[4], uint8_t hop_c,
                      const uint8_t dst_lla[16], size_t *out_len);
uint8_t *stat_req_bld (Cry *s, uint32_t req_id, const uint8_t dst_lla[16],
                       uint8_t *buf, size_t *out_len);
uint8_t *stat_rsp_bld (Cry *s, uint32_t req_id, uint64_t total_len,
                       uint64_t off, const uint8_t *chunk, size_t chunk_len,
                       const uint8_t dst_lla[16], uint8_t *buf,
                       size_t *out_len);
int pkt_dec (Cry *s, uint8_t *raw, size_t raw_len, uint8_t *pt_buf,
             size_t pt_len, PktHdr *hdr_out, uint8_t **pt_out,
             size_t *pt_len_out);
int pkt_dec_from (Cry *s, const uint8_t src_lla[16], uint8_t *raw,
                  size_t raw_len, uint8_t *pt_buf, size_t pt_len,
                  PktHdr *hdr_out, uint8_t **pt_out, size_t *pt_len_out,
                  bool allow_psk_fallback, bool *used_psk,
                  uint8_t matched_lla[16]);
int pkt_prs_stat_req (const uint8_t *pt, size_t pt_len, uint32_t *req_id);
int pkt_prs_stat_rsp (const uint8_t *pt, size_t pt_len, uint32_t *req_id,
                      uint64_t *off, uint64_t *total_len,
                      const uint8_t **chunk, size_t *chunk_len);
