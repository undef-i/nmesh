#include "pkt.h"
#include "packet.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t
u64_rd (const uint8_t *s)
{
  return ((uint64_t)s[0] << 56) | ((uint64_t)s[1] << 48)
         | ((uint64_t)s[2] << 40) | ((uint64_t)s[3] << 32)
         | ((uint64_t)s[4] << 24) | ((uint64_t)s[5] << 16)
         | ((uint64_t)s[6] << 8) | (uint64_t)s[7];
}

static uint32_t
u32_rd (const uint8_t *s)
{
  return ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16)
         | ((uint32_t)s[2] << 8) | (uint32_t)s[3];
}

static void
u64_wr (uint8_t *dst, uint64_t v)
{
  dst[0] = (uint8_t)(v >> 56);
  dst[1] = (uint8_t)(v >> 48);
  dst[2] = (uint8_t)(v >> 40);
  dst[3] = (uint8_t)(v >> 32);
  dst[4] = (uint8_t)(v >> 24);
  dst[5] = (uint8_t)(v >> 16);
  dst[6] = (uint8_t)(v >> 8);
  dst[7] = (uint8_t)(v);
}

static void
u16_wr (uint8_t *dst, uint16_t v)
{
  dst[0] = (uint8_t)(v >> 8);
  dst[1] = (uint8_t)v;
}

static void
u32_wr (uint8_t *dst, uint32_t v)
{
  dst[0] = (uint8_t)(v >> 24);
  dst[1] = (uint8_t)(v >> 16);
  dst[2] = (uint8_t)(v >> 8);
  dst[3] = (uint8_t)v;
}

void
hdr_bld (uint8_t pkt_type, uint8_t rel_f, uint8_t hop_c,
         uint8_t hdr[PKT_CH_SZ])
{
  hdr[0] = (uint8_t)(pkt_type & PKT_TF_TYPE_MASK);
  if (rel_f != 0)
    hdr[0] |= PKT_TF_REL;
  hdr[1] = hop_c;
}

uint8_t *
pkt_enc_psk (Cry *s, const uint8_t hdr[PKT_CH_SZ], const uint8_t *payload,
             size_t pl_len, uint8_t *buf, size_t *out_len)
{
  if (!s)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t nonce[PKT_NONCE_SZ], mac[PKT_MAC_SZ];
  uint8_t *ct_ptr = buf + PKT_NONCE_SZ + PKT_MAC_SZ;
  memcpy (ct_ptr, hdr, PKT_CH_SZ);
  memcpy (ct_ptr + PKT_CH_SZ, payload, pl_len);
  cry_enc (s, ct_ptr, pl_len + PKT_CH_SZ, NULL, 0, nonce, mac, ct_ptr);
  memcpy (buf, nonce, PKT_NONCE_SZ);
  memcpy (buf + PKT_NONCE_SZ, mac, PKT_MAC_SZ);
  *out_len = PKT_HDR_SZ + pl_len;
  return buf;
}

uint8_t *
pkt_enc_to (Cry *s, const uint8_t dst_lla[16], const uint8_t hdr[PKT_CH_SZ],
            const uint8_t *payload, size_t pl_len, uint8_t *buf,
            size_t *out_len)
{
  if (!cry_peer_ready (s, dst_lla))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t nonce[PKT_NONCE_SZ], mac[PKT_MAC_SZ];
  uint8_t *ct_ptr = buf + PKT_NONCE_SZ + PKT_MAC_SZ;
  memcpy (ct_ptr, hdr, PKT_CH_SZ);
  memcpy (ct_ptr + PKT_CH_SZ, payload, pl_len);
  if (cry_enc_to (s, dst_lla, ct_ptr, pl_len + PKT_CH_SZ, NULL, 0, nonce,
                  mac, ct_ptr)
      != 0)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  memcpy (buf, nonce, PKT_NONCE_SZ);
  memcpy (buf + PKT_NONCE_SZ, mac, PKT_MAC_SZ);
  *out_len = PKT_HDR_SZ + pl_len;
  return buf;
}

uint8_t *
data_bld_zc_cnt (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len,
                 uint8_t rel_f, uint8_t hop_c, uint64_t cnt,
                 const uint8_t dst_lla[16], size_t *out_len)
{
  if (!cry_peer_ready (s, dst_lla))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t *payload = ipv6_ptr_start;
  size_t pl_len = ipv6_len;
  uint8_t *pkt_ptr = payload - PKT_HDR_SZ;
  uint8_t *inner_ptr = payload - PKT_CH_SZ;
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_DATA, rel_f, hop_c, hdr);
  memcpy (inner_ptr, hdr, PKT_CH_SZ);
  if (cry_enc_cnt_to (s, dst_lla, cnt, inner_ptr, pl_len + PKT_CH_SZ, NULL,
                      0, pkt_ptr, pkt_ptr + PKT_NONCE_SZ, inner_ptr)
      != 0)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  *out_len = PKT_HDR_SZ + pl_len;
  return pkt_ptr;
}

uint8_t *
data_bld_zc (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len, uint8_t rel_f,
             uint8_t hop_c, const uint8_t dst_lla[16], size_t *out_len)
{
  if (!cry_peer_ready (s, dst_lla))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  return data_bld_zc_cnt (s, ipv6_ptr_start, ipv6_len, rel_f, hop_c,
                          cry_cnt_take (s, 1), dst_lla, out_len);
}

uint8_t *
frag_bld_zc (Cry *s, uint8_t *chunk_ptr, size_t chunk_len, uint32_t msg_id,
             size_t off, bool mf, uint8_t rel_f, const uint8_t dest_tail[4],
             uint8_t hop_c, const uint8_t dst_lla[16], size_t *out_len)
{
  if (!cry_peer_ready (s, dst_lla))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  if ((off % FRAG_OFF_UNIT) != 0 || off / FRAG_OFF_UNIT > FRAG_OFF_MASK)
    return NULL;
  uint8_t *payload = chunk_ptr;
  size_t pl_len = chunk_len;
  payload -= sizeof (FragHdr);
  u32_wr (payload, msg_id);
  uint16_t off_mf
      = (uint16_t)((off / FRAG_OFF_UNIT) | (mf ? FRAG_MF_MASK : 0U));
  u16_wr (payload + 4, off_mf);
  pl_len += sizeof (FragHdr);
  if (rel_f != 0 && dest_tail != NULL)
    {
      payload -= 4;
      memcpy (payload, dest_tail, 4);
      pl_len += 4;
    }
  uint8_t *pkt_ptr = payload - PKT_HDR_SZ;
  uint8_t *inner_ptr = payload - PKT_CH_SZ;
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_FRAG, rel_f, hop_c, hdr);
  memcpy (inner_ptr, hdr, PKT_CH_SZ);
  if (cry_enc_to (s, dst_lla, inner_ptr, pl_len + PKT_CH_SZ, NULL, 0,
                  pkt_ptr, pkt_ptr + PKT_NONCE_SZ, inner_ptr)
      != 0)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  *out_len = PKT_HDR_SZ + pl_len;
  return pkt_ptr;
}

uint8_t *
stat_req_bld (Cry *s, uint32_t req_id, const uint8_t dst_lla[16],
              uint8_t *buf, size_t *out_len)
{
  uint8_t payload[4];
  u32_wr (payload, req_id);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_STAT_REQ, 0, 32, hdr);
  if (!dst_lla)
    return pkt_enc_psk (s, hdr, payload, sizeof (payload), buf, out_len);
  return pkt_enc_to (s, dst_lla, hdr, payload, sizeof (payload), buf, out_len);
}

uint8_t *
stat_rsp_bld (Cry *s, uint32_t req_id, uint64_t total_len, uint64_t off,
              const uint8_t *chunk, size_t chunk_len,
              const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len)
{
  if (!chunk || chunk_len > STAT_RSP_CHUNK_MAX)
    return NULL;
  uint8_t payload[PKT_PT_MAX];
  u32_wr (payload, req_id);
  u64_wr (payload + 4, off);
  u64_wr (payload + 12, total_len);
  memcpy (payload + sizeof (StatHdr), chunk, chunk_len);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_STAT_RSP, 0, 32, hdr);
  if (!dst_lla)
    return pkt_enc_psk (s, hdr, payload, sizeof (StatHdr) + chunk_len, buf,
                        out_len);
  return pkt_enc_to (s, dst_lla, hdr, payload, sizeof (StatHdr) + chunk_len,
                     buf, out_len);
}

int
pkt_dec (Cry *s, uint8_t *raw, size_t raw_len, uint8_t *pt_buf,
         size_t pt_len, PktHdr *hdr_out, uint8_t **pt_out, size_t *pt_len_out)
{
  if (raw_len < PKT_HDR_SZ)
    return -1;
  const uint8_t *nonce = raw;
  const uint8_t *mac = raw + PKT_NONCE_SZ;
  const uint8_t *ct = raw + PKT_NONCE_SZ + PKT_MAC_SZ;
  size_t ct_len = raw_len - PKT_NONCE_SZ - PKT_MAC_SZ;
  if (ct_len < PKT_CH_SZ)
    return -1;
  uint8_t *pt = pt_buf ? pt_buf : (raw + PKT_NONCE_SZ + PKT_MAC_SZ);
  size_t pt_cap = pt_buf ? pt_len : ct_len;
  if (ct_len > pt_cap)
    return -1;
  if (cry_dec (s, ct, ct_len, NULL, 0, nonce, mac, pt) != 0)
    return -1;
  uint8_t tf = pt[0];
  hdr_out->pkt_type = (uint8_t)(tf & PKT_TF_TYPE_MASK);
  hdr_out->rel_f = (uint8_t)((tf & PKT_TF_REL) != 0);
  hdr_out->hop_c = pt[1];
  *pt_out = pt + PKT_CH_SZ;
  *pt_len_out = ct_len - PKT_CH_SZ;
  return 0;
}

int
pkt_dec_from (Cry *s, const uint8_t src_lla[16], uint8_t *raw, size_t raw_len,
              uint8_t *pt_buf, size_t pt_len, PktHdr *hdr_out,
              uint8_t **pt_out, size_t *pt_len_out, bool allow_psk_fallback,
              bool *used_psk, uint8_t matched_lla[16])
{
  if (raw_len < PKT_HDR_SZ)
    return -1;
  const uint8_t *nonce = raw;
  const uint8_t *mac = raw + PKT_NONCE_SZ;
  const uint8_t *ct = raw + PKT_NONCE_SZ + PKT_MAC_SZ;
  size_t ct_len = raw_len - PKT_NONCE_SZ - PKT_MAC_SZ;
  if (ct_len < PKT_CH_SZ)
    return -1;
  uint8_t *pt = pt_buf ? pt_buf : (raw + PKT_NONCE_SZ + PKT_MAC_SZ);
  size_t pt_cap = pt_buf ? pt_len : ct_len;
  if (ct_len > pt_cap)
    return -1;
  bool psk = false;
  if (matched_lla)
    memset (matched_lla, 0, 16);
  if (cry_dec_from (s, src_lla, ct, ct_len, NULL, 0, nonce, mac, pt, NULL,
                    matched_lla)
      != 0)
    {
      if (s && s->auth_ibs && !allow_psk_fallback)
        return -1;
      if (cry_dec (s, ct, ct_len, NULL, 0, nonce, mac, pt) != 0)
        return -1;
      psk = true;
    }
  uint8_t tf = pt[0];
  hdr_out->pkt_type = (uint8_t)(tf & PKT_TF_TYPE_MASK);
  hdr_out->rel_f = (uint8_t)((tf & PKT_TF_REL) != 0);
  hdr_out->hop_c = pt[1];
  if (psk && hdr_out->pkt_type != PT_PING && hdr_out->pkt_type != PT_PONG
      && hdr_out->pkt_type != PT_STAT_REQ && hdr_out->pkt_type != PT_STAT_RSP)
    return -1;
  if (used_psk)
    *used_psk = psk;
  *pt_out = pt + PKT_CH_SZ;
  *pt_len_out = ct_len - PKT_CH_SZ;
  return 0;
}

int
pkt_prs_stat_req (const uint8_t *pt, size_t pt_len, uint32_t *req_id)
{
  if (!pt || pt_len < 4 || !req_id)
    return -1;
  *req_id = u32_rd (pt);
  return 0;
}

int
pkt_prs_stat_rsp (const uint8_t *pt, size_t pt_len, uint32_t *req_id,
                  uint64_t *off, uint64_t *total_len, const uint8_t **chunk,
                  size_t *chunk_len)
{
  if (!pt || pt_len < sizeof (StatHdr) || !req_id || !off || !total_len
      || !chunk || !chunk_len)
    return -1;
  *req_id = u32_rd (pt);
  *off = u64_rd (pt + 4);
  *total_len = u64_rd (pt + 12);
  *chunk = pt + sizeof (StatHdr);
  *chunk_len = pt_len - sizeof (StatHdr);
  return 0;
}
