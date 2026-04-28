#include "gossip.h"
#include "bogon.h"
#include "packet.h"
#include "tcp.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define REL_M_UNK 1200U
static uint64_t
u64_rd (const uint8_t *s)
{
  return ((uint64_t)s[0] << 56) | ((uint64_t)s[1] << 48)
         | ((uint64_t)s[2] << 40) | ((uint64_t)s[3] << 32)
         | ((uint64_t)s[4] << 24) | ((uint64_t)s[5] << 16)
         | ((uint64_t)s[6] << 8) | (uint64_t)s[7];
}

static uint16_t
u16_rd (const uint8_t *s)
{
  return (uint16_t)(((uint16_t)s[0] << 8) | s[1]);
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

static void
gsp_ent_ser (uint8_t *dst, const GspEnt *src)
{
  memcpy (dst, src->lla, 16);
  memcpy (dst + 16, src->ep_ip, 16);
  u16_wr (dst + 32, src->ep_port);
  dst[34] = src->flags;
  dst[35] = src->state;
  u16_wr (dst + 36, src->mtu);
  u32_wr (dst + 38, src->seq);
  u32_wr (dst + 42, src->adv_m);
  memcpy (dst + 46, src->nhop_lla, 16);
  u64_wr (dst + 62, src->ver);
}

static void
gsp_ent_des (GspEnt *dst, const uint8_t *src)
{
  memcpy (dst->lla, src, 16);
  memcpy (dst->ep_ip, src + 16, 16);
  dst->ep_port = u16_rd (src + 32);
  dst->flags = src[34];
  dst->state = src[35];
  dst->mtu = u16_rd (src + 36);
  dst->seq = u32_rd (src + 38);
  dst->adv_m = u32_rd (src + 42);
  memcpy (dst->nhop_lla, src + 46, 16);
  dst->ver = u64_rd (src + 62);
}

static bool
lla_inf_s (Rt *rt, const uint8_t src_ip[16], uint16_t src_port,
           uint8_t out_lla[16])
{
  for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, src_ip, 16) != 0)
        continue;
      if (re->ep_port != src_port)
        continue;
      if (!IS_LLA_VAL (re->lla))
        continue;
      memcpy (out_lla, re->lla, 16);
      return true;
    }
  return false;
}

static bool
p_is_me (const Rt *rt, const uint8_t our_lla[16], const uint8_t ip[16],
         uint16_t port)
{
  for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      if (memcmp (re->lla, our_lla, 16) != 0)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      return true;
    }
  return false;
}

static uint16_t
mtu_inf_s (const Rt *rt, const uint8_t src_ip[16], uint16_t src_port)
{
  uint16_t best = 0;
  for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, src_ip, 16) != 0)
        continue;
      if (re->ep_port != src_port)
        continue;
      if (!re->is_act || re->state == RT_DED)
        continue;
      uint16_t mtu = re->mtu;
      if (mtu == 0)
        continue;
      if (best == 0 || mtu < best)
        best = mtu;
    }
  return best;
}

static bool
gsp_has_mapped_ep (const uint8_t *pt, size_t act_cnt, const uint8_t ip[16],
                   uint16_t port)
{
  if (!pt || !ip || port == 0)
    return false;
  for (size_t i = 0; i < act_cnt; i++)
    {
      GspEnt ent;
      gsp_ent_des (&ent, pt + 2 + i * GSP_SZ);
      static const uint8_t z_lla[16] = { 0 };
      if (memcmp (ent.lla, z_lla, 16) == 0)
        continue;
      if (!IS_LLA_VAL (ent.lla))
        continue;
      if (memcmp (ent.ep_ip, ip, 16) != 0 || ent.ep_port != port)
        continue;
      return true;
    }
  return false;
}

bool
is_ip_bgn (const uint8_t ip[16])
{
  return bogon_ip_match (ip);
}

static bool
gsp_self_ep_exp_ok (const Re *re, const uint8_t our_lla[16])
{
  if (!re || !our_lla)
    return false;
  if (re->r2d != 0)
    return false;
  if (!re->is_act || re->state != RT_ACT)
    return false;
  if (memcmp (re->lla, our_lla, 16) != 0)
    return true;
  return re->rx_ts != 0;
}

static bool
gsp_ent_exp_ok (const Re *re, const uint8_t our_lla[16])
{
  static const uint8_t z[16] = { 0 };
  bool is_z = false;
  if (!re || !our_lla)
    return false;
  if (re->r2d != 0)
    return false;
  if (is_ip_bgn (re->ep_ip))
    return false;
  is_z = (memcmp (re->lla, z, 16) == 0);
  if (!is_z && !IS_LLA_VAL (re->lla))
    return false;
  return gsp_self_ep_exp_ok (re, our_lla);
}

uint32_t
gsp_exp_cnt (const Rt *rt, const uint8_t our_lla[16])
{
  uint32_t cnt = 0;
  if (!rt || !our_lla)
    return 0;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      if (gsp_ent_exp_ok (&rt->re_arr[i], our_lla))
        cnt++;
    }
  return cnt;
}

static void
hdr_bld (uint8_t pkt_type, uint8_t rel_f, uint8_t hop_c,
         uint8_t hdr[PKT_CH_SZ])
{
  hdr[0] = (uint8_t)(pkt_type & PKT_TF_TYPE_MASK);
  if (rel_f != 0)
    hdr[0] |= PKT_TF_REL;
  hdr[1] = hop_c;
}

static uint8_t *
pkt_enc (Cry *s, const uint8_t hdr[PKT_CH_SZ], const uint8_t *payload,
         size_t pl_len, uint8_t *buf, size_t *out_len)
{
  uint8_t nonce[PKT_NONCE_SZ], mac[PKT_MAC_SZ];
  memcpy (buf, hdr, PKT_CH_SZ);
  uint8_t *ct_ptr = buf + PKT_CH_SZ + PKT_NONCE_SZ + PKT_MAC_SZ;
  cry_enc (s, payload, pl_len, hdr, PKT_CH_SZ, nonce, mac, ct_ptr);
  memcpy (buf + PKT_CH_SZ, nonce, PKT_NONCE_SZ);
  memcpy (buf + PKT_CH_SZ + PKT_NONCE_SZ, mac, PKT_MAC_SZ);
  *out_len = PKT_HDR_SZ + pl_len;
  return buf;
}

uint8_t *
ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port, uint64_t ts,
          uint64_t sid, uint64_t prb_tok, uint8_t *buf, size_t *out_len)
{
  uint8_t payload[PING_PL_SZ];
  u64_wr (payload, ts);
  u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  u16_wr (payload + 32, our_port);
  u64_wr (payload + 34, prb_tok);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_PING, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, PING_PL_SZ, buf, out_len);
}

uint8_t *
pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port, uint64_t o_ts,
          uint64_t sid, uint64_t rx_ts, uint64_t prb_tok, uint8_t *buf,
          size_t *out_len)
{
  uint8_t payload[PONG_PL_SZ];
  u64_wr (payload, o_ts);
  u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  u16_wr (payload + 32, our_port);
  u64_wr (payload + 34, rx_ts);
  u64_wr (payload + 42, prb_tok);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_PONG, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, PONG_PL_SZ, buf, out_len);
}

static void
gsp_ent_mask_dir (GspEnt *ent)
{
  if (!ent)
    return;
  memset (ent->ep_ip, 0, 16);
  ent->ep_port = 0;
  ent->mtu = 0;
  memset (ent->nhop_lla, 0, 16);
  ent->flags &= (uint8_t)~GSP_F_SEL_DIR;
  ent->flags |= GSP_F_NO_DIR;
}

uint8_t *
gsp_bld (Cry *s, Rt *rt, int s_off,
         const uint8_t our_lla[16], bool self_dir_ok, bool dst_no_dir,
         uint8_t *buf, size_t *out_len)
{
  uint8_t pl_buf[2 + GSP_MAX * GSP_SZ];
  int act_cnt = 0;
  uint32_t exp_cnt = 0;
  uint32_t exp_off = 0;
  uint32_t exp_idx = 0;
  if (!rt)
    {
      *out_len = 0;
      return buf;
    }
  exp_cnt = gsp_exp_cnt (rt, our_lla);
  if (exp_cnt == 0)
    {
      *out_len = 0;
      return buf;
    }
  exp_off = (s_off > 0) ? ((uint32_t)s_off % exp_cnt) : 0;
  for (int re_idx = 0; re_idx < (int)rt->cnt && act_cnt < GSP_MAX; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      static const uint8_t z[16] = { 0 };
      bool is_z = (memcmp (re->lla, z, 16) == 0);
      if (!gsp_ent_exp_ok (re, our_lla))
        continue;
      if (exp_idx++ < exp_off)
        continue;
      GspEnt gsp_ent;
      memcpy (gsp_ent.lla, re->lla, 16);
      memcpy (gsp_ent.ep_ip, re->ep_ip, 16);
      gsp_ent.ep_port = re->ep_port;
      bool no_dir = false;
      if (!is_z && memcmp (re->lla, our_lla, 16) == 0)
        no_dir = !self_dir_ok;
      else if (!is_z)
        no_dir = rt_src_no_dir (rt, re->lla);
      gsp_ent.flags = (!no_dir && rt_dir_is_sel (rt, re)) ? GSP_F_SEL_DIR : 0;
      if (no_dir)
        gsp_ent.flags |= GSP_F_NO_DIR;
      if (tp_mask_has (re->tp_mask, TP_PROTO_UDP))
        gsp_ent.flags |= GSP_F_TP_UDP;
      if (tp_mask_has (re->tp_mask, TP_PROTO_TCP))
        gsp_ent.flags |= GSP_F_TP_TCP;
      gsp_ent.state = (uint8_t)re->state;
      gsp_ent.mtu
          = (re->is_act && re->state == RT_ACT) ? rt_dir_mtu_get (rt, re) : 0;
      gsp_ent.seq = re->seq;
      gsp_ent.adv_m = re->rt_m;
      if (memcmp (re->lla, our_lla, 16) == 0
          && (gsp_ent.adv_m == 0 || gsp_ent.adv_m >= RT_M_INF))
        gsp_ent.adv_m = RT_M_INF;
      memcpy (gsp_ent.nhop_lla, re->nhop_lla, 16);
      gsp_ent.ver = re->ver;
      if (dst_no_dir && memcmp (re->lla, our_lla, 16) != 0)
        gsp_ent_mask_dir (&gsp_ent);
      size_t wr_off = (size_t)(2 + act_cnt * (int)GSP_SZ);
      gsp_ent_ser (pl_buf + wr_off, &gsp_ent);
      act_cnt++;
    }
  if (act_cnt == 0)
    {
      *out_len = 0;
      return buf;
    }
  u16_wr (pl_buf, (uint16_t)act_cnt);
  size_t pl_len = (size_t)(2 + act_cnt * (int)GSP_SZ);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_GSP, 0, 32, hdr);
  return pkt_enc (s, hdr, pl_buf, pl_len, buf, out_len);
}

uint8_t *
gsp_dt_bld (Cry *s, Rt *rt, const uint8_t tgt_lla[16],
            const uint8_t our_lla[16], bool self_dir_ok, bool dst_no_dir,
            uint8_t *buf, size_t *out_len)
{
  uint8_t pl_buf[2 + GSP_MAX * GSP_SZ];
  int act_cnt = 0;
  if (!rt)
    {
      *out_len = 0;
      return buf;
    }
  for (int re_idx = 0; re_idx < (int)rt->cnt && act_cnt < GSP_MAX; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      static const uint8_t z[16] = { 0 };
      if (memcmp (re->lla, tgt_lla, 16) != 0)
        continue;
      bool is_z = (memcmp (re->lla, z, 16) == 0);
      if (!gsp_ent_exp_ok (re, our_lla))
        continue;
      GspEnt gsp_ent;
      memcpy (gsp_ent.lla, re->lla, 16);
      memcpy (gsp_ent.ep_ip, re->ep_ip, 16);
      gsp_ent.ep_port = re->ep_port;
      bool no_dir = false;
      if (!is_z && memcmp (re->lla, our_lla, 16) == 0)
        no_dir = !self_dir_ok;
      else if (!is_z)
        no_dir = rt_src_no_dir (rt, re->lla);
      gsp_ent.flags = (!no_dir && rt_dir_is_sel (rt, re)) ? GSP_F_SEL_DIR : 0;
      if (no_dir)
        gsp_ent.flags |= GSP_F_NO_DIR;
      if (tp_mask_has (re->tp_mask, TP_PROTO_UDP))
        gsp_ent.flags |= GSP_F_TP_UDP;
      if (tp_mask_has (re->tp_mask, TP_PROTO_TCP))
        gsp_ent.flags |= GSP_F_TP_TCP;
      gsp_ent.state = (uint8_t)re->state;
      gsp_ent.mtu
          = (re->is_act && re->state == RT_ACT) ? rt_dir_mtu_get (rt, re) : 0;
      gsp_ent.seq = re->seq;
      gsp_ent.adv_m = re->rt_m;
      if (memcmp (re->lla, our_lla, 16) == 0
          && (gsp_ent.adv_m == 0 || gsp_ent.adv_m >= RT_M_INF))
        gsp_ent.adv_m = RT_M_INF;
      memcpy (gsp_ent.nhop_lla, re->nhop_lla, 16);
      gsp_ent.ver = re->ver;
      if (dst_no_dir && memcmp (re->lla, our_lla, 16) != 0)
        gsp_ent_mask_dir (&gsp_ent);
      size_t wr_off = (size_t)(2 + act_cnt * (int)GSP_SZ);
      gsp_ent_ser (pl_buf + wr_off, &gsp_ent);
      act_cnt++;
    }
  u16_wr (pl_buf, (uint16_t)act_cnt);
  size_t pl_len = (size_t)(2 + act_cnt * (int)GSP_SZ);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_GSP, 0, 32, hdr);
  return pkt_enc (s, hdr, pl_buf, pl_len, buf, out_len);
}

uint8_t *
seq_req_bld (Cry *s, const uint8_t tgt_lla[16], uint8_t *buf, size_t *out_len)
{
  uint8_t payload[16];
  memcpy (payload, tgt_lla, 16);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_SEQ_REQ, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, sizeof (payload), buf, out_len);
}

uint8_t *
hp_bld (Cry *s, const uint8_t req_lla[16], const uint8_t tgt_lla[16],
        uint8_t *buf, size_t *out_len)
{
  uint8_t payload[32];
  memcpy (payload, req_lla, 16);
  memcpy (payload + 16, tgt_lla, 16);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_HP, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, 32, buf, out_len);
}

uint8_t *
data_bld_zc_cnt (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len,
                 uint8_t rel_f, uint8_t hop_c, uint64_t cnt,
                 size_t *out_len)
{
  uint8_t *payload = ipv6_ptr_start;
  size_t pl_len = ipv6_len;
  uint8_t *pkt_ptr = payload - PKT_HDR_SZ;
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_DATA, rel_f, hop_c, hdr);
  memcpy (pkt_ptr, hdr, PKT_CH_SZ);
  cry_enc_cnt (s, cnt, payload, pl_len, pkt_ptr, PKT_CH_SZ,
               pkt_ptr + PKT_CH_SZ, pkt_ptr + PKT_CH_SZ + PKT_NONCE_SZ,
               payload);
  *out_len = PKT_HDR_SZ + pl_len;
  return pkt_ptr;
}

uint8_t *
data_bld_zc (Cry *s, uint8_t *ipv6_ptr_start, size_t ipv6_len, uint8_t rel_f,
             uint8_t hop_c, size_t *out_len)
{
  return data_bld_zc_cnt (s, ipv6_ptr_start, ipv6_len, rel_f, hop_c,
                          cry_cnt_take (s, 1), out_len);
}

uint8_t *
frag_bld_zc (Cry *s, uint8_t *chunk_ptr, size_t chunk_len, uint32_t msg_id,
             uint16_t off, bool mf, uint8_t rel_f, const uint8_t dest_tail[4],
             uint8_t hop_c, size_t *out_len)
{
  if ((off & FRAG_MF_MASK) != 0)
    return NULL;
  uint8_t *payload = chunk_ptr;
  size_t pl_len = chunk_len;
  payload -= sizeof (FragHdr);
  u32_wr (payload, msg_id);
  uint16_t off_mf = (uint16_t)(off | (mf ? FRAG_MF_MASK : 0U));
  u16_wr (payload + 4, off_mf);
  pl_len += sizeof (FragHdr);
  if (rel_f != 0 && dest_tail != NULL)
    {
      payload -= 4;
      memcpy (payload, dest_tail, 4);
      pl_len += 4;
    }
  uint8_t *pkt_ptr = payload - PKT_HDR_SZ;
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_FRAG, rel_f, hop_c, hdr);
  memcpy (pkt_ptr, hdr, PKT_CH_SZ);
  cry_enc (s, payload, pl_len, pkt_ptr, PKT_CH_SZ, pkt_ptr + PKT_CH_SZ,
           pkt_ptr + PKT_CH_SZ + PKT_NONCE_SZ, payload);
  *out_len = PKT_HDR_SZ + pl_len;
  return pkt_ptr;
}

uint8_t *
mtu_prb_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu, size_t t_pl_len,
             uint8_t *buf, size_t *out_len)
{
  size_t pl_len = sizeof (ProbeHdr);
  if (t_pl_len > PKT_HDR_SZ)
    {
      pl_len = t_pl_len - PKT_HDR_SZ;
      if (pl_len < sizeof (ProbeHdr))
        pl_len = sizeof (ProbeHdr);
    }
  if (pl_len > PKT_PT_MAX)
    pl_len = PKT_PT_MAX;
  uint8_t payload[PKT_PT_MAX];
  memset (payload, 0, pl_len);
  u32_wr (payload, probe_id);
  u16_wr (payload + 4, probe_mtu);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_MTU_PRB, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, pl_len, buf, out_len);
}

uint8_t *
mtu_ack_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu, uint8_t *buf,
             size_t *out_len)
{
  uint8_t payload[sizeof (ProbeHdr)];
  u32_wr (payload, probe_id);
  u16_wr (payload + 4, probe_mtu);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_MTU_ACK, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, sizeof (payload), buf, out_len);
}

uint8_t *
stat_req_bld (Cry *s, uint32_t req_id, uint8_t *buf, size_t *out_len)
{
  uint8_t payload[4];
  u32_wr (payload, req_id);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_STAT_REQ, 0, 32, hdr);
  return pkt_enc (s, hdr, payload, sizeof (payload), buf, out_len);
}

uint8_t *
stat_rsp_bld (Cry *s, uint32_t req_id, uint64_t total_len, uint64_t off,
              const uint8_t *chunk, size_t chunk_len, uint8_t *buf,
              size_t *out_len)
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
  return pkt_enc (s, hdr, payload, sizeof (StatHdr) + chunk_len, buf, out_len);
}

int
pkt_dec (Cry *s, uint8_t *raw, size_t raw_len, uint8_t *pt_buf,
         size_t pt_len, PktHdr *hdr_out, uint8_t **pt_out, size_t *pt_len_out)
{
  if (raw_len < PKT_HDR_SZ)
    return -1;
  uint8_t tf = raw[0];
  hdr_out->pkt_type = (uint8_t)(tf & PKT_TF_TYPE_MASK);
  hdr_out->rel_f = (uint8_t)((tf & PKT_TF_REL) != 0);
  hdr_out->hop_c = raw[1];
  const uint8_t *nonce = raw + PKT_CH_SZ;
  const uint8_t *mac = raw + PKT_CH_SZ + PKT_NONCE_SZ;
  const uint8_t *ct = raw + PKT_HDR_SZ;
  size_t ct_len = raw_len - PKT_HDR_SZ;
  uint8_t *pt = pt_buf ? pt_buf : (raw + PKT_HDR_SZ);
  size_t pt_cap = pt_buf ? pt_len : ct_len;
  if (ct_len > pt_cap)
    return -1;
  if (cry_dec (s, ct, ct_len, raw, PKT_CH_SZ, nonce, mac, pt) != 0)
    return -1;
  *pt_out = pt;
  *pt_len_out = ct_len;
  return 0;
}

int
gsp_prs_mtu_prb (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                 uint16_t *probe_mtu)
{
  if (!pt || pt_len < sizeof (ProbeHdr) || !probe_id || !probe_mtu)
    return -1;
  *probe_id = u32_rd (pt);
  *probe_mtu = u16_rd (pt + 4);
  return 0;
}

int
gsp_prs_mtu_ack (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                 uint16_t *probe_mtu)
{
  return gsp_prs_mtu_prb (pt, pt_len, probe_id, probe_mtu);
}

int
gsp_prs_stat_req (const uint8_t *pt, size_t pt_len, uint32_t *req_id)
{
  if (!pt || pt_len < 4 || !req_id)
    return -1;
  *req_id = u32_rd (pt);
  return 0;
}

int
gsp_prs_stat_rsp (const uint8_t *pt, size_t pt_len, uint32_t *req_id,
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

int
on_ping (const uint8_t *pt, size_t pt_len, uint64_t *o_ts, uint64_t *sid,
         uint8_t *lla, uint16_t *port, uint64_t *prb_tok)
{
  if (!pt || pt_len < PING_PL_SZ)
    return -1;
  *o_ts = u64_rd (pt);
  if (sid)
    *sid = u64_rd (pt + 8);
  if (lla)
    memcpy (lla, pt + 16, 16);
  if (port)
    *port = u16_rd (pt + 32);
  if (prb_tok)
    *prb_tok = u64_rd (pt + 34);
  return 0;
}

int
on_pong (const uint8_t *pt, size_t pt_len, uint64_t *o_ts, uint64_t *sid,
         uint8_t *lla, uint16_t *port, uint64_t *rx_ts, uint64_t *prb_tok)
{
  if (!pt || pt_len < PONG_PL_SZ)
    return -1;
  if (o_ts)
    *o_ts = u64_rd (pt);
  if (sid)
    *sid = u64_rd (pt + 8);
  if (lla)
    memcpy (lla, pt + 16, 16);
  if (port)
    *port = u16_rd (pt + 32);
  if (rx_ts)
    *rx_ts = u64_rd (pt + 34);
  if (prb_tok)
    *prb_tok = u64_rd (pt + 42);
  return 0;
}

int
on_gsp (const uint8_t *pt, size_t pt_len, const uint8_t src_ip[16],
        uint16_t src_port, const uint8_t our_lla[16], Rt *rt, PPool *pool,
        bool allow_dir_hint, uint64_t sys_ts, bool *is_mod, bool *o_req_seq,
        uint8_t seq_tgt[16])
{
  if (!pt || pt_len < 2)
    return -1;
  uint16_t cnt = u16_rd (pt);
  size_t max_cnt = (pt_len - 2) / GSP_SZ;
  size_t act_cnt = cnt < (uint16_t)max_cnt ? cnt : (uint16_t)max_cnt;
  uint32_t rt_c_old = rt->cnt;
  *is_mod = false;
  if (o_req_seq)
    *o_req_seq = false;
  uint8_t src_lla[16] = { 0 };
  bool has_s_lla = lla_inf_s (rt, src_ip, src_port, src_lla);
  uint16_t mtu_s = mtu_inf_s (rt, src_ip, src_port);
  bool saw_self_adv = false;
  bool saw_self_sel_dir = false;
  uint16_t self_sel_dir_mtu = 0;
  for (size_t gsp_idx = 0; gsp_idx < act_cnt; gsp_idx++)
    {
      size_t rd_off = 2 + gsp_idx * GSP_SZ;
      GspEnt gsp_ent;
      gsp_ent_des (&gsp_ent, pt + rd_off);
      static const uint8_t z_lla[16] = { 0 };
      bool is_z = (memcmp (gsp_ent.lla, z_lla, 16) == 0);
      if (!is_z && !IS_LLA_VAL (gsp_ent.lla))
        continue;
      if (is_z)
        {
          if (is_ip_bgn (gsp_ent.ep_ip))
            continue;
          if (gsp_has_mapped_ep (pt, act_cnt, gsp_ent.ep_ip, gsp_ent.ep_port))
            continue;
          if (allow_dir_hint
              && !p_is_me (rt, our_lla, gsp_ent.ep_ip, gsp_ent.ep_port))
            {
              uint8_t tp_mask = 0;
              if ((gsp_ent.flags & GSP_F_TP_UDP) != 0)
                tp_mask |= TP_MASK_UDP;
              if ((gsp_ent.flags & GSP_F_TP_TCP) != 0)
                tp_mask |= TP_MASK_TCP;
              if (tp_mask == 0)
                tp_mask = TP_MASK_UDP | TP_MASK_TCP;
              rt_ep_upd (rt, z_lla, gsp_ent.ep_ip, gsp_ent.ep_port, tp_mask,
                         sys_ts);
              if (pool)
                {
                  pp_add (pool, gsp_ent.ep_ip, gsp_ent.ep_port);
                }
            }
          continue;
        }
      uint32_t n_seq = gsp_ent.seq;
      uint32_t adv_m = gsp_ent.adv_m;
      uint16_t gsp_mtu = gsp_ent.mtu;
      bool no_dir = (gsp_ent.flags & GSP_F_NO_DIR) != 0;
      uint16_t rel_mtu = 0;
      if (memcmp (gsp_ent.lla, our_lla, 16) == 0)
        {
          saw_self_adv = true;
          if ((gsp_ent.flags & GSP_F_SEL_DIR) != 0 && gsp_mtu >= RT_MTU_MIN)
            {
              saw_self_sel_dir = true;
              self_sel_dir_mtu = gsp_mtu;
            }
          continue;
        }
      if (mtu_s > 0 && gsp_mtu > 0)
        {
          rel_mtu = (mtu_s < gsp_mtu) ? mtu_s : gsp_mtu;
        }
      else if (mtu_s > 0)
        {
          rel_mtu = mtu_s;
        }
      else
        {
          rel_mtu = gsp_mtu;
        }
      bool is_adv_rch = (adv_m > 0 && adv_m < RT_M_INF);
      bool is_s_alive = ((RtSt)gsp_ent.state != RT_DED);
      bool has_dir_hint
          = !IS_LLA_VAL (gsp_ent.nhop_lla)
            || memcmp (gsp_ent.nhop_lla, gsp_ent.lla, 16) == 0;
      bool loc_req_seq = false;
      bool feasible
          = rt_fsb (rt, gsp_ent.lla, n_seq, adv_m, gsp_ent.ver, &loc_req_seq);
      SrcEnt *se = NULL;
      for (uint32_t si = 0; si < rt->src_cnt; si++)
        {
          if (memcmp (rt->sources[si].rt_id, gsp_ent.lla, 16) == 0)
            {
              se = &rt->sources[si];
              break;
            }
        }
      bool is_new_poison
          = (adv_m >= RT_M_INF) && (!se || se->fwd_m < RT_M_INF);

      bool src_fresh = feasible || is_new_poison;
      if (!src_fresh && loc_req_seq && o_req_seq && seq_tgt)
        {
          *o_req_seq = true;
          memcpy (seq_tgt, gsp_ent.lla, 16);
        }

      if (src_fresh)
        {
          rt_src_upd (rt, gsp_ent.lla, n_seq, adv_m, gsp_ent.ver, no_dir,
                      sys_ts);
        }
      bool is_s_self = (memcmp (gsp_ent.ep_ip, src_ip, 16) == 0
                        && gsp_ent.ep_port == src_port);
      if (src_fresh && no_dir && !is_s_self)
        rt_dir_hint_prune (rt, gsp_ent.lla);
      if (!is_s_self)
        {
          Re rel_re;
          memset (&rel_re, 0, sizeof (rel_re));
          memcpy (rel_re.lla, gsp_ent.lla, 16);
          memcpy (rel_re.ep_ip, src_ip, 16);
          rel_re.ep_port = src_port;
          rel_re.ver = gsp_ent.ver;
          rel_re.seq = n_seq;
          rel_re.adv_m = adv_m;
          rel_re.r2d = is_adv_rch ? adv_m : (is_s_alive ? REL_M_UNK : RT_M_INF);
          rel_re.rt_m = rel_re.r2d;
          if (rel_mtu > 0)
            {
              rel_re.mtu = rel_mtu;
              rel_re.mtu_lkg = rel_mtu;
              rel_re.mtu_ukb = rel_mtu;
            }
          rel_re.state = is_s_alive ? RT_ACT : RT_DED;
          rel_re.is_act = is_s_alive;
          rel_re.tp_mask = 0;
          if ((gsp_ent.flags & GSP_F_TP_UDP) != 0)
            rel_re.tp_mask |= TP_MASK_UDP;
          if ((gsp_ent.flags & GSP_F_TP_TCP) != 0)
            rel_re.tp_mask |= TP_MASK_TCP;
          if (rel_re.tp_mask == 0)
            rel_re.tp_mask = TP_MASK_UDP | TP_MASK_TCP;
          rel_re.rto = RTO_INIT;
          if (has_s_lla)
            memcpy (rel_re.nhop_lla, src_lla, 16);
          rt_upd (rt, &rel_re, sys_ts);
        }
      bool import_dir_hint
          = src_fresh && allow_dir_hint && !no_dir && has_dir_hint
            && (is_s_self || (gsp_ent.flags & GSP_F_SEL_DIR) != 0);
      if (import_dir_hint)
        {
          if (is_ip_bgn (gsp_ent.ep_ip))
            continue;
          Re dir_re;
          memset (&dir_re, 0, sizeof (dir_re));
          memcpy (dir_re.lla, gsp_ent.lla, 16);
          memcpy (dir_re.ep_ip, gsp_ent.ep_ip, 16);
          dir_re.ep_port = gsp_ent.ep_port;
          dir_re.ver = gsp_ent.ver;
          dir_re.seq = n_seq;
          dir_re.adv_m = adv_m;
          dir_re.r2d = 0;
          dir_re.rt_m = RT_M_INF;
          dir_re.sm_m = RT_M_INF;
          if (gsp_mtu > 0)
            {
              dir_re.mtu = gsp_mtu;
              dir_re.mtu_lkg = gsp_mtu;
              dir_re.mtu_ukb = gsp_mtu;
            }
          dir_re.state = ((RtSt)gsp_ent.state == RT_DED) ? RT_DED : RT_PND;
          dir_re.is_act = false;
          dir_re.tp_mask = 0;
          if ((gsp_ent.flags & GSP_F_TP_UDP) != 0)
            dir_re.tp_mask |= TP_MASK_UDP;
          if ((gsp_ent.flags & GSP_F_TP_TCP) != 0)
            dir_re.tp_mask |= TP_MASK_TCP;
          if (dir_re.tp_mask == 0)
            dir_re.tp_mask = TP_MASK_UDP | TP_MASK_TCP;
          dir_re.rto = RTO_INIT;
          if (IS_LLA_VAL (gsp_ent.nhop_lla))
            memcpy (dir_re.nhop_lla, gsp_ent.nhop_lla, 16);
          else
            memcpy (dir_re.nhop_lla, gsp_ent.lla, 16);
          rt_upd (rt, &dir_re, sys_ts);
          if (pool
              && !p_is_me (rt, our_lla, gsp_ent.ep_ip, gsp_ent.ep_port))
            {
              pp_add (pool, gsp_ent.ep_ip, gsp_ent.ep_port);
            }
        }
    }
  if (has_s_lla && saw_self_adv)
    {
      rt_peer_rev_mtu_set (rt, src_lla, saw_self_sel_dir ? self_sel_dir_mtu : 0);
    }
  if (rt->cnt != rt_c_old || rt->gsp_dirty)
    *is_mod = true;
  return 0;
}

int
on_seq_req (const uint8_t *pt, size_t pt_len, uint8_t tgt_lla[16])
{
  if (!pt)
    return -1;
  if (pt_len < 16)
    return -1;
  memcpy (tgt_lla, pt, 16);
  return 0;
}

int
on_hp (const uint8_t *pt, size_t pt_len, Cry *s, Udp *udp, Rt *rt,
       const Cfg *cfg, const uint8_t o_lla[16], uint64_t sid, uint64_t ts)
{
  if (!pt || pt_len < 32)
    return -1;
  uint8_t req_lla[16], tgt_lla[16];
  memcpy (req_lla, pt, 16);
  memcpy (tgt_lla, pt + 16, 16);
  if (memcmp (tgt_lla, o_lla, 16) == 0)
    {
      Re req_re;
      bool has_re = rt_dir_fnd (rt, req_lla, &req_re);
      if (!has_re)
        {
          for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
            {
              Re *re = &rt->re_arr[re_idx];
              if (re->r2d != 0)
                continue;
              if (re->state == RT_DED)
                continue;
              if (memcmp (re->lla, req_lla, 16) != 0)
                continue;
              req_re = *re;
              has_re = true;
              break;
            }
        }
      if (has_re)
        {
          uint8_t p_buf[UDP_PL_MAX];
          size_t p_len;
          ping_bld (s, o_lla, cfg ? cfg->port : 0, ts, sid, 0, p_buf,
                    &p_len);
          if (cfg)
            (void)tp_send_ctrl (udp, rt, cfg, req_re.ep_ip, req_re.ep_port,
                                p_buf, p_len);
          else
            udp_tx (udp, req_re.ep_ip, req_re.ep_port, p_buf, p_len);
        }
      return 0;
    }
  Re tgt_re;
  if (rt_dir_fnd (rt, tgt_lla, &tgt_re))
    {
      uint8_t out_buf[UDP_PL_MAX];
      size_t out_len;
      hp_bld (s, req_lla, tgt_lla, out_buf, &out_len);
      if (cfg)
        (void)tp_send_ctrl (udp, rt, cfg, tgt_re.ep_ip, tgt_re.ep_port,
                            out_buf, out_len);
      else
        udp_tx (udp, tgt_re.ep_ip, tgt_re.ep_port, out_buf, out_len);
    }
  return 0;
}
