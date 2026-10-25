#include "nbr.h"
#include "pkt.h"
#include "bogon.h"
#include "ibs.h"
#include "packet.h"
#include "tcp.h"
#include <sodium.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PING_KX_PL_SZ (PING_PL_SZ + CRY_KX_PUB_SZ)
#define PONG_KX_PL_SZ (PONG_PL_SZ + CRY_KX_PUB_SZ)

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

bool
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

uint16_t
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

bool
is_ip_bgn (const uint8_t ip[16])
{
  return bogon_ip_match (ip);
}

uint8_t *
ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port, uint64_t ts,
          uint64_t sid, uint64_t prb_tok, uint8_t *buf, size_t *out_len)
{
  if (!s)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t payload[PING_KX_PL_SZ];
  u64_wr (payload, ts);
  u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  u16_wr (payload + 32, our_port);
  u64_wr (payload + 34, prb_tok);
  memcpy (payload + PING_PL_SZ, cry_kx_pub (s), CRY_KX_PUB_SZ);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_PING, 0, 32, hdr);
  return pkt_enc_psk (s, hdr, payload, sizeof (payload), buf, out_len);
}

uint8_t *
pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port, uint64_t o_ts,
          uint64_t sid, uint64_t rx_ts, uint64_t prb_tok, uint8_t *buf,
          size_t *out_len)
{
  if (!s)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t payload[PONG_KX_PL_SZ];
  u64_wr (payload, o_ts);
  u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  u16_wr (payload + 32, our_port);
  u64_wr (payload + 34, rx_ts);
  u64_wr (payload + 42, prb_tok);
  memcpy (payload + PONG_PL_SZ, cry_kx_pub (s), CRY_KX_PUB_SZ);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_PONG, 0, 32, hdr);
  return pkt_enc_psk (s, hdr, payload, sizeof (payload), buf, out_len);
}

size_t
ibs_ping_pl_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
                 uint64_t ts, uint64_t sid, uint64_t prb_tok,
                 const uint8_t our_ip[16], const uint8_t ckie[IBS_CKIE_SZ],
                 uint8_t *pl)
{
  u64_wr (pl, ts);
  u64_wr (pl + 8, sid);
  memcpy (pl + 16, our_lla, 16);
  u16_wr (pl + 32, our_port);
  u64_wr (pl + 34, prb_tok);
  memcpy (pl + PING_PL_SZ, cry_kx_pub (s), CRY_KX_PUB_SZ);
  memcpy (pl + PING_KX_PL_SZ, our_ip, 16);
  if (ckie)
    memcpy (pl + IBS_PING_CKIE_OFF, ckie, IBS_CKIE_SZ);
  else
    memset (pl + IBS_PING_CKIE_OFF, 0, IBS_CKIE_SZ);
  return IBS_PING_PL_SZ;
}

void
ibs_pl_hash (const uint8_t *pl, uint8_t out[IBS_CKIE_SZ])
{
  uint8_t tmp[IBS_PING_PL_SZ];
  memcpy (tmp, pl, sizeof (tmp));
  memset (tmp + IBS_PING_CKIE_OFF, 0, IBS_CKIE_SZ);
  crypto_generichash (out, IBS_CKIE_SZ, tmp, sizeof (tmp), NULL, 0);
}

void
ibs_ckie_calc (const uint8_t key[IBS_CKIE_SZ], const uint8_t lla[16],
               const uint8_t ip[16], uint16_t port,
               const uint8_t pl_hash[IBS_CKIE_SZ], uint64_t bucket,
               uint8_t out[IBS_CKIE_SZ])
{
  uint8_t in[16 + 16 + 2 + IBS_CKIE_SZ + 8];
  memcpy (in, lla, 16);
  memcpy (in + 16, ip, 16);
  u16_wr (in + 32, port);
  memcpy (in + 34, pl_hash, IBS_CKIE_SZ);
  u64_wr (in + 34 + IBS_CKIE_SZ, bucket);
  crypto_generichash (out, IBS_CKIE_SZ, in, sizeof (in), key, IBS_CKIE_SZ);
}

uint8_t *
ibs_ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
              uint64_t ts, uint64_t sid, uint64_t prb_tok,
              const uint8_t our_ip[16], const uint8_t ckie[IBS_CKIE_SZ],
              uint8_t *buf, size_t *out_len)
{
  if (!s || !buf || !out_len || !s->auth_ibs)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t payload[IBS_PING_PL_SZ];
  ibs_ping_pl_bld (s, our_lla, our_port, ts, sid, prb_tok, our_ip, ckie,
                   payload);
  uint8_t sig[IBS_SIG_SZ];
  if (!ibs_sign (s->ibs_sk, our_lla, 16, payload, sizeof (payload), sig))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_IBS_PING, 0, 32, hdr);
  uint8_t *out = buf;
  memcpy (out, hdr, PKT_CH_SZ);
  memcpy (out + PKT_CH_SZ, payload, sizeof (payload));
  memcpy (out + PKT_CH_SZ + sizeof (payload), sig, IBS_SIG_SZ);
  *out_len = PKT_CH_SZ + sizeof (payload) + IBS_SIG_SZ;
  return out;
}

uint8_t *
ibs_pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
              uint64_t o_ts, uint64_t sid, uint64_t rx_ts,
              uint64_t prb_tok, const uint8_t our_ip[16],
              uint8_t *buf, size_t *out_len)
{
  if (!s || !buf || !out_len || !s->auth_ibs)
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t payload[IBS_PONG_PL_SZ];
  u64_wr (payload, o_ts);
  u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  u16_wr (payload + 32, our_port);
  u64_wr (payload + 34, rx_ts);
  u64_wr (payload + 42, prb_tok);
  memcpy (payload + PONG_PL_SZ, cry_kx_pub (s), CRY_KX_PUB_SZ);
  memcpy (payload + PONG_KX_PL_SZ, our_ip, 16);
  uint8_t sig[IBS_SIG_SZ];
  if (!ibs_sign (s->ibs_sk, our_lla, 16, payload, sizeof (payload), sig))
    {
      if (out_len)
        *out_len = 0;
      return NULL;
    }
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_IBS_PONG, 0, 32, hdr);
  uint8_t *out = buf;
  memcpy (out, hdr, PKT_CH_SZ);
  memcpy (out + PKT_CH_SZ, payload, sizeof (payload));
  memcpy (out + PKT_CH_SZ + sizeof (payload), sig, IBS_SIG_SZ);
  *out_len = PKT_CH_SZ + sizeof (payload) + IBS_SIG_SZ;
  return out;
}

uint8_t *
hp_bld (Cry *s, const uint8_t req_lla[16], const uint8_t tgt_lla[16],
        const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len)
{
  uint8_t payload[32];
  memcpy (payload, req_lla, 16);
  memcpy (payload + 16, tgt_lla, 16);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_HP, 0, 32, hdr);
  return pkt_enc_to (s, dst_lla, hdr, payload, 32, buf, out_len);
}

uint8_t *
mtu_prb_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu, size_t t_pl_len,
             const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len)
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
  return pkt_enc_to (s, dst_lla, hdr, payload, pl_len, buf, out_len);
}

uint8_t *
mtu_ack_bld (Cry *s, uint32_t probe_id, uint16_t probe_mtu,
             const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len)
{
  uint8_t payload[sizeof (ProbeHdr)];
  u32_wr (payload, probe_id);
  u16_wr (payload + 4, probe_mtu);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_MTU_ACK, 0, 32, hdr);
  return pkt_enc_to (s, dst_lla, hdr, payload, sizeof (payload), buf, out_len);
}

int
nbr_prs_mtu_prb (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                 uint16_t *probe_mtu)
{
  if (!pt || pt_len < sizeof (ProbeHdr) || !probe_id || !probe_mtu)
    return -1;
  *probe_id = u32_rd (pt);
  *probe_mtu = u16_rd (pt + 4);
  return 0;
}

int
nbr_prs_mtu_ack (const uint8_t *pt, size_t pt_len, uint32_t *probe_id,
                 uint16_t *probe_mtu)
{
  return nbr_prs_mtu_prb (pt, pt_len, probe_id, probe_mtu);
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

const uint8_t *
on_ping_kx (const uint8_t *pt, size_t pt_len)
{
  if (!pt || pt_len < PING_KX_PL_SZ)
    return NULL;
  return pt + PING_PL_SZ;
}

const uint8_t *
on_pong_kx (const uint8_t *pt, size_t pt_len)
{
  if (!pt || pt_len < PONG_KX_PL_SZ)
    return NULL;
  return pt + PONG_PL_SZ;
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
      hp_bld (s, req_lla, tgt_lla, tgt_re.lla, out_buf, &out_len);
      if (out_len == 0)
        return 0;
      if (cfg)
        (void)tp_send_ctrl (udp, rt, cfg, tgt_re.ep_ip, tgt_re.ep_port,
                            out_buf, out_len);
      else
        udp_tx (udp, tgt_re.ep_ip, tgt_re.ep_port, out_buf, out_len);
    }
  return 0;
}
