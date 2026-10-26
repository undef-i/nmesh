#include "forward.h"
#include "frag.h"
#include "nbr.h"
#include "pkt.h"
#include "mss.h"
#include "packet.h"
#include "tcp.h"
#include "utils.h"
#include <linux/if_ether.h>
#include <string.h>

static bool
tx_path_use_tcp (const Rt *rt, const Cfg *cfg, const uint8_t tx_ip[16],
                 uint16_t tx_port)
{
  if (!rt || !cfg || !tx_ip || tx_port == 0)
    return false;
  return cfg_tp_pick (cfg, rt_ep_tp_mask (rt, tx_ip, tx_port)) == TP_PROTO_TCP;
}

static bool
rt_nh_get (Rt *rt, const Cfg *cfg, const uint8_t dest_lla[16], RtDec *out_dec,
           uint8_t out_ip[16], uint16_t *out_port)
{
  if (!rt || !cfg || !dest_lla || !out_dec || !out_ip || !out_port)
    return false;
  RtDec dec = rt_sel (rt, dest_lla, cfg->p2p);
  if (dec.type == RT_DIR)
    {
      memcpy (out_ip, dec.dir.ip, 16);
      *out_port = dec.dir.port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  if (dec.type == RT_REL)
    {
      memcpy (out_ip, dec.rel.relay_ip, 16);
      *out_port = dec.rel.relay_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  if (dec.type == RT_VP)
    {
      uint8_t gw_ip[16] = { 0 };
      uint16_t gw_port = 0;
      if (!rt_gw_fnd (rt, cfg->addr, !cfg->p2p, gw_ip, &gw_port))
        return false;
      memcpy (out_ip, gw_ip, 16);
      *out_port = gw_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  return false;
}

static bool
rt_nh_lla_get (const Rt *rt, const RtDec *dec, const uint8_t dest_lla[16],
               const uint8_t tx_ip[16], uint16_t tx_port,
               uint8_t out_lla[16])
{
  if (!rt || !dec || !dest_lla || !tx_ip || !out_lla || tx_port == 0)
    return false;
  if (dec->type == RT_DIR)
    {
      memcpy (out_lla, dest_lla, 16);
      return true;
    }
  if (dec->type == RT_REL)
    {
      memcpy (out_lla, dec->rel.relay_lla, 16);
      return IS_LLA_VAL (out_lla);
    }
  return rt_ep_peer_lla (rt, tx_ip, tx_port, out_lla);
}

static void
frame_l3_info_get (const uint8_t *frame_pkt, size_t frame_len, size_t *l3_off,
                   uint16_t *eth_type)
{
  if (!l3_off || !eth_type)
    return;
  *l3_off = ETH_HLEN;
  *eth_type = 0;
  if (!frame_pkt || frame_len < ETH_HLEN)
    return;
  *eth_type = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
  if ((*eth_type == 0x8100U || *eth_type == 0x88A8U)
      && frame_len >= ETH_HLEN + 4U + 20U)
    {
      *eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
      *l3_off = ETH_HLEN + 4U;
    }
}


typedef struct
{
  RtDec dec;
  uint8_t tx_ip[16];
  uint16_t tx_port;
  uint8_t tx_lla[16];
  bool has_tx_lla;
  uint16_t pmtu;
  bool use_tcp;
  uint16_t max_vnet;
  size_t chunk_max;
} FwdPath;

static bool
fwd_resolve (Rt *rt, const Cfg *cfg, const uint8_t dest_lla[16],
             const uint8_t src_ip[16], uint16_t src_port, FwdPath *fp)
{
  memset (fp, 0, sizeof (*fp));
  if (!rt_nh_get (rt, cfg, dest_lla, &fp->dec, fp->tx_ip, &fp->tx_port))
    return false;
  fp->has_tx_lla = rt_nh_lla_get (rt, &fp->dec, dest_lla, fp->tx_ip,
                                  fp->tx_port, fp->tx_lla);
  if (src_ip && memcmp (fp->tx_ip, src_ip, 16) == 0
      && fp->tx_port == src_port)
    return false;
  fp->pmtu = rt_mtu (rt, &fp->dec);
  fp->use_tcp = tx_path_use_tcp (rt, cfg, fp->tx_ip, fp->tx_port);
  fp->max_vnet = fp->use_tcp ? tp_vnet_cap_get ()
                             : tnl_vnet_cap_get (fp->pmtu, fp->tx_ip);
  fp->chunk_max = fp->use_tcp ? pkt_frag_pl_cap_get (true)
                              : tnl_frag_pl_cap_get (fp->max_vnet, true);
  return fp->chunk_max != 0;
}

static bool
fwd_send_frag (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
               const FwdPath *fp, uint8_t *chunk_dst, size_t chunk_len,
               uint32_t mid, size_t abs_off, bool mf,
               const uint8_t dst_tail[4], uint8_t hop_c, uint64_t ts)
{
  size_t out_len = 0;
  uint8_t *out_ptr
      = frag_bld_zc (cry_ctx, chunk_dst, chunk_len, mid, abs_off, mf, 1,
                     dst_tail, hop_c, fp->has_tx_lla ? fp->tx_lla : NULL,
                     &out_len);
  if (!out_ptr || out_len == 0)
    return false;
  if (!tp_send (udp, rt, cfg, fp->tx_ip, fp->tx_port, out_ptr, out_len))
    return false;
  rt_tx_ack (rt, fp->tx_ip, fp->tx_port, ts);
  return true;
}

static void
fwd_hop_pulse (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
               const uint8_t dest_lla[16], const FwdPath *fp)
{
  if (fp->dec.type != RT_REL || !cfg->p2p)
    return;
  if (tx_path_use_tcp (rt, cfg, fp->dec.rel.relay_ip, fp->dec.rel.relay_port))
    return;
  static uint8_t hp_buf[UDP_PL_MAX];
  size_t hp_len = 0;
  hp_bld (cry_ctx, cfg->addr, dest_lla, fp->dec.rel.relay_lla, hp_buf,
          &hp_len);
  (void)tp_send_ctrl (udp, rt, cfg, fp->dec.rel.relay_ip, fp->dec.rel.relay_port,
                      hp_buf, hp_len);
}

bool
rel_fwd_dat (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             const uint8_t dest_lla[16], const uint8_t *vnet_frame,
             size_t vnet_len, uint8_t hop_c, uint64_t ts,
             const uint8_t src_ip[16], uint16_t src_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !vnet_frame)
    return false;
  if (vnet_len < VNET_HL + ETH_HLEN || vnet_len > FRAG_DATA_MAX
      || vnet_len > UINT16_MAX)
    return false;
  size_t frame_len = vnet_len - VNET_HL;
  if (hop_c == 0)
    return false;
  FwdPath fp;
  if (!fwd_resolve (rt, cfg, dest_lla, src_ip, src_port, &fp))
    return false;
  static uint8_t relay_vnet_buf[TP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
  static uint8_t rel_dat_stage[TP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
  uint8_t *relay_vnet = relay_vnet_buf + TAP_HR + PKT_HDR_SZ;
  memcpy (relay_vnet, vnet_frame, vnet_len);
  uint8_t *frame_pkt = relay_vnet + VNET_HL;
  size_t l3_off = ETH_HLEN;
  uint16_t eth_type = 0;
  frame_l3_info_get (frame_pkt, frame_len, &l3_off, &eth_type);
  if (!fp.use_tcp && (eth_type == 0x0800U || eth_type == 0x86DDU)
      && frame_len > l3_off)
    {
      uint16_t max_in_l3 = tnl_inner_l3_cap_get (fp.max_vnet, l3_off);
      if (max_in_l3 >= 88U)
        mss_clp (frame_pkt + l3_off, frame_len - l3_off, max_in_l3);
    }
  bool is_tiny = false;
  if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
    {
      is_tiny = (fp.chunk_max < 64U)
                && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
    }
  if (!is_tiny && (size_t)vnet_len <= (size_t)fp.max_vnet)
    {
      size_t out_len = 0;
      uint8_t *out_ptr
          = data_bld_zc (cry_ctx, relay_vnet, vnet_len, 1, hop_c,
                         fp.has_tx_lla ? fp.tx_lla : NULL, &out_len);
      if (!out_ptr || out_len == 0)
        return false;
      if (!tp_send (udp, rt, cfg, fp.tx_ip, fp.tx_port, out_ptr, out_len))
        return false;
      rt_tx_ack (rt, fp.tx_ip, fp.tx_port, ts);
    }
  else
    {
      size_t frag_vnet_max = frag_vnet_len_max (fp.chunk_max);
      if (frag_vnet_max == 0 || vnet_len > frag_vnet_max)
        return false;
      uint32_t mid = g_frag_mid++;
      if (g_frag_mid == 0)
        g_frag_mid = 1;
      uint8_t dst_tail[4];
      memcpy (dst_tail, dest_lla + 12, 4);
      size_t off = 0;
      while (off < vnet_len)
        {
          size_t chunk_len = vnet_len - off;
          if (chunk_len > fp.chunk_max)
            chunk_len = fp.chunk_max;
          bool mf = (off + chunk_len) < vnet_len;
          if (mf)
            chunk_len &= ~(size_t)(FRAG_OFF_UNIT - 1U);
          if (chunk_len == 0)
            return false;
          uint8_t *chunk_dst
              = rel_dat_stage + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
          memcpy (chunk_dst, relay_vnet + off, chunk_len);
          if (!fwd_send_frag (udp, cry_ctx, rt, cfg, &fp, chunk_dst,
                              chunk_len, mid, off, mf, dst_tail, hop_c, ts))
            return false;
          off += chunk_len;
        }
    }
  fwd_hop_pulse (udp, cry_ctx, rt, cfg, dest_lla, &fp);
  return true;
}

bool
relay_fwd_frag (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                const uint8_t dest_lla[16], uint32_t mid, uint32_t frag_off,
                bool mf_in, const uint8_t *chunk, size_t chunk_len,
                uint8_t hop_c, uint64_t ts, const uint8_t s_ip[16],
                uint16_t s_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !chunk)
    return false;
  if (hop_c == 0)
    return false;
  FwdPath fp;
  if (!fwd_resolve (rt, cfg, dest_lla, s_ip, s_port, &fp))
    return false;
  size_t frag_vnet_max = frag_vnet_len_max (fp.chunk_max);
  if (frag_vnet_max == 0
      || (size_t)frag_off + chunk_len > frag_vnet_max)
    return false;
  uint8_t dst_tail[4];
  memcpy (dst_tail, dest_lla + 12, 4);
  static uint8_t rel_fg_buf[UDP_PL_MAX + TAP_HR];
  uint8_t *chunk_dst_base
      = rel_fg_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
  for (size_t sub_off = 0; sub_off < chunk_len;)
    {
      size_t sub_len = chunk_len - sub_off;
      if (sub_len > fp.chunk_max)
        sub_len = fp.chunk_max;
      bool is_last_sub = (sub_off + sub_len) == chunk_len;
      bool mf_out = mf_in || !is_last_sub;
      if (mf_out)
        sub_len &= ~(size_t)(FRAG_OFF_UNIT - 1U);
      if (sub_len == 0)
        return false;
      memcpy (chunk_dst_base, chunk + sub_off, sub_len);
      if (!fwd_send_frag (udp, cry_ctx, rt, cfg, &fp, chunk_dst_base,
                          sub_len, mid, (size_t)frag_off + sub_off, mf_out,
                          dst_tail, hop_c, ts))
        return false;
      sub_off += sub_len;
    }
  fwd_hop_pulse (udp, cry_ctx, rt, cfg, dest_lla, &fp);
  return true;
}
