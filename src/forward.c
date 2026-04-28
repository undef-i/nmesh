#include "forward.h"
#include "frag.h"
#include "gossip.h"
#include "mss.h"
#include "packet.h"
#include "tcp.h"
#include "utils.h"
#include <linux/if_ether.h>
#include <string.h>

static uint16_t
ep_mtu_get (const Rt *rt, const uint8_t ip[16], uint16_t port)
{
  uint16_t best = 0;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (!re->is_act || re->state == RT_DED)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      uint16_t mtu
          = (re->mtu > 0) ? re->mtu
                          : ((re->mtu_lkg > 0) ? re->mtu_lkg : RT_MTU_MIN);
      if (best == 0 || mtu < best)
        best = mtu;
    }
  return (best > 0) ? best : RT_MTU_MIN;
}

static uint16_t
tx_path_pmtu_get (const Cfg *cfg, const uint8_t tx_ip[16], uint16_t path_mtu)
{
  uint16_t pmtu = (path_mtu >= RT_MTU_MIN) ? path_mtu : RT_MTU_MIN;
  if (!cfg || cfg->mtu_probe)
    return pmtu;
  uint16_t local_mtu = udp_ep_mtu_get (tx_ip);
  if (local_mtu >= RT_MTU_MIN && local_mtu < pmtu)
    pmtu = local_mtu;
  return pmtu;
}

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
  RtDec dec = rt_sel (rt, dest_lla, cfg->p2p == P2P_EN);
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
      if (!rt_gw_fnd (rt, cfg->addr, cfg->p2p != P2P_EN, gw_ip, &gw_port))
        return false;
      memcpy (out_ip, gw_ip, 16);
      *out_port = gw_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  return false;
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

bool
rel_fwd_dat (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             const uint8_t dest_lla[16], const uint8_t *vnet_frame,
             size_t vnet_len, uint8_t hop_c, uint64_t ts,
             const uint8_t src_ip[16], uint16_t src_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !vnet_frame)
    return false;
  if (vnet_len < VNET_HL + ETH_HLEN || vnet_len > TAP_F_MAX
      || vnet_len > UINT16_MAX)
    return false;
  size_t frame_len = vnet_len - VNET_HL;
  if (hop_c == 0)
    return false;
  RtDec dec;
  uint8_t tx_ip[16] = { 0 };
  uint16_t tx_port = 0;
  if (!rt_nh_get (rt, cfg, dest_lla, &dec, tx_ip, &tx_port))
    {
      return false;
    }
  if (src_ip && memcmp (tx_ip, src_ip, 16) == 0 && tx_port == src_port)
    {
      return false;
    }
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  bool use_tcp = tx_path_use_tcp (rt, cfg, tx_ip, tx_port);
  pmtu = tx_path_pmtu_get (cfg, tx_ip, pmtu);
  static uint8_t relay_vnet_buf[UDP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
  uint8_t *relay_vnet = relay_vnet_buf + TAP_HR + PKT_HDR_SZ;
  memcpy (relay_vnet, vnet_frame, vnet_len);
  uint8_t *frame_pkt = relay_vnet + VNET_HL;
  uint16_t max_vnet = use_tcp ? tp_vnet_cap_get () : tnl_vnet_cap_get (pmtu, tx_ip);
  size_t l3_off = ETH_HLEN;
  uint16_t eth_type = 0;
  frame_l3_info_get (frame_pkt, frame_len, &l3_off, &eth_type);
  if (!use_tcp && (eth_type == 0x0800U || eth_type == 0x86DDU)
      && frame_len > l3_off)
    {
      uint16_t max_in_l3 = tnl_inner_l3_cap_get (max_vnet, l3_off);
      if (max_in_l3 >= 88U)
        mss_clp (frame_pkt + l3_off, frame_len - l3_off, max_in_l3);
    }
  size_t chunk_max = use_tcp ? pkt_frag_pl_cap_get (true)
                             : tnl_frag_pl_cap_get (max_vnet, true);
  if (chunk_max == 0)
    return false;
  bool is_tiny = false;
  if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
    {
      is_tiny = (chunk_max < 64U)
                && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
    }
  if (!is_tiny && (size_t)vnet_len <= (size_t)max_vnet)
    {
      size_t out_len = 0;
      uint8_t *out_ptr
          = data_bld_zc (cry_ctx, relay_vnet, vnet_len, 1, hop_c, &out_len);
      if (tp_send (udp, rt, cfg, tx_ip, tx_port, out_ptr, out_len))
        {
          rt_tx_ack (rt, tx_ip, tx_port, ts);
          g_tx_ts = ts;
        }
    }
  else
    {
      size_t frag_vnet_max = frag_vnet_len_max (chunk_max);
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
          if (chunk_len > chunk_max)
            chunk_len = chunk_max;
          uint8_t *chunk_dst
              = relay_vnet_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
          memcpy (chunk_dst, relay_vnet + off, chunk_len);
          size_t out_len = 0;
          bool mf = (off + chunk_len) < vnet_len;
          uint8_t *out_ptr
              = frag_bld_zc (cry_ctx, chunk_dst, chunk_len, mid, (uint16_t)off,
                             mf, 1, dst_tail, hop_c, &out_len);
          if (!out_ptr || out_len == 0)
            {
              off += chunk_len;
              continue;
            }
          if (tp_send (udp, rt, cfg, tx_ip, tx_port, out_ptr, out_len))
            {
              rt_tx_ack (rt, tx_ip, tx_port, ts);
              g_tx_ts = ts;
            }
          off += chunk_len;
        }
    }
  if (dec.type == RT_REL && cfg->p2p == P2P_EN
      && !tx_path_use_tcp (rt, cfg, dec.rel.relay_ip, dec.rel.relay_port))
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      (void)tp_send_ctrl (udp, rt, cfg, dec.rel.relay_ip, dec.rel.relay_port,
                          hp_buf, hp_len);
    }
  return true;
}

bool
relay_fwd_frag (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                const uint8_t dest_lla[16], uint32_t mid, uint16_t frag_off,
                bool mf_in, const uint8_t *chunk, size_t chunk_len,
                uint8_t hop_c, uint64_t ts, const uint8_t s_ip[16],
                uint16_t s_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !chunk)
    return false;
  if (hop_c == 0)
    return false;
  RtDec dec;
  uint8_t tx_ip[16] = { 0 };
  uint16_t tx_port = 0;
  if (!rt_nh_get (rt, cfg, dest_lla, &dec, tx_ip, &tx_port))
    {
      return false;
    }
  if (s_ip && memcmp (tx_ip, s_ip, 16) == 0 && tx_port == s_port)
    {
      return false;
    }
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  bool use_tcp = tx_path_use_tcp (rt, cfg, tx_ip, tx_port);
  pmtu = tx_path_pmtu_get (cfg, tx_ip, pmtu);
  uint16_t max_vnet = use_tcp ? tp_vnet_cap_get () : tnl_vnet_cap_get (pmtu, tx_ip);
  size_t chunk_max = use_tcp ? pkt_frag_pl_cap_get (true)
                             : tnl_frag_pl_cap_get (max_vnet, true);
  if (chunk_max == 0)
    return false;
  size_t frag_vnet_max = frag_vnet_len_max (chunk_max);
  if (frag_vnet_max == 0
      || (size_t)frag_off + chunk_len > frag_vnet_max)
    return false;
  uint8_t dst_tail[4];
  memcpy (dst_tail, dest_lla + 12, 4);
  bool is_tx = false;
  static uint8_t rel_fg_buf[UDP_PL_MAX + TAP_HR];
  uint8_t *chunk_dst_base
      = rel_fg_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
  for (size_t sub_off = 0; sub_off < chunk_len;)
    {
      size_t sub_len = chunk_len - sub_off;
      if (sub_len > chunk_max)
        sub_len = chunk_max;
      uint32_t abs_off = (uint32_t)frag_off + (uint32_t)sub_off;
      memcpy (chunk_dst_base, chunk + sub_off, sub_len);
      size_t out_len = 0;
      bool is_last_sub = (sub_off + sub_len) == chunk_len;
      bool mf_out = mf_in || !is_last_sub;
      uint8_t *out_ptr = frag_bld_zc (cry_ctx, chunk_dst_base, sub_len, mid,
                                      (uint16_t)abs_off, mf_out, 1, dst_tail,
                                      hop_c, &out_len);
      if (!out_ptr || out_len == 0)
        {
          sub_off += sub_len;
          continue;
        }
      if (tp_send (udp, rt, cfg, tx_ip, tx_port, out_ptr, out_len))
        {
          rt_tx_ack (rt, tx_ip, tx_port, ts);
          g_tx_ts = ts;
        }
      is_tx = true;
      sub_off += sub_len;
    }
  if (is_tx && dec.type == RT_REL && cfg->p2p == P2P_EN
      && !tx_path_use_tcp (rt, cfg, dec.rel.relay_ip, dec.rel.relay_port))
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      (void)tp_send_ctrl (udp, rt, cfg, dec.rel.relay_ip, dec.rel.relay_port,
                          hp_buf, hp_len);
    }
  return is_tx;
}
