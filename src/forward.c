#include "forward.h"
#include "frag.h"
#include "gossip.h"
#include "mss.h"
#include "packet.h"
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
      if (!rt_gw_fnd (rt, cfg->addr, gw_ip, &gw_port))
        return false;
      memcpy (out_ip, gw_ip, 16);
      *out_port = gw_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  return false;
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
  const uint8_t *frame = vnet_frame + VNET_HL;
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
  if (!cfg->mtu_probe)
    {
      static uint8_t relay_frame_buf[UDP_PL_MAX + TAP_HR]
          __attribute__ ((aligned (32)));
      uint8_t *relay_vnet = relay_frame_buf + TAP_HR + PKT_HDR_SZ;
      memcpy (relay_vnet, vnet_frame, vnet_len);
      uint8_t *frame_pkt = relay_vnet + VNET_HL;
      size_t l3_off = ETH_HLEN;
      uint16_t eth_type
          = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
      if ((eth_type == 0x8100U || eth_type == 0x88A8U)
          && frame_len >= ETH_HLEN + 4 + 20)
        {
          eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
          l3_off = ETH_HLEN + 4;
        }
      if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off
          && cfg->mtu >= 88U)
        {
          mss_clp (frame_pkt + l3_off, frame_len - l3_off, cfg->mtu);
        }
      size_t out_len = 0;
      uint8_t *out_ptr
          = data_bld_zc (cry_ctx, relay_vnet, vnet_len, 1, hop_c, &out_len);
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
      if (dec.type == RT_REL && cfg->p2p == P2P_EN)
        {
          static uint8_t hp_buf[UDP_PL_MAX];
          size_t hp_len = 0;
          hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
          udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
        }
      return true;
    }
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
  const uint16_t tnl_oh = (uint16_t)(oip_oh + 8U + PKT_HDR_SZ);
  int32_t frag_cap
      = (int32_t)pmtu - (int32_t)(tnl_oh + (uint16_t)sizeof (FragHdr) + 4U);
  if (frag_cap <= 0)
    return false;
  static uint8_t rel_p_buf[UDP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
  uint8_t *frame_pkt = rel_p_buf + TAP_HR + PKT_HDR_SZ;
  memcpy (frame_pkt, frame, frame_len);
  uint16_t m_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
  {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type
        = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
        eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
        l3_off = ETH_HLEN + 4;
      }
    if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
      {
        uint16_t m_in_l3 = (m_tap_f > l3_off + 20U)
                               ? (uint16_t)(m_tap_f - l3_off - 20U)
                               : 0;
        if (m_in_l3 >= 88U)
          {
            mss_clp (frame_pkt + l3_off, frame_len - l3_off, m_in_l3);
          }
      }
  }
  bool is_tiny = false;
  {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type
        = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
        eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
        l3_off = ETH_HLEN + 4;
      }
    if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
      {
        is_tiny = (frag_cap < 64)
                  && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
      }
  }
  if (!is_tiny && ((size_t)vnet_len + (size_t)tnl_oh) <= (size_t)pmtu)
    {
      size_t out_len = 0;
      uint8_t *out_ptr = data_bld_zc (cry_ctx, (uint8_t *)vnet_frame, vnet_len,
                                      1, hop_c, &out_len);
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
    }
  else
    {
      size_t frag_pfx = sizeof (FragHdr) + 4U;
      if (m_tap_f <= frag_pfx)
        return false;
      size_t chunk_max = m_tap_f - frag_pfx;
      if (chunk_max == 0)
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
              = rel_p_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
          memcpy (chunk_dst, vnet_frame + off, chunk_len);
          size_t out_len = 0;
          bool mf = (off + chunk_len) < vnet_len;
          if (off > 0x7fffU)
            break;
          uint8_t *out_ptr
              = frag_bld_zc (cry_ctx, chunk_dst, chunk_len, mid, (uint16_t)off,
                             mf, 1, dst_tail, hop_c, &out_len);
          if (!out_ptr || out_len == 0)
            {
              off += chunk_len;
              continue;
            }
          udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
          rt_tx_ack (rt, tx_ip, tx_port, ts);
          g_tx_ts = ts;
          off += chunk_len;
        }
    }
  if (dec.type == RT_REL && cfg->p2p == P2P_EN)
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
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
  if (!cfg->mtu_probe)
    {
      uint8_t dst_tail[4];
      memcpy (dst_tail, dest_lla + 12, 4);
      static uint8_t relay_frag_buf[UDP_PL_MAX + TAP_HR];
      uint8_t *chunk_dst
          = relay_frag_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
      memcpy (chunk_dst, chunk, chunk_len);
      size_t out_len = 0;
      uint8_t *out_ptr
          = frag_bld_zc (cry_ctx, chunk_dst, chunk_len, mid, frag_off, mf_in,
                         1, dst_tail, hop_c, &out_len);
      if (!out_ptr || out_len == 0)
        return false;
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
      if (dec.type == RT_REL && cfg->p2p == P2P_EN)
        {
          static uint8_t hp_buf[UDP_PL_MAX];
          size_t hp_len = 0;
          hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
          udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
        }
      return true;
    }
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
  const uint16_t tnl_oh = (uint16_t)(oip_oh + 8U + PKT_HDR_SZ);
  uint16_t m_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
  size_t frag_pfx = sizeof (FragHdr) + 4U;
  if (m_tap_f <= frag_pfx)
    return false;
  size_t chunk_max = m_tap_f - frag_pfx;
  if (chunk_max == 0)
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
      if (abs_off > UINT16_MAX)
        break;
      memcpy (chunk_dst_base, chunk + sub_off, sub_len);
      size_t out_len = 0;
      bool is_last_sub = (sub_off + sub_len) == chunk_len;
      bool mf_out = mf_in || !is_last_sub;
      if (abs_off > 0x7fffU)
        break;
      uint8_t *out_ptr = frag_bld_zc (cry_ctx, chunk_dst_base, sub_len, mid,
                                      (uint16_t)abs_off, mf_out, 1, dst_tail,
                                      hop_c, &out_len);
      if (!out_ptr || out_len == 0)
        {
          sub_off += sub_len;
          continue;
        }
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
      is_tx = true;
      sub_off += sub_len;
    }
  if (is_tx && dec.type == RT_REL && cfg->p2p == P2P_EN)
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
    }
  return is_tx;
}
