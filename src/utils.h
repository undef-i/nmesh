#pragma once
#include "bogon.h"
#include "packet.h"
#include "route.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VNET_HL 10
#define TAP_F_MAX (FRAG_DATA_MAX - VNET_HL)
_Static_assert (FRAG_OFF_MASK * FRAG_OFF_UNIT >= TAP_F_MAX,
                "fragment offset space must cover the largest frame");
#define EV_MAX 10
#define ID_TAP 1
#define ID_UDP 2
#define ID_TMR 3
#define ID_STD 4
#define ID_CFG 5
#define ID_TAP_NOTE 6
#define TICK_INTV 1
#define UPD_TK 30
/* Age thresholds are the cumulative sums of the doubling intervals. */
#define UM_PRB_I1 2000ULL
#define UM_PRB_I2 4000ULL
#define UM_PRB_I3 8000ULL
#define UM_PRB_I4 16000ULL
#define UM_PRB_I5 32000ULL
#define UM_PRB_I6 64000ULL
#define UM_PRB_IMAX 120000ULL
#define UM_PRB_A1 (UM_PRB_I1)
#define UM_PRB_A2 (UM_PRB_A1 + UM_PRB_I2)
#define UM_PRB_A3 (UM_PRB_A2 + UM_PRB_I3)
#define UM_PRB_A4 (UM_PRB_A3 + UM_PRB_I4)
#define UM_PRB_A5 (UM_PRB_A4 + UM_PRB_I5)
#define UM_PRB_A6 (UM_PRB_A5 + UM_PRB_I6)

extern uint32_t g_frag_mid;
extern uint32_t g_rnd_st;

uint64_t sys_ts (void);
uint64_t wall_ts (void);
uint32_t u32_rnd (void);
bool rt_gw_fnd (const Rt *rt, const uint8_t our_lla[16], bool static_only,
                uint8_t out_ip[16], uint16_t *out_port);

static inline uint64_t
re_probe_age_ms (const Re *re, uint64_t now)
{
  if (!re || re->rx_ts == 0 || now <= re->rx_ts)
    return 0;
  return now - re->rx_ts;
}


static inline int32_t
re_m (const Re *re)
{
  return re->rt_m;
}

static inline bool
is_ip_v4m (const uint8_t ip[16])
{
  if (!ip)
    return false;
  return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
         && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0
         && ip[10] == 0xff && ip[11] == 0xff;
}

static inline bool
is_underlay_ip (const uint8_t ip[16])
{
  return ip && !bogon_ip_match (ip);
}

static inline bool
ip6_tcp_off_get (const uint8_t *pkt, size_t len, size_t *ip_hl)
{
  if (!pkt || !ip_hl)
    return false;
  if (len < 40)
    return false;
  uint8_t nh = pkt[6];
  size_t off = 40;
  while (off < len)
    {
      if (nh == 6)
        {
          *ip_hl = off;
          return true;
        }
      if (nh == 0 || nh == 43 || nh == 60)
        {
          if (off + 2 > len)
            return false;
          uint8_t n_nh = pkt[off];
          uint8_t ext_len = pkt[off + 1];
          size_t step = 8U + ((size_t)ext_len * 8U);
          if (step == 0 || off + step > len)
            return false;
          nh = n_nh;
          off += step;
          continue;
        }
      if (nh == 44)
        {
          if (off + 8 > len)
            return false;
          nh = pkt[off];
          off += 8;
          continue;
        }
      return false;
    }
  return false;
}

static inline bool
is_tcp_syn (const uint8_t *l3, size_t l3_len)
{
  if (!l3 || l3_len < 20)
    return false;
  uint8_t v = (uint8_t)((l3[0] >> 4) & 0x0f);
  if (v == 4)
    {
      uint8_t ihl = (uint8_t)((l3[0] & 0x0f) * 4);
      if (ihl < 20 || ((size_t)ihl + 20U) > l3_len)
        return false;
      if (l3[9] != 6)
        return false;
      return (l3[ihl + 13] & 0x02U) != 0;
    }
  if (v == 6)
    {
      size_t off = 0;
      if (!ip6_tcp_off_get (l3, l3_len, &off))
        return false;
      if (off + 20U > l3_len)
        return false;
      return (l3[off + 13] & 0x02U) != 0;
    }
  return false;
}

static inline uint16_t
tnl_vnet_cap_get (uint16_t path_mtu, const uint8_t tx_ip[16])
{
  uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
  uint32_t tnl_oh = (uint32_t)oip_oh + 8U + (uint32_t)PKT_HDR_SZ;
  return (path_mtu > tnl_oh) ? (uint16_t)(path_mtu - tnl_oh) : 0;
}

static inline uint16_t
tp_vnet_cap_get (void)
{
  return (uint16_t)TP_VNET_MAX;
}

static inline uint16_t
tnl_inner_l3_cap_get (uint16_t vnet_cap, size_t frame_l3_off)
{
  size_t inner_oh = (size_t)VNET_HL + frame_l3_off;
  return (vnet_cap > inner_oh) ? (uint16_t)(vnet_cap - inner_oh) : 0;
}

static inline size_t
tnl_frag_pl_cap_get (uint16_t vnet_cap, bool is_relay)
{
  size_t frag_oh = sizeof (FragHdr) + (is_relay ? 4U : 0U);
  return (vnet_cap > frag_oh) ? (size_t)(vnet_cap - frag_oh) : 0;
}

static inline size_t
pkt_frag_pl_cap_get (bool is_relay)
{
  size_t frag_oh = sizeof (FragHdr) + (is_relay ? 4U : 0U);
  return (PKT_PT_MAX > frag_oh) ? (size_t)(PKT_PT_MAX - frag_oh) : 0;
}
