#pragma once
#include "bogon.h"
#include "packet.h"
#include "route.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TAP_F_MAX 65550
#define VNET_HL 10
#define EV_MAX 10
#define ID_TAP 1
#define ID_UDP 2
#define ID_TMR 3
#define ID_STD 4
#define ID_CFG 5
#define ID_TAP_NOTE 6
#define GSP_INTV 1
#define UPD_TK 30
#define PEER_FLS_TK 5
#define KA_TMO 20000ULL
#define UM_PRB_A1 15000ULL
#define UM_PRB_A2 45000ULL
#define UM_PRB_A3 105000ULL
#define UM_PRB_A4 225000ULL
#define UM_PRB_A5 465000ULL
#define UM_PRB_A6 945000ULL
#define UM_PRB_I1 2000ULL
#define UM_PRB_I2 4000ULL
#define UM_PRB_I3 8000ULL
#define UM_PRB_I4 16000ULL
#define UM_PRB_I5 32000ULL
#define UM_PRB_I6 64000ULL
#define UM_PRB_IMAX 120000ULL

extern uint64_t g_tx_ts;
extern uint64_t g_rx_ts;
extern uint32_t g_frag_mid;
extern uint32_t g_rnd_st;
extern Rt *g_rt;

uint64_t sys_ts (void);
uint32_t u32_rnd (void);
bool rt_gw_fnd (const Rt *rt, const uint8_t our_lla[16], uint8_t out_ip[16],
                uint16_t *out_port);

static inline uint64_t
re_probe_age_ms (const Re *re, uint64_t now)
{
  if (!re || re->rx_ts == 0 || now <= re->rx_ts)
    return 0;
  return now - re->rx_ts;
}

static inline uint32_t
re_m (const Re *re)
{
  if (re->lat > 0 && re->lat < RTT_UNK)
    return re->lat;
  if (re->sm_m > 0 && re->sm_m < RT_M_INF && re->sm_m != RTT_UNK)
    return re->sm_m;
  if (re->rt_m > 0 && re->rt_m < RT_M_INF && re->rt_m != RTT_UNK)
    return re->rt_m;
  return RT_M_INF;
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
      if (l3_len < 60)
        return false;
      if (l3[6] != 6)
        return false;
      return (l3[40 + 13] & 0x02U) != 0;
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
