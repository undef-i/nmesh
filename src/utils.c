#include "utils.h"
#include <string.h>
#include <time.h>

uint64_t g_tx_ts = 0;
uint64_t g_rx_ts = 0;
uint32_t g_frag_mid = 1;
uint32_t g_rnd_st = 0;
Rt *g_rt = NULL;

uint64_t
sys_ts (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint32_t
u32_rnd (void)
{
  if (g_rnd_st == 0)
    {
      uint64_t s = sys_ts ();
      g_rnd_st = (uint32_t)(s ^ (s >> 32) ^ 0x9e3779b9U);
      if (g_rnd_st == 0)
        g_rnd_st = 0x6d2b79f5U;
    }
  uint32_t x = g_rnd_st;
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  g_rnd_st = x;
  return x;
}

bool
rt_gw_fnd (const Rt *rt, const uint8_t our_lla[16], bool static_only,
           uint8_t out_ip[16], uint16_t *out_port)
{
  bool has_res = false;
  uint32_t best = RT_M_INF;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (!re->is_act || re->state == RT_DED)
        continue;
      if (re->r2d != 0)
        continue;
      if (static_only && !re->is_static)
        continue;
      if (memcmp (re->lla, our_lla, 16) == 0)
        continue;
      uint32_t m = re_m (re);
      if (m >= RT_M_INF)
        continue;
      if (!has_res || m < best)
        {
          memcpy (out_ip, re->ep_ip, 16);
          *out_port = re->ep_port;
          best = m;
          has_res = true;
        }
    }
  return has_res;
}
