#include "replay.h"
#include <string.h>

#define RX_RP_MAX 512
#define RX_RP_W 16
#define RX_RP_B (RX_RP_W * 64)

typedef struct
{
  bool is_act;
  uint8_t ip[16];
  uint16_t port;
  uint8_t sid[4];
  uint64_t max_cnt;
  uint64_t map[RX_RP_W];
} RxRp;

static RxRp g_rx_rp[RX_RP_MAX];

static uint64_t
nonce_cnt_rd (const uint8_t nonce[PKT_NONCE_SZ])
{
  return ((uint64_t)nonce[4] << 56) | ((uint64_t)nonce[5] << 48)
         | ((uint64_t)nonce[6] << 40) | ((uint64_t)nonce[7] << 32)
         | ((uint64_t)nonce[8] << 24) | ((uint64_t)nonce[9] << 16)
         | ((uint64_t)nonce[10] << 8) | (uint64_t)nonce[11];
}

static void
nonce_sid_rd (const uint8_t nonce[PKT_NONCE_SZ], uint8_t sid[4])
{
  memcpy (sid, nonce, 4);
}

static void
rx_rp_map_rst (uint64_t map[RX_RP_W])
{
  memset (map, 0, sizeof (uint64_t) * RX_RP_W);
}

static void
rx_rp_map_shl (uint64_t map[RX_RP_W], uint64_t sh)
{
  if (sh == 0)
    return;
  if (sh >= RX_RP_B)
    {
      rx_rp_map_rst (map);
      return;
    }
  uint64_t tmp[RX_RP_W] = { 0 };
  size_t w_sh = (size_t)(sh / 64);
  size_t b_sh = (size_t)(sh % 64);
  for (int i = RX_RP_W - 1; i >= 0; i--)
    {
      if ((size_t)i < w_sh)
        continue;
      size_t src = (size_t)i - w_sh;
      uint64_t v = map[src] << b_sh;
      if (b_sh != 0 && src > 0)
        {
          v |= (map[src - 1] >> (64 - b_sh));
        }
      tmp[i] = v;
    }
  memcpy (map, tmp, sizeof (tmp));
}

static bool
rx_rp_map_tst (const uint64_t map[RX_RP_W], uint64_t df)
{
  if (df >= RX_RP_B)
    return false;
  size_t wi = (size_t)(df / 64);
  size_t bi = (size_t)(df % 64);
  return (map[wi] & (1ULL << bi)) != 0;
}

static void
rx_rp_map_set (uint64_t map[RX_RP_W], uint64_t df)
{
  if (df >= RX_RP_B)
    return;
  size_t wi = (size_t)(df / 64);
  size_t bi = (size_t)(df % 64);
  map[wi] |= (1ULL << bi);
}

bool
rx_rp_chk (const uint8_t ip[16], uint16_t port,
           const uint8_t nonce[PKT_NONCE_SZ])
{
  uint8_t sid[4];
  nonce_sid_rd (nonce, sid);
  uint64_t cnt = nonce_cnt_rd (nonce);

  static int l_idx = 0;
  RxRp *slot = NULL;

  if (g_rx_rp[l_idx].is_act && g_rx_rp[l_idx].port == port
      && memcmp (g_rx_rp[l_idx].ip, ip, 16) == 0
      && memcmp (g_rx_rp[l_idx].sid, sid, sizeof (sid)) == 0)
    {
      slot = &g_rx_rp[l_idx];
    }
  else
    {
      RxRp *same_ep = NULL;
      for (size_t i = 0; i < RX_RP_MAX; i++)
        {
          if (!g_rx_rp[i].is_act)
            {
              if (!slot)
                slot = &g_rx_rp[i];
              continue;
            }
          if (memcmp (g_rx_rp[i].ip, ip, 16) != 0 || g_rx_rp[i].port != port)
            continue;
          if (memcmp (g_rx_rp[i].sid, sid, sizeof (sid)) == 0)
            {
              slot = &g_rx_rp[i];
              break;
            }
          if (!same_ep)
            same_ep = &g_rx_rp[i];
        }
      if (!slot)
        slot = same_ep;
      if (!slot)
        return false;
      l_idx = (int)(slot - g_rx_rp);
    }

  if (!slot->is_act)
    {
      slot->is_act = true;
      memcpy (slot->ip, ip, 16);
      slot->port = port;
      memcpy (slot->sid, sid, sizeof (sid));
      slot->max_cnt = cnt;
      rx_rp_map_rst (slot->map);
      rx_rp_map_set (slot->map, 0);
      return true;
    }
  if (memcmp (slot->sid, sid, sizeof (sid)) != 0)
    {
      memcpy (slot->sid, sid, sizeof (sid));
      slot->max_cnt = cnt;
      rx_rp_map_rst (slot->map);
      rx_rp_map_set (slot->map, 0);
      return true;
    }
  if (cnt > slot->max_cnt)
    {
      uint64_t sh = cnt - slot->max_cnt;
      rx_rp_map_shl (slot->map, sh);
      rx_rp_map_set (slot->map, 0);
      slot->max_cnt = cnt;
      return true;
    }
  uint64_t df = slot->max_cnt - cnt;
  if (df >= RX_RP_B)
    return false;
  if (rx_rp_map_tst (slot->map, df))
    return false;
  rx_rp_map_set (slot->map, df);
  return true;
}

void
rx_rp_rst_ep (const uint8_t ip[16], uint16_t port)
{
  for (size_t i = 0; i < RX_RP_MAX; i++)
    {
      if (!g_rx_rp[i].is_act)
        continue;
      if (memcmp (g_rx_rp[i].ip, ip, 16) != 0)
        continue;
      if (g_rx_rp[i].port != port)
        continue;
      memset (&g_rx_rp[i], 0, sizeof (g_rx_rp[i]));
    }
}

void
rx_rp_rst_lla (Rt *rt, const uint8_t lla[16])
{
  if (!rt || !lla)
    return;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (memcmp (re->lla, lla, 16) != 0)
        continue;
      rx_rp_rst_ep (re->ep_ip, re->ep_port);
    }
}