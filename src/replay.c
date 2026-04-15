#include "replay.h"
#include "utils.h"
#include <string.h>

#define RX_RP_MAX 512
#define RX_RP_W 256
#define RX_RP_B (RX_RP_W * 64)

typedef struct
{
  bool is_act;
  uint8_t ip[16];
  uint16_t port;
  uint8_t sid[4];
  uint64_t max_cnt;
  uint64_t last_ts;
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
rx_rp_map_clr (uint64_t map[RX_RP_W], uint64_t cnt)
{
  size_t wi = (size_t)((cnt % RX_RP_B) / 64U);
  size_t bi = (size_t)(cnt & 63U);
  map[wi] &= ~(1ULL << bi);
}

static bool
rx_rp_map_tst (const uint64_t map[RX_RP_W], uint64_t cnt)
{
  size_t wi = (size_t)((cnt % RX_RP_B) / 64U);
  size_t bi = (size_t)(cnt & 63U);
  return (map[wi] & (1ULL << bi)) != 0;
}

static void
rx_rp_map_set (uint64_t map[RX_RP_W], uint64_t cnt)
{
  size_t wi = (size_t)((cnt % RX_RP_B) / 64U);
  size_t bi = (size_t)(cnt & 63U);
  map[wi] |= (1ULL << bi);
}

static void
rx_rp_slot_init (RxRp *slot, const uint8_t ip[16], uint16_t port,
                 const uint8_t sid[4], uint64_t cnt, uint64_t now)
{
  if (!slot)
    return;
  slot->is_act = true;
  memcpy (slot->ip, ip, 16);
  slot->port = port;
  memcpy (slot->sid, sid, sizeof (slot->sid));
  slot->max_cnt = cnt;
  slot->last_ts = now;
  rx_rp_map_rst (slot->map);
  rx_rp_map_set (slot->map, cnt);
}

bool
rx_rp_chk (const uint8_t ip[16], uint16_t port,
           const uint8_t nonce[PKT_NONCE_SZ])
{
  uint8_t sid[4];
  nonce_sid_rd (nonce, sid);
  uint64_t cnt = nonce_cnt_rd (nonce);
  uint64_t now = sys_ts ();

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
      RxRp *stale = NULL;
      uint64_t stale_ts = UINT64_MAX;
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
          if (now > g_rx_rp[i].last_ts
              && (now - g_rx_rp[i].last_ts) > UM_PRB_IMAX
              && g_rx_rp[i].last_ts < stale_ts)
            {
              stale = &g_rx_rp[i];
              stale_ts = g_rx_rp[i].last_ts;
            }
        }
      if (!slot)
        slot = same_ep;
      if (!slot)
        slot = stale;
      if (!slot)
        return false;
      l_idx = (int)(slot - g_rx_rp);
    }

  if (!slot->is_act)
    {
      rx_rp_slot_init (slot, ip, port, sid, cnt, now);
      return true;
    }
  if (memcmp (slot->sid, sid, sizeof (sid)) != 0)
    {
      rx_rp_slot_init (slot, ip, port, sid, cnt, now);
      return true;
    }
  if (cnt > slot->max_cnt)
    {
      uint64_t sh = cnt - slot->max_cnt;
      if (sh >= RX_RP_B)
        {
          rx_rp_map_rst (slot->map);
        }
      else
        {
          for (uint64_t clr = slot->max_cnt + 1; clr <= cnt; clr++)
            rx_rp_map_clr (slot->map, clr);
        }
      slot->max_cnt = cnt;
      slot->last_ts = now;
      rx_rp_map_set (slot->map, cnt);
      return true;
    }
  uint64_t df = slot->max_cnt - cnt;
  if (df >= RX_RP_B)
    return false;
  if (rx_rp_map_tst (slot->map, cnt))
    return false;
  slot->last_ts = now;
  rx_rp_map_set (slot->map, cnt);
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
