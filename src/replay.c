#include "replay.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RX_RP_CAP_INIT 512U
#define RX_RP_W 256
#define RX_RP_B (RX_RP_W * 64)
#define RX_RP_SID_SZ PKT_NONCE_SID_SZ
#define RX_RP_LF_NUM 3U
#define RX_RP_LF_DEN 4U
#define RX_RP_HOT_N (RX_RP_CAP_INIT / 128U)

typedef enum
{
  RX_RP_EMPTY = 0,
  RX_RP_USED,
  RX_RP_TOMB,
} RxRpSt;

typedef struct
{
  RxRpSt st;
  uint8_t sid[RX_RP_SID_SZ];
  uint64_t max_cnt;
  uint64_t last_ts;
  uint64_t map[RX_RP_W];
} RxRp;

static RxRp *g_rx_rp = NULL;
static uint32_t g_rx_rp_cap = 0;
static uint32_t g_rx_rp_used = 0;
static uint32_t g_rx_rp_tomb = 0;
static uint64_t g_rx_rp_last_warn_ts;
static uint32_t g_rx_rp_last_idx = UINT32_MAX;
static uint32_t g_rx_rp_hot_idx[RX_RP_HOT_N] = { UINT32_MAX, UINT32_MAX,
                                                 UINT32_MAX, UINT32_MAX };
static uint32_t g_rx_rp_hot_pos = 0;

static uint64_t
nonce_cnt_rd (const uint8_t nonce[PKT_NONCE_SZ])
{
  size_t off = PKT_NONCE_SID_SZ;
  return ((uint64_t)nonce[off] << 56) | ((uint64_t)nonce[off + 1] << 48)
         | ((uint64_t)nonce[off + 2] << 40)
         | ((uint64_t)nonce[off + 3] << 32)
         | ((uint64_t)nonce[off + 4] << 24)
         | ((uint64_t)nonce[off + 5] << 16)
         | ((uint64_t)nonce[off + 6] << 8) | (uint64_t)nonce[off + 7];
}

static void
nonce_sid_rd (const uint8_t nonce[PKT_NONCE_SZ], uint8_t sid[RX_RP_SID_SZ])
{
  memcpy (sid, nonce, RX_RP_SID_SZ);
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

static bool
rx_rp_sid_eq (const RxRp *slot, const uint8_t sid[RX_RP_SID_SZ])
{
  return slot && slot->st == RX_RP_USED
         && memcmp (slot->sid, sid, RX_RP_SID_SZ) == 0;
}

static bool
rx_rp_slot_stale (const RxRp *slot, uint64_t now)
{
  return slot && slot->st == RX_RP_USED && now > slot->last_ts
         && (now - slot->last_ts) > UM_PRB_IMAX;
}

static void
rx_rp_hot_invalidate (uint32_t idx)
{
  if (g_rx_rp_last_idx == idx)
    g_rx_rp_last_idx = UINT32_MAX;
  for (uint32_t i = 0; i < RX_RP_HOT_N; i++)
    {
      if (g_rx_rp_hot_idx[i] == idx)
        g_rx_rp_hot_idx[i] = UINT32_MAX;
    }
}

static void
rx_rp_hot_reset (void)
{
  g_rx_rp_last_idx = UINT32_MAX;
  for (uint32_t i = 0; i < RX_RP_HOT_N; i++)
    g_rx_rp_hot_idx[i] = UINT32_MAX;
  g_rx_rp_hot_pos = 0;
}

static void
rx_rp_hot_note (uint32_t idx)
{
  g_rx_rp_last_idx = idx;
  for (uint32_t i = 0; i < RX_RP_HOT_N; i++)
    {
      if (g_rx_rp_hot_idx[i] == idx)
        return;
    }
  g_rx_rp_hot_idx[g_rx_rp_hot_pos] = idx;
  g_rx_rp_hot_pos = (g_rx_rp_hot_pos + 1U) % RX_RP_HOT_N;
}

static void
rx_rp_slot_tomb (RxRp *slot)
{
  if (!slot || slot->st != RX_RP_USED)
    return;
  uint32_t idx = UINT32_MAX;
  if (g_rx_rp && slot >= g_rx_rp && slot < (g_rx_rp + g_rx_rp_cap))
    idx = (uint32_t)(slot - g_rx_rp);
  slot->st = RX_RP_TOMB;
  g_rx_rp_used--;
  g_rx_rp_tomb++;
  if (idx != UINT32_MAX)
    rx_rp_hot_invalidate (idx);
}

static void
rx_rp_slot_init (RxRp *slot, const uint8_t sid[RX_RP_SID_SZ], uint64_t cnt,
                 uint64_t now)
{
  if (!slot)
    return;
  if (slot->st != RX_RP_USED)
    {
      if (slot->st == RX_RP_TOMB && g_rx_rp_tomb > 0)
        g_rx_rp_tomb--;
      g_rx_rp_used++;
    }
  slot->st = RX_RP_USED;
  memcpy (slot->sid, sid, sizeof (slot->sid));
  slot->max_cnt = cnt;
  slot->last_ts = now;
  rx_rp_map_rst (slot->map);
  rx_rp_map_set (slot->map, cnt);
}

static uint64_t
rx_rp_sid_hash (const uint8_t sid[RX_RP_SID_SZ])
{
  uint64_t x = 0;
  memcpy (&x, sid, sizeof (x));
  x *= 0x9e3779b185ebca87ULL;
  x ^= x >> 33;
  return x;
}

static uint32_t
rx_rp_cap_fit (uint32_t need)
{
  uint32_t cap = g_rx_rp_cap ? g_rx_rp_cap : RX_RP_CAP_INIT;
  while (cap < need)
    {
      if (cap > (UINT32_MAX / 2U))
        return need;
      cap *= 2U;
    }
  return cap;
}

static void
rx_rp_warn_grow_fail (uint32_t new_cap)
{
  uint64_t now = sys_ts ();
  if (now <= g_rx_rp_last_warn_ts
      || (g_rx_rp_last_warn_ts != 0
          && (now - g_rx_rp_last_warn_ts) < 5000ULL))
    return;
  fprintf (stderr, "replay: failed to expand window table to %u slots\n",
           (unsigned)new_cap);
  g_rx_rp_last_warn_ts = now;
}

static void
rx_rp_insert_raw (RxRp *tab, uint32_t cap, const RxRp *src)
{
  uint32_t mask = cap - 1U;
  uint32_t idx = (uint32_t)(rx_rp_sid_hash (src->sid) & mask);
  while (tab[idx].st == RX_RP_USED)
    idx = (idx + 1U) & mask;
  tab[idx] = *src;
}

static bool
rx_rp_rehash (uint32_t need_cap, uint64_t now)
{
  uint32_t new_cap = rx_rp_cap_fit (need_cap);
  RxRp *new_arr = calloc ((size_t)new_cap, sizeof (*new_arr));
  if (!new_arr)
    {
      rx_rp_warn_grow_fail (new_cap);
      return false;
    }

  uint32_t used = 0;
  for (uint32_t i = 0; i < g_rx_rp_cap; i++)
    {
      if (g_rx_rp[i].st != RX_RP_USED || rx_rp_slot_stale (&g_rx_rp[i], now))
        continue;
      rx_rp_insert_raw (new_arr, new_cap, &g_rx_rp[i]);
      used++;
    }

  free (g_rx_rp);
  g_rx_rp = new_arr;
  g_rx_rp_cap = new_cap;
  g_rx_rp_used = used;
  g_rx_rp_tomb = 0;
  rx_rp_hot_reset ();
  return true;
}

static bool
rx_rp_maybe_rehash (uint64_t now, uint32_t add_used)
{
  if (g_rx_rp_cap == 0)
    return rx_rp_rehash (RX_RP_CAP_INIT, now);
  uint32_t occ = g_rx_rp_used + g_rx_rp_tomb + add_used;
  if ((uint64_t)occ * RX_RP_LF_DEN >= (uint64_t)g_rx_rp_cap * RX_RP_LF_NUM)
    return rx_rp_rehash (g_rx_rp_cap * 2U, now);
  if (g_rx_rp_tomb > g_rx_rp_used && g_rx_rp_tomb > (g_rx_rp_cap / 8U))
    return rx_rp_rehash (g_rx_rp_cap, now);
  return true;
}

static RxRp *
rx_rp_hot_lookup_idx (uint32_t idx, const uint8_t sid[RX_RP_SID_SZ],
                      uint64_t now)
{
  if (idx >= g_rx_rp_cap)
    return NULL;
  RxRp *slot = &g_rx_rp[idx];
  if (slot->st != RX_RP_USED)
    return NULL;
  if (rx_rp_slot_stale (slot, now))
    {
      rx_rp_slot_tomb (slot);
      return NULL;
    }
  return rx_rp_sid_eq (slot, sid) ? slot : NULL;
}

static RxRp *
rx_rp_probe_slot (const uint8_t sid[RX_RP_SID_SZ], uint64_t now, bool *found)
{
  if (found)
    *found = false;
  if (g_rx_rp_cap == 0)
    return NULL;

  uint32_t mask = g_rx_rp_cap - 1U;
  uint32_t idx = (uint32_t)(rx_rp_sid_hash (sid) & mask);
  uint32_t first_tomb = UINT32_MAX;

  for (uint32_t n = 0; n < g_rx_rp_cap; n++, idx = (idx + 1U) & mask)
    {
      RxRp *slot = &g_rx_rp[idx];
      if (slot->st == RX_RP_EMPTY)
        {
          if (first_tomb != UINT32_MAX)
            return &g_rx_rp[first_tomb];
          return slot;
        }
      if (slot->st == RX_RP_TOMB)
        {
          if (first_tomb == UINT32_MAX)
            first_tomb = idx;
          continue;
        }
      if (rx_rp_slot_stale (slot, now))
        {
          rx_rp_slot_tomb (slot);
          if (first_tomb == UINT32_MAX)
            first_tomb = idx;
          continue;
        }
      if (rx_rp_sid_eq (slot, sid))
        {
          if (found)
            *found = true;
          return slot;
        }
    }
  if (first_tomb != UINT32_MAX)
    return &g_rx_rp[first_tomb];
  return NULL;
}

static RxRp *
rx_rp_find_slot (const uint8_t sid[RX_RP_SID_SZ], uint64_t now, bool *found)
{
  RxRp *slot = NULL;
  bool probe_found = false;

  if (found)
    *found = false;
  if (g_rx_rp_cap == 0)
    return NULL;

  if (g_rx_rp_last_idx < g_rx_rp_cap)
    {
      slot = rx_rp_hot_lookup_idx (g_rx_rp_last_idx, sid, now);
      if (found)
        *found = slot != NULL;
    }
  if (!slot)
    {
      for (uint32_t i = 0; i < RX_RP_HOT_N; i++)
        {
          uint32_t idx = g_rx_rp_hot_idx[i];
          if (idx == UINT32_MAX || idx == g_rx_rp_last_idx)
            continue;
          slot = rx_rp_hot_lookup_idx (idx, sid, now);
          if (slot)
            {
              if (found)
                *found = true;
              break;
            }
        }
    }
  if (!slot)
    {
      slot = rx_rp_probe_slot (sid, now, &probe_found);
      if (found)
        *found = probe_found;
    }
  if (slot && found && *found)
    rx_rp_hot_note ((uint32_t)(slot - g_rx_rp));
  return slot;
}

bool
rx_rp_chk (const uint8_t nonce[PKT_NONCE_SZ])
{
  uint8_t sid[RX_RP_SID_SZ];
  nonce_sid_rd (nonce, sid);
  uint64_t cnt = nonce_cnt_rd (nonce);
  uint64_t now = sys_ts ();
  bool found = false;
  RxRp *slot = rx_rp_find_slot (sid, now, &found);
  if (!slot || !found)
    return true;
  if (cnt > slot->max_cnt)
    return true;
  uint64_t df = slot->max_cnt - cnt;
  if (df >= RX_RP_B)
    return false;
  return !rx_rp_map_tst (slot->map, cnt);
}

bool
rx_rp_cmt (const uint8_t nonce[PKT_NONCE_SZ])
{
  uint8_t sid[RX_RP_SID_SZ];
  nonce_sid_rd (nonce, sid);
  uint64_t cnt = nonce_cnt_rd (nonce);
  uint64_t now = sys_ts ();
  bool found = false;
  RxRp *slot = NULL;

  if (g_rx_rp_cap == 0 && !rx_rp_rehash (RX_RP_CAP_INIT, now))
    return false;

  slot = rx_rp_find_slot (sid, now, &found);
  if (!slot)
    return false;
  if (!found)
    {
      if (!rx_rp_maybe_rehash (now, 1U))
        return false;
      slot = rx_rp_probe_slot (sid, now, &found);
      if (!slot)
        return false;
    }
  if (!slot)
    return false;
  rx_rp_hot_note ((uint32_t)(slot - g_rx_rp));
  if (!found)
    {
      rx_rp_slot_init (slot, sid, cnt, now);
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
  (void)ip;
  (void)port;
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
