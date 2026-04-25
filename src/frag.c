#include "frag.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FBktMeta *g_frag_meta = NULL;
static FBktData *g_frag_data = NULL;
static uint32_t g_frag_cap = 0;

static uint64_t
sys_ts (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static bool
frag_tab_rsv (uint32_t need)
{
  if (need <= g_frag_cap)
    return true;
  uint32_t new_cap = g_frag_cap ? g_frag_cap : FRAG_BKT_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }

  FBktMeta *new_meta = calloc ((size_t)new_cap, sizeof (*new_meta));
  if (!new_meta)
    return false;
  FBktData *new_data = calloc ((size_t)new_cap, sizeof (*new_data));
  if (!new_data)
    {
      free (new_meta);
      return false;
    }
  if (g_frag_cap > 0)
    {
      memcpy (new_meta, g_frag_meta, (size_t)g_frag_cap * sizeof (*new_meta));
      memcpy (new_data, g_frag_data, (size_t)g_frag_cap * sizeof (*new_data));
    }
  free (g_frag_meta);
  free (g_frag_data);
  g_frag_meta = new_meta;
  g_frag_data = new_data;
  g_frag_cap = new_cap;
  return true;
}

static bool
frag_bkt_bufs_ensure (FBktData *d)
{
  if (!d)
    return false;
  if (!d->buf)
    {
      d->buf = malloc (65535U);
      if (!d->buf)
        return false;
    }
  if (!d->rx_bmp)
    {
      d->rx_bmp = malloc ((65535U / 8U) + 1U);
      if (!d->rx_bmp)
        {
          free (d->buf);
          d->buf = NULL;
          return false;
        }
    }
  return true;
}

static int
frag_bkt_get (const uint8_t src_lla[16], uint32_t msg_id)
{
  for (uint32_t i = 0; i < g_frag_cap; i++)
    {
      if (!g_frag_meta[i].is_act)
        continue;
      if (g_frag_meta[i].msg_id == msg_id
          && memcmp (g_frag_meta[i].src_lla, src_lla, 16) == 0)
        return (int)i;
    }
  return -1;
}

static int
frag_bkt_new (const uint8_t src_lla[16], uint32_t msg_id)
{
  if (!frag_tab_rsv (g_frag_cap > 0 ? g_frag_cap : FRAG_BKT_CAP_INIT))
    return -1;

  int idx = -1;
  for (uint32_t i = 0; i < g_frag_cap; i++)
    {
      if (!g_frag_meta[i].is_act)
        {
          idx = (int)i;
          break;
        }
    }
  if (idx < 0)
    {
      uint32_t old_cap = g_frag_cap;
      if (!frag_tab_rsv (old_cap + 1U))
        return -1;
      idx = (int)old_cap;
    }

  FBktMeta *m = &g_frag_meta[idx];
  FBktData *d = &g_frag_data[idx];
  if (!frag_bkt_bufs_ensure (d))
    return -1;

  memset (m, 0, sizeof (*m));
  memset (d->rx_bmp, 0, (65535U / 8U) + 1U);
  memcpy (m->src_lla, src_lla, 16);
  m->msg_id = msg_id;
  m->cre_ts = sys_ts ();
  m->is_act = true;
  return idx;
}

uint8_t *
frag_asm (const uint8_t src_lla[16], uint32_t msg_id, uint16_t off, bool mf,
          const uint8_t *data, size_t data_len, uint16_t *out_len)
{
  if (!data || data_len == 0 || (size_t)off + data_len > 65535)
    return NULL;

  int idx = frag_bkt_get (src_lla, msg_id);
  if (idx < 0)
    idx = frag_bkt_new (src_lla, msg_id);
  if (idx < 0)
    return NULL;

  FBktMeta *m = &g_frag_meta[idx];
  FBktData *d = &g_frag_data[idx];
  if (!d->buf || !d->rx_bmp)
    return NULL;
  uint16_t end = (uint16_t)((size_t)off + data_len);

  if (!mf)
    {
      if (end == 0 || (m->end_seen && m->tot_len != end))
        return NULL;
      m->tot_len = end;
      m->end_seen = true;
    }

  if (m->end_seen && end > m->tot_len)
    return NULL;
  memcpy (d->buf + off, data, data_len);
  for (size_t i = 0; i < data_len; i++)
    {
      uint32_t pos = (uint32_t)off + (uint32_t)i;
      uint32_t bit_idx = pos >> 3;
      uint8_t mask = (uint8_t)(1U << (pos & 7U));

      if ((d->rx_bmp[bit_idx] & mask) == 0)
        {
          d->rx_bmp[bit_idx] |= mask;
          m->rx_bytes++;
        }
    }

  if (m->end_seen && m->rx_bytes == m->tot_len)
    {
      if (out_len)
        *out_len = m->tot_len;
      m->is_act = false;
      return d->buf;
    }
  return NULL;
}

void
frag_reap_tk (uint64_t now)
{
  for (uint32_t i = 0; i < g_frag_cap; i++)
    {
      if (!g_frag_meta[i].is_act)
        continue;
      if (now < g_frag_meta[i].cre_ts || now - g_frag_meta[i].cre_ts > 1500ULL)
        g_frag_meta[i].is_act = false;
    }
}
