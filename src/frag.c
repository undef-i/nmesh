#include "frag.h"
#include <string.h>
#include <time.h>

static FBktMeta g_frag_meta[FRAG_BKT_MAX];
static FBktData g_frag_data[FRAG_BKT_MAX];

static uint64_t sys_ts (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int frag_bkt_get (const uint8_t src_lla[16], uint32_t msg_id)
{
  for (int i = 0; i < FRAG_BKT_MAX; i++)
    {
      if (!g_frag_meta[i].is_act) continue;
      if (g_frag_meta[i].msg_id == msg_id && memcmp(g_frag_meta[i].src_lla, src_lla, 16) == 0)
        return i;
    }
  return -1;
}

static int frag_bkt_new (const uint8_t src_lla[16], uint32_t msg_id)
{
  uint64_t now = sys_ts ();
  uint32_t start = msg_id % FRAG_BKT_MAX;
  int oldest_idx = -1;
  uint64_t oldest_ts = UINT64_MAX;

  for (uint32_t step = 0; step < FRAG_BKT_MAX; step++)
    {
      uint32_t idx = (start + step) % FRAG_BKT_MAX;
      FBktMeta *m = &g_frag_meta[idx];

      if (!m->is_act)
        {
          oldest_idx = (int)idx;
          break;
        }
      if (m->cre_ts < oldest_ts)
        {
          oldest_ts = m->cre_ts;
          oldest_idx = (int)idx;
        }
    }

  if (oldest_idx >= 0)
    {
      FBktMeta *m = &g_frag_meta[oldest_idx];
      FBktData *d = &g_frag_data[oldest_idx];


      memset (m, 0, sizeof (*m));
      memset (d->rx_bmp, 0, sizeof (d->rx_bmp));

      memcpy (m->src_lla, src_lla, 16);
      m->msg_id = msg_id;
      m->cre_ts = now;
      m->is_act = true;
      return oldest_idx;
    }
  return -1;
}

uint8_t *
frag_asm (const uint8_t src_lla[16], uint32_t msg_id, uint16_t off, bool mf, 
          const uint8_t *data, size_t data_len, uint16_t *out_len)
{
  if (!data || data_len == 0 || (size_t)off + data_len > 65535)
    return NULL;

  int idx = frag_bkt_get (src_lla, msg_id);
  if (idx < 0) idx = frag_bkt_new (src_lla, msg_id);
  if (idx < 0) return NULL;

  FBktMeta *m = &g_frag_meta[idx];
  FBktData *d = &g_frag_data[idx];
  uint16_t end = (uint16_t)((size_t)off + data_len);

  if (!mf)
    {
      if (end == 0 || (m->end_seen && m->tot_len != end)) return NULL;
      m->tot_len = end;
      m->end_seen = true;
    }

  if (m->end_seen && end > m->tot_len) return NULL;
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
      if (out_len) *out_len = m->tot_len;
      m->is_act = false;
      return d->buf;
    }
  return NULL;
}

void frag_reap_tk (uint64_t sys_ts)
{
  for (int i = 0; i < FRAG_BKT_MAX; i++)
    {
      if (!g_frag_meta[i].is_act) continue;
      if (sys_ts < g_frag_meta[i].cre_ts || sys_ts - g_frag_meta[i].cre_ts > 1500ULL)
        {
          g_frag_meta[i].is_act = false;
        }
    }
}
