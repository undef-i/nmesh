#include "frag.h"
#include <string.h>
#include <time.h>
static FBkt g_frag_bkt[FRAG_BKT_MAX];

static uint64_t
sys_ts (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static FBkt *
frag_bkt_get (uint32_t msg_id)
{
  for (int i = 0; i < FRAG_BKT_MAX; i++)
    {
      if (!g_frag_bkt[i].is_act)
        continue;
      if (g_frag_bkt[i].msg_id == msg_id)
        return &g_frag_bkt[i];
    }
  return NULL;
}

static FBkt *
frag_bkt_new (uint32_t msg_id)
{
  uint32_t start = msg_id % FRAG_BKT_MAX;
  for (uint32_t step = 0; step < FRAG_BKT_MAX; step++)
    {
      uint32_t idx = (start + step) % FRAG_BKT_MAX;
      if (g_frag_bkt[idx].is_act)
        continue;
      FBkt *b = &g_frag_bkt[idx];
      memset (b, 0, sizeof (*b));
      b->msg_id = msg_id;
      b->cre_ts = sys_ts ();
      b->is_act = true;
      return b;
    }
  return NULL;
}

uint8_t *
frag_asm (uint32_t msg_id, uint16_t off, uint16_t tot_len, const uint8_t *data,
          size_t data_len)
{
  if (!data)
    return NULL;
  if (tot_len == 0)
    return NULL;
  if (data_len == 0)
    return NULL;
  if ((size_t)off + data_len > tot_len)
    return NULL;
  FBkt *b = frag_bkt_get (msg_id);
  if (!b)
    b = frag_bkt_new (msg_id);
  if (!b)
    return NULL;
  if (b->tot_len == 0)
    {
      b->tot_len = tot_len;
    }
  if (b->tot_len != tot_len)
    {
      b->is_act = false;
      return NULL;
    }
  memcpy (b->buf + off, data, data_len);
  for (size_t i = 0; i < data_len; i++)
    {
      uint32_t pos = (uint32_t)off + (uint32_t)i;
      uint32_t bit_idx = pos >> 3;
      uint8_t mask = (uint8_t)(1U << (pos & 7U));
      if ((b->rx_bmp[bit_idx] & mask) != 0)
        continue;
      b->rx_bmp[bit_idx] |= mask;
      if (b->rx_bytes < b->tot_len)
        b->rx_bytes++;
    }
  if (b->rx_bytes == b->tot_len)
    {
      b->is_act = false;
      return b->buf;
    }
  return NULL;
}

void
frag_reap_tk (uint64_t sys_ts)
{
  for (int i = 0; i < FRAG_BKT_MAX; i++)
    {
      FBkt *b = &g_frag_bkt[i];
      if (!b->is_act)
        continue;
      if (sys_ts < b->cre_ts)
        {
          b->is_act = false;
          continue;
        }
      if (sys_ts - b->cre_ts > 1500ULL)
        {
          b->is_act = false;
        }
    }
}
