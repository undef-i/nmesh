#include "route.h"
#include "tcp.h"
#include "udp.h"
#include "utils.h"
#include "packet.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define RT_STL_HL 6ULL
#define RT_DED_HL 30ULL
#define RT_REL_STL_HL 12ULL
#define RT_REL_DED_HL 24ULL
#define RT_STL_TS (RT_HL_INTV * RT_STL_HL)
#define RT_DED_TS (RT_HL_INTV * RT_DED_HL)
#define RT_REL_STL (RT_HL_INTV * RT_REL_STL_HL)
#define RT_REL_DED (RT_HL_INTV * RT_REL_DED_HL)
#define RT_SRC_GC_HL 18ULL
#define RT_SRC_GC_TS (RT_HL_INTV * RT_SRC_GC_HL)
#define RT_PRB_TMO 15000ULL
#define RT_PRB_PACE 1000ULL
#define RT_MTU_HLD 600000ULL
#define RT_METRIC_SLOT_INV 0ULL
static bool is_z16 (const uint8_t lla[16]);
static const SrcEnt *src_fnd_c (const Rt *t, const uint8_t rt_id[16]);

static bool
rt_direct_ep_ip_ok (const uint8_t ip[16])
{
  if (!ip)
    return false;
  /* IPv6 link-local needs scope_id/ifindex; endpoint model has only ip:port. */
  if (!is_ip_v4m (ip) && IS_LLA_VAL (ip))
    return false;
  return true;
}

uint16_t
rt_mtu_ub (const Rt *t)
{
  uint32_t upper = RT_MTU_MAX;
  if (t && t->mtu_ub >= RT_MTU_MIN && t->mtu_ub < upper)
    {
      upper = t->mtu_ub;
    }
  {
    uint32_t impl_ub = 48U + (uint32_t)UDP_PL_MAX;
    if (impl_ub < upper)
      upper = impl_ub;
  }
  if (upper < RT_MTU_MIN)
    upper = RT_MTU_MIN;
  return (uint16_t)upper;
}

static uint16_t
rt_ptb_path_mtu_min (const uint8_t ip[16])
{
  uint32_t oip_oh = is_ip_v4m (ip) ? 20U : 40U;
  uint32_t proto_min = is_ip_v4m (ip) ? 68U : 1280U;
  uint32_t tunnel_min = oip_oh + 8U + (uint32_t)PKT_HDR_SZ + RT_MTU_MIN;
  uint32_t min = (proto_min > tunnel_min) ? proto_min : tunnel_min;
  return (min > UINT16_MAX) ? UINT16_MAX : (uint16_t)min;
}

static uint16_t
re_mtu_ub (const Rt *t, const Re *re)
{
  uint16_t upper = rt_mtu_ub (t);
  if (t && re && re->r2d == 0 && !is_z16 (re->ep_ip)
      && re->ep_port != 0)
    {
      uint16_t ep_mtu = udp_ep_mtu_get (re->ep_ip);
      if (ep_mtu >= RT_MTU_MIN && ep_mtu < upper)
        upper = ep_mtu;
    }
  return upper;
}

static uint16_t
re_mtu_base (const Rt *t, const Re *re)
{
  uint16_t base = RT_MTU_MIN;
  if (t && t->mtu_base >= RT_MTU_MIN)
    base = t->mtu_base;
  uint16_t upper = re_mtu_ub (t, re);
  if (base > upper)
    base = upper;
  return base;
}

static uint16_t
re_mtu_fix (const Rt *t, const Re *re)
{
  uint16_t fixed = re_mtu_ub (t, re);
  if (!re)
    return fixed;
  if (re->mtu_lkg > 0 && re->mtu_lkg < fixed)
    fixed = re->mtu_lkg;
  if (re->mtu_ukb >= RT_MTU_MIN && re->mtu_ukb < fixed)
    fixed = re->mtu_ukb;
  if (re->mtu_lkg == 0)
    {
      uint16_t base = re_mtu_base (t, re);
      if (fixed > base)
        fixed = base;
    }
  return fixed;
}

static uint16_t
re_mtu_cur (const Rt *t, const Re *re)
{
  (void)t;
  if (!re || re->mtu_lkg == 0)
    return RT_MTU_MIN;
  return re->mtu_lkg;
}

static bool
re_mtu_is_searching (const Re *re)
{
  if (!re)
    return false;
  return re->mtu_ukb > re->mtu_lkg;
}

static void
re_mtu_search_kick (Re *re)
{
  if (!re_mtu_is_searching (re))
    return;
  re->prb_i_ts = 0;
  re->prb_tx_ts = 0;
}

bool
rt_loss_pct_get (const Re *re, uint32_t *out_pct)
{
  if (!re || !out_pct || !re->loss_ok)
    return false;
  *out_pct = re->loss_pct;
  return true;
}

static void
re_mtu_sync (Rt *t, Re *re)
{
  if (!t || !re)
    return;
  uint16_t upper = re_mtu_ub (t, re);
  if (!t->mtu_probe && re->r2d == 0)
    {
      uint16_t fixed = re_mtu_fix (t, re);
      re->mtu_lkg = fixed;
      re->mtu_ukb = fixed;
      re->mtu_st = MTU_ST_F;
      re->prb_i_ts = 0;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_tx_ts = 0;
      re->prb_ddl = 0;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      return;
    }
  uint16_t floor = (re->r2d == 0) ? re_mtu_base (t, re) : RT_MTU_MIN;
  if (re->mtu_lkg < floor)
    re->mtu_lkg = floor;
  if (re->mtu_lkg > upper)
    re->mtu_lkg = upper;
  if (re->mtu_ukb == 0)
    re->mtu_ukb = upper;
  if (re->mtu_ukb < re->mtu_lkg)
    re->mtu_ukb = re->mtu_lkg;
  if (re->mtu_ukb > upper)
    re->mtu_ukb = upper;
  if (re->prb_i_ts == 0 && re->prb_tx_ts > 0)
    re->prb_i_ts = re->prb_tx_ts;
  if (re->prb_tx_ts == 0 && re->prb_i_ts > 0)
    re->prb_tx_ts = re->prb_i_ts;
  if (re->mtu_st != MTU_ST_B && re->mtu_st != MTU_ST_S
      && re->mtu_st != MTU_ST_F)
    {
      re->mtu_st = MTU_ST_B;
    }
}

static void
re_rx_note (Re *re, uint64_t sys_ts)
{
  re->rx_ts = sys_ts;
}

static bool
re_dir_activate (Re *re, uint64_t sys_ts)
{
  bool was_act = re->state == RT_ACT;
  if (!was_act && sys_ts > 0)
    re->pnd_ts = sys_ts;
  re->pong_ts = sys_ts;
  re->state = RT_ACT;
  return !was_act;
}

static bool
re_dir_activate_seen (Re *re, uint64_t sys_ts)
{
  uint64_t pong_ts = re->pong_ts;
  bool was = re_dir_activate (re, sys_ts);
  re->pong_ts = pong_ts;
  return was;
}

static void
re_rx_ack (Re *re, uint64_t sys_ts)
{
  re_rx_note (re, sys_ts);
  (void)re_dir_activate (re, sys_ts);
}

/* RFC 6298 in scaled form: srtt x8, rttvar x4, RTO = SRTT + 4 * RTTVAR. */
static void
re_rto_upd (Re *re, uint32_t rtt_ms)
{
  if (re->srtt == 0)
    {
      re->srtt = rtt_ms << 3;
      re->rttvar = rtt_ms << 1;
    }
  else
    {
      int32_t dt = (int32_t)rtt_ms - (int32_t)(re->srtt >> 3);
      re->srtt = (uint32_t)((int32_t)re->srtt + dt);
      if (dt < 0)
        dt = -dt;
      re->rttvar = re->rttvar - (re->rttvar >> 2) + (uint32_t)dt;
    }
  uint32_t rto = (re->srtt >> 3) + re->rttvar;
  if (rto < RTO_MIN)
    rto = RTO_MIN;
  if (rto > RTO_MAX)
    rto = RTO_MAX;
  re->rto = rto;
}

static int32_t
pth_m (const Pth *pth)
{
  return pth->rt_m;
}

static int32_t
pth_rel_tot_m (RtMap *map, const Pth *p)
{
  RtMap *nh = NULL;
  HASH_FIND (hh, map, p->nhop_lla, 16, nh);
  if (!nh || !nh->sel_dir_pth)
    return RT_F_INF;
  int32_t n2r = pth_m (nh->sel_dir_pth);
  if (n2r == RT_F_INF || p->rt_m == RT_F_INF)
    return RT_F_INF;
  int64_t tot64 = (int64_t)n2r + (int64_t)p->rt_m;
  if (tot64 >= RT_F_INF)
    return RT_F_INF - 1;
  if (tot64 <= -RT_F_INF)
    return -RT_F_INF + 1;
  return (int32_t)tot64;
}

static bool
pth_loss_pct_get (const Pth *pth, uint32_t *out_pct)
{
  if (!pth || !out_pct || !pth->loss_ok)
    return false;
  *out_pct = pth->loss_pct;
  return true;
}

static bool
pth_dir_btr (const Pth *cand, const Pth *best)
{
  if (!cand)
    return false;
  if (!best)
    return true;

  int32_t cand_m = pth_m (cand);
  int32_t best_m = pth_m (best);
  if (cand_m != best_m)
    return cand_m < best_m;

  uint32_t cand_loss = 0;
  uint32_t best_loss = 0;
  bool cand_has_loss = pth_loss_pct_get (cand, &cand_loss);
  bool best_has_loss = pth_loss_pct_get (best, &best_loss);
  if (cand_has_loss && best_has_loss && cand_loss != best_loss)
    return cand_loss < best_loss;
  if (cand_has_loss != best_has_loss)
    return cand_has_loss;

  int ip_cmp = memcmp (cand->ep_ip, best->ep_ip, 16);
  if (ip_cmp != 0)
    return ip_cmp < 0;
  if (cand->ep_port != best->ep_port)
    return cand->ep_port < best->ep_port;
  return false;
}

static uint64_t
metric_slot_id (uint64_t sys_ts)
{
  return (sys_ts / RT_PRB_INTV) + 1ULL;
}

static bool
metric_slot_in_win (uint64_t now_slot, uint64_t slot)
{
  if (slot == RT_METRIC_SLOT_INV || now_slot < slot)
    return false;
  return (now_slot - slot) < RT_METRIC_WIN_BINS;
}

static void
re_loss_upd (Re *re, uint64_t sys_ts)
{
  uint64_t now_slot = metric_slot_id (sys_ts);
  uint64_t tx = 0, rx = 0;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      if (!metric_slot_in_win (now_slot, re->prb_win_id[i]))
        continue;
      tx += re->prb_win_tx[i];
      rx += re->prb_win_rx[i];
    }
  if (tx == 0 || rx > tx)
    {
      re->loss_ok = false;
      re->loss_pct = 0;
      return;
    }
  re->loss_ok = true;
  re->loss_pct = (uint32_t)(((tx - rx) * 100ULL + (tx / 2ULL)) / tx);
}

static void
prb_win_note (Re *re, uint64_t slot_ts, bool is_tx)
{
  uint64_t slot = metric_slot_id (slot_ts);
  size_t idx = (size_t)((slot - 1ULL) % RT_METRIC_WIN_BINS);
  if (re->prb_win_id[idx] != slot)
    {
      re->prb_win_id[idx] = slot;
      re->prb_win_tx[idx] = 0;
      re->prb_win_rx[idx] = 0;
    }
  if (is_tx)
    re->prb_win_tx[idx]++;
  else
    re->prb_win_rx[idx]++;
}

void
rt_prb_tx_note (Re *re, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return;
  prb_win_note (re, sys_ts, true);
  re_loss_upd (re, sys_ts);
}

static void
re_metric_win_clear (Re *re)
{
  if (!re)
    return;
  memset (re->rtt_win_id, 0, sizeof (re->rtt_win_id));
  memset (re->rtt_win_min, 0, sizeof (re->rtt_win_min));
  memset (re->fwd_win_id, 0, sizeof (re->fwd_win_id));
  memset (re->fwd_win_min, 0, sizeof (re->fwd_win_min));
}

static void
re_rtt_win_seed (Re *re, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      if (re->rtt_win_id[i] != RT_METRIC_SLOT_INV)
        return;
    }
  uint32_t seed = re->sm_m;
  if (seed == 0 || seed == RTT_UNK || seed >= RT_M_INF)
    return;
  uint64_t slot = metric_slot_id (sys_ts);
  size_t idx = (size_t)((slot - 1ULL) % RT_METRIC_WIN_BINS);
  re->rtt_win_id[idx] = slot;
  re->rtt_win_min[idx] = seed;
}

static void
re_rtt_win_add (Re *re, uint32_t rtt_ms, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return;
  if (rtt_ms == 0)
    rtt_ms = 1;
  if (rtt_ms == RTT_UNK || rtt_ms >= RT_M_INF)
    return;
  uint64_t slot = metric_slot_id (sys_ts);
  size_t idx = (size_t)((slot - 1ULL) % RT_METRIC_WIN_BINS);
  if (re->rtt_win_id[idx] != slot)
    {
      re->rtt_win_id[idx] = slot;
      re->rtt_win_min[idx] = rtt_ms;
      return;
    }
  if (re->rtt_win_min[idx] == 0 || re->rtt_win_min[idx] >= RT_M_INF
      || rtt_ms < re->rtt_win_min[idx])
    re->rtt_win_min[idx] = rtt_ms;
}

static uint32_t
re_rtt_win_cur (const Re *re, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return RT_M_INF;
  uint64_t now_slot = metric_slot_id (sys_ts);
  uint32_t best = RT_M_INF;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      uint64_t slot = re->rtt_win_id[i];
      if (!metric_slot_in_win (now_slot, slot))
        continue;
      uint32_t sample = re->rtt_win_min[i];
      if (sample == 0 || sample == RTT_UNK || sample >= RT_M_INF)
        continue;
      if (sample < best)
        best = sample;
    }
  return best;
}

static void
re_fwd_win_seed (Re *re, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      if (re->fwd_win_id[i] != RT_METRIC_SLOT_INV)
        return;
    }
  if (re->rt_m == RT_F_INF)
    return;
  uint64_t slot = metric_slot_id (sys_ts);
  size_t idx = (size_t)((slot - 1ULL) % RT_METRIC_WIN_BINS);
  re->fwd_win_id[idx] = slot;
  re->fwd_win_min[idx] = re->rt_m;
}

static void
re_fwd_win_add (Re *re, int64_t fwd_obs, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return;
  uint64_t slot = metric_slot_id (sys_ts);
  size_t idx = (size_t)((slot - 1ULL) % RT_METRIC_WIN_BINS);
  if (re->fwd_win_id[idx] != slot)
    {
      re->fwd_win_id[idx] = slot;
      re->fwd_win_min[idx] = fwd_obs;
      return;
    }
  if (fwd_obs < re->fwd_win_min[idx])
    re->fwd_win_min[idx] = fwd_obs;
}

static int32_t
re_fwd_win_cur (const Re *re, uint64_t sys_ts)
{
  if (!re || sys_ts == 0)
    return RT_F_INF;
  uint64_t now_slot = metric_slot_id (sys_ts);
  int64_t best = 0;
  bool seen = false;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      uint64_t slot = re->fwd_win_id[i];
      if (!metric_slot_in_win (now_slot, slot))
        continue;
      if (!seen || re->fwd_win_min[i] < best)
        {
          best = re->fwd_win_min[i];
          seen = true;
        }
    }
  if (!seen)
    return RT_F_INF;
  if (best >= RT_F_INF)
    return RT_F_INF - 1;
  if (best <= -RT_F_INF)
    return -RT_F_INF + 1;
  return (int32_t)best;
}

static bool
re_metric_refresh (Re *re, uint64_t sys_ts)
{
  if (!re || re->r2d != 0 || sys_ts == 0)
    return false;
  uint32_t old_sm = re->sm_m;
  int32_t old_rt = re->rt_m;
  re_rtt_win_seed (re, sys_ts);

  re->sm_m = re_rtt_win_cur (re, sys_ts);
  re_fwd_win_seed (re, sys_ts);
  re->rt_m = re_fwd_win_cur (re, sys_ts);
  return re->sm_m != old_sm || re->rt_m != old_rt;
}

static void
re_rtt_min_apply (Re *re, uint32_t rtt_ms, int64_t fwd_obs, bool has_fwd,
                  uint64_t sys_ts)
{
  if (!re)
    return;
  re_rtt_win_add (re, rtt_ms, sys_ts);
  if (has_fwd)
    re_fwd_win_add (re, fwd_obs, sys_ts);
  re_metric_refresh (re, sys_ts);
}


static bool
re_use_tcp (const Cfg *cfg, const Re *re)
{
  if (!cfg || !re || re->r2d != 0 || re->ep_port == 0)
    return false;
  return cfg_tp_pick (cfg, re->tp_mask) == TP_PROTO_TCP;
}

static bool
is_z16 (const uint8_t lla[16])
{
  static const uint8_t z_lla[16] = { 0 };
  return memcmp (lla, z_lla, 16) == 0;
}

static Pth *
pth_alloc (Rt *t)
{
  if (t->pth_pool)
    {
      Pth *p = t->pth_pool;
      t->pth_pool = p->next;
      memset (p, 0, sizeof (*p));
      return p;
    }
  return calloc (1, sizeof (Pth));
}

static void
pth_free (Rt *t, Pth *p)
{
  if (!p)
    return;
  p->next = t->pth_pool;
  t->pth_pool = p;
}

static RtMap *
rtm_alloc (Rt *t)
{
  if (t->rtm_pool)
    {
      RtMap *m = t->rtm_pool;
      t->rtm_pool = m->pool_next;
      memset (m, 0, sizeof (*m));
      return m;
    }
  return calloc (1, sizeof (RtMap));
}

static void
rtm_free (Rt *t, RtMap *m)
{
  if (!m)
    return;
  m->pool_next = t->rtm_pool;
  t->rtm_pool = m;
}

static void
rt_map_fre (Rt *t, RtMap *map)
{
  RtMap *rtm, *tmp;
  HASH_ITER (hh, map, rtm, tmp)
  {
    Pth *pth = rtm->paths;
    while (pth)
      {
        Pth *nxt_path = pth->next;
        pth_free (t, pth);
        pth = nxt_path;
      }
    rtm->paths = NULL;
    HASH_DEL (map, rtm);
    rtm_free (t, rtm);
  }
}

static void
pth_pool_fre (Rt *t)
{
  while (t && t->pth_pool)
    {
      Pth *nxt = t->pth_pool->next;
      free (t->pth_pool);
      t->pth_pool = nxt;
    }
}

static void
rtm_pool_fre (Rt *t)
{
  while (t && t->rtm_pool)
    {
      RtMap *nxt = t->rtm_pool->pool_next;
      free (t->rtm_pool);
      t->rtm_pool = nxt;
    }
}

void
rt_free (Rt *t)
{
  if (!t)
    return;
  rt_map_fre (t, t->map);
  t->map = NULL;
  pth_pool_fre (t);
  rtm_pool_fre (t);
  free (t->re_arr);
  free (t->sources);
  memset (t, 0, sizeof (*t));
}

int
rt_cpy (Rt *dst, const Rt *src)
{
  if (!dst || !src)
    return -1;
  if (dst == src)
    return 0;
  Rt snap;
  rt_init (&snap);
  memcpy (snap.our_lla, src->our_lla, 16);
  snap.prb_nxt_id = src->prb_nxt_id;
  snap.mtu_ub = src->mtu_ub;
  snap.mtu_probe = src->mtu_probe;
  snap.map_dirty = true;
  snap.adv_dirty = src->adv_dirty;
  snap.boot_ts = src->boot_ts;
  snap.loc_last_ts = src->loc_last_ts;
  snap.sync_rev = src->sync_rev;
  snap.adv_tx_cnt = src->adv_tx_cnt;
  snap.ping_tx_cnt = src->ping_tx_cnt;
  snap.pong_tx_cnt = src->pong_tx_cnt;
  snap.hp_tx_cnt = src->hp_tx_cnt;
  snap.ctrl_tx_b = src->ctrl_tx_b;
  snap.ctrl_rx_b = src->ctrl_rx_b;
  snap.ctrl_last_ts = src->ctrl_last_ts;
  snap.ctrl_last_tx_b = src->ctrl_last_tx_b;
  snap.ctrl_last_rx_b = src->ctrl_last_rx_b;
  snap.ctrl_now_tx_bps = src->ctrl_now_tx_bps;
  snap.ctrl_now_rx_bps = src->ctrl_now_rx_bps;
  if (src->cnt > 0)
    {
      snap.re_arr = malloc ((size_t)src->cnt * sizeof (Re));
      if (!snap.re_arr)
        {
          rt_free (&snap);
          return -1;
        }
      memcpy (snap.re_arr, src->re_arr, (size_t)src->cnt * sizeof (Re));
      snap.cnt = src->cnt;
      snap.cap = src->cnt;
    }
  if (src->src_cnt > 0)
    {
      snap.sources = malloc ((size_t)src->src_cnt * sizeof (SrcEnt));
      if (!snap.sources)
        {
          rt_free (&snap);
          return -1;
        }
      memcpy (snap.sources, src->sources,
              (size_t)src->src_cnt * sizeof (SrcEnt));
      snap.src_cnt = src->src_cnt;
      snap.src_cap = src->src_cnt;
    }
  rt_free (dst);
  *dst = snap;
  return 0;
}

static void
re_to_pth (const Re *re, Pth *pth)
{
  memset (pth, 0, sizeof (*pth));
  memcpy (pth->ep_ip, re->ep_ip, 16);
  pth->ep_port = re->ep_port;
  pth->ver = re->ver;
  pth->sid = re->sid;
  pth->adv_m = re->adv_m;
  pth->adv_loss = re->adv_loss;
  pth->rt_m = re->rt_m;
  memcpy (pth->nhop_lla, re->nhop_lla, 16);
  pth->state = re->state;
  pth->is_static = re->is_static;
  pth->tp_mask = re->tp_mask;
  pth->pong_ts = re->pong_ts;
  pth->rx_ts = re->rx_ts;
  pth->tx_ts = re->tx_ts;
  pth->srtt = re->srtt;
  pth->rttvar = re->rttvar;
  pth->rto = re->rto;
  pth->sm_m = re->sm_m;
  pth->r2d = re->r2d;
  pth->path_len = re->path_len;
  memcpy (pth->path, re->path, sizeof (pth->path));
  pth->mtu_lkg = re->mtu_lkg;
  pth->mtu_ukb = re->mtu_ukb;
  pth->peer_rev_mtu = re->peer_rev_mtu;
  pth->mtu_st = re->mtu_st;
  pth->bhck = re->bhck;
  pth->prb_i_ts = re->prb_i_ts;
  pth->prb_mtu = re->prb_mtu;
  pth->prb_id = re->prb_id;
  pth->prb_tx = re->prb_tx;
  pth->prb_tx_ts = re->prb_tx_ts;
  pth->prb_ddl = re->prb_ddl;
  pth->vfy_ts = re->vfy_ts;
  pth->hld_ts = re->hld_ts;
  pth->prb_ts = re->prb_ts;
  pth->prb_wts = re->prb_wts;
  pth->prb_tok = re->prb_tok;
  pth->loss_pct = re->loss_pct;
  pth->loss_ok = re->loss_ok;
  pth->pnd_ts = re->pnd_ts;
  pth->hp_ts = re->hp_ts;
  pth->dat_ts = re->dat_ts;
}

static void
rt_map_rbd (Rt *t)
{
  t->map_dirty = false;
  RtMap *n_map = NULL;
  uint64_t now = sys_ts ();

  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d == 0)
        re_metric_refresh (re, now);
      RtMap *rtm = NULL;
      HASH_FIND (hh, n_map, re->lla, 16, rtm);
      if (!rtm)
        {
          rtm = rtm_alloc (t);
          if (!rtm)
            continue;
          memcpy (rtm->lla, re->lla, 16);
          HASH_ADD (hh, n_map, lla, 16, rtm);
        }

      Pth *pth = pth_alloc (t);
      if (!pth)
        continue;
      re_to_pth (re, pth);
      pth->next = rtm->paths;
      rtm->paths = pth;

      if (pth->r2d == 0 && pth->state == RT_ACT)
        {
          if (pth_dir_btr (pth, rtm->sel_dir_pth))
            rtm->sel_dir_pth = pth;
        }
    }

  RtMap *rtm, *tmp;
  HASH_ITER (hh, n_map, rtm, tmp)
  {
    int dir_act_cnt = 0;
    int32_t best_rel_m = RT_F_INF;
    for (Pth *p = rtm->paths; p; p = p->next)
      {
        if (p->r2d == 0 && p->state == RT_ACT)
          dir_act_cnt++;
        if (p->state != RT_ACT)
          continue;

        if (p->r2d > 0)
          {
            if (memcmp (p->nhop_lla, t->our_lla, 16) == 0)
              continue;

            int32_t tot = pth_rel_tot_m (n_map, p);
            if (tot == RT_F_INF)
              continue;

            if (!rtm->sel_rel_pth || tot < best_rel_m
                || (tot == best_rel_m
                    && p->adv_m < rtm->sel_rel_pth->adv_m))
              {
                rtm->sel_rel_pth = p;
                best_rel_m = tot;
              }
          }
      }

    for (Pth *p = rtm->paths; p; p = p->next)
      {
        if (p->r2d == 0 && p->state == RT_PND)
          {
            rtm->has_pnd_dir = true;
            break;
          }
      }
  }

  rt_map_fre (t, t->map);
  t->map = n_map;
}

static void
rt_map_mark (Rt *t)
{
  if (!t)
    return;
  t->sync_rev++;
  t->map_dirty = true;
}

static void
rt_map_ens (Rt *t)
{
  if (!t)
    return;
  if (!t->map || t->map_dirty)
    rt_map_rbd (t);
}

static bool
pth_is_re (const Pth *pth, const Re *re)
{
  return pth && re && memcmp (pth->ep_ip, re->ep_ip, 16) == 0
         && pth->ep_port == re->ep_port && pth->r2d == re->r2d;
}

bool
rt_dir_is_sel (Rt *t, const Re *re)
{
  if (!t || !re)
    return false;
  if (re->r2d != 0 || is_z16 (re->lla))
    return false;
  rt_map_ens (t);
  RtMap *rtm = NULL;
  HASH_FIND (hh, t->map, re->lla, 16, rtm);
  if (!rtm || !rtm->sel_dir_pth)
    return false;
  return pth_is_re (rtm->sel_dir_pth, re);
}

RtMap *
rt_map_all (Rt *t)
{
  if (!t)
    return NULL;
  rt_map_ens (t);
  return t->map;
}

void
rt_pth_lims (const Rt *t, const Pth *pth, uint16_t *out_lkg,
             uint16_t *out_ukb, bool *out_srch)
{
  uint16_t lkg = pth->mtu_lkg ? pth->mtu_lkg : RT_MTU_MIN;
  uint16_t ukb = pth->mtu_ukb ? pth->mtu_ukb : rt_mtu_ub (t);
  uint16_t cap = pth->peer_rev_mtu >= RT_MTU_MIN ? pth->peer_rev_mtu : 0;
  if (cap)
    {
      if (lkg > cap)
        lkg = cap;
      if (ukb > cap)
        ukb = cap;
    }
  if (ukb < lkg)
    ukb = lkg;
  if (out_lkg)
    *out_lkg = lkg;
  if (out_ukb)
    *out_ukb = ukb;
  if (out_srch)
    *out_srch = ukb > lkg;
}

static bool
rt_cap_chk (Rt *t, uint32_t extra)
{
  if (t->cnt + extra <= t->cap)
    return true;
  uint32_t n_cap = (t->cap == 0) ? 64 : t->cap;
  while (n_cap < t->cnt + extra)
    {
      if (n_cap > UINT32_MAX / 2U)
        return false;
      n_cap *= 2U;
    }
  Re *n_re_arr = (Re *)realloc (t->re_arr, (size_t)n_cap * sizeof (Re));
  if (!n_re_arr)
    return false;
  t->re_arr = n_re_arr;
  t->cap = n_cap;
  return true;
}

static bool
src_cap_chk (Rt *t, uint32_t extra)
{
  if (t->src_cnt + extra <= t->src_cap)
    return true;
  uint32_t n_cap = (t->src_cap == 0) ? 64 : t->src_cap;
  while (n_cap < t->src_cnt + extra)
    {
      if (n_cap > UINT32_MAX / 2U)
        return false;
      n_cap *= 2U;
    }
  SrcEnt *n_re_arr
      = (SrcEnt *)realloc (t->sources, (size_t)n_cap * sizeof (SrcEnt));
  if (!n_re_arr)
    return false;
  t->sources = n_re_arr;
  t->src_cap = n_cap;
  return true;
}

static SrcEnt *
src_fnd (Rt *t, const uint8_t rt_id[16])
{
  for (uint32_t i = 0; i < t->src_cnt; i++)
    {
      if (memcmp (t->sources[i].rt_id, rt_id, 16) == 0)
        {
          return &t->sources[i];
        }
    }
  return NULL;
}

static const SrcEnt *
src_fnd_c (const Rt *t, const uint8_t rt_id[16])
{
  for (uint32_t i = 0; i < t->src_cnt; i++)
    {
      if (memcmp (t->sources[i].rt_id, rt_id, 16) == 0)
        {
          return &t->sources[i];
        }
    }
  return NULL;
}

static void
rt_zero_ep_rm (Rt *t, const uint8_t ip[16], uint16_t port, bool match_port)
{
  static const uint8_t z_lla[16] = { 0 };
  uint32_t wr_idx = 0;
  for (uint32_t rd_idx = 0; rd_idx < t->cnt; rd_idx++)
    {
      Re *re = &t->re_arr[rd_idx];
      bool is_rm = (re->r2d == 0) && (memcmp (re->lla, z_lla, 16) == 0)
                   && (memcmp (re->ep_ip, ip, 16) == 0)
                   && (!match_port || (re->ep_port == port));
      if (!is_rm)
        {
          if (wr_idx != rd_idx)
            t->re_arr[wr_idx] = t->re_arr[rd_idx];
          wr_idx++;
        }
    }
  t->cnt = wr_idx;
}

static void
rt_dir_ep_rm_same_ip (Rt *t, const uint8_t lla[16], const uint8_t ip[16],
                      uint16_t port)
{
  uint32_t wr_idx = 0;
  for (uint32_t rd_idx = 0; rd_idx < t->cnt; rd_idx++)
    {
      Re *re = &t->re_arr[rd_idx];
      bool is_same
          = (re->r2d == 0) && !is_z16 (re->lla)
            && (memcmp (re->lla, lla, 16) == 0)
            && (memcmp (re->ep_ip, ip, 16) == 0) && (re->ep_port != port);
      if (!is_same)
        {
          if (wr_idx != rd_idx)
            t->re_arr[wr_idx] = t->re_arr[rd_idx];
          wr_idx++;
        }
    }
  t->cnt = wr_idx;
}

static Re *
rt_dir_ep_roam_pick (Rt *t, const uint8_t lla[16], const uint8_t ip[16],
                     uint16_t n_port)
{
  Re *best = NULL;
  uint64_t best_seen = 0;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0 || is_z16 (re->lla))
        continue;
      if (memcmp (re->lla, lla, 16) != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port == n_port)
        continue;
      uint64_t seen = re->rx_ts;
      if (re->pong_ts > seen)
        seen = re->pong_ts;
      bool cand_act = re->state == RT_ACT;
      bool best_act = best && best->state == RT_ACT;
      if (!best || (cand_act && !best_act)
          || (cand_act == best_act && seen > best_seen))
        {
          best = re;
          best_seen = seen;
        }
    }
  return best;
}

static bool
rt_dir_has_other_ep (const Rt *t, const uint8_t lla[16], const uint8_t ip[16],
                     uint16_t port)
{
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *re = &t->re_arr[i];
      if (re->r2d != 0 || is_z16 (re->lla))
        continue;
      if (re->state == RT_DED)
        continue;
      if (memcmp (re->lla, lla, 16) != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) == 0 && re->ep_port == port)
        continue;
      return true;
    }
  return false;
}

void
pp_init (PPool *p, const char *persist_path)
{
  memset (p, 0, sizeof (*p));
  p->persist_path = persist_path;
}

void
pp_free (PPool *p)
{
  if (!p)
    return;
  free (p->re_arr);
  p->re_arr = NULL;
  p->cnt = 0;
  p->cap = 0;
}

static bool
pp_rsv (PPool *p, int need)
{
  if (!p)
    return false;
  if (need <= p->cap)
    return true;
  int new_cap = (p->cap > 0) ? p->cap : PEER_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (INT32_MAX / 2))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2;
    }
  PAnc *new_arr = realloc (p->re_arr, sizeof (*new_arr) * (size_t)new_cap);
  if (!new_arr)
    {
      fprintf (stderr, "pool: failed to expand peer pool to %d entries\n",
               new_cap);
      return false;
    }
  p->re_arr = new_arr;
  p->cap = new_cap;
  return true;
}

void
pp_add (PPool *p, const uint8_t ip[16], uint16_t port)
{
  if (!p)
    return;
  for (int peer_idx = 0; peer_idx < p->cnt; peer_idx++)
    {
      if (memcmp (p->re_arr[peer_idx].ip, ip, 16) == 0
          && p->re_arr[peer_idx].port == port)
        return;
    }
  if (!pp_rsv (p, p->cnt + 1))
    return;
  memcpy (p->re_arr[p->cnt].ip, ip, 16);
  p->re_arr[p->cnt].port = port;
  p->cnt++;
}

void
rt_init (Rt *t)
{
  memset (t, 0, sizeof (*t));
  t->prb_nxt_id = 1;
  t->mtu_ub = RT_MTU_MAX;
  t->mtu_base = RT_MTU_MIN;
  t->mtu_probe = false;
  t->boot_ts = sys_ts ();
}

void
rt_pmtu_ub_set (Rt *t, uint16_t mtu)
{
  if (!t)
    return;
  if (mtu < RT_MTU_MIN)
    mtu = RT_MTU_MIN;
  t->mtu_ub = mtu;
  if (!t->mtu_probe)
    {
      for (uint32_t i = 0; i < t->cnt; i++)
        re_mtu_sync (t, &t->re_arr[i]);
    }
}

void
rt_pmtu_base_set (Rt *t, uint16_t mtu)
{
  if (!t)
    return;
  if (mtu < RT_MTU_MIN)
    mtu = RT_MTU_MIN;
  t->mtu_base = mtu;
  if (!t->mtu_probe)
    {
      for (uint32_t i = 0; i < t->cnt; i++)
        re_mtu_sync (t, &t->re_arr[i]);
    }
}

void
rt_mtu_probe_set (Rt *t, bool is_on)
{
  if (!t || t->mtu_probe == is_on)
    return;
  t->mtu_probe = is_on;
  bool is_mod = false;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      uint16_t old_mtu = re->mtu_lkg;
      if (is_on)
        {
          re->mtu_lkg = re_mtu_base (t, re);
          re->mtu_ukb = re_mtu_ub (t, re);
          re->mtu_st = MTU_ST_B;
          re->prb_i_ts = 0;
          re->prb_mtu = 0;
          re->prb_id = 0;
          re->prb_tx = 0;
          re->prb_tx_ts = 0;
          re->prb_ddl = 0;
          re->bhck = BHCK_NONE;
          re->vfy_ts = 0;
          re->hld_ts = 0;
        }
      re_mtu_sync (t, re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu_lkg != old_mtu)
        is_mod = true;
    }
  if (is_mod)
    rt_adv_dirty_set (t);
}

static uint64_t
rt_nhop_pong_age (const Rt *t, const uint8_t nhop_lla[16], uint64_t sys_ts)
{
  if (is_z16 (nhop_lla) || memcmp (nhop_lla, t->our_lla, 16) == 0)
    return 0;
  uint64_t best = 0;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *nh = &t->re_arr[i];
      if (nh->r2d != 0 || memcmp (nh->lla, nhop_lla, 16) != 0)
        continue;
      if (nh->pong_ts > best)
        best = nh->pong_ts;
    }
  if (best == 0)
    return UINT64_MAX;
  if (sys_ts <= best)
    return 0;
  return sys_ts - best;
}

static bool
rt_nhop_proof_ok (const Rt *t, const uint8_t nhop_lla[16], uint64_t sys_ts)
{
  return rt_nhop_pong_age (t, nhop_lla, sys_ts) <= RT_KA_TMO;
}

void
rt_upd (Rt *t, const Re *re, uint64_t sys_ts)
{
  bool is_zero = is_z16 (re->lla);
  bool is_loc_inj = false;
  bool is_rel = (re->r2d > 0);
  if (!is_zero && !IS_LLA_VAL (re->lla))
    return;
  if (!is_zero && memcmp (re->lla, t->our_lla, 16) == 0)
    {
      is_loc_inj = (re->r2d == 0)
                   && (re->rt_m == 0 || re->adv_m == 0 || re->is_static);
      if (!is_loc_inj)
        return;
    }
  if (!is_rel && !rt_direct_ep_ip_ok (re->ep_ip))
    return;
  bool is_dir_obs = !is_zero && !is_rel && !is_loc_inj;
  bool rel_proof_ok = !is_rel || rt_nhop_proof_ok (t, re->nhop_lla, sys_ts);
  if (!is_zero && !is_rel)
    {
      Re *roam = rt_dir_ep_roam_pick (t, re->lla, re->ep_ip, re->ep_port);
      if (roam)
        roam->ep_port = re->ep_port;
      rt_zero_ep_rm (t, re->ep_ip, re->ep_port, false);
      rt_dir_ep_rm_same_ip (t, re->lla, re->ep_ip, re->ep_port);
    }
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *cur_re = &t->re_arr[i];
      if (is_zero)
        {
          if (memcmp (cur_re->ep_ip, re->ep_ip, 16) == 0
              && cur_re->ep_port == re->ep_port && cur_re->r2d == 0)
            {
              return;
            }
          continue;
        }
      if (memcmp (cur_re->lla, re->lla, 16) != 0)
        continue;
      if ((cur_re->r2d > 0) != is_rel)
        continue;
      if (memcmp (cur_re->ep_ip, re->ep_ip, 16) != 0)
        continue;
      if (cur_re->ep_port != re->ep_port)
        continue;
      cur_re->tp_mask |= re->tp_mask;
      cur_re->adv_m = re->adv_m;
      cur_re->adv_loss = re->adv_loss;
      if (is_rel)
        cur_re->rt_m = re->rt_m;
      else if (cur_re->rt_m == RT_F_INF && re->rt_m != RT_F_INF)
        cur_re->rt_m = re->rt_m;
      if (re->state == RT_DED)
        {
          cur_re->state = RT_DED;
        }
      else if (((is_rel && rel_proof_ok) || is_loc_inj)
               && re->state == RT_ACT)
        {
          if (is_rel && cur_re->state != RT_ACT)
            rt_adv_dirty_set (t);
          cur_re->state = RT_ACT;
        }
      else if (cur_re->state != RT_ACT && cur_re->state != RT_DED)
        {
          cur_re->state = RT_PND;
        }
      if (IS_LLA_VAL (re->nhop_lla))
        memcpy (cur_re->nhop_lla, re->nhop_lla, 16);
      if (is_rel)
        {
          cur_re->path_len = re->path_len;
          memcpy (cur_re->path, re->path, sizeof (cur_re->path));
        }
      bool pmtu_local = cur_re->r2d == 0;
      if (re->mtu_lkg > 0 && !pmtu_local)
        cur_re->mtu_lkg = re->mtu_lkg;
      if (re->mtu_ukb > 0 && !pmtu_local)
        cur_re->mtu_ukb = re->mtu_ukb;
      if (re->prb_mtu > 0)
        cur_re->prb_mtu = re->prb_mtu;
      if (re->prb_id > 0)
        cur_re->prb_id = re->prb_id;
      if (re->prb_i_ts > 0)
        cur_re->prb_i_ts = re->prb_i_ts;
      if (re->prb_tx_ts > 0)
        cur_re->prb_tx_ts = re->prb_tx_ts;
      re_mtu_sync (t, cur_re);
      if (is_rel)
        {
          if (re->state != RT_DED)
            {
              if (sys_ts > 0)
                cur_re->pong_ts = sys_ts;
              if (sys_ts > 0)
                re_rx_note (cur_re, sys_ts);
            }
        }
      else if (is_loc_inj && sys_ts > 0)
        {
          re_rx_ack (cur_re, sys_ts);
        }
      rt_map_mark (t);
      return;
    }
  if (rt_cap_chk (t, 1))
    {
      Re ne = *re;
      ne.pong_ts = sys_ts;
      ne.rx_ts = sys_ts;
      if (ne.rto == 0)
        ne.rto = RTO_INIT;
      if (ne.r2d > 0)
        ne.rt_m = ne.adv_m;
      else if (ne.rt_m == 0)
        ne.rt_m = RT_F_INF;
      if (ne.adv_m == 0 && ne.rt_m != RT_F_INF)
        ne.adv_m = ne.rt_m;
      if (is_dir_obs)
        {
          ne.mtu_lkg = re_mtu_base (t, &ne);
          ne.mtu_ukb = rt_mtu_ub (t);
        }
      else if (ne.mtu_ukb == 0)
        ne.mtu_ukb = (!t->mtu_probe && ne.r2d == 0) ? ne.mtu_lkg
                                                    : rt_mtu_ub (t);
      ne.prb_i_ts = 0;
      ne.mtu_st = MTU_ST_B;
      re_mtu_sync (t, &ne);
      if (is_dir_obs)
        {
          ne.state = RT_PND;
        }
      else if (is_rel && !rel_proof_ok)
        {
          ne.state = RT_PND;
        }
      t->re_arr[t->cnt++] = ne;
      rt_map_mark (t);
      if (is_rel && ne.state == RT_ACT)
        rt_adv_dirty_set (t);
    }
}

bool
rt_dir_fnd (Rt *t, const uint8_t dst_lla[16], Re *out)
{
  if (is_z16 (dst_lla))
    return false;
  rt_map_ens (t);
  RtMap *re = NULL;
  HASH_FIND (hh, t->map, dst_lla, 16, re);
  if (!re)
    return false;

  Pth *selected = re->sel_dir_pth;
  if (!selected)
    return false;
  if (pth_m (selected) >= RT_F_INF)
    return false;

  memset (out, 0, sizeof (*out));
  memcpy (out->lla, re->lla, 16);
  memcpy (out->ep_ip, selected->ep_ip, 16);
  out->ep_port = selected->ep_port;
  out->ver = selected->ver;
  out->sid = selected->sid;
  out->adv_m = selected->adv_m;
  out->adv_loss = selected->adv_loss;
  out->rt_m = selected->rt_m;
  memcpy (out->nhop_lla, selected->nhop_lla, 16);
  out->state = selected->state;
  out->is_static = selected->is_static;
  out->tp_mask = selected->tp_mask;
  out->pong_ts = selected->pong_ts;
  out->rx_ts = selected->rx_ts;
  out->tx_ts = selected->tx_ts;
  out->srtt = selected->srtt;
  out->rttvar = selected->rttvar;
  out->rto = selected->rto;
  out->sm_m = selected->sm_m;
  out->r2d = selected->r2d;
  out->mtu_lkg = selected->mtu_lkg;
  out->mtu_ukb = selected->mtu_ukb;
  out->peer_rev_mtu = selected->peer_rev_mtu;
  out->mtu_st = selected->mtu_st;
  out->prb_i_ts = selected->prb_i_ts;
  out->prb_mtu = selected->prb_mtu;
  out->prb_id = selected->prb_id;
  out->prb_tx = selected->prb_tx;
  out->prb_tx_ts = selected->prb_tx_ts;
  out->prb_ddl = selected->prb_ddl;
  out->vfy_ts = selected->vfy_ts;
  out->hld_ts = selected->hld_ts;
  out->prb_ts = selected->prb_ts;
  out->prb_tok = selected->prb_tok;
  return true;
}

void
rt_rtt_upd (Rt *t, const uint8_t peer_lla[16], const uint8_t ip[16],
            uint16_t port, uint32_t rtt_ms, int64_t fwd_obs, bool has_fwd,
            uint64_t sys_ts)
{
  if (rtt_ms == 0)
    rtt_ms = 1;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      if (t->re_arr[i].r2d != 0)
        continue;
      if (memcmp (t->re_arr[i].lla, peer_lla, 16) != 0)
        continue;
      if (memcmp (t->re_arr[i].ep_ip, ip, 16) != 0)
        continue;
      if (t->re_arr[i].ep_port != port)
        continue;
      re_rtt_min_apply (&t->re_arr[i], rtt_ms, fwd_obs, has_fwd, sys_ts);
      re_rx_note (&t->re_arr[i], sys_ts);
      (void)re_dir_activate (&t->re_arr[i], sys_ts);
      re_rto_upd (&t->re_arr[i], rtt_ms);
      rt_map_mark (t);
      return;
    }
}

bool
rt_ping_sample_upd (Rt *t, const uint8_t peer_lla[16], uint64_t prb_tok,
                    uint32_t rtt_ms, int64_t fwd_obs, bool has_fwd,
                    uint64_t sys_ts)
{
  if (!t || !peer_lla || prb_tok == 0)
    return false;
  if (rtt_ms == 0)
    rtt_ms = 1;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->lla, peer_lla, 16) != 0)
        continue;
      if (re->prb_tok != prb_tok)
        continue;
      re_rtt_min_apply (re, rtt_ms, fwd_obs, has_fwd, sys_ts);
      re_rx_note (re, sys_ts);
      (void)re_dir_activate (re, sys_ts);
      re_rto_upd (re, rtt_ms);
      re->prb_tok = 0;
      prb_win_note (re, re->prb_ts, false);
      re_loss_upd (re, sys_ts);
      rt_map_mark (t);
      return true;
    }
  return false;
}

static void
rt_ep_reconcile (Rt *t, const uint8_t lla[16], const uint8_t ip[16],
                 uint16_t port, int *zero_idx)
{
  *zero_idx = -1;
  Re *roam = rt_dir_ep_roam_pick (t, lla, ip, port);
  if (roam)
    {
      roam->ep_port = port;
    }
  else
    {
      for (uint32_t i = 0; i < t->cnt; i++)
        {
          Re *re = &t->re_arr[i];
          if (re->r2d != 0 || !is_z16 (re->lla))
            continue;
          if (memcmp (re->ep_ip, ip, 16) != 0)
            continue;
          if (re->ep_port != port)
            continue;
          *zero_idx = (int)i;
          break;
        }
    }
  if (*zero_idx < 0)
    rt_zero_ep_rm (t, ip, port, false);
  rt_dir_ep_rm_same_ip (t, lla, ip, port);
}

static void
rt_ep_apply (Rt *t, Re *re, const uint8_t lla[16], uint8_t tp_mask,
             uint64_t sys_ts, bool id_changed)
{
  RtSt was_state = re->state;
  bool was_act = was_state == RT_ACT;
  bool has_alt = rt_dir_has_other_ep (t, lla, re->ep_ip, re->ep_port);
  bool should_act = was_act;
  if (!should_act && !has_alt)
    should_act = true;
  if (should_act)
    (void)re_dir_activate_seen (re, sys_ts);
  else
    {
      re->state = RT_PND;
      if (re->pnd_ts == 0 || was_act || was_state != RT_PND)
        re->pnd_ts = sys_ts;
    }
  re_rx_note (re, sys_ts);
  if (tp_mask != 0)
    re->tp_mask |= tp_mask;
  memcpy (re->nhop_lla, lla, 16);
  re_mtu_sync (t, re);
  rt_map_mark (t);
  if (should_act && (id_changed || !was_act))
    rt_adv_dirty_set (t);
}

void
rt_ep_upd (Rt *t, const uint8_t lla[16], const uint8_t ip[16], uint16_t port,
           uint8_t tp_mask, uint64_t sys_ts)
{
  static const uint8_t z_lla[16] = { 0 };
  bool is_zero_lla = (memcmp (lla, z_lla, 16) == 0);
  int zero_idx = -1;
  if (!rt_direct_ep_ip_ok (ip))
    return;
  if (!is_zero_lla && !IS_LLA_VAL (lla))
    return;
  if (!is_zero_lla && memcmp (lla, t->our_lla, 16) == 0)
    return;
  if (!is_zero_lla)
    rt_ep_reconcile (t, lla, ip, port, &zero_idx);
  if (is_zero_lla)
    {
      for (uint32_t i = 0; i < t->cnt; i++)
        {
          if (memcmp (t->re_arr[i].ep_ip, ip, 16) == 0
              && t->re_arr[i].r2d == 0)
            {
              return;
            }
        }
    }
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      if (memcmp (t->re_arr[i].lla, lla, 16) != 0)
        continue;
      if (t->re_arr[i].r2d != 0)
        continue;
      if (memcmp (t->re_arr[i].ep_ip, ip, 16) != 0)
        continue;
      if (t->re_arr[i].ep_port != port)
        continue;
      rt_ep_apply (t, &t->re_arr[i], lla, tp_mask, sys_ts, false);
      return;
    }
  if (zero_idx >= 0)
    {
      Re *re = &t->re_arr[zero_idx];
      memcpy (re->lla, lla, 16);
      rt_ep_apply (t, re, lla, tp_mask, sys_ts, true);
      return;
    }
  if (rt_cap_chk (t, 1))
    {
      Re ne;
      memset (&ne, 0, sizeof (ne));
      memcpy (ne.lla, lla, 16);
      memcpy (ne.ep_ip, ip, 16);
      ne.ep_port = port;
      ne.r2d = 0;
      ne.tp_mask = tp_mask;
      ne.state = rt_dir_has_other_ep (t, lla, ip, port) ? RT_PND
                                                         : RT_ACT;
      ne.pnd_ts = sys_ts;
      ne.pong_ts = sys_ts;
      ne.rx_ts = sys_ts;
      ne.rto = RTO_INIT;
      ne.sm_m = 0;
      ne.rt_m = RT_F_INF;
      ne.adv_m = ne.rt_m;
      ne.adv_loss = 0;
      ne.mtu_lkg = re_mtu_base (t, &ne);
      ne.mtu_ukb = rt_mtu_ub (t);
      ne.mtu_st = MTU_ST_B;
      ne.prb_i_ts = 0;
      re_mtu_sync (t, &ne);
      memcpy (ne.nhop_lla, lla, 16);
      t->re_arr[t->cnt++] = ne;
      rt_map_mark (t);
      if (!is_zero_lla && ne.state == RT_ACT)
        {
          rt_adv_dirty_set (t);
        }
      if (!is_zero_lla)
        {
          char lla_str[INET6_ADDRSTRLEN] = { 0 };
          if (inet_ntop (AF_INET6, lla, lla_str, sizeof (lla_str)) != NULL)
            printf ("routing: discovered peer lla: %s\n", lla_str);
          else
            printf ("routing: discovered peer lla: "
                    "<invalid>\n");
        }
    }
}

void
rt_rx_ack (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts)
{
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      re_rx_note (re, sys_ts);
    }
}

void
rt_tx_ack (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts)
{
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      re->tx_ts = sys_ts;
    }
}

bool
rt_dat_upd (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts)
{
  if (!t)
    return false;
  Re *hit = NULL;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      hit = re;
      break;
    }

  if (!hit || hit->r2d != 0 || hit->state != RT_ACT)
    return false;

  bool is_mod = false;
  if (hit->dat_ts == 0)
    {
      hit->dat_ts = sys_ts ? sys_ts : 1;
      is_mod = true;
    }

  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re == hit || re->r2d != 0)
        continue;
      if (memcmp (re->lla, hit->lla, 16) != 0)
        continue;
      if (re->dat_ts == 0)
        continue;
      re->dat_ts = 0;
      is_mod = true;
    }

  if (is_mod)
    rt_map_mark (t);
  return is_mod;
}
void
rt_adv_dirty_set (Rt *t)
{
  if (t)
    t->adv_dirty = true;
}

Pth *
rt_map_pick (Rt *t, RtMap *re, bool is_p2p)
{
  Pth *b_dir_pth = re->sel_dir_pth;
  Pth *b_rel_pth = re->sel_rel_pth;
  bool dir_ok = (b_dir_pth != NULL && pth_m (b_dir_pth) < RT_F_INF);
  bool rel_ok = (b_rel_pth != NULL
                 && pth_rel_tot_m (t->map, b_rel_pth) < RT_F_INF);
  if (!is_p2p)
    {
      if (dir_ok && b_dir_pth->is_static)
        return b_dir_pth;
      if (rel_ok)
        return b_rel_pth;
      return NULL;
    }
  if (dir_ok)
    return b_dir_pth;
  if (re->has_pnd_dir && !rel_ok)
    return NULL;
  if (rel_ok)
    return b_rel_pth;
  return NULL;
}

int32_t
rt_pth_metric (Rt *t, const Pth *pth)
{
  if (!t || !pth)
    return RT_F_INF;
  rt_map_ens (t);
  if (pth->r2d == 0)
    return pth_m (pth);
  return pth_rel_tot_m (t->map, pth);
}

RtDec
rt_sel (Rt *t, const uint8_t dst_lla[16], bool is_p2p)
{
  RtDec dec;
  memset (&dec, 0, sizeof (dec));

  if (is_z16 (dst_lla))
    {
      dec.type = RT_VP;
      return dec;
    }
  if (memcmp (dst_lla, t->our_lla, 16) == 0)
    {
      dec.type = RT_NONE;
      return dec;
    }
  rt_map_ens (t);

  RtMap *re = NULL;
  HASH_FIND (hh, t->map, dst_lla, 16, re);
  if (!re)
    {
      dec.type = RT_VP;
      return dec;
    }

  Pth *pick = rt_map_pick (t, re, is_p2p);
  if (!pick)
    {
      dec.type = RT_VP;
      return dec;
    }
  if (pick->r2d == 0)
    {
      dec.type = RT_DIR;
      memcpy (dec.dir.ip, pick->ep_ip, 16);
      dec.dir.port = pick->ep_port;
      return dec;
    }
  dec.type = RT_REL;
  memcpy (dec.rel.relay_ip, pick->ep_ip, 16);
  dec.rel.relay_port = pick->ep_port;
  memcpy (dec.rel.relay_lla, pick->nhop_lla, 16);
  return dec;
}

static const Re *
rt_dir_match (const Rt *t, const RtDec *sel)
{
  if (!t || !sel || sel->type != RT_DIR)
    return NULL;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *re = &t->re_arr[i];
      if (re->state != RT_ACT)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, sel->dir.ip, 16) != 0)
        continue;
      if (re->ep_port != sel->dir.port)
        continue;
      return re;
    }
  return NULL;
}

static uint16_t
rt_dir_peer_rev_cap (const Re *re)
{
  if (!re || re->peer_rev_mtu < RT_MTU_MIN)
    return 0;
  return re->peer_rev_mtu;
}

uint16_t
rt_dir_mtu_adv (const Rt *t, const Re *re)
{
  return re_mtu_cur (t, re);
}

uint16_t
rt_dir_mtu_get (const Rt *t, const Re *re)
{
  uint16_t mtu = re_mtu_cur (t, re);
  uint16_t peer_rev_mtu = rt_dir_peer_rev_cap (re);
  if (peer_rev_mtu > 0 && peer_rev_mtu < mtu)
    mtu = peer_rev_mtu;
  return mtu;
}

uint16_t
rt_mtu (const Rt *t, const RtDec *sel)
{
  if (!t || !sel)
    return RT_MTU_MIN;
  if (sel->type == RT_DIR)
    {
      const Re *match = rt_dir_match (t, sel);
      if (match)
        return rt_dir_mtu_get (t, match);
      return RT_MTU_MIN;
    }
  if (sel->type == RT_REL)
    {
      uint16_t l2r_mtu = 0;
      uint16_t r2d_mtu = 0;
      for (uint32_t i = 0; i < t->cnt; i++)
        {
          const Re *re = &t->re_arr[i];
          if (re->state != RT_ACT)
            continue;
          if (memcmp (re->ep_ip, sel->rel.relay_ip, 16) != 0)
            continue;
          if (re->ep_port != sel->rel.relay_port)
            continue;
          uint16_t mtu = rt_dir_mtu_get (t, re);
          if (re->r2d == 0)
            {
              if (l2r_mtu == 0 || mtu < l2r_mtu)
                l2r_mtu = mtu;
            }
          else
            {
              if (!is_z16 (sel->rel.relay_lla)
                  && memcmp (re->nhop_lla, sel->rel.relay_lla, 16) != 0)
                {
                  continue;
                }
              if (r2d_mtu == 0 || mtu < r2d_mtu)
                r2d_mtu = mtu;
            }
        }
      if (l2r_mtu == 0 && r2d_mtu == 0)
        return RT_MTU_MIN;
      if (l2r_mtu == 0)
        return r2d_mtu;
      if (r2d_mtu == 0)
        return l2r_mtu;
      return (l2r_mtu < r2d_mtu) ? l2r_mtu : r2d_mtu;
    }
  return RT_MTU_MIN;
}

void
rt_peer_rev_mtu_set (Rt *t, const uint8_t peer_lla[16], uint16_t peer_rev_mtu)
{
  if (!t || !peer_lla || !IS_LLA_VAL (peer_lla))
    return;
  if (memcmp (peer_lla, t->our_lla, 16) == 0)
    return;
  if (peer_rev_mtu > rt_mtu_ub (t))
    peer_rev_mtu = rt_mtu_ub (t);
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->lla, peer_lla, 16) != 0)
        continue;
      re->peer_rev_mtu = peer_rev_mtu;
    }
}

void
rt_mtu_tk (Rt *t, uint64_t sys_ts)
{
  if (!t)
    return;
  if (!t->mtu_probe)
    return;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (re->state != RT_ACT)
        continue;
      if (memcmp (re->lla, t->our_lla, 16) == 0)
        continue;
      re_mtu_sync (t, re);
      if (re->hld_ts != 0 && sys_ts >= re->hld_ts)
        {
          re->mtu_ukb = rt_mtu_ub (t);
          if (re->mtu_ukb < re->mtu_lkg)
            re->mtu_ukb = re->mtu_lkg;
          re->mtu_st = MTU_ST_S;
          re->bhck = BHCK_NONE;
          re->hld_ts = 0;
          re->vfy_ts = 0;
        }
      if (re->prb_mtu == 0)
        continue;
      if (sys_ts < re->prb_ddl)
        continue;
      if (re->prb_tx >= RT_PRB_MAX)
        {
          uint16_t fail_mtu = re->prb_mtu;
          if (re->bhck == BHCK_BASE)
            {
              re->bhck = BHCK_NONE;
              re->hld_ts = sys_ts + RT_MTU_HLD;
            }
          else if (fail_mtu > re->mtu_lkg)
            {
              if ((uint16_t)(fail_mtu - 1U) < re->mtu_ukb)
                re->mtu_ukb = (uint16_t)(fail_mtu - 1U);
              if (re->mtu_ukb < re->mtu_lkg)
                re->mtu_ukb = re->mtu_lkg;
              re->mtu_st = MTU_ST_S;
              re->vfy_ts = 0;
            }
          else if (re->bhck == BHCK_CONFIRM)
            {
              re->mtu_ukb = (uint16_t)(fail_mtu - 1U);
              re->mtu_lkg = re_mtu_base (t, re);
              re->bhck = BHCK_NONE;
              re->mtu_st = MTU_ST_S;
              re->vfy_ts = 0;
            }
          else if (fail_mtu == re->mtu_lkg && re->mtu_lkg > re_mtu_base (t, re))
            {
              re->bhck = BHCK_BASE;
              re->mtu_st = MTU_ST_S;
            }
          else
            {
              re->hld_ts = sys_ts + RT_MTU_HLD;
              re->mtu_st
                  = (re->mtu_ukb <= re->mtu_lkg) ? MTU_ST_F : MTU_ST_S;
            }
          re->prb_mtu = 0;
          re->prb_id = 0;
          re->prb_tx = 0;
          re->prb_ddl = 0;
          re_mtu_sync (t, re);
          continue;
        }
      else
        {
          re->prb_tx_ts = 0;
          re->prb_ddl = sys_ts + RT_PRB_TMO;
          continue;
        }
    }
}

void
rt_mtu_probe_idle (Rt *t)
{
  if (!t)
    return;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      re->prb_i_ts = 0;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_tx_ts = 0;
      re->prb_ddl = 0;
      re->bhck = BHCK_NONE;
    }
}

bool
rt_mprb_rdy (Rt *t, uint64_t sys_ts, Re *out_re, uint16_t *prb_mtu,
             uint32_t *prb_id)
{
  if (!t || !out_re || !prb_mtu || !prb_id)
    return false;
  if (!t->mtu_probe)
    return false;
  uint16_t mtu_ub = rt_mtu_ub (t);
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (re->state == RT_DED)
        continue;
      if (memcmp (re->lla, t->our_lla, 16) == 0)
        continue;
      re_mtu_sync (t, re);
      if (re->hld_ts != 0 && sys_ts < re->hld_ts)
        continue;
      if (re->prb_mtu != 0)
        {
          if (sys_ts < re->prb_tx_ts + RT_PRB_PACE)
            continue;
          if (re->prb_tx >= RT_PRB_MAX)
            continue;
          re->prb_tx++;
          re->prb_tx_ts = sys_ts;
          re->prb_ddl = sys_ts + RT_PRB_TMO;
          *out_re = *re;
          *prb_mtu = re->prb_mtu;
          *prb_id = re->prb_id;
          return true;
        }
      if (sys_ts >= re->prb_i_ts && (sys_ts - re->prb_i_ts) < RT_PRB_INTV)
        continue;
      uint16_t probe_mtu;
      if (re->bhck == BHCK_BASE)
        probe_mtu = re_mtu_base (t, re);
      else if (re->bhck == BHCK_CONFIRM)
        probe_mtu = re->mtu_lkg;
      else if (re->mtu_ukb <= re->mtu_lkg)
        {
          if (re->vfy_ts == 0)
            re->vfy_ts = sys_ts;
          if (sys_ts >= re->vfy_ts && (sys_ts - re->vfy_ts) >= RT_PRB_TMO)
            {
              re->hld_ts
                  = sys_ts + RT_MTU_HLD;
              re->vfy_ts = 0;
              re->mtu_st = MTU_ST_F;
              continue;
            }
          probe_mtu = re->mtu_lkg;
        }
      else
        {
          re->vfy_ts = 0;
          if (re->mtu_st == MTU_ST_B)
            probe_mtu = re->mtu_ukb;
          else
            probe_mtu = (uint16_t)((re->mtu_lkg + re->mtu_ukb + 1U) / 2U);
          re->mtu_st = MTU_ST_S;
        }
      if (probe_mtu < RT_MTU_MIN)
        probe_mtu = RT_MTU_MIN;
      if (probe_mtu > mtu_ub)
        probe_mtu = mtu_ub;
      uint32_t probe_id = (t->prb_nxt_id == 0) ? 1U : t->prb_nxt_id;
      t->prb_nxt_id = probe_id + 1U;
      re->prb_mtu = probe_mtu;
      re->prb_id = probe_id;
      re->prb_tx = 1;
      re->prb_i_ts = sys_ts;
      re->prb_tx_ts = sys_ts;
      re->prb_ddl = sys_ts + RT_PRB_TMO;
      *out_re = *re;
      *prb_mtu = probe_mtu;
      *prb_id = probe_id;
      return true;
    }
  return false;
}

void
rt_pmtu_ack_ep (Rt *t, const uint8_t ip[16], uint16_t port, uint32_t probe_id,
                uint16_t probe_mtu, uint64_t sys_ts)
{
  if (!t || !ip || probe_id == 0 || probe_mtu == 0)
    return;
  if (!t->mtu_probe)
    return;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      if (re->prb_id != probe_id)
        continue;
      if (re->prb_mtu != probe_mtu)
        continue;
      if (re->bhck == BHCK_BASE && probe_mtu == re_mtu_base (t, re))
        re->bhck = BHCK_CONFIRM;
      else if (re->bhck == BHCK_CONFIRM && probe_mtu == re->mtu_lkg)
        re->bhck = BHCK_NONE;
      uint16_t old_mtu = re->mtu_lkg;
      uint16_t mtu_ub = rt_mtu_ub (t);
      if (probe_mtu > mtu_ub)
        probe_mtu = mtu_ub;
      if (probe_mtu < RT_MTU_MIN)
        probe_mtu = RT_MTU_MIN;
      if (probe_mtu > re->mtu_lkg)
        re->mtu_lkg = probe_mtu;
      if (re->mtu_ukb < re->mtu_lkg)
        re->mtu_ukb = re->mtu_lkg;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      if (re->mtu_ukb <= re->mtu_lkg)
        {
          if (re->vfy_ts == 0)
            re->vfy_ts = sys_ts;
          re->mtu_st = MTU_ST_F;
        }
      else
        {
          re->vfy_ts = 0;
          re->hld_ts = 0;
          re->mtu_st = MTU_ST_S;
        }
      re_mtu_sync (t, re);
      re_mtu_search_kick (re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu_lkg != old_mtu)
        {
          rt_adv_dirty_set (t);
        }
      return;
    }
}

void
rt_pmtu_ptb_ep (Rt *t, const uint8_t ip[16], uint16_t port, uint16_t pmtu,
                uint64_t sys_ts)
{
  if (!t || !ip || pmtu < rt_ptb_path_mtu_min (ip))
    return;
  if (!t->mtu_probe)
    return;
  uint16_t ub = rt_mtu_ub (t);
  if (pmtu > ub)
    pmtu = ub;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      if (!re->prb_tx || re->prb_tx_ts == 0)
        continue;
      if (re->prb_ddl > 0 && sys_ts > re->prb_ddl)
        continue;
      uint16_t old_mtu = re->mtu_lkg;
      re->mtu_ukb = pmtu;
      if (re->mtu_lkg > pmtu)
        re->mtu_lkg = pmtu;
      re->mtu_st = MTU_ST_S;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
      re_mtu_search_kick (re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu_lkg != old_mtu)
        {
          rt_adv_dirty_set (t);
        }
    }
}

void
rt_emsg_hnd (Rt *t, const uint8_t ip[16], uint16_t port, size_t atmpt_plen,
             uint64_t sys_ts)
{
  if (!t || !ip)
    return;
  if (!t->mtu_probe)
    return;
  uint16_t mtu_ub = rt_mtu_ub (t);
  uint16_t oip_oh = is_ip_v4m (ip) ? 20U : 40U;
  uint16_t ip_udp_oh = (uint16_t)(oip_oh + 8U);
  uint32_t mtu_val32 = (uint32_t)atmpt_plen + (uint32_t)ip_udp_oh;
  if (mtu_val32 < RT_MTU_MIN)
    mtu_val32 = RT_MTU_MIN;
  if (mtu_val32 > mtu_ub)
    mtu_val32 = mtu_ub;
  uint16_t atmpt_mtu = (uint16_t)mtu_val32;
  uint16_t fail_ukb
      = (atmpt_mtu > RT_MTU_MIN) ? (uint16_t)(atmpt_mtu - 1U) : RT_MTU_MIN;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      uint16_t old_mtu = re->mtu_lkg;
      if (fail_ukb < re->mtu_ukb)
        re->mtu_ukb = fail_ukb;
      if (re->mtu_lkg > re->mtu_ukb)
        re->mtu_lkg = re->mtu_ukb;
      re->mtu_st = MTU_ST_B;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re->prb_i_ts = sys_ts;
      re->prb_tx_ts = sys_ts;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
      re_mtu_search_kick (re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu_lkg != old_mtu)
        {
          rt_adv_dirty_set (t);
        }
    }
}

void
rt_unr_hnd (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts)
{
  if (!t || !ip)
    return;
  bool is_mod = false;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      if (re->pong_ts > 0 && sys_ts >= re->pong_ts
          && (sys_ts - re->pong_ts) <= RT_PRB_INTV)
        {
          re->tx_ts = sys_ts;
          continue;
        }
      bool was_live = re->state == RT_ACT;
      re->state = RT_PND;
      re->rt_m = RT_F_INF;
      re->sm_m = RT_M_INF;
      re_metric_win_clear (re);
      re->tx_ts = sys_ts;
      if (was_live)
        is_mod = true;
    }
  if (is_mod)
    rt_map_mark (t);
}

int
rt_act_get (Rt *t, Re *buf, int buf_len, int s_off)
{
  int act_cnt = 0;
  for (uint32_t scan_idx = 0; scan_idx < t->cnt && act_cnt < buf_len;
       scan_idx++)
    {
      uint32_t re_idx = ((uint32_t)s_off + scan_idx) % t->cnt;
      if (t->re_arr[re_idx].state == RT_ACT)
        buf[act_cnt++] = t->re_arr[re_idx];
    }
  return act_cnt;
}

void
rt_prn_st (Rt *t, const Cfg *cfg, uint64_t sys_ts)
{
  uint32_t old_cnt = t->cnt;
  uint32_t wr_idx = 0;
  bool any_ded = false;
  bool is_mod = false;
  rt_map_ens (t);
  for (uint32_t rd_idx = 0; rd_idx < t->cnt; rd_idx++)
    {
      Re *re = &t->re_arr[rd_idx];
      bool is_rel = (re->r2d != 0);
      uint64_t stl_ts = is_rel ? RT_REL_STL : RT_STL_TS;
      uint64_t ded_ts = is_rel ? RT_REL_DED : RT_DED_TS;
      if (!is_rel && re_metric_refresh (re, sys_ts))
        is_mod = true;
      if (!is_rel && re_use_tcp (cfg, re))
        {
          if (tp_alive_get (re->lla, re->ep_ip, re->ep_port))
            {
              RtSt was_state = re->state;
              int32_t old_rt_m = re->rt_m;
              re_rx_ack (re, sys_ts);
              if (re->state != was_state || re->rt_m != old_rt_m)
                is_mod = true;
              t->re_arr[wr_idx++] = *re;
              continue;
            }
          if (re->state == RT_ACT)
            {
              re->state = RT_PND;
              re->rt_m = RT_F_INF;
              re->sm_m = RT_M_INF;
              re_metric_win_clear (re);
              re->pnd_ts = sys_ts;
              is_mod = true;
            }
        }
      if (!is_rel && re->state == RT_ACT && re->pong_ts > 0
          && !is_z16 (re->lla)
          && memcmp (re->lla, t->our_lla, 16) != 0
          && sys_ts > re->pong_ts && (sys_ts - re->pong_ts) > RT_KA_TMO)
        {
          if (rt_dir_is_sel (t, re))
            any_ded = true;
          re->state = RT_PND;
          re->rt_m = RT_F_INF;
          re->sm_m = RT_M_INF;
          re_metric_win_clear (re);
          re->pnd_ts = sys_ts;
          is_mod = true;
        }
      if (is_rel && re->state != RT_DED)
        {
          uint64_t nh_age = rt_nhop_pong_age (t, re->nhop_lla, sys_ts);
          if (nh_age > RT_STL_TS)
            {
              if (re->state == RT_ACT)
                any_ded = true;
              re->state = RT_DED;
              re->rt_m = RT_F_INF;
              re->sm_m = RT_M_INF;
              re_metric_win_clear (re);
              is_mod = true;
            }
          else if (re->state == RT_ACT && nh_age > RT_KA_TMO)
            {
              if (re->state == RT_ACT)
                any_ded = true;
              re->state = RT_PND;
              re->rt_m = RT_F_INF;
              re->sm_m = RT_M_INF;
              re_metric_win_clear (re);
              re->pnd_ts = sys_ts;
              is_mod = true;
            }
        }
      if (sys_ts > re->rx_ts)
        {
          uint64_t age = sys_ts - re->rx_ts;
          if (!is_rel && age > stl_ts)
            {
              if (re->state != RT_DED)
                {
                  if (rt_dir_is_sel (t, re))
                    any_ded = true;
                  re->state = RT_DED;
                  re->rt_m = RT_F_INF;
                  re->sm_m = RT_M_INF;
                  re_metric_win_clear (re);
                  is_mod = true;
                }
              else
                {
                  re->state = RT_DED;
                  re->rt_m = RT_F_INF;
                  re->sm_m = RT_M_INF;
                  re_metric_win_clear (re);
                }
            }
          if (!re->is_static)
            {
              if (age > ded_ts)
                continue;
              if (!is_rel && re->sm_m >= RT_M_INF && age > RT_GHS_TS)
                {
                  is_mod = true;
                  continue;
                }
            }
        }
      t->re_arr[wr_idx++] = *re;
    }
  t->cnt = wr_idx;
  if (t->cnt != old_cnt)
    is_mod = true;
  if (is_mod)
    rt_map_mark (t);
  if (any_ded)
    rt_adv_dirty_set (t);
}

void
rt_src_gc (Rt *t, uint64_t sys_ts)
{
  uint32_t wr_idx = 0;
  for (uint32_t rd_idx = 0; rd_idx < t->src_cnt; rd_idx++)
    {
      SrcEnt *se = &t->sources[rd_idx];
      if (sys_ts > se->gc_ts && (sys_ts - se->gc_ts) > RT_SRC_GC_TS)
        {
          continue;
        }
      t->sources[wr_idx++] = *se;
    }
  t->src_cnt = wr_idx;
}

bool
rt_src_no_dir (const Rt *t, const uint8_t rt_id[16])
{
  if (!t || !rt_id)
    return false;
  const SrcEnt *se = src_fnd_c (t, rt_id);
  return se ? se->no_dir : false;
}

bool
rt_src_no_dir_known (const Rt *t, const uint8_t rt_id[16], bool *out_no_dir)
{
  if (out_no_dir)
    *out_no_dir = false;
  if (!t || !rt_id)
    return false;
  const SrcEnt *se = src_fnd_c (t, rt_id);
  if (!se)
    return false;
  if (out_no_dir)
    *out_no_dir = se->no_dir;
  return true;
}

uint8_t
rt_ep_tp_mask (const Rt *t, const uint8_t ip[16], uint16_t port)
{
  if (!t || !ip || port == 0)
    return TP_MASK_UDP | TP_MASK_TCP;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *re = &t->re_arr[i];
      if (re->r2d != 0 || re->state == RT_DED)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0 || re->ep_port != port)
        continue;
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) == 0)
        continue;
      return re->tp_mask != 0 ? re->tp_mask : (TP_MASK_UDP | TP_MASK_TCP);
    }
  return TP_MASK_UDP | TP_MASK_TCP;
}

bool
rt_ep_peer_lla (const Rt *t, const uint8_t ip[16], uint16_t port,
                uint8_t out_lla[16])
{
  if (!t || !ip || !out_lla || port == 0)
    return false;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *re = &t->re_arr[i];
      if (re->r2d != 0 || re->state == RT_DED || is_z16 (re->lla))
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0 || re->ep_port != port)
        continue;
      if (memcmp (re->lla, t->our_lla, 16) == 0)
        continue;
      memcpy (out_lla, re->lla, 16);
      return true;
    }
  return false;
}

bool
rt_peer_ep_fnd (const Rt *t, const uint8_t peer_lla[16], uint8_t out_ip[16],
                uint16_t *out_port)
{
  if (!t || !peer_lla || !out_ip || !out_port || is_z16 (peer_lla))
    return false;
  const Re *best = NULL;
  uint64_t best_ts = 0;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      const Re *re = &t->re_arr[i];
      if (re->r2d != 0 || re->state == RT_DED)
        continue;
      if (memcmp (re->lla, peer_lla, 16) != 0)
        continue;
      uint64_t seen = re->rx_ts;
      if (re->pong_ts > seen)
        seen = re->pong_ts;
      bool re_act = re->state == RT_ACT;
      bool best_act = best && best->state == RT_ACT;
      if (!best || (re_act && !best_act)
          || (re_act == best_act && seen > best_ts))
        {
          best = re;
          best_ts = seen;
        }
    }
  if (!best || best->ep_port == 0)
    return false;
  memcpy (out_ip, best->ep_ip, 16);
  *out_port = best->ep_port;
  return true;
}

void
rt_src_upd_auth (Rt *t, const uint8_t rt_id[16],
                 uint64_t ver, bool no_dir,
                 bool can_clear_no_dir, uint64_t sys_ts)
{
  SrcEnt *se = src_fnd (t, rt_id);
  if (!se)
    {
      if (!src_cap_chk (t, 1))
        return;
      se = &t->sources[t->src_cnt++];
      memset (se, 0, sizeof (*se));
      memcpy (se->rt_id, rt_id, 16);
      se->last_ver = ver;
      se->no_dir = no_dir;
      se->gc_ts = sys_ts;
      rt_map_mark (t);
      return;
    }
  bool old_no_dir = se->no_dir;
  if (ver > 0)
    se->last_ver = ver;
  se->no_dir = no_dir || (old_no_dir && !can_clear_no_dir);
  se->gc_ts = sys_ts;
  if (se->no_dir != old_no_dir)
    rt_map_mark (t);
}

void
rt_src_upd (Rt *t, const uint8_t rt_id[16],
            uint64_t ver, bool no_dir, uint64_t sys_ts)
{
  rt_src_upd_auth (t, rt_id, ver, no_dir, false, sys_ts);
}

void
rt_dir_hint_prune (Rt *t, const uint8_t lla[16])
{
  if (!t || !lla || !IS_LLA_VAL (lla))
    return;
  if (memcmp (lla, t->our_lla, 16) == 0)
    return;
  uint32_t wr_idx = 0;
  bool is_mod = false;
  for (uint32_t rd_idx = 0; rd_idx < t->cnt; rd_idx++)
    {
      Re *re = &t->re_arr[rd_idx];
      bool is_rm = re->r2d == 0 && memcmp (re->lla, lla, 16) == 0
                   && !re->is_static;
      if (is_rm)
        {
          is_mod = true;
          continue;
        }
      if (wr_idx != rd_idx)
        t->re_arr[wr_idx] = t->re_arr[rd_idx];
      wr_idx++;
    }
  if (is_mod)
    {
      t->cnt = wr_idx;
      rt_map_mark (t);
    }
}

bool
rt_peer_sess (Rt *t, const uint8_t rt_id[16], uint64_t peer_sid,
              uint64_t sys_ts)
{
  if (peer_sid == 0)
    return false;
  bool is_rbt = false;
  for (uint32_t re_idx = 0; re_idx < t->cnt; re_idx++)
    {
      Re *re = &t->re_arr[re_idx];
      if (memcmp (re->lla, rt_id, 16) != 0)
        continue;
      if (re->sid == 0)
        {
          re->sid = peer_sid;
          continue;
        }
      if (re->sid != peer_sid)
        {
          is_rbt = true;
          break;
        }
    }
  if (!is_rbt)
    return false;
  for (uint32_t re_idx = 0; re_idx < t->cnt; re_idx++)
    {
      Re *re = &t->re_arr[re_idx];
      if (memcmp (re->lla, rt_id, 16) != 0)
        continue;
      re->sid = peer_sid;
      re->adv_m = RT_F_INF;
      re->rt_m = (re->r2d == 0) ? RT_F_INF : re->rt_m;
      if (re->r2d == 0)
        {
          re->state = RT_PND;
        }
    }
  SrcEnt *se = src_fnd (t, rt_id);
  if (se)
    {
      se->last_ver = 0;
      se->gc_ts = sys_ts;
    }
  rt_map_mark (t);
  return true;
}
