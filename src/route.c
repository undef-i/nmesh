#include "route.h"
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
#define RT_UPD_INTV (RT_HL_INTV * 4ULL)
#define RT_REL_STL (RT_UPD_INTV * 3ULL)
#define RT_REL_DED (RT_UPD_INTV * 6ULL)
#define RT_STL_TS (RT_HL_INTV * RT_STL_HL)
#define RT_DED_TS (RT_HL_INTV * RT_DED_HL)
#define RT_LIV_TK 4000ULL
#define RT_LIV_B 16U
#define RT_PRB_TMO 2000ULL
#define RT_MTU_VFY 10000ULL
#define RT_MTU_HLD 600000ULL
#define RT_MTU_EPS 10U
#define RT_METRIC_SLOT_INV 0ULL
static bool
seq_gt (uint32_t a, uint32_t b)
{
  return ((int32_t)(a - b)) > 0;
}

static bool
seq_lt (uint32_t a, uint32_t b)
{
  return seq_gt (b, a);
}

static bool is_z16 (const uint8_t lla[16]);

static bool
rt_direct_ep_ip_ok (const uint8_t ip[16])
{
  if (!ip)
    return false;
  /* IPv6 link-local needs scope_id/ifindex; endpoint model has only ip:port. */
  if (!is_ip_v4m (ip) && ip[0] == 0xfe && ((ip[1] & 0xc0) == 0x80))
    return false;
  return true;
}

static uint16_t
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
re_mtu_boot (const Rt *t, const Re *re)
{
  if (!re)
    return RT_MTU_DEF;
  if (re->r2d != 0)
    return RT_MTU_DEF;
  return (t && t->mtu_probe) ? RT_MTU_DEF : re_mtu_ub (t, re);
}

static uint16_t
re_mtu_fix (const Rt *t, const Re *re)
{
  uint16_t fixed = re_mtu_ub (t, re);
  if (!re)
    return fixed;
  if (re->mtu > 0 && re->mtu < fixed)
    fixed = re->mtu;
  if (re->mtu_lkg > 0 && re->mtu_lkg < fixed)
    fixed = re->mtu_lkg;
  if (re->mtu_ukb >= RT_MTU_MIN && re->mtu_ukb < fixed)
    fixed = re->mtu_ukb;
  return fixed;
}

static uint16_t
re_mtu_cur (const Rt *t, const Re *re)
{
  if (!re)
    return RT_MTU_DEF;
  if (re->mtu > 0)
    return re->mtu;
  if (re->mtu_lkg > 0)
    return re->mtu_lkg;
  return re_mtu_boot (t, re);
}

static bool
re_mtu_is_searching (const Re *re)
{
  if (!re)
    return false;
  return re->mtu_ukb > (uint16_t)(re->mtu_lkg + RT_MTU_EPS);
}

static void
re_mtu_search_kick (Re *re)
{
  if (!re_mtu_is_searching (re))
    return;
  re->prb_i_ts = 0;
  re->prb_tx_ts = 0;
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
      re->mtu = fixed;
      re->mtu_lkg = fixed;
      re->mtu_ukb = fixed;
      re->mtu_st = MTU_ST_F;
      re->prb_i_ts = 0;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_tx_ts = 0;
      re->prb_ddl = 0;
      re->ack_ts = 0;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      return;
    }
  if (re->mtu_lkg == 0)
    {
      if (re->mtu > 0)
        re->mtu_lkg = re->mtu;
      else
        re->mtu_lkg = re_mtu_boot (t, re);
    }
  if (re->mtu == 0)
    re->mtu = re->mtu_lkg;
  if (re->mtu < RT_MTU_MIN)
    re->mtu = RT_MTU_MIN;
  if (re->mtu > upper)
    re->mtu = upper;
  if (re->mtu_ukb == 0)
    re->mtu_ukb = upper;
  if (re->mtu_lkg < RT_MTU_MIN)
    re->mtu_lkg = RT_MTU_MIN;
  if (re->mtu_lkg > upper)
    re->mtu_lkg = upper;
  if (re->mtu_ukb < re->mtu_lkg)
    re->mtu_ukb = re->mtu_lkg;
  if (re->mtu_ukb > upper)
    re->mtu_ukb = upper;
  re->mtu = re->mtu_lkg;
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
re_map_dcy (Re *re, uint64_t sys_ts)
{
  if (re->rx_base == 0)
    {
      re->rx_base = sys_ts;
      return;
    }
  if (sys_ts <= re->rx_base)
    return;
  uint64_t diff = sys_ts - re->rx_base;
  uint64_t shift = diff / RT_LIV_TK;
  if (shift == 0)
    return;
  if (shift >= RT_LIV_B)
    re->rx_bmp = 0;
  else
    re->rx_bmp = (uint16_t)(re->rx_bmp << shift);
  re->rx_base += shift * RT_LIV_TK;
}

static void
re_rx_note (Re *re, uint64_t sys_ts)
{
  re_map_dcy (re, sys_ts);
  re->rx_bmp |= 0x0001U;
  re->rx_ts = sys_ts;
}

static bool
re_dir_activate (Re *re, uint64_t sys_ts)
{
  bool was_act = re->is_act && re->state == RT_ACT;
  if (!was_act && sys_ts > 0)
    re->pnd_ts = sys_ts;
  re->pong_ts = sys_ts;
  re->is_act = true;
  re->state = RT_ACT;
  return !was_act;
}

static void
re_rx_ack (Re *re, uint64_t sys_ts)
{
  re_rx_note (re, sys_ts);
  (void)re_dir_activate (re, sys_ts);
}

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
      re->rttvar
          = re->rttvar - (re->rttvar >> 2) + (uint32_t)((uint32_t)dt >> 2);
    }
  uint32_t rto = (re->srtt >> 3) + re->rttvar;
  if (rto < RTO_MIN)
    rto = RTO_MIN;
  if (rto > RTO_MAX)
    rto = RTO_MAX;
  re->rto = rto;
}

static uint32_t
pth_m (const Pth *pth)
{
  uint32_t m = pth->sm_m;
  if (m == 0 || m == RTT_UNK || m >= RT_M_INF)
    m = pth->rt_m;
  return m;
}

static uint64_t
pth_last_rx_ts (const Pth *pth)
{
  if (!pth)
    return 0;
  uint64_t ts = pth->rx_ts;
  if (pth->pong_ts > ts)
    ts = pth->pong_ts;
  return ts;
}

static bool
pth_dir_btr (const Pth *cand, const Pth *best)
{
  if (!cand)
    return false;
  if (!best)
    return true;

  uint32_t cand_m = pth_m (cand);
  uint32_t best_m = pth_m (best);
  if (cand_m != best_m)
    return cand_m < best_m;

  uint64_t cand_ts = pth_last_rx_ts (cand);
  uint64_t best_ts = pth_last_rx_ts (best);
  if (cand_ts != best_ts)
    return cand_ts > best_ts;

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
re_metric_win_clear (Re *re)
{
  if (!re)
    return;
  memset (re->rtt_win_id, 0, sizeof (re->rtt_win_id));
  memset (re->rtt_win_min, 0, sizeof (re->rtt_win_min));
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

static bool
re_metric_refresh (Re *re, uint64_t sys_ts)
{
  if (!re || re->r2d != 0 || sys_ts == 0)
    return false;
  uint32_t old_sm = re->sm_m;
  uint32_t old_rt = re->rt_m;
  bool rtt_seen = false;
  for (size_t i = 0; i < RT_METRIC_WIN_BINS; i++)
    {
      if (re->rtt_win_id[i] != RT_METRIC_SLOT_INV)
        {
          rtt_seen = true;
          break;
        }
    }

  re_rtt_win_seed (re, sys_ts);

  re->sm_m = re_rtt_win_cur (re, sys_ts);
  if (re->sm_m < RT_M_INF)
    re->rt_m = re->sm_m;
  else if (rtt_seen)
    re->rt_m = RT_M_INF;
  return re->sm_m != old_sm || re->rt_m != old_rt;
}

static void
re_rtt_min_apply (Re *re, uint32_t rtt_ms, uint64_t sys_ts)
{
  if (!re)
    return;
  re_rtt_win_add (re, rtt_ms, sys_ts);
  re_metric_refresh (re, sys_ts);
}

static uint32_t
re_dir_seed_m (const Re *re)
{
  if (!re)
    return RTO_INIT;
  if (re->sm_m > 0 && re->sm_m != RTT_UNK && re->sm_m < RT_M_INF)
    return re->sm_m;
  if (re->rt_m > 0 && re->rt_m < RT_M_INF)
    return re->rt_m;
  return RTO_INIT;
}

static bool
re_is_recent (const Re *re, uint64_t sys_ts)
{
  if (!re || re->rx_ts == 0 || sys_ts <= re->rx_ts)
    return false;
  uint64_t age = sys_ts - re->rx_ts;
  uint64_t win = re->rto;
  if (win < RT_PRB_TMO)
    win = RT_PRB_TMO;
  if (win > RT_STL_TS)
    win = RT_STL_TS;
  return age <= win;
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
    rtm->sel_pth = NULL;
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
  snap.gsp_dirty = src->gsp_dirty;
  snap.boot_ts = src->boot_ts;
  snap.loc_last_ts = src->loc_last_ts;
  snap.sync_rev = src->sync_rev;
  snap.gsp_off = src->gsp_off;
  snap.gsp_last_ts = src->gsp_last_ts;
  snap.gsp_tx_cnt = src->gsp_tx_cnt;
  snap.gsp_dt_tx_cnt = src->gsp_dt_tx_cnt;
  snap.ping_tx_cnt = src->ping_tx_cnt;
  snap.pong_tx_cnt = src->pong_tx_cnt;
  snap.hp_tx_cnt = src->hp_tx_cnt;
  snap.seqreq_tx_cnt = src->seqreq_tx_cnt;
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
  pth->seq = re->seq;
  pth->adv_m = re->adv_m;
  pth->rt_m = re->rt_m;
  memcpy (pth->nhop_lla, re->nhop_lla, 16);
  pth->state = re->state;
  pth->is_act = re->is_act;
  pth->is_static = re->is_static;
  pth->tp_mask = re->tp_mask;
  pth->pong_ts = re->pong_ts;
  pth->rx_ts = re->rx_ts;
  pth->tx_ts = re->tx_ts;
  pth->rx_base = re->rx_base;
  pth->rx_bmp = re->rx_bmp;
  pth->srtt = re->srtt;
  pth->rttvar = re->rttvar;
  pth->rto = re->rto;
  pth->sm_m = re->sm_m;
  pth->r2d = re->r2d;
  pth->mtu = re->mtu;
  pth->mtu_lkg = re->mtu_lkg;
  pth->mtu_ukb = re->mtu_ukb;
  pth->peer_rev_mtu = re->peer_rev_mtu;
  pth->mtu_st = re->mtu_st;
  pth->mtu_ukb_soft = re->mtu_ukb_soft;
  pth->prb_i_ts = re->prb_i_ts;
  pth->prb_mtu = re->prb_mtu;
  pth->prb_id = re->prb_id;
  pth->prb_tx = re->prb_tx;
  pth->prb_tx_ts = re->prb_tx_ts;
  pth->prb_ddl = re->prb_ddl;
  pth->ack_ts = re->ack_ts;
  pth->vfy_ts = re->vfy_ts;
  pth->hld_ts = re->hld_ts;
  pth->prb_ts = re->prb_ts;
  pth->prb_tok = re->prb_tok;
  pth->prb_tx_cnt = re->prb_tx_cnt;
  pth->prb_rx_cnt = re->prb_rx_cnt;
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
          rtm->sel_dir_m = UINT32_MAX;
          rtm->sel_rel_m = UINT32_MAX;
          HASH_ADD (hh, n_map, lla, 16, rtm);
        }

      Pth *pth = pth_alloc (t);
      if (!pth)
        continue;
      re_to_pth (re, pth);
      pth->next = rtm->paths;
      rtm->paths = pth;

      if (pth->r2d == 0 && pth->is_act && pth->state == RT_ACT)
        {
          if (pth_dir_btr (pth, rtm->sel_dir_pth))
            {
              rtm->sel_dir_pth = pth;
              rtm->sel_dir_m = pth_m (pth);
            }
        }
    }

  RtMap *rtm, *tmp;
  HASH_ITER (hh, n_map, rtm, tmp)
  {
    int dir_act_cnt = 0;
    for (Pth *p = rtm->paths; p; p = p->next)
      {
        if (p->r2d == 0 && p->is_act && p->state == RT_ACT)
          dir_act_cnt++;
        if (!p->is_act || p->state != RT_ACT)
          continue;

        if (p->r2d > 0)
          {
            if (memcmp (p->nhop_lla, t->our_lla, 16) == 0)
              continue;

            RtMap *nh = NULL;
            HASH_FIND (hh, n_map, p->nhop_lla, 16, nh);
            if (!nh || !nh->sel_dir_pth)
              continue;

            uint32_t n2r = nh->sel_dir_m;
            if (n2r >= RT_M_INF)
              continue;

            uint32_t tot = n2r + p->r2d;
            if (!rtm->sel_rel_pth || tot < rtm->sel_rel_m)
              {
                rtm->sel_rel_pth = p;
                rtm->sel_rel_m = tot;
              }
          }
      }

    rtm->sel_pth = rtm->sel_dir_pth ? rtm->sel_dir_pth : rtm->sel_rel_pth;

    for (Pth *p = rtm->paths; p; p = p->next)
      {
        if (p->r2d == 0 && !p->is_act && p->state == RT_PND)
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
      bool cand_act = re->is_act && re->state == RT_ACT;
      bool best_act = best && best->is_act && best->state == RT_ACT;
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
  int is_v4 = (ip[0] == 0 && ip[1] == 0 && ip[10] == 0xff && ip[11] == 0xff);
  if (is_v4)
    /* fprintf (stderr, "pool: discovered peer %u.%u.%u.%u:%u\n", ip[12],
                ip[13], ip[14], ip[15], port); */
    ;
  else
    {
      char ip_str[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, ip, ip_str, sizeof (ip_str));
      /* fprintf (stderr, "pool: discovered peer [%s]:%u\n", ip_str, port); */
    }
  memcpy (p->re_arr[p->cnt].ip, ip, 16);
  p->re_arr[p->cnt].port = port;
  p->cnt++;
  p->is_dirty = true;
}

void
rt_init (Rt *t)
{
  memset (t, 0, sizeof (*t));
  t->prb_nxt_id = 1;
  t->mtu_ub = RT_MTU_MAX;
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
      uint16_t old_mtu = re->mtu;
      if (is_on)
        {
          re->mtu = RT_MTU_DEF;
          re->mtu_lkg = RT_MTU_DEF;
          re->mtu_ukb = re_mtu_ub (t, re);
          re->mtu_st = MTU_ST_B;
          re->mtu_ukb_soft = false;
          re->prb_i_ts = 0;
          re->prb_mtu = 0;
          re->prb_id = 0;
          re->prb_tx = 0;
          re->prb_tx_ts = 0;
          re->prb_ddl = 0;
          re->ack_ts = 0;
          re->vfy_ts = 0;
          re->hld_ts = 0;
        }
      re_mtu_sync (t, re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu != old_mtu)
        is_mod = true;
    }
  if (is_mod)
    rt_gsp_dirty_set (t, "mtu_probe_set (direct mtu)");
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
      if ((is_rel || is_loc_inj) && re->is_act)
        cur_re->is_act = true;
      cur_re->tp_mask = re->tp_mask;
      if (seq_gt (re->seq, cur_re->seq))
        cur_re->seq = re->seq;
      if (re->adv_m > 0)
        cur_re->adv_m = re->adv_m;
      if (is_rel)
        {
          if (re->rt_m > 0)
            cur_re->rt_m = re->rt_m;
        }
      else
        {
          if (cur_re->rt_m >= RT_M_INF || cur_re->rt_m == 0)
            {
              if (re->rt_m > 0)
                cur_re->rt_m = re->rt_m;
            }
        }
      if (re->state == RT_DED)
        {
          cur_re->state = RT_DED;
          cur_re->is_act = false;
        }
      else if ((is_rel || is_loc_inj) && (re->state == RT_ACT || re->is_act))
        {
          cur_re->state = RT_ACT;
          cur_re->is_act = true;
        }
      else if (cur_re->state != RT_ACT && cur_re->state != RT_DED)
        {
          cur_re->state = RT_PND;
        }
      if (IS_LLA_VAL (re->nhop_lla))
        memcpy (cur_re->nhop_lla, re->nhop_lla, 16);
      if (re->mtu > 0)
        cur_re->mtu = re->mtu;
      if (cur_re->mtu < RT_MTU_MIN)
        cur_re->mtu = RT_MTU_MIN;
      if (cur_re->mtu == 0)
        cur_re->mtu
            = (cur_re->mtu_lkg > 0) ? cur_re->mtu_lkg
                                    : ((cur_re->r2d == 0) ? RT_MTU_MIN
                                                          : RT_MTU_DEF);
      if (re->mtu_lkg > 0)
        cur_re->mtu_lkg = re->mtu_lkg;
      if (re->mtu_ukb > 0)
        cur_re->mtu_ukb = re->mtu_ukb;
      if (re->prb_mtu > 0)
        cur_re->prb_mtu = re->prb_mtu;
      if (re->prb_id > 0)
        cur_re->prb_id = re->prb_id;
      if (re->prb_i_ts > 0)
        cur_re->prb_i_ts = re->prb_i_ts;
      if (re->prb_tx_ts > 0)
        cur_re->prb_tx_ts = re->prb_tx_ts;
      if (re->ack_ts > 0)
        cur_re->ack_ts = re->ack_ts;
      re_mtu_sync (t, cur_re);
      if (is_rel)
        {
          if (sys_ts > 0)
            cur_re->pong_ts = sys_ts;
          else if (cur_re->pong_ts == 0)
            cur_re->pong_ts = sys_ts;
          if (sys_ts > 0)
            re_rx_ack (cur_re, sys_ts);
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
      ne.rx_base = sys_ts;
      ne.rx_bmp = is_rel ? 0x0001U : 0;
      if (ne.rto == 0)
        ne.rto = RTO_INIT;
      if (ne.rt_m == 0)
        {
          if (ne.r2d > 0)
            ne.rt_m = ne.r2d;
          else
            ne.rt_m = RT_M_INF;
        }
      if (ne.adv_m == 0)
        ne.adv_m = ne.rt_m;
      if (ne.mtu == 0)
        {
          if (!t->mtu_probe && ne.r2d == 0)
            ne.mtu = re_mtu_ub (t, &ne);
          else
            ne.mtu = (ne.mtu_lkg > 0) ? ne.mtu_lkg
                                      : ((ne.r2d == 0) ? RT_MTU_DEF
                                                       : RT_MTU_DEF);
        }
      if (ne.mtu < RT_MTU_MIN)
        ne.mtu = RT_MTU_MIN;
      if (ne.mtu_lkg == 0)
        ne.mtu_lkg = ne.mtu;
      if (ne.mtu_ukb == 0)
        ne.mtu_ukb = (!t->mtu_probe && ne.r2d == 0) ? ne.mtu : rt_mtu_ub (t);
      ne.prb_i_ts = 0;
      ne.mtu_st = MTU_ST_B;
      ne.mtu_ukb_soft = false;
      re_mtu_sync (t, &ne);
      if (is_dir_obs)
        {
          ne.is_act = false;
          ne.state = RT_PND;
        }
      else
        {
          if (ne.state == 0 && !ne.is_act)
            ne.state = RT_PND;
          if (ne.is_act)
            ne.state = RT_ACT;
        }
      t->re_arr[t->cnt++] = ne;
      rt_map_mark (t);
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
  if (re->sel_dir_m >= RT_M_INF)
    return false;

  re->sel_pth = selected;
  memset (out, 0, sizeof (*out));
  memcpy (out->lla, re->lla, 16);
  memcpy (out->ep_ip, selected->ep_ip, 16);
  out->ep_port = selected->ep_port;
  out->ver = selected->ver;
  out->sid = selected->sid;
  out->seq = selected->seq;
  out->adv_m = selected->adv_m;
  out->rt_m = selected->rt_m;
  memcpy (out->nhop_lla, selected->nhop_lla, 16);
  out->state = selected->state;
  out->is_act = selected->is_act;
  out->is_static = selected->is_static;
  out->tp_mask = selected->tp_mask;
  out->pong_ts = selected->pong_ts;
  out->rx_ts = selected->rx_ts;
  out->tx_ts = selected->tx_ts;
  out->rx_base = selected->rx_base;
  out->rx_bmp = selected->rx_bmp;
  out->srtt = selected->srtt;
  out->rttvar = selected->rttvar;
  out->rto = selected->rto;
  out->sm_m = selected->sm_m;
  out->r2d = selected->r2d;
  out->mtu = selected->mtu;
  out->mtu_lkg = selected->mtu_lkg;
  out->mtu_ukb = selected->mtu_ukb;
  out->peer_rev_mtu = selected->peer_rev_mtu;
  out->mtu_st = selected->mtu_st;
  out->mtu_ukb_soft = selected->mtu_ukb_soft;
  out->prb_i_ts = selected->prb_i_ts;
  out->prb_mtu = selected->prb_mtu;
  out->prb_id = selected->prb_id;
  out->prb_tx = selected->prb_tx;
  out->prb_tx_ts = selected->prb_tx_ts;
  out->prb_ddl = selected->prb_ddl;
  out->ack_ts = selected->ack_ts;
  out->vfy_ts = selected->vfy_ts;
  out->hld_ts = selected->hld_ts;
  out->prb_ts = selected->prb_ts;
  out->prb_tok = selected->prb_tok;
  return true;
}

void
rt_rtt_upd (Rt *t, const uint8_t peer_lla[16], const uint8_t ip[16],
            uint16_t port, uint32_t rtt_ms, uint64_t sys_ts)
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
      re_rtt_min_apply (&t->re_arr[i], rtt_ms, sys_ts);
      re_rx_note (&t->re_arr[i], sys_ts);
      (void)re_dir_activate (&t->re_arr[i], sys_ts);
      re_rto_upd (&t->re_arr[i], rtt_ms);
      {
        char lla_str[INET6_ADDRSTRLEN] = { 0 };
        char ip_str[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop (AF_INET6, peer_lla, lla_str, sizeof (lla_str));
        if (is_ip_v4m (ip))
          inet_ntop (AF_INET, ip + 12, ip_str, sizeof (ip_str));
        else
          inet_ntop (AF_INET6, ip, ip_str, sizeof (ip_str));
        /* fprintf (stderr,
                    "route: rtt update lla=%s ep=%s:%u rtt=%u sm=%u\n",
                    lla_str, ip_str, port, rtt_ms, t->re_arr[i].sm_m); */
      }
      rt_map_mark (t);
      return;
    }
}

bool
rt_ping_sample_upd (Rt *t, const uint8_t peer_lla[16], uint64_t prb_tok,
                    uint32_t rtt_ms, uint64_t sys_ts)
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
      re_rtt_min_apply (re, rtt_ms, sys_ts);
      re_rx_note (re, sys_ts);
      (void)re_dir_activate (re, sys_ts);
      re_rto_upd (re, rtt_ms);
      re->prb_tok = 0;
      re->prb_rx_cnt++;
      rt_map_mark (t);
      return true;
    }
  return false;
}

void
rt_ep_upd (Rt *t, const uint8_t lla[16], const uint8_t ip[16], uint16_t port,
           uint64_t sys_ts)
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
    {
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
              zero_idx = (int)i;
              break;
            }
        }
      if (zero_idx < 0)
        rt_zero_ep_rm (t, ip, port, false);
      rt_dir_ep_rm_same_ip (t, lla, ip, port);
    }
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
      {
        char lla_str[INET6_ADDRSTRLEN] = { 0 };
        char ip_str[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop (AF_INET6, lla, lla_str, sizeof (lla_str));
        if (is_ip_v4m (ip))
          inet_ntop (AF_INET, ip + 12, ip_str, sizeof (ip_str));
        else
          inet_ntop (AF_INET6, ip, ip_str, sizeof (ip_str));
        /* fprintf (stderr,
                    "route: ep refresh lla=%s ep=%s:%u state=%d rt_m=%u\n",
                    lla_str, ip_str, port, (int)t->re_arr[i].state,
                    t->re_arr[i].rt_m); */
      }
      bool was_act = t->re_arr[i].is_act;
      RtSt was_state = t->re_arr[i].state;
      bool was_zero = is_z16 (t->re_arr[i].lla);
      bool has_alt = rt_dir_has_other_ep (t, lla, ip, port);
      bool should_act = was_act && was_state == RT_ACT;
      if (!should_act && !has_alt)
        should_act = true;
      if (!is_zero_lla)
        {
          memcpy (t->re_arr[i].lla, lla, 16);
          if (should_act)
            (void)re_dir_activate (&t->re_arr[i], sys_ts);
          else
            {
              t->re_arr[i].is_act = false;
              t->re_arr[i].state = RT_PND;
              if (t->re_arr[i].pnd_ts == 0 || was_act || was_state != RT_PND)
                t->re_arr[i].pnd_ts = sys_ts;
            }
        }
      re_rx_note (&t->re_arr[i], sys_ts);
      memcpy (t->re_arr[i].nhop_lla, lla, 16);
      if (t->re_arr[i].mtu == 0)
        {
          if (!t->mtu_probe && t->re_arr[i].r2d == 0)
            t->re_arr[i].mtu = re_mtu_ub (t, &t->re_arr[i]);
          else
            t->re_arr[i].mtu = (t->re_arr[i].mtu_lkg > 0)
                                   ? t->re_arr[i].mtu_lkg
                                   : RT_MTU_DEF;
        }
      if (t->re_arr[i].mtu < RT_MTU_MIN)
        t->re_arr[i].mtu = RT_MTU_MIN;
      if (t->re_arr[i].mtu_lkg == 0)
        t->re_arr[i].mtu_lkg = t->re_arr[i].mtu;
      if (t->re_arr[i].mtu_ukb == 0)
        t->re_arr[i].mtu_ukb = rt_mtu_ub (t);
      re_mtu_sync (t, &t->re_arr[i]);
      if (t->re_arr[i].rt_m >= RT_M_INF)
        {
          t->re_arr[i].rt_m = re_dir_seed_m (&t->re_arr[i]);
        }
      rt_map_mark (t);
      if (!is_zero_lla && should_act && (was_zero || !was_act || was_state != RT_ACT))
        {
          rt_gsp_dirty_set (t, "ep_upd (direct active)");
        }
      return;
    }
  if (zero_idx >= 0)
    {
      Re *re = &t->re_arr[zero_idx];
      bool was_act = re->is_act;
      RtSt was_state = re->state;
      bool has_alt = rt_dir_has_other_ep (t, lla, ip, port);
      bool should_act = was_act && was_state == RT_ACT;
      if (!should_act && !has_alt)
        should_act = true;
      memcpy (re->lla, lla, 16);
      if (should_act)
        (void)re_dir_activate (re, sys_ts);
      else
        {
          re->is_act = false;
          re->state = RT_PND;
          if (re->pnd_ts == 0 || was_act || was_state != RT_PND)
            re->pnd_ts = sys_ts;
        }
      re_rx_note (re, sys_ts);
      memcpy (re->nhop_lla, lla, 16);
      if (re->mtu == 0)
        {
          if (!t->mtu_probe && re->r2d == 0)
            re->mtu = re_mtu_ub (t, re);
          else
            re->mtu = (re->mtu_lkg > 0) ? re->mtu_lkg : RT_MTU_DEF;
        }
      if (re->mtu < RT_MTU_MIN)
        re->mtu = RT_MTU_MIN;
      if (re->mtu_lkg == 0)
        re->mtu_lkg = re->mtu;
      if (re->mtu_ukb == 0)
        re->mtu_ukb = rt_mtu_ub (t);
      re_mtu_sync (t, re);
      if (re->rt_m >= RT_M_INF)
        re->rt_m = re_dir_seed_m (re);
      rt_map_mark (t);
      if (should_act && (!was_act || was_state != RT_ACT || !is_zero_lla))
        rt_gsp_dirty_set (t, "ep_upd (zero promote)");
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
      ne.is_act = !rt_dir_has_other_ep (t, lla, ip, port);
      ne.state = ne.is_act ? RT_ACT : RT_PND;
      ne.pnd_ts = sys_ts;
      ne.pong_ts = sys_ts;
      ne.rx_ts = sys_ts;
      ne.rx_base = sys_ts;
      ne.rx_bmp = 0x0001U;
      ne.rto = RTO_INIT;
      ne.sm_m = 0;
      ne.rt_m = re_dir_seed_m (&ne);
      ne.adv_m = ne.rt_m;
      ne.seq = 1;
      ne.mtu = re_mtu_boot (t, &ne);
      ne.mtu_lkg = ne.mtu;
      ne.mtu_ukb = (!t->mtu_probe) ? ne.mtu : rt_mtu_ub (t);
      ne.mtu_st = MTU_ST_B;
      ne.mtu_ukb_soft = false;
      ne.prb_i_ts = 0;
      re_mtu_sync (t, &ne);
      memcpy (ne.nhop_lla, lla, 16);
      {
        char lla_str[INET6_ADDRSTRLEN] = { 0 };
        char ip_str[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop (AF_INET6, lla, lla_str, sizeof (lla_str));
        if (is_ip_v4m (ip))
          inet_ntop (AF_INET, ip + 12, ip_str, sizeof (ip_str));
        else
          inet_ntop (AF_INET6, ip, ip_str, sizeof (ip_str));
        /* fprintf (stderr,
                    "route: ep create lla=%s ep=%s:%u state=%d rt_m=%u\n",
                    lla_str, ip_str, port, (int)ne.state, ne.rt_m); */
      }
      t->re_arr[t->cnt++] = ne;
      rt_map_mark (t);
      if (!is_zero_lla && ne.is_act)
        {
          rt_gsp_dirty_set (t, "ep_upd (direct new)");
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

  if (!hit || hit->r2d != 0 || !hit->is_act || hit->state != RT_ACT)
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
rt_gsp_dirty_set (Rt *t, const char *r)
{
  (void)r;
  if (t)
    t->gsp_dirty = true;
}

bool
rt_gsp_refresh_due (const Rt *t, uint64_t sys_ts)
{
  if (!t || t->gsp_dirty || t->gsp_last_ts == 0 || sys_ts <= t->gsp_last_ts)
    return false;
  return (sys_ts - t->gsp_last_ts) >= RT_UPD_INTV;
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

  Pth *b_dir_pth = re->sel_dir_pth;
  Pth *b_rel_pth = re->sel_rel_pth;
  bool dir_ok = (b_dir_pth != NULL && re->sel_dir_m < RT_M_INF);
  bool rel_ok = (b_rel_pth != NULL && re->sel_rel_m < RT_M_INF);

  if (!is_p2p)
    {
      if (dir_ok && b_dir_pth->is_static)
        {
          dec.type = RT_DIR;
          memcpy (dec.dir.ip, b_dir_pth->ep_ip, 16);
          dec.dir.port = b_dir_pth->ep_port;
          return dec;
        }
      if (rel_ok)
        {
          dec.type = RT_REL;
          memcpy (dec.rel.relay_ip, b_rel_pth->ep_ip, 16);
          dec.rel.relay_port = b_rel_pth->ep_port;
          memcpy (dec.rel.relay_lla, b_rel_pth->nhop_lla, 16);
          return dec;
        }
      dec.type = RT_VP;
      return dec;
    }

  if (dir_ok)
    {
      dec.type = RT_DIR;
      memcpy (dec.dir.ip, b_dir_pth->ep_ip, 16);
      dec.dir.port = b_dir_pth->ep_port;
      return dec;
    }
  if (re->has_pnd_dir && !rel_ok)
    {
      dec.type = RT_VP;
      return dec;
    }
  if (rel_ok)
    {
      dec.type = RT_REL;
      memcpy (dec.rel.relay_ip, b_rel_pth->ep_ip, 16);
      dec.rel.relay_port = b_rel_pth->ep_port;
      memcpy (dec.rel.relay_lla, b_rel_pth->nhop_lla, 16);
      return dec;
    }

  dec.type = RT_VP;
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
      if (!re->is_act || re->state == RT_DED)
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
rt_dir_mtu_get (const Rt *t, const Re *re)
{
  uint16_t mtu = re_mtu_cur (t, re);
  uint16_t peer_rev_mtu = rt_dir_peer_rev_cap (re);
  if (peer_rev_mtu > 0 && peer_rev_mtu < mtu)
    mtu = peer_rev_mtu;
  return mtu;
}

static void
rt_dir_part_lims (const Rt *t, const Re *re, uint16_t *out_lkg,
                  uint16_t *out_ukb, bool *out_is_searching)
{
  uint16_t cur = re_mtu_cur (t, re);
  uint16_t lkg = (re->mtu_lkg > 0) ? re->mtu_lkg : cur;
  uint16_t ukb = (re->mtu_ukb > 0) ? re->mtu_ukb : rt_mtu_ub (t);
  uint16_t peer_rev_mtu = rt_dir_peer_rev_cap (re);
  if (peer_rev_mtu > 0)
    {
      if (lkg > peer_rev_mtu)
        lkg = peer_rev_mtu;
      if (ukb > peer_rev_mtu)
        ukb = peer_rev_mtu;
    }
  if (ukb < lkg)
    ukb = lkg;
  if (out_lkg)
    *out_lkg = lkg;
  if (out_ukb)
    *out_ukb = ukb;
  if (out_is_searching)
    *out_is_searching = ukb > (uint16_t)(lkg + RT_MTU_EPS);
}

uint16_t
rt_mtu (const Rt *t, const RtDec *sel)
{
  if (!t || !sel)
    return RT_MTU_DEF;
  if (sel->type == RT_DIR)
    {
      const Re *match = rt_dir_match (t, sel);
      if (match)
        return rt_dir_mtu_get (t, match);
      return t->mtu_probe ? RT_MTU_DEF : RT_MTU_DEF;
    }
  if (sel->type == RT_REL)
    {
      uint16_t l2r_mtu = 0;
      uint16_t r2d_mtu = 0;
      for (uint32_t i = 0; i < t->cnt; i++)
        {
          const Re *re = &t->re_arr[i];
          if (!re->is_act || re->state == RT_DED)
            continue;
          if (memcmp (re->ep_ip, sel->rel.relay_ip, 16) != 0)
            continue;
          if (re->ep_port != sel->rel.relay_port)
            continue;
          uint16_t mtu = re->mtu;
          if (mtu == 0)
            continue;
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
  return RT_MTU_DEF;
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
      if (!re->is_act || re->state == RT_DED)
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
          re->mtu_ukb_soft = false;
          re->hld_ts = 0;
          re->vfy_ts = 0;
        }
      if (re->prb_mtu == 0)
        continue;
      if (sys_ts < re->prb_ddl)
        continue;
      if (re->prb_tx >= RT_PRB_BST)
        {
          bool kick_search = false;
          uint16_t fail_mtu = re->prb_mtu;
          if (fail_mtu > re->mtu_lkg && fail_mtu > RT_MTU_MIN
                   && (uint16_t)(fail_mtu - 1U) < re->mtu_ukb)
            {
              if (re->mtu_ukb_soft)
                {
                  re->mtu_ukb = (uint16_t)(fail_mtu - 1U);
                  if (re->mtu_ukb < re->mtu_lkg)
                    re->mtu_ukb = re->mtu_lkg;
                  if (re->mtu > re->mtu_lkg)
                    re->mtu = re->mtu_lkg;
                  re->vfy_ts = 0;
                }
              else
                {
                  kick_search = true;
                }
              re->mtu_st = MTU_ST_S;
              re->mtu_ukb_soft = true;
            }
          else
            {
              re->mtu_ukb_soft = false;
              re->mtu_st
                  = (re->mtu_ukb <= (uint16_t)(re->mtu_lkg + RT_MTU_EPS))
                        ? MTU_ST_F
                        : MTU_ST_S;
            }
          re->prb_mtu = 0;
          re->prb_id = 0;
          re->prb_tx = 0;
          re->prb_ddl = 0;
          re_mtu_sync (t, re);
          if (kick_search)
            re_mtu_search_kick (re);
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
      if (re->state != RT_ACT)
        continue;
      if (memcmp (re->lla, t->our_lla, 16) == 0)
        continue;
      re_mtu_sync (t, re);
      if (re->mtu_lkg > mtu_ub)
        re->mtu_lkg = mtu_ub;
      if (re->mtu_ukb < re->mtu_lkg)
        re->mtu_ukb = re->mtu_lkg;
      if (re->mtu_ukb > mtu_ub)
        re->mtu_ukb = mtu_ub;
      if (re->hld_ts != 0 && sys_ts < re->hld_ts)
        continue;
      if (re->prb_mtu != 0)
        {
          if (sys_ts < re->prb_tx_ts + 1000ULL)
            continue;
          if (re->prb_tx >= RT_PRB_BST)
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
      if (re->mtu_ukb <= (uint16_t)(re->mtu_lkg + RT_MTU_EPS))
        {
          if (re->vfy_ts == 0)
            re->vfy_ts = sys_ts;
          if (sys_ts >= re->vfy_ts && (sys_ts - re->vfy_ts) >= RT_MTU_VFY)
            {
              re->hld_ts
                  = sys_ts + (re->mtu_ukb_soft ? RT_PRB_INTV : RT_MTU_HLD);
              re->vfy_ts = 0;
              re->mtu_st = MTU_ST_F;
              continue;
            }
          probe_mtu = re->mtu_lkg;
        }
      else
        {
          re->vfy_ts = 0;
          if (re->mtu_st == MTU_ST_B && re->mtu_lkg < RT_MTU_DEF
              && re->mtu_ukb > RT_MTU_DEF)
            probe_mtu = RT_MTU_DEF;
          else
            probe_mtu = (uint16_t)((re->mtu_lkg + re->mtu_ukb) / 2U);
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
      uint16_t old_mtu = re->mtu;
      uint16_t mtu_ub = rt_mtu_ub (t);
      if (probe_mtu > mtu_ub)
        probe_mtu = mtu_ub;
      if (probe_mtu < RT_MTU_MIN)
        probe_mtu = RT_MTU_MIN;
      if (probe_mtu > re->mtu_lkg)
        re->mtu_lkg = probe_mtu;
      if (re->mtu_ukb < re->mtu_lkg)
        re->mtu_ukb = re->mtu_lkg;
      re->mtu = re->mtu_lkg;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re->ack_ts = sys_ts;
      re->mtu_ukb_soft = false;
      if (re->mtu_ukb <= (uint16_t)(re->mtu_lkg + RT_MTU_EPS))
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
          && re->mtu != old_mtu)
        {
          rt_gsp_dirty_set (t, "pmtu_ack (direct mtu)");
        }
      return;
    }
}

void
rt_pmtu_ptb_ep (Rt *t, const uint8_t ip[16], uint16_t port, uint16_t pmtu,
                uint64_t sys_ts)
{
  if (!t || !ip || pmtu == 0)
    return;
  if (!t->mtu_probe)
    return;
  uint16_t ub = rt_mtu_ub (t);
  if (pmtu < RT_MTU_MIN)
    pmtu = RT_MTU_MIN;
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
      uint16_t old_mtu = re->mtu;
      re->mtu_ukb = pmtu;
      if (re->mtu_lkg > pmtu)
        re->mtu_lkg = pmtu;
      re->mtu = re->mtu_lkg;
      re->mtu_st = MTU_ST_S;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re->ack_ts = sys_ts;
      re->mtu_ukb_soft = false;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
      re_mtu_search_kick (re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu != old_mtu)
        {
          rt_gsp_dirty_set (t, "pmtu_ptb (direct mtu)");
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
      uint16_t old_mtu = re->mtu;
      if (fail_ukb < RT_MTU_DEF)
        {
          re->mtu_lkg = RT_MTU_MIN;
          re->mtu = RT_MTU_MIN;
        }
      else
        {
          re->mtu_lkg = RT_MTU_DEF;
          re->mtu = RT_MTU_DEF;
        }
      re->mtu_ukb = fail_ukb;
      if (re->mtu_ukb < re->mtu_lkg)
        re->mtu_ukb = re->mtu_lkg;
      re->mtu_st = MTU_ST_B;
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re->prb_i_ts = sys_ts;
      re->prb_tx_ts = sys_ts;
      re->mtu_ukb_soft = false;
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
      re_mtu_search_kick (re);
      if (!is_z16 (re->lla) && memcmp (re->lla, t->our_lla, 16) != 0
          && re->mtu != old_mtu)
        {
          rt_gsp_dirty_set (t, "emsg_hnd (direct mtu)");
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
      {
        char lla_str[INET6_ADDRSTRLEN] = { 0 };
        char ip_str[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop (AF_INET6, re->lla, lla_str, sizeof (lla_str));
        if (is_ip_v4m (ip))
          inet_ntop (AF_INET, ip + 12, ip_str, sizeof (ip_str));
        else
          inet_ntop (AF_INET6, ip, ip_str, sizeof (ip_str));
        /* fprintf (stderr,
                    "route: unreachable -> pending lla=%s ep=%s:%u "
                    "old_state=%d old_rt_m=%u\n",
                    lla_str, ip_str, port, (int)re->state, re->rt_m); */
      }
      if (re->r2d == 0)
        {
          if (re_is_recent (re, sys_ts))
            {
              re->tx_ts = sys_ts;
              continue;
            }
          if (re->is_act && re->state == RT_ACT && re->rx_ts > 0
              && sys_ts > re->rx_ts && (sys_ts - re->rx_ts) <= KA_TMO)
            {
              re->tx_ts = sys_ts;
              continue;
            }
        }
      re->is_act = false;
      re->state = RT_PND;
      re->rt_m = RT_M_INF;
      re->sm_m = RT_M_INF;
      re_metric_win_clear (re);
      re->tx_ts = sys_ts;
      is_mod = true;
    }
  if (is_mod)
    rt_map_mark (t);
}

bool
rt_pmtu_st (const Rt *t, const RtDec *sel, uint16_t *out_path_mtu,
            uint16_t *prb_mtu, bool *out_is_searching, bool *out_is_fixed)
{
  if (!t || !sel)
    return false;
  const Re *match = rt_dir_match (t, sel);
  if (!match)
    {
      if (out_path_mtu)
        *out_path_mtu = rt_mtu (t, sel);
      if (prb_mtu)
        *prb_mtu = 0;
      if (out_is_searching)
        *out_is_searching = false;
      if (out_is_fixed)
        *out_is_fixed = true;
      return false;
    }
  uint16_t mtu = re_mtu_cur (t, match);
  bool is_srch = false;
  mtu = rt_dir_mtu_get (t, match);
  rt_dir_part_lims (t, match, NULL, NULL, &is_srch);
  bool is_fix = !is_srch;
  if (out_path_mtu)
    *out_path_mtu = mtu;
  if (prb_mtu)
    *prb_mtu = match->prb_mtu;
  if (out_is_searching)
    *out_is_searching = is_srch;
  if (out_is_fixed)
    *out_is_fixed = is_fix;
  return true;
}

bool
rt_pmtu_lims (const Rt *t, const RtDec *sel, uint16_t *out_lkg,
              uint16_t *out_ukb, MtuSt *state)
{
  if (!t || !sel)
    return false;
  if (sel->type != RT_DIR)
    {
      if (out_lkg)
        *out_lkg = rt_mtu (t, sel);
      if (out_ukb)
        *out_ukb = rt_mtu (t, sel);
      if (state)
        *state = MTU_ST_F;
      return false;
    }
  const Re *match = rt_dir_match (t, sel);
  if (match)
    {
      uint16_t lkg = 0;
      uint16_t ukb = 0;
      bool is_srch = false;
      rt_dir_part_lims (t, match, &lkg, &ukb, &is_srch);
      if (out_lkg)
        *out_lkg = lkg;
      if (out_ukb)
        *out_ukb = ukb;
      if (state)
        *state = is_srch ? MTU_ST_S : MTU_ST_F;
      return true;
    }
  if (out_lkg)
    *out_lkg = rt_mtu (t, sel);
  if (out_ukb)
    *out_ukb = rt_mtu (t, sel);
  if (state)
    *state = MTU_ST_B;
  return false;
}

int
rt_act_get (Rt *t, Re *buf, int buf_len, int s_off)
{
  int act_cnt = 0;
  for (uint32_t scan_idx = 0; scan_idx < t->cnt && act_cnt < buf_len;
       scan_idx++)
    {
      uint32_t re_idx = ((uint32_t)s_off + scan_idx) % t->cnt;
      if (t->re_arr[re_idx].is_act)
        buf[act_cnt++] = t->re_arr[re_idx];
    }
  return act_cnt;
}

void
rt_prn_st (Rt *t, uint64_t sys_ts)
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
      re_map_dcy (re, sys_ts);
      if (!is_rel && re_metric_refresh (re, sys_ts))
        is_mod = true;
      if (sys_ts > re->rx_ts)
        {
          uint64_t age = sys_ts - re->rx_ts;
          if (age > stl_ts && re->rx_bmp == 0)
            {
              if (re->is_act || re->state != RT_DED)
                {
                  char lla_str[64];
                  inet_ntop (AF_INET6, re->lla, lla_str, sizeof (lla_str));
                  printf ("prn_st: node %s DIED (age=%llu ms, state=%d)\n",
                          lla_str, (unsigned long long)age, (int)re->state);
                  if (rt_dir_is_sel (t, re))
                    any_ded = true;
                  re->is_act = false;
                  re->state = RT_DED;
                  re->rt_m = RT_M_INF;
                  re->sm_m = RT_M_INF;
                  re_metric_win_clear (re);
                  is_mod = true;
                }
              else
                {
                  re->state = RT_DED;
                  re->rt_m = RT_M_INF;
                  re->sm_m = RT_M_INF;
                  re_metric_win_clear (re);
                }
            }
          if (!re->is_static)
            {
              if (age > ded_ts && re->rx_bmp == 0)
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
    rt_gsp_dirty_set (t, "prn_st (node ded)");
}

void
rt_src_gc (Rt *t, uint64_t sys_ts)
{
  uint32_t wr_idx = 0;
  for (uint32_t rd_idx = 0; rd_idx < t->src_cnt; rd_idx++)
    {
      SrcEnt *se = &t->sources[rd_idx];
      if (sys_ts > se->gc_ts && (sys_ts - se->gc_ts) > 180000ULL)
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
      if (!best || (re->is_act && !best->is_act)
          || (re->is_act == best->is_act && seen > best_ts))
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

bool
rt_fsb (Rt *t, const uint8_t rt_id[16], uint32_t n_seq, uint32_t n_metric,
        uint64_t n_ver, bool *req_seq)
{
  if (req_seq)
    *req_seq = false;
  SrcEnt *se = src_fnd (t, rt_id);
  if (!se)
    return true;
  if (n_ver > 0 && se->last_ver > 0 && n_ver < se->last_ver)
    {
      return true;
    }
  if (seq_gt (n_seq, se->fwd_seq))
    return true;
  if (n_seq == se->fwd_seq && n_metric < se->fwd_m)
    return true;
  if (seq_lt (n_seq, se->fwd_seq) && req_seq)
    *req_seq = true;
  return false;
}

void
rt_src_upd (Rt *t, const uint8_t rt_id[16], uint32_t seq, uint32_t metric,
            uint64_t ver, bool no_dir, uint64_t sys_ts)
{
  SrcEnt *se = src_fnd (t, rt_id);
  if (!se)
    {
      if (!src_cap_chk (t, 1))
        return;
      se = &t->sources[t->src_cnt++];
      memset (se, 0, sizeof (*se));
      memcpy (se->rt_id, rt_id, 16);
      se->fwd_seq = seq;
      se->fwd_m = metric;
      se->last_ver = ver;
      se->no_dir = no_dir;
      se->gc_ts = sys_ts;
      return;
    }
  if (ver > 0 && se->last_ver > 0 && ver < se->last_ver)
    {
      se->fwd_seq = seq;
      se->fwd_m = metric;
    }
  else if (seq_gt (seq, se->fwd_seq)
           || (seq == se->fwd_seq && metric < se->fwd_m))
    {
      se->fwd_seq = seq;
      se->fwd_m = metric;
    }
  if (ver > 0)
    se->last_ver = ver;
  se->no_dir = no_dir;
  se->gc_ts = sys_ts;
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
  {
    char lla_str[INET6_ADDRSTRLEN] = { 0 };
    inet_ntop (AF_INET6, rt_id, lla_str, sizeof (lla_str));
    /* fprintf (stderr,
                "route: peer session reset lla=%s new_sid=%016llx\n",
                lla_str, (unsigned long long)peer_sid); */
  }
  for (uint32_t re_idx = 0; re_idx < t->cnt; re_idx++)
    {
      Re *re = &t->re_arr[re_idx];
      if (memcmp (re->lla, rt_id, 16) != 0)
        continue;
      re->sid = peer_sid;
      re->seq = 1;
      re->adv_m = RT_M_INF;
      re->rt_m = (re->r2d == 0) ? RT_M_INF : re->rt_m;
      if (re->r2d == 0)
        {
          re->is_act = false;
          re->state = RT_PND;
        }
      re->pong_ts = sys_ts;
    }
  SrcEnt *se = src_fnd (t, rt_id);
  if (se)
    {
      se->fwd_seq = 0;
      se->fwd_m = RT_M_INF;
      se->last_ver = 0;
      se->no_dir = false;
      se->gc_ts = sys_ts;
    }
  rt_map_mark (t);
  return true;
}
