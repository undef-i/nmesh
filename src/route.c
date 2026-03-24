#include "route.h"
#include "utils.h"
#include "packet.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define RT_HL_INTV 10000ULL
#define RT_STL_HL 6ULL
#define RT_DED_HL 30ULL
#define RT_GHS_HL 30ULL
#define RT_UPD_INTV (RT_HL_INTV * 4ULL)
#define RT_REL_STL (RT_UPD_INTV * 3ULL)
#define RT_REL_DED (RT_UPD_INTV * 6ULL)
#define RT_STL_TS (RT_HL_INTV * RT_STL_HL)
#define RT_DED_TS (RT_HL_INTV * RT_DED_HL)
#define RT_GHS_TS (RT_HL_INTV * RT_GHS_HL)
#define RT_LIV_TK 4000ULL
#define RT_LIV_B 16U
#define RT_PRB_INTV 5000ULL
#define RT_PRB_TMO 2000ULL
#define RT_MTU_VFY 10000ULL
#define RT_MTU_HLD 600000ULL
#define RT_MTU_EPS 10U
#define RT_PRB_BST 3U

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



static void
re_mtu_sync (Rt *t, Re *re)
{
  if (!t || !re)
    return;
  uint16_t upper = rt_mtu_ub (t);
  if (re->mtu == 0)
    re->mtu = RT_MTU_DEF;
  if (re->mtu < RT_MTU_MIN)
    re->mtu = RT_MTU_MIN;
  if (re->mtu > upper)
    re->mtu = upper;
  if (re->mtu_lkg == 0)
    re->mtu_lkg = re->mtu;
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
re_rx_ack (Re *re, uint64_t sys_ts)
{
  re_map_dcy (re, sys_ts);
  re->rx_bmp |= 0x0001U;
  re->rx_ts = sys_ts;
  re->pong_ts = sys_ts;
  re->is_act = true;
  re->state = RT_ACT;
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
  pth->pong_ts = re->pong_ts;
  pth->rx_ts = re->rx_ts;
  pth->tx_ts = re->tx_ts;
  pth->rx_base = re->rx_base;
  pth->rx_bmp = re->rx_bmp;
  pth->srtt = re->srtt;
  pth->rttvar = re->rttvar;
  pth->rto = re->rto;
  pth->sm_m = re->sm_m;
  pth->lat = re->lat;
  pth->r2d = re->r2d;
  pth->mtu = re->mtu;
  pth->mtu_lkg = re->mtu_lkg;
  pth->mtu_ukb = re->mtu_ukb;
  pth->mtu_st = re->mtu_st;
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
}

static void
rt_map_rbd (Rt *t)
{
  t->map_dirty = false;
  RtMap *n_map = NULL;

  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
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

      if (pth->r2d == 0 && pth->is_act && pth->state != RT_DED)
        {
          uint32_t m = pth_m (pth);
          if (!rtm->sel_dir_pth || m < rtm->sel_dir_m)
            {
              rtm->sel_dir_pth = pth;
              rtm->sel_dir_m = m;
            }
        }
    }

  RtMap *rtm, *tmp;
  HASH_ITER (hh, n_map, rtm, tmp)
  {
    for (Pth *p = rtm->paths; p; p = p->next)
      {
        if (!p->is_act || p->state == RT_DED)
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

static bool
rt_gsp_affects_dir (Rt *t, const Re *re)
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

void
pp_init (PPool *p, const char *persist_path)
{
  memset (p, 0, sizeof (*p));
  p->persist_path = persist_path;
}

void
pp_add (PPool *p, const uint8_t ip[16], uint16_t port)
{
  for (int peer_idx = 0; peer_idx < p->cnt; peer_idx++)
    {
      if (memcmp (p->re_arr[peer_idx].ip, ip, 16) == 0
          && p->re_arr[peer_idx].port == port)
        return;
    }
  if (p->cnt >= PEER_MAX)
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
}

void
rt_pmtu_ub_set (Rt *t, uint16_t mtu)
{
  if (!t)
    return;
  if (mtu < RT_MTU_MIN)
    mtu = RT_MTU_MIN;
  t->mtu_ub = mtu;
}

void
rt_upd (Rt *t, const Re *re, uint64_t sys_ts)
{
  bool is_zero = is_z16 (re->lla);
  if (!is_zero && !IS_LLA_VAL (re->lla))
    return;
  if (!is_zero && memcmp (re->lla, t->our_lla, 16) == 0)
    {
      bool is_loc_inj = (re->r2d == 0)
                        && (re->rt_m == 0 || re->adv_m == 0 || re->is_static);
      if (!is_loc_inj)
        return;
    }
  bool is_rel = (re->r2d > 0);
  if (!is_zero && !is_rel)
    {
      rt_zero_ep_rm (t, re->ep_ip, re->ep_port, false);
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
      if (re->is_act)
        cur_re->is_act = true;
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
      else if (re->state == RT_ACT || re->is_act)
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
        cur_re->mtu = RT_MTU_DEF;
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
          else if (ne.lat < RTT_UNK)
            ne.rt_m = ne.lat;
          else
            ne.rt_m = RT_M_INF;
        }
      if (ne.adv_m == 0)
        ne.adv_m = ne.rt_m;
      if (ne.mtu == 0)
        ne.mtu = RT_MTU_DEF;
      if (ne.mtu < RT_MTU_MIN)
        ne.mtu = RT_MTU_MIN;
      if (ne.mtu_lkg == 0)
        ne.mtu_lkg = ne.mtu;
      if (ne.mtu_ukb == 0)
        ne.mtu_ukb = rt_mtu_ub (t);
      ne.prb_i_ts = 0;
      ne.mtu_st = MTU_ST_B;
      re_mtu_sync (t, &ne);
      if (ne.state == 0 && !ne.is_act)
        ne.state = RT_PND;
      if (ne.is_act)
        ne.state = RT_ACT;
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
  out->pong_ts = selected->pong_ts;
  out->rx_ts = selected->rx_ts;
  out->tx_ts = selected->tx_ts;
  out->rx_base = selected->rx_base;
  out->rx_bmp = selected->rx_bmp;
  out->srtt = selected->srtt;
  out->rttvar = selected->rttvar;
  out->rto = selected->rto;
  out->sm_m = selected->sm_m;
  out->lat = selected->lat;
  out->r2d = selected->r2d;
  out->mtu = selected->mtu;
  out->mtu_lkg = selected->mtu_lkg;
  out->mtu_ukb = selected->mtu_ukb;
  out->mtu_st = selected->mtu_st;
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
      t->re_arr[i].lat = rtt_ms;
      re_rx_ack (&t->re_arr[i], sys_ts);
      re_rto_upd (&t->re_arr[i], rtt_ms);
      if (t->re_arr[i].sm_m == 0 || t->re_arr[i].sm_m >= RT_M_INF)
        {
          t->re_arr[i].sm_m = rtt_ms;
        }
      else
        {
          t->re_arr[i].sm_m = (t->re_arr[i].sm_m * 7U + rtt_ms) / 8U;
          if (t->re_arr[i].sm_m == 0)
            t->re_arr[i].sm_m = 1;
        }
      t->re_arr[i].rt_m = t->re_arr[i].sm_m;
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

void
rt_ep_upd (Rt *t, const uint8_t lla[16], const uint8_t ip[16], uint16_t port,
           uint64_t sys_ts)
{
  static const uint8_t z_lla[16] = { 0 };
  bool is_z16 = (memcmp (lla, z_lla, 16) == 0);
  if (!is_z16 && !IS_LLA_VAL (lla))
    return;
  if (!is_z16 && memcmp (lla, t->our_lla, 16) == 0)
    return;
  if (!is_z16)
    {
      rt_zero_ep_rm (t, ip, port, false);
    }
  if (is_z16)
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
      re_rx_ack (&t->re_arr[i], sys_ts);
      memcpy (t->re_arr[i].nhop_lla, lla, 16);
      if (t->re_arr[i].mtu == 0)
        t->re_arr[i].mtu = RT_MTU_DEF;
      if (t->re_arr[i].mtu < RT_MTU_MIN)
        t->re_arr[i].mtu = RT_MTU_MIN;
      if (t->re_arr[i].mtu_lkg == 0)
        t->re_arr[i].mtu_lkg = t->re_arr[i].mtu;
      if (t->re_arr[i].mtu_ukb == 0)
        t->re_arr[i].mtu_ukb = rt_mtu_ub (t);
      re_mtu_sync (t, &t->re_arr[i]);
      if (t->re_arr[i].rt_m >= RT_M_INF)
        {
          t->re_arr[i].rt_m
              = (t->re_arr[i].sm_m > 0 && t->re_arr[i].sm_m != RTT_UNK
                 && t->re_arr[i].sm_m < RT_M_INF)
                    ? t->re_arr[i].sm_m
                    : RT_M_INF;
        }
      rt_map_mark (t);
      return;
    }
  if (rt_cap_chk (t, 1))
    {
      Re ne;
      memset (&ne, 0, sizeof (ne));
      memcpy (ne.lla, lla, 16);
      memcpy (ne.ep_ip, ip, 16);
      ne.ep_port = port;
      ne.lat = RTT_UNK;
      ne.r2d = 0;
      ne.is_act = true;
      ne.state = RT_ACT;
      ne.pong_ts = sys_ts;
      ne.rx_ts = sys_ts;
      ne.rx_base = sys_ts;
      ne.rx_bmp = 0x0001U;
      ne.rto = RTO_INIT;
      ne.sm_m = 0;
      ne.rt_m = RT_M_INF;
      ne.adv_m = RT_M_INF;
      ne.seq = 1;
      ne.mtu = RT_MTU_DEF;
      ne.mtu_lkg = RT_MTU_DEF;
      ne.mtu_ukb = rt_mtu_ub (t);
      ne.mtu_st = MTU_ST_B;
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
      if (!is_z16)
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
  bool is_mod = false;
  for (uint32_t i = 0; i < t->cnt; i++)
    {
      Re *re = &t->re_arr[i];
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      if (!re->is_act || re->state != RT_ACT)
        {
          if (rt_gsp_affects_dir (t, re))
            is_mod = true;
        }
      re_rx_ack (re, sys_ts);
    }
  if (is_mod)
    {
      rt_map_mark (t);
      rt_gsp_dirty_set (t, "rx_ack (state mod)");
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
void
rt_gsp_dirty_set (Rt *t, const char *r)
{
  (void)r;
  if (t)
    t->gsp_dirty = true;
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
  if (!is_p2p)
    {
      dec.type = RT_VP;
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

  if (dir_ok && rel_ok)
    {
      if (re->sel_dir_m <= re->sel_rel_m)
        {
          dec.type = RT_DIR;
          memcpy (dec.dir.ip, b_dir_pth->ep_ip, 16);
          dec.dir.port = b_dir_pth->ep_port;
        }
      else
        {
          dec.type = RT_REL;
          memcpy (dec.rel.relay_ip, b_rel_pth->ep_ip, 16);
          dec.rel.relay_port = b_rel_pth->ep_port;
          memcpy (dec.rel.relay_lla, b_rel_pth->nhop_lla, 16);
        }
      return dec;
    }
  if (re->has_pnd_dir && !rel_ok)
    {
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

uint16_t
rt_mtu (const Rt *t, const RtDec *sel)
{
  if (!t || !sel)
    return RT_MTU_DEF;
  if (sel->type == RT_DIR)
    {
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
          return (re->mtu > 0) ? re->mtu : RT_MTU_DEF;
        }
      return RT_MTU_DEF;
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
rt_mtu_tk (Rt *t, uint64_t sys_ts)
{
  if (!t)
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
          re->hld_ts = 0;
          re->vfy_ts = 0;
        }
      if (re->prb_mtu == 0)
        continue;
      if (sys_ts < re->prb_ddl)
        continue;
      bool has_pong = (re->pong_ts >= re->prb_tx_ts)
                      && ((re->pong_ts - re->prb_tx_ts) <= RT_PRB_TMO);
      if (!has_pong)
        {
          re->prb_mtu = 0;
          re->prb_id = 0;
          re->prb_tx = 0;
          re->prb_ddl = 0;
          re_mtu_sync (t, re);
          continue;
        }
      if (re->prb_tx >= 2)
        {
          uint16_t fail_mtu = re->prb_mtu;
          if (fail_mtu <= re->mtu_lkg)
            {
              re->mtu_ukb = fail_mtu;
              re->mtu_lkg = RT_MTU_MIN;
              re->mtu = RT_MTU_MIN;
            }
          else if (fail_mtu > RT_MTU_MIN
                   && (uint16_t)(fail_mtu - 1U) < re->mtu_ukb)
            {
              re->mtu_ukb = (uint16_t)(fail_mtu - 1U);
            }
          if (re->mtu_ukb < re->mtu_lkg)
            re->mtu_ukb = re->mtu_lkg;
          if (re->mtu > re->mtu_lkg)
            re->mtu = re->mtu_lkg;
          re->vfy_ts = 0;
          re->mtu_st = MTU_ST_S;
        }
      else
        {
          re->prb_tx++;
          re->prb_tx_ts = sys_ts;
          re->prb_ddl = sys_ts + RT_PRB_TMO;
          continue;
        }
      re->prb_mtu = 0;
      re->prb_id = 0;
      re->prb_tx = 0;
      re->prb_ddl = 0;
      re_mtu_sync (t, re);
    }
}

bool
rt_mprb_rdy (Rt *t, uint64_t sys_ts, Re *out_re, uint16_t *prb_mtu,
             uint32_t *prb_id)
{
  if (!t || !out_re || !prb_mtu || !prb_id)
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
          re->prb_tx++;
          re->prb_tx_ts = sys_ts;
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
              re->hld_ts = sys_ts + RT_MTU_HLD;
              re->vfy_ts = 0;
              re->mtu_st = MTU_ST_F;
              continue;
            }
          probe_mtu = re->mtu_lkg;
        }
      else
        {
          re->vfy_ts = 0;
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
      return;
    }
}

void
rt_pmtu_ptb_ep (Rt *t, const uint8_t ip[16], uint16_t port, uint16_t pmtu,
                uint64_t sys_ts)
{
  if (!t || !ip || pmtu == 0)
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
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
    }
}

void
rt_emsg_hnd (Rt *t, const uint8_t ip[16], uint16_t port, size_t atmpt_plen,
             uint64_t sys_ts)
{
  if (!t || !ip)
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
      re->vfy_ts = 0;
      re->hld_ts = 0;
      re_mtu_sync (t, re);
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
      re->is_act = false;
      re->state = RT_PND;
      re->rt_m = RT_M_INF;
      re->sm_m = RT_M_INF;
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
  const Re *match = NULL;
  if (sel->type == RT_DIR)
    {
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
          match = re;
          break;
        }
    }
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
  uint16_t mtu = (match->mtu > 0) ? match->mtu : RT_MTU_DEF;
  bool is_srch = (match->prb_mtu != 0)
                 || (match->mtu_ukb > (uint16_t)(match->mtu_lkg + RT_MTU_EPS));
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
      if (out_lkg)
        *out_lkg = (re->mtu_lkg > 0) ? re->mtu_lkg : RT_MTU_DEF;
      if (out_ukb)
        *out_ukb = (re->mtu_ukb > 0) ? re->mtu_ukb : rt_mtu_ub (t);
      if (state)
        *state = re->mtu_st;
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
  uint32_t wr_idx = 0;
  bool any_ded = false;
  rt_map_ens (t);
  for (uint32_t rd_idx = 0; rd_idx < t->cnt; rd_idx++)
    {
      Re *re = &t->re_arr[rd_idx];
      bool is_rel = (re->r2d != 0);
      uint64_t stl_ts = is_rel ? RT_REL_STL : RT_STL_TS;
      uint64_t ded_ts = is_rel ? RT_REL_DED : RT_DED_TS;
      re_map_dcy (re, sys_ts);
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
                  if (rt_gsp_affects_dir (t, re))
                    any_ded = true;
                  re->is_act = false;
                  re->state = RT_DED;
                  re->rt_m = RT_M_INF;
                }
              else
                {
                  re->state = RT_DED;
                  re->rt_m = RT_M_INF;
                }
            }
          if (!re->is_static)
            {
              if (age > ded_ts && re->rx_bmp == 0)
                continue;
              if (!is_rel && re->lat == RTT_UNK && age > RT_GHS_TS)
                continue;
            }
        }
      t->re_arr[wr_idx++] = *re;
    }
  t->cnt = wr_idx;
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
            uint64_t ver, uint64_t sys_ts)
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
  se->gc_ts = sys_ts;
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
      se->gc_ts = sys_ts;
    }
  rt_map_mark (t);
  return true;
}
