#include "adm.h"
#include "adv.h"
#include "nbr.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

static Adm g_adm;
static bool g_adm_init = false;

Adm *
adm_glob (void)
{
  if (!g_adm_init)
    {
      adm_init (&g_adm);
      g_adm_init = true;
    }
  return &g_adm;
}

void
adm_init (Adm *a)
{
  memset (a, 0, sizeof (*a));
  pthread_mutex_init (&a->mtx, NULL);
}

void
adm_lock (Adm *a)
{
  pthread_mutex_lock (&a->mtx);
}

void
adm_unlock (Adm *a)
{
  pthread_mutex_unlock (&a->mtx);
}

static bool
ep_eq (const uint8_t ip1[16], uint16_t p1, const uint8_t ip2[16], uint16_t p2)
{
  return p1 == p2 && memcmp (ip1, ip2, 16) == 0;
}

static bool
adm_ep_static (Rt *rt, const uint8_t ip[16], uint16_t port)
{
  if (!rt || !ip || port == 0)
    return false;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (re->r2d != 0 || !re->is_static)
        continue;
      if (re->ep_port == port && memcmp (re->ep_ip, ip, 16) == 0)
        return true;
    }
  return false;
}

AdmEnt *
adm_fnd (Adm *a, const uint8_t lla[16])
{
  if (!a || !lla)
    return NULL;
  for (uint32_t i = 0; i < a->cnt; i++)
    if (memcmp (a->arr[i].lla, lla, 16) == 0)
      return &a->arr[i];
  return NULL;
}

AdmEnt *
adm_get (Adm *a, const Cfg *cfg, const uint8_t lla[16])
{
  AdmEnt *e = adm_fnd (a, lla);
  if (e)
    return e;
  if (a->cnt == a->cap)
    {
      uint32_t ncap = a->cap ? a->cap * 2 : 16;
      AdmEnt *na = realloc (a->arr, (size_t)ncap * sizeof (AdmEnt));
      if (!na)
        return NULL;
      a->arr = na;
      a->cap = ncap;
    }
  e = &a->arr[a->cnt++];
  memset (e, 0, sizeof (*e));
  memcpy (e->lla, lla, 16);
  e->st = ADM_UNKNOWN;
  e->chal_buck = 0;
  if (cfg)
    e->p2p_ok = cfg->p2p;
  return e;
}

const char *
adm_st_name (AdmSt st)
{
  switch (st)
    {
    case ADM_PROBING:
      return "probing";
    case ADM_ADMITTED:
      return "admitted";
    case ADM_SUSPECT:
      return "suspect";
    case ADM_DEAD:
      return "dead";
    default:
      return "unknown";
    }
}

static void
adm_pub (Rt *rt, AdmEnt *e, uint8_t tp_mask, uint64_t ts)
{
  if (!rt || !e || !e->ep_ok)
    return;
  rt_ep_upd (rt, e->lla, e->ep_ip, e->ep_port, tp_mask, ts);
}

static void
adm_restart (Adm *a, Cry *cry, Rt *rt, Adv *adv, AdmEnt *e, uint64_t new_sid,
             uint64_t ts)
{
  (void)a;
  e->st = ADM_PROBING;
  if (e->ep_ok)
    {
      memcpy (e->cand_ip, e->ep_ip, 16);
      e->cand_port = e->ep_port;
      e->cand_ok = true;
    }
  e->kx_cur = false;
  e->chal_ok = false;
  e->ckie_in_ok = false;
  if (cry)
    cry_peer_drop (cry, e->lla);
  if (rt)
    rt_adm_sess (rt, e->lla, new_sid, ts);
  if (adv)
    adv_ses_drop (adv, e->lla);
  e->sid = new_sid;
  e->sid_ok = true;
  e->ts_adm = 0;
  e->ts_pong = 0;
}

static void
adm_admit (Adm *a, Cry *cry, Rt *rt, const Cfg *cfg, AdmEnt *e,
           const uint8_t ip[16], uint16_t port, uint64_t sid,
           const uint8_t *kx, bool is_pong, bool from_tcp, uint64_t ts)
{
  (void)a;
  (void)cfg;
  bool ep_switch = !e->ep_ok || !ep_eq (e->ep_ip, e->ep_port, ip, port);
  if (e->st == ADM_ADMITTED && ep_switch)
    e->ep_sw++;
  memcpy (e->ep_ip, ip, 16);
  e->ep_port = port;
  e->ep_ok = true;
  e->cand_ok = false;
  e->st = ADM_ADMITTED;
  if (sid != 0)
    {
      e->sid = sid;
      e->sid_ok = true;
    }
  if (kx && !from_tcp && cry)
    {
      if (cry_peer_rekey (cry, cfg->addr, e->lla, kx))
        e->kx_cur = true;
    }
  e->chal_ok = false;
  e->ts_adm = ts;
  e->ts_seen = ts;
  if (is_pong)
    e->ts_pong = ts;
  adm_pub (rt, e, from_tcp ? TP_MASK_TCP : TP_MASK_UDP, ts);
}

static void
adm_chal_issue (Adm *a, Cry *cry, AdmEnt *e, const uint8_t ip[16],
                uint16_t port, AdjOut *out)
{
  uint64_t bucket = wall_ts () / IBS_TS_SKEW_MAX;
  if (e)
    {
      if (e->chal_ok && e->chal_buck == bucket)
        {
          out->res = ADJ_CHAL;
          ibs_ckie_calc (cry->ibs_ckie_key, e->lla, ip, port, bucket,
                         out->ckie_pl);
          return;
        }
      e->chal_ok = true;
      e->chal_buck = bucket;
      e->chal_cnt++;
    }
  else
    a->chal_oth++;
  out->res = ADJ_CHAL;
  ibs_ckie_calc (cry->ibs_ckie_key, e ? e->lla : out->lla, ip, port, bucket,
                 out->ckie_pl);
}

static void
adm_seed_i (Adm *a, Rt *rt, const Cfg *cfg, PPool *pool)
{
  if (!a || !rt || !cfg)
    return;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (re->r2d != 0 || re->ep_port == 0)
        continue;
      if (memcmp (re->lla, cfg->addr, 16) == 0)
        continue;
      if (!IS_LLA_VAL (re->lla))
        continue;
      AdmEnt *e = adm_get (a, cfg, re->lla);
      if (!e)
        continue;
      e->is_static = e->is_static || re->is_static;
      memcpy (e->seed_ip, re->ep_ip, 16);
      e->seed_port = re->ep_port;
      if (e->st == ADM_UNKNOWN)
        {
          e->st = ADM_PROBING;
          memcpy (e->cand_ip, re->ep_ip, 16);
          e->cand_port = re->ep_port;
          e->cand_ok = true;
        }
    }
  if (pool)
    {
      for (int i = 0; i < pool->cnt; i++)
        {
          bool known = false;
          for (uint32_t j = 0; j < a->cnt; j++)
            if (a->arr[j].cand_ok
                && ep_eq (a->arr[j].cand_ip, a->arr[j].cand_port,
                          pool->re_arr[i].ip, pool->re_arr[i].port))
              known = true;
          (void)known;
        }
    }
}

void
adm_seed (Adm *a, Rt *rt, const Cfg *cfg, PPool *pool)
{
  adm_lock (a);
  adm_seed_i (a, rt, cfg, pool);
  adm_unlock (a);
}

static void
adm_evidence_i (Adm *a, const Cfg *cfg, const uint8_t lla[16],
                const uint8_t ip[16], uint16_t port)
{
  if (!a || !lla || !IS_LLA_VAL (lla) || port == 0)
    return;
  AdmEnt *e = adm_get (a, cfg, lla);
  if (!e)
    return;
  if (e->st == ADM_ADMITTED || e->st == ADM_SUSPECT)
    return;
  memcpy (e->cand_ip, ip, 16);
  e->cand_port = port;
  e->cand_ok = true;
  if (e->st == ADM_UNKNOWN || e->st == ADM_DEAD)
    e->st = ADM_PROBING;
}

void
adm_evidence (Adm *a, const Cfg *cfg, const uint8_t lla[16],
              const uint8_t ip[16], uint16_t port)
{
  adm_lock (a);
  adm_evidence_i (a, cfg, lla, ip, port);
  adm_unlock (a);
}

uint64_t
adm_tok_next (AdmEnt *e, uint64_t sys_ts, uint64_t wall_ts_v)
{
  bool reuse = e->tok_cur != 0 && e->tok_ts != 0 && sys_ts >= e->tok_ts
               && (sys_ts - e->tok_ts) < RT_PRB_TMO;
  if (reuse)
    return e->tok_cur;
  uint64_t t = (((uint64_t)u32_rnd () << 32) | (uint64_t)u32_rnd ());
  if (e->tok_cur != 0)
    e->tok_prv = e->tok_cur;
  e->tok_cur = t;
  e->tok_ts = sys_ts;
  e->tok_wts = wall_ts_v;
  return t;
}

static void
adm_on_ckie_i (Adm *a, const uint8_t src_ip[16], uint16_t src_port,
               const uint8_t *pl, size_t pl_len)
{
  if (!a || !pl || pl_len < IBS_CKIE_PL_SZ)
    return;
  for (uint32_t i = 0; i < a->cnt; i++)
    {
      AdmEnt *e = &a->arr[i];
      bool hit = (e->ep_ok
                  && ep_eq (e->ep_ip, e->ep_port, src_ip, src_port))
                 || (e->cand_ok
                     && ep_eq (e->cand_ip, e->cand_port, src_ip, src_port))
                 || (e->seed_port != 0
                     && ep_eq (e->seed_ip, e->seed_port, src_ip, src_port));
      if (!hit)
        continue;
      memcpy (e->ckie_in, pl, IBS_CKIE_SZ);
      e->ckie_in_ok = true;
      memcpy (e->ckie_src_ip, src_ip, 16);
      e->ckie_src_port = src_port;
      return;
    }
  a->drop_ckie_oth++;
}

void
adm_on_ckie (Adm *a, const uint8_t src_ip[16], uint16_t src_port,
             const uint8_t *pl, size_t pl_len)
{
  adm_lock (a);
  adm_on_ckie_i (a, src_ip, src_port, pl, pl_len);
  adm_unlock (a);
}

static void
adm_tcp_auth_i (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
                const uint8_t lla[16], const uint8_t ip[16], uint16_t port,
                uint64_t sid, uint64_t ts)
{
  AdmEnt *e = adm_get (a, cfg, lla);
  if (!e)
    return;
  e->tp_tcp = true;
  e->ts_seen = ts;
  if (e->sid_ok && sid != 0 && sid != e->sid
      && (e->st == ADM_ADMITTED || e->st == ADM_SUSPECT))
    adm_restart (a, cry, rt, adv, e, sid, ts);
  adm_admit (a, cry, rt, cfg, e, ip, port, sid, NULL, false, true, ts);
}

void
adm_tcp_auth (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
              const uint8_t lla[16], const uint8_t ip[16], uint16_t port,
              uint64_t sid, uint64_t ts)
{
  adm_lock (a);
  adm_tcp_auth_i (a, cry, rt, adv, cfg, lla, ip, port, sid, ts);
  adm_unlock (a);
}

static void
adm_tcp_close_i (Adm *a, const uint8_t lla[16])
{
  AdmEnt *e = adm_fnd (a, lla);
  if (e)
    e->tp_tcp = false;
}

void
adm_tcp_close (Adm *a, const uint8_t lla[16])
{
  adm_lock (a);
  adm_tcp_close_i (a, lla);
  adm_unlock (a);
}

static void
adm_judge_ibs_i (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
                 uint8_t pt_type, const uint8_t *pl, size_t pl_sz,
                 const uint8_t *sig,
                 const uint8_t src_ip[16], uint16_t src_port, bool from_tcp,
                 uint64_t ts, AdjOut *out)
{
  memset (out, 0, sizeof (*out));
  out->res = ADJ_DROP;
  bool is_ping = (pt_type == PT_PING);
  uint64_t req_ts = 0, peer_sid = 0, peer_rx = 0, tok = 0;
  uint8_t claimed[16];
  int prc;
  if (is_ping)
    prc = on_ping (pl, pl_sz, &req_ts, &peer_sid, claimed, NULL, &tok);
  else
    prc = on_pong (pl, pl_sz, &req_ts, &peer_sid, claimed, NULL, &peer_rx,
                   &tok);
  if (prc != 0 || !IS_LLA_VAL (claimed)
      || memcmp (claimed, cfg->addr, 16) == 0)
    {
      a->drop_oth++;
      return;
    }
  memcpy (out->lla, claimed, 16);
  out->has_lla = true;
  const uint8_t *kx = is_ping ? on_ping_kx (pl, pl_sz)
                              : on_pong_kx (pl, pl_sz);
  if (from_tcp)
    kx = NULL;
  AdmEnt *e = adm_fnd (a, claimed);
  if (e)
    e->ts_seen = ts;
  if (e && !cfg->p2p && !e->is_static && !from_tcp)
    {
      if (adm_ep_static (rt, src_ip, src_port))
        e->is_static = true;
      else
        {
          e->drop_state++;
          return;
        }
    }
  bool ckie_ok = false;
  if (is_ping && !from_tcp)
    {
      const uint8_t *ckie = pl + IBS_PING_CKIE_OFF;
      bool has_ckie = false;
      for (int i = 0; i < IBS_CKIE_SZ; i++)
        if (ckie[i] != 0)
          has_ckie = true;
      if (has_ckie)
        {
          uint64_t bucket = wall_ts () / IBS_TS_SKEW_MAX;
          uint8_t want[IBS_CKIE_SZ];
          ibs_ckie_calc (cry->ibs_ckie_key, claimed, src_ip, src_port,
                         bucket, want);
          ckie_ok = memcmp (want, ckie, IBS_CKIE_SZ) == 0;
          if (!ckie_ok)
            {
              ibs_ckie_calc (cry->ibs_ckie_key, claimed, src_ip, src_port,
                             bucket - 1, want);
              ckie_ok = memcmp (want, ckie, IBS_CKIE_SZ) == 0;
            }
          if (!ckie_ok && e)
            e->drop_ckie++;
        }
    }
  bool tok_ok = false;
  if (!is_ping && e)
    tok_ok = tok != 0 && (tok == e->tok_cur || tok == e->tok_prv);
    if (e && !is_ping && !tok_ok && tok != 0)
      {
        Re *are = rt_dir_ent (rt, claimed);
        if (!are || (tok != are->prb_tok && tok != are->prb_tok_prv))
          {
            static const uint8_t z16[16] = { 0 };
            are = NULL;
            for (uint32_t i = 0; i < rt->cnt && !are; i++)
              {
                Re *re = &rt->re_arr[i];
                if (re->r2d != 0 || memcmp (re->lla, z16, 16) != 0)
                  continue;
                if (re->ep_port != src_port
                    || memcmp (re->ep_ip, src_ip, 16) != 0)
                  continue;
                if (tok == re->prb_tok || tok == re->prb_tok_prv)
                  are = re;
              }
          }
        if (are && (tok == are->prb_tok || tok == are->prb_tok_prv))
          {
            e->tok_cur = are->prb_tok;
            e->tok_prv = are->prb_tok_prv;
            e->tok_ts = are->prb_ts;
            e->tok_wts = are->prb_wts;
            tok_ok = true;
          }
      }
  int sig_st = sig ? -1 : 1;
  bool at_cur0 = e && (e->st == ADM_ADMITTED || e->st == ADM_SUSPECT)
                 && e->ep_ok
                 && ep_eq (e->ep_ip, e->ep_port, src_ip, src_port);
  bool need_vfy = ckie_ok || tok_ok || at_cur0;
  bool vfy = !need_vfy;
  if (need_vfy)
    {
      if (sig_st < 0)
        sig_st = ibs_verify (cry->ibs_mpk, claimed, 16, pl, pl_sz, sig)
                     ? 1
                     : 0;
      vfy = sig_st == 1;
      if (!vfy)
        {
          if (e)
            e->drop_ibs++;
          else
            a->drop_oth++;
          return;
        }
    }
  if (vfy && e && e->sid_ok && peer_sid != 0 && peer_sid != e->sid
      && (e->st == ADM_ADMITTED || e->st == ADM_SUSPECT))
    adm_restart (a, cry, rt, adv, e, peer_sid, ts);
  if (vfy && e && !e->sid_ok && peer_sid != 0)
    {
      e->sid = peer_sid;
      e->sid_ok = true;
    }
  if (!e)
    {
      if (!is_ping && tok != 0 && rt)
        {
          static const uint8_t z16[16] = { 0 };
          bool anchor = false;
          for (uint32_t i = 0; i < rt->cnt && !anchor; i++)
            {
              Re *re = &rt->re_arr[i];
              if (re->r2d != 0 || memcmp (re->lla, z16, 16) != 0)
                continue;
              if (memcmp (re->ep_ip, src_ip, 16) == 0
                  && re->ep_port == src_port
                  && (re->prb_tok == tok || re->prb_tok_prv == tok))
                anchor = true;
            }
          if (anchor)
            {
              if (sig_st < 0)
                sig_st = ibs_verify (cry->ibs_mpk, claimed, 16, pl, pl_sz,
                                     sig)
                             ? 1
                             : 0;
              if (sig_st != 1)
                {
                  a->drop_oth++;
                  return;
                }
              vfy = true;
              e = adm_get (a, cfg, claimed);
              if (e)
                {
                          adm_admit (a, cry, rt, cfg, e, src_ip, src_port,
                             peer_sid, kx, true, from_tcp, ts);
                  out->res = ADJ_ADMIT;
                  return;
                }
            }
        }
      if (is_ping)
        {
          if (!vfy)
            {
              adm_chal_issue (a, cry, NULL, src_ip, src_port, out);
              return;
            }
          e = adm_get (a, cfg, claimed);
          if (!e)
            {
              a->drop_oth++;
              return;
            }
          e->st = ADM_PROBING;
          memcpy (e->cand_ip, src_ip, 16);
          e->cand_port = src_port;
          e->cand_ok = true;
          e->ts_seen = ts;
          if (peer_sid != 0)
            {
              e->sid = peer_sid;
              e->sid_ok = true;
            }
          if (ckie_ok)
            {
              adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid,
                         kx, false, from_tcp, ts);
              out->res = ADJ_ADMIT;
            }
          else
            adm_chal_issue (a, cry, e, src_ip, src_port, out);
          return;
        }
      if (!vfy)
        {
          adm_chal_issue (a, cry, NULL, src_ip, src_port, out);
          return;
        }
      e = adm_get (a, cfg, claimed);
      if (!e)
        {
          a->drop_oth++;
          return;
        }
      e->st = ADM_PROBING;
      memcpy (e->cand_ip, src_ip, 16);
      e->cand_port = src_port;
      e->cand_ok = true;
      e->ts_seen = ts;
      if (peer_sid != 0)
        {
          e->sid = peer_sid;
          e->sid_ok = true;
        }
      adm_chal_issue (a, cry, e, src_ip, src_port, out);
      return;
    }
  if (e->st == ADM_ADMITTED || e->st == ADM_SUSPECT)
    {
      bool at_cur = e->ep_ok
                    && ep_eq (e->ep_ip, e->ep_port, src_ip, src_port);
      if (at_cur)
        {
          if (!is_ping && from_tcp)
            {
              out->res = ADJ_ADMIT;
              return;
            }
          adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid, kx,
                     !is_ping, from_tcp, ts);
          out->res = ADJ_ADMIT;
          return;
        }
      if (!is_ping && tok_ok)
        {
          adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid, kx,
                     true, from_tcp, ts);
          out->res = ADJ_ADMIT;
          return;
        }
      if (is_ping && ckie_ok)
        {
          adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid, kx,
                     false, from_tcp, ts);
          out->res = ADJ_ADMIT;
          return;
        }
      if (is_ping)
        {
          memcpy (e->cand_ip, src_ip, 16);
          e->cand_port = src_port;
          e->cand_ok = true;
          adm_chal_issue (a, cry, e, src_ip, src_port, out);
          return;
        }
      e->drop_tok++;
      return;
    }
  if (!is_ping)
    {
      if (tok_ok)
        {
          adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid, kx,
                     true, from_tcp, ts);
          out->res = ADJ_ADMIT;
        }
      else
        {
          memcpy (e->cand_ip, src_ip, 16);
          e->cand_port = src_port;
          e->cand_ok = true;
          e->ts_seen = ts;
          adm_chal_issue (a, cry, e, src_ip, src_port, out);
        }
      return;
    }
  if (ckie_ok || from_tcp)
    {
      adm_admit (a, cry, rt, cfg, e, src_ip, src_port, peer_sid, kx, false,
                 from_tcp, ts);
      out->res = ADJ_ADMIT;
      return;
    }
  memcpy (e->cand_ip, src_ip, 16);
  e->cand_port = src_port;
  e->cand_ok = true;
  if (e->st == ADM_UNKNOWN || e->st == ADM_DEAD)
    e->st = ADM_PROBING;
  adm_chal_issue (a, cry, e, src_ip, src_port, out);
}

void
adm_judge_ibs (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
               uint8_t pt_type, const uint8_t *pl, size_t pl_sz,
               const uint8_t *sig,
               const uint8_t src_ip[16], uint16_t src_port, bool from_tcp,
               uint64_t ts, AdjOut *out)
{
  adm_lock (a);
  adm_judge_ibs_i (a, cry, rt, adv, cfg, pt_type, pl, pl_sz, sig, src_ip,
                   src_port, from_tcp, ts, out);
  adm_unlock (a);
}

static bool
adm_judge_aead_i (Adm *a, Rt *rt, const Cfg *cfg, const uint8_t lla[16],
                  bool has_lla, const uint8_t src_ip[16], uint16_t src_port,
                  uint64_t ts, AdjOut *out)
{
  memset (out, 0, sizeof (*out));
  out->res = ADJ_DROP;
  if (!has_lla || !lla || !IS_LLA_VAL (lla)
      || memcmp (lla, cfg->addr, 16) == 0)
    {
      a->drop_oth++;
      return false;
    }
  memcpy (out->lla, lla, 16);
  out->has_lla = true;
  AdmEnt *e = adm_fnd (a, lla);
  if (!e)
    {
      a->drop_oth++;
      return false;
    }
  e->ts_seen = ts;
  if (!cfg->p2p && !e->is_static)
    {
      if (adm_ep_static (rt, src_ip, src_port))
        e->is_static = true;
      else
        {
          e->drop_state++;
          return false;
        }
    }
  if (e->st != ADM_ADMITTED && e->st != ADM_SUSPECT)
    {
      e->drop_state++;
      return false;
    }
  if (e->ep_ok && !ep_eq (e->ep_ip, e->ep_port, src_ip, src_port)
      && src_port != 0)
    {
      e->ep_sw++;
      memcpy (e->ep_ip, src_ip, 16);
      e->ep_port = src_port;
      adm_pub (rt, e, TP_MASK_UDP, ts);
    }
  e->ts_adm = ts;
  if (e->st == ADM_SUSPECT)
    e->st = ADM_ADMITTED;
  out->res = ADJ_ADMIT;
  return true;
}

bool
adm_judge_aead (Adm *a, Rt *rt, const Cfg *cfg, const uint8_t lla[16],
                bool has_lla, const uint8_t src_ip[16], uint16_t src_port,
                uint64_t ts, AdjOut *out)
{
  adm_lock (a);
  bool ok = adm_judge_aead_i (a, rt, cfg, lla, has_lla, src_ip, src_port,
                              ts, out);
  adm_unlock (a);
  return ok;
}

static void
adm_tick_i (Adm *a, Rt *rt, Cry *cry, Adv *adv, const Cfg *cfg, uint64_t ts)
{
  if (!a || !rt || !cfg)
    return;
  for (uint32_t i = 0; i < a->cnt; i++)
    {
      AdmEnt *e = &a->arr[i];
      if (e->st == ADM_ADMITTED && !e->tp_tcp && e->ts_pong > 0
          && ts > e->ts_pong && (ts - e->ts_pong) > RT_KA_TMO)
        e->st = ADM_SUSPECT;
      uint64_t last = e->ts_adm > e->ts_seen ? e->ts_adm : e->ts_seen;
      bool since_dead = e->ts_dead != 0 && e->ts_seen <= e->ts_dead
                         && e->ts_adm <= e->ts_dead;
      if (e->st != ADM_DEAD && e->st != ADM_UNKNOWN && !e->tp_tcp
          && !since_dead
          && last > 0 && ts > last && (ts - last) > RT_STL_TS
          && (e->ts_seen == 0 || (ts - e->ts_seen) > RT_STL_TS))
        {
          e->st = ADM_DEAD;
          e->ts_dead = ts;
          e->kx_cur = false;
          e->chal_ok = false;
          if (cry)
            cry_peer_drop (cry, e->lla);
          if (adv)
            adv_ses_drop (adv, e->lla);
        }
      if (e->st == ADM_DEAD && e->is_static)
        {
          e->st = ADM_PROBING;
          memcpy (e->cand_ip, e->seed_ip, 16);
          e->cand_port = e->seed_port;
          e->cand_ok = e->seed_port != 0;
          e->ts_dead = 0;
        }
      if (e->tp_tcp && e->ep_ok)
        rt_rx_ack (rt, e->ep_ip, e->ep_port, ts);
      Re *re = rt_dir_ent (rt, e->lla);
      if (re)
        {
          RtSt want = RT_DED;
          if (e->st == ADM_ADMITTED)
            want = RT_ACT;
          else if (e->st == ADM_SUSPECT || e->st == ADM_PROBING
                   || e->st == ADM_UNKNOWN)
            want = RT_PND;
          if (e->st != ADM_DEAD && re->state != want)
            re->state = want;
          if ((e->st == ADM_ADMITTED || e->st == ADM_SUSPECT)
              && e->ts_adm > re->rx_ts)
            re->rx_ts = e->ts_adm;
          if (e->tok_cur != 0)
            {
              re->prb_tok = e->tok_cur;
              re->prb_tok_prv = e->tok_prv;
              re->prb_ts = e->tok_ts;
              re->prb_wts = e->tok_wts;
            }
          if (!e->ckie_in_ok)
            {
              for (uint32_t j = 0; j < rt->cnt && !e->ckie_in_ok; j++)
                {
                  Re *zr = &rt->re_arr[j];
                  if (zr->r2d != 0 || !zr->ibs_ckie_ok)
                    continue;
                  if ((e->ep_ok
                       && ep_eq (e->ep_ip, e->ep_port, zr->ep_ip,
                                 zr->ep_port))
                      || (e->cand_ok
                          && ep_eq (e->cand_ip, e->cand_port, zr->ep_ip,
                                    zr->ep_port))
                      || ep_eq (e->seed_ip, e->seed_port, zr->ep_ip,
                                zr->ep_port))
                    {
                      memcpy (e->ckie_in, zr->ibs_ckie, IBS_CKIE_SZ);
                      e->ckie_in_ok = true;
                      memcpy (e->ckie_src_ip, zr->ep_ip, 16);
                      e->ckie_src_port = zr->ep_port;
                      zr->ibs_ckie_ok = false;
                    }
                }
            }
        }
    }
  for (uint32_t i = 0; i < a->cnt;)
    {
      AdmEnt *e = &a->arr[i];
      if (e->st == ADM_DEAD && !e->is_static && e->ts_dead > 0
          && ts > e->ts_dead && (ts - e->ts_dead) > RT_DED_TS)
        {
          rt_dir_del (rt, e->lla);
          memmove (&a->arr[i], &a->arr[i + 1],
                   (size_t)(a->cnt - i - 1) * sizeof (AdmEnt));
          a->cnt--;
        }
      else
        i++;
    }
}

void
adm_tick (Adm *a, Rt *rt, Cry *cry, Adv *adv, const Cfg *cfg, uint64_t ts)
{
  adm_lock (a);
  adm_tick_i (a, rt, cry, adv, cfg, ts);
  adm_unlock (a);
}
