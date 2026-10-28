#include "adv.h"
#include "bogon.h"
#include "utils.h"
#include "nbr.h"
#include "pkt.h"
#include "packet.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>

static uint16_t
u16_rd (const uint8_t *s)
{
  return (uint16_t)(((uint16_t)s[0] << 8) | s[1]);
}

static uint32_t
u32_rd (const uint8_t *s)
{
  return ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16)
         | ((uint32_t)s[2] << 8) | (uint32_t)s[3];
}

static void
u16_wr (uint8_t *dst, uint16_t v)
{
  dst[0] = (uint8_t)(v >> 8);
  dst[1] = (uint8_t)v;
}

static void
u32_wr (uint8_t *dst, uint32_t v)
{
  dst[0] = (uint8_t)(v >> 24);
  dst[1] = (uint8_t)(v >> 16);
  dst[2] = (uint8_t)(v >> 8);
  dst[3] = (uint8_t)v;
}

static uint32_t
lla_id (const uint8_t lla[16])
{
  return u32_rd (lla + 12);
}

static size_t
ent_sz (const AdvEnt *e)
{
  return ADV_CORE_SZ + 1 + (size_t)e->path_len * 4;
}

static bool
ent_eq (const AdvEnt *a, const AdvEnt *b)
{
  uint8_t ba[ADV_CORE_SZ + 1 + 4 * ADV_PATH_MAX];
  uint8_t bb[ADV_CORE_SZ + 1 + 4 * ADV_PATH_MAX];
  size_t la = adv_ent_ser (ba, a);
  size_t lb = adv_ent_ser (bb, b);
  return la == lb && memcmp (ba, bb, la) == 0;
}

static bool
ent_is_wd (const AdvEnt *e)
{
  return e->adv_m >= RT_F_INF && e->state == (uint8_t)RT_DED;
}

static void
tx_mark (Rt *rt, size_t len, const uint8_t dst_ip[16], uint16_t dst_port,
         uint64_t ts)
{
  if (!rt)
    return;
  rt->adv_tx_cnt++;
  rt->ctrl_tx_b += (uint64_t)len;
  if (dst_ip && dst_port != 0)
    rt_tx_ack (rt, dst_ip, dst_port, ts);
}

static bool
adv_send (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, const Re *peer,
          uint8_t pt_type, const uint8_t *pl, size_t pl_len, uint64_t now)
{
  static uint8_t s_buf[UDP_PL_MAX];
  uint8_t hdr[PKT_CH_SZ];
  size_t out_len = 0;
  hdr_bld (pt_type, 0, 32, hdr);
  pkt_enc_to (cry_ctx, peer->lla, hdr, pl, pl_len, s_buf, &out_len);
  if (out_len == 0)
    return false;
  if (!tp_send_ctrl (udp, rt, cfg, peer->ep_ip, peer->ep_port, s_buf,
                     out_len))
    return false;
  tx_mark (rt, out_len, peer->ep_ip, peer->ep_port, now);
  return true;
}

void
adv_init (Adv *a)
{
  memset (a, 0, sizeof (*a));
}

static void
ses_clr (AdvSes *ses)
{
  free (ses->unack_buf);
  ses->unack_buf = NULL;
  ses->unack_len = 0;
  ses->unack_seq = 0;
  ses->unack_ts = 0;
  ses->unack_retx = false;
  ses->srtt_ms = 0;
  ses->rttvar_ms = 0;
  ses->rto_ms = 0;
  free (ses->sent);
  ses->sent = NULL;
  ses->sent_cnt = 0;
  ses->sent_cap = 0;
  free (ses->pend);
  ses->pend = NULL;
  ses->pend_cnt = 0;
  ses->acc = true;
  ses->tx_nxt = 0;
  ses->rx_last = 0;
}

void
adv_free (Adv *a)
{
  if (!a)
    return;
  for (uint32_t i = 0; i < a->cnt; i++)
    ses_clr (&a->ses[i]);
  free (a->ses);
  memset (a, 0, sizeof (*a));
}

static AdvSes *
ses_fnd (Adv *a, const uint8_t lla[16])
{
  for (uint32_t i = 0; i < a->cnt; i++)
    if (memcmp (a->ses[i].lla, lla, 16) == 0)
      return &a->ses[i];
  return NULL;
}

AdvSes *
adv_ses_get (Adv *a, const uint8_t lla[16], uint64_t sid)
{
  AdvSes *ses = ses_fnd (a, lla);
  if (ses)
    {
      if (sid != 0 && ses->sid != sid)
        {
          ses_clr (ses);
          ses->sid = sid;
        }
      return ses;
    }
  if (a->cnt == a->cap)
    {
      uint32_t ncap = a->cap ? a->cap * 2 : 4;
      AdvSes *ns = realloc (a->ses, (size_t)ncap * sizeof (AdvSes));
      if (!ns)
        return NULL;
      a->ses = ns;
      a->cap = ncap;
    }
  ses = &a->ses[a->cnt++];
  memset (ses, 0, sizeof (*ses));
  memcpy (ses->lla, lla, 16);
  ses->sid = sid;
  return ses;
}

void
adv_ses_drop (Adv *a, const uint8_t lla[16])
{
  for (uint32_t i = 0; i < a->cnt; i++)
    {
      if (memcmp (a->ses[i].lla, lla, 16) != 0)
        continue;
      ses_clr (&a->ses[i]);
      memmove (&a->ses[i], &a->ses[i + 1],
               (size_t)(a->cnt - i - 1) * sizeof (AdvSes));
      a->cnt--;
      return;
    }
}

static bool
ent_key_eq (const AdvEnt *a, const AdvEnt *b)
{
  return memcmp (a->lla, b->lla, 16) == 0
         && memcmp (a->nhop_lla, b->nhop_lla, 16) == 0
         && memcmp (a->ep_ip, b->ep_ip, 16) == 0 && a->ep_port == b->ep_port;
}

static int
sent_fnd (const AdvSes *ses, const AdvEnt *key)
{
  for (uint32_t i = 0; i < ses->sent_cnt; i++)
    if (ent_key_eq (&ses->sent[i], key))
      return (int)i;
  return -1;
}

static bool
sent_put (AdvSes *ses, const AdvEnt *e)
{
  int idx = sent_fnd (ses, e);
  if (idx >= 0)
    {
      ses->sent[idx] = *e;
      return true;
    }
  if (ses->sent_cnt == ses->sent_cap)
    {
      uint32_t ncap = ses->sent_cap ? ses->sent_cap * 2 : 8;
      AdvEnt *ns = realloc (ses->sent, (size_t)ncap * sizeof (AdvEnt));
      if (!ns)
        return false;
      ses->sent = ns;
      ses->sent_cap = ncap;
    }
  ses->sent[ses->sent_cnt++] = *e;
  return true;
}

static void
sent_del (AdvSes *ses, const AdvEnt *key)
{
  int idx = sent_fnd (ses, key);
  if (idx < 0)
    return;
  memmove (&ses->sent[idx], &ses->sent[idx + 1],
           (size_t)(ses->sent_cnt - (uint32_t)idx - 1) * sizeof (AdvEnt));
  ses->sent_cnt--;
}

static void
ses_apply_pend (AdvSes *ses)
{
  for (uint32_t i = 0; i < ses->pend_cnt; i++)
    {
      const AdvEnt *e = &ses->pend[i];
      if (ent_is_wd (e))
        sent_del (ses, e);
      else
        (void)sent_put (ses, e);
    }
  ses->pend_cnt = 0;
}

int
adv_on_ack (Adv *a, const uint8_t src_lla[16], const uint8_t *pt,
            size_t pt_len, uint64_t now)
{
  if (!pt || pt_len < 4)
    return -1;
  uint32_t seq = u32_rd (pt);
  AdvSes *ses = ses_fnd (a, src_lla);
  if (!ses || ses->unack_seq == 0 || seq != ses->unack_seq)
    return -1;
  if (!ses->unack_retx && now > ses->unack_ts)
    {
      uint64_t sample = now - ses->unack_ts;
      if (ses->srtt_ms == 0)
        {
          ses->srtt_ms = sample;
          ses->rttvar_ms = sample / 2;
        }
      else
        {
          uint64_t err = (ses->srtt_ms > sample)
                             ? ses->srtt_ms - sample
                             : sample - ses->srtt_ms;
          ses->rttvar_ms = (3 * ses->rttvar_ms + err) / 4;
          ses->srtt_ms = (7 * ses->srtt_ms + sample) / 8;
        }
      uint64_t rto = ses->srtt_ms + 4 * ses->rttvar_ms;
      if (rto < RTO_MIN)
        rto = RTO_MIN;
      if (rto > RTO_MAX)
        rto = RTO_MAX;
      ses->rto_ms = rto;
    }
  ses_apply_pend (ses);
  free (ses->unack_buf);
  ses->unack_buf = NULL;
  ses->unack_len = 0;
  ses->unack_seq = 0;
  ses->unack_ts = 0;
  ses->unack_retx = false;
  return 0;
}

int
adv_on_upd (Adv *a, const uint8_t src_lla[16], const uint8_t *pt,
            size_t pt_len, uint32_t *ack_seq)
{
  if (!pt || pt_len < 6)
    return -1;
  uint32_t seq = u32_rd (pt);
  AdvSes *ses = ses_fnd (a, src_lla);
  if (ack_seq)
    *ack_seq = seq;
  if (seq == 0)
    return 1;
  if (ses && seq <= ses->rx_last)
    return 1;
  if (ses)
    ses->rx_last = seq;
  return 0;
}

uint8_t *
adv_ack_bld (Cry *s, uint32_t seq, const uint8_t dst_lla[16], uint8_t *buf,
             size_t *out_len)
{
  uint8_t payload[4];
  u32_wr (payload, seq);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_ADV_ACK, 0, 32, hdr);
  return pkt_enc_to (s, dst_lla, hdr, payload, sizeof (payload), buf,
                     out_len);
}

void
adv_tick (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, Adv *a,
          uint64_t now)
{
  bool rev_changed = (rt->sync_rev != a->last_rev);
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (re->state != RT_ACT)
        continue;
      if (memcmp (re->lla, cfg->addr, 16) == 0)
        continue;
      if (re->ep_port == 0)
        continue;
      AdvSes *ses = adv_ses_get (a, re->lla, re->sid);
      if (!ses)
        continue;
      if (rev_changed)
        ses->acc = true;
      if (ses->unack_seq != 0)
        {
          uint64_t rto = ses->rto_ms ? ses->rto_ms : RTO_INIT;
          if (now - ses->unack_ts < rto)
            continue;
          free (ses->unack_buf);
          ses->unack_buf = NULL;
          ses->unack_len = 0;
          ses->unack_seq = 0;
          ses->unack_ts = 0;
          free (ses->pend);
          ses->pend = NULL;
          ses->pend_cnt = 0;
          ses->unack_retx = true;
          uint64_t nrto = rto * 2;
          ses->rto_ms = nrto > RTO_MAX ? RTO_MAX : nrto;
          ses->acc = true;
        }
      if (!ses->acc)
        continue;
      bool peer_no_dir = false;
      (void)rt_src_no_dir_known (rt, re->lla, &peer_no_dir);
      bool self_dir_ok = cfg->p2p && !peer_no_dir;
      AdvEnt *set = malloc ((size_t)(rt->cnt ? rt->cnt : 1)
                            * sizeof (AdvEnt));
      if (!set)
        continue;
      uint32_t set_cnt = adv_set_bld (rt, cfg->addr, self_dir_ok,
                                      peer_no_dir, cfg->p2p, NULL, set,
                                      rt->cnt);
      uint16_t known = (re->mtu_lkg > 0) ? re->mtu_lkg : RT_MTU_MIN;
      uint32_t budget
          = (known > TNL_OH_MAX) ? (uint32_t)(known - TNL_OH_MAX) : 1U;
      size_t used = 6;
      uint32_t ch_cap = set_cnt + ses->sent_cnt;
      AdvEnt *ch = malloc ((size_t)(ch_cap ? ch_cap : 1)
                           * sizeof (AdvEnt));
      uint32_t ch_cnt = 0;
      bool more = false;
      if (ch)
        {
          for (uint32_t k = 0; k < ses->sent_cnt; k++)
            {
              bool in_cur = false;
              for (uint32_t m = 0; m < set_cnt; m++)
                if (ent_key_eq (&set[m], &ses->sent[k]))
                  in_cur = true;
              if (in_cur)
                continue;
              if (ch_cnt > 0 && used >= budget)
                {
                  more = true;
                  break;
                }
              AdvEnt wd = ses->sent[k];
              wd.adv_m = RT_F_INF;
              wd.state = (uint8_t)RT_DED;
              ch[ch_cnt++] = wd;
              used += ent_sz (&wd);
            }
          if (!more)
            {
              for (uint32_t k = 0; k < set_cnt; k++)
                {
                  int si = sent_fnd (ses, &set[k]);
                  if (si >= 0 && ent_eq (&ses->sent[si], &set[k]))
                    continue;
                  if (ch_cnt > 0 && used >= budget)
                    {
                      more = true;
                      break;
                    }
                  ch[ch_cnt++] = set[k];
                  used += ent_sz (&set[k]);
                }
            }
        }
      bool sent_new = false;
      if (ch && ch_cnt > 0)
        {
          size_t pl_len = used;
          uint8_t *pl = malloc (pl_len);
          if (pl)
            {
              uint32_t seq = ++ses->tx_nxt;
              u32_wr (pl, seq);
              u16_wr (pl + 4, (uint16_t)ch_cnt);
              size_t off = 6;
              for (uint32_t k = 0; k < ch_cnt; k++)
                off += adv_ent_ser (pl + off, &ch[k]);
              if (adv_send (udp, cry_ctx, rt, cfg, re, PT_ADV_UPD, pl,
                            off, now))
                {
                  free (ses->unack_buf);
                  ses->unack_buf = pl;
                  ses->unack_len = off;
                  ses->unack_seq = seq;
                  ses->unack_ts = now;
                  free (ses->pend);
                  ses->pend = ch;
                  ses->pend_cnt = ch_cnt;
                  ch = NULL;
                  sent_new = true;
                }
              else
                free (pl);
            }
        }
      if (sent_new)
        {
          if (!more)
            ses->acc = false;
        }
      else if (ch && !more)
        ses->acc = false;
      free (ch);
      free (set);
    }
  for (uint32_t i = 0; i < a->cnt;)
    {
      bool has_dir = false;
      for (uint32_t j = 0; j < rt->cnt; j++)
        {
          if (rt->re_arr[j].r2d == 0
              && memcmp (rt->re_arr[j].lla, a->ses[i].lla, 16) == 0)
            has_dir = true;
        }
      if (!has_dir)
        adv_ses_drop (a, a->ses[i].lla);
      else
        i++;
    }
  a->last_rev = rt->sync_rev;
}

static uint64_t
u64_rd (const uint8_t *s)
{
  return ((uint64_t)s[0] << 56) | ((uint64_t)s[1] << 48)
         | ((uint64_t)s[2] << 40) | ((uint64_t)s[3] << 32)
         | ((uint64_t)s[4] << 24) | ((uint64_t)s[5] << 16)
         | ((uint64_t)s[6] << 8) | (uint64_t)s[7];
}



static void
u64_wr (uint8_t *dst, uint64_t v)
{
  dst[0] = (uint8_t)(v >> 56);
  dst[1] = (uint8_t)(v >> 48);
  dst[2] = (uint8_t)(v >> 40);
  dst[3] = (uint8_t)(v >> 32);
  dst[4] = (uint8_t)(v >> 24);
  dst[5] = (uint8_t)(v >> 16);
  dst[6] = (uint8_t)(v >> 8);
  dst[7] = (uint8_t)(v);
}



size_t
adv_ent_ser (uint8_t *dst, const AdvEnt *src)
{
  memcpy (dst, src->lla, 16);
  memcpy (dst + 16, src->ep_ip, 16);
  u16_wr (dst + 32, src->ep_port);
  dst[34] = src->flags;
  dst[35] = src->state;
  u16_wr (dst + 36, src->mtu);
  u32_wr (dst + 38, src->adv_m);
  dst[42] = src->adv_loss;
  memcpy (dst + 43, src->nhop_lla, 16);
  u64_wr (dst + 59, src->ver);
  dst[67] = src->path_len;
  for (uint8_t i = 0; i < src->path_len; i++)
    u32_wr (dst + 68 + (size_t)i * 4, src->path[i]);
  return ADV_CORE_SZ + 1 + (size_t)src->path_len * 4;
}

int
adv_ent_des (AdvEnt *dst, const uint8_t *src, size_t avail)
{
  if (avail < ADV_CORE_SZ + 1)
    return -1;
  memcpy (dst->lla, src, 16);
  memcpy (dst->ep_ip, src + 16, 16);
  dst->ep_port = u16_rd (src + 32);
  dst->flags = src[34];
  dst->state = src[35];
  dst->mtu = u16_rd (src + 36);
  dst->adv_m = u32_rd (src + 38);
  dst->adv_loss = src[42];
  memcpy (dst->nhop_lla, src + 43, 16);
  dst->ver = u64_rd (src + 59);
  dst->path_len = src[67];
  if (dst->path_len > ADV_PATH_MAX)
    return -1;
  size_t need = ADV_CORE_SZ + 1 + (size_t)dst->path_len * 4;
  if (avail < need)
    return -1;
  for (uint8_t i = 0; i < dst->path_len; i++)
    dst->path[i] = u32_rd (src + 68 + (size_t)i * 4);
  return (int)need;
}


static bool
p_is_me (const Rt *rt, const uint8_t our_lla[16], const uint8_t ip[16],
         uint16_t port)
{
  for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      if (memcmp (re->lla, our_lla, 16) != 0)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      return true;
    }
  return false;
}

static bool
has_mapped_ep (const uint8_t *pt, size_t pt_len, size_t act_cnt,
                   const uint8_t ip[16], uint16_t port)
{
  if (!pt || !ip || port == 0)
    return false;
  size_t rd_off = 2;
  for (size_t i = 0; i < act_cnt; i++)
    {
      AdvEnt ent;
      int consumed = adv_ent_des (&ent, pt + rd_off, pt_len - rd_off);
      if (consumed < 0)
        return false;
      rd_off += (size_t)consumed;
      static const uint8_t z_lla[16] = { 0 };
      if (memcmp (ent.lla, z_lla, 16) == 0)
        continue;
      if (!IS_LLA_VAL (ent.lla))
        continue;
      if (memcmp (ent.ep_ip, ip, 16) != 0 || ent.ep_port != port)
        continue;
      return true;
    }
  return false;
}

static bool
self_ep_exp_ok (const Re *re, const uint8_t our_lla[16])
{
  if (!re || !our_lla)
    return false;
  if (re->state != RT_ACT)
    return false;
  if (memcmp (re->lla, our_lla, 16) != 0)
    return true;
  return re->rx_ts != 0;
}

static bool
ent_exp_ok (const Re *re, const uint8_t our_lla[16])
{
  static const uint8_t z[16] = { 0 };
  bool is_z = false;
  if (!re || !our_lla)
    return false;
  if (bogon_ip_match (re->ep_ip))
    return false;
  is_z = (memcmp (re->lla, z, 16) == 0);
  if (!is_z && !IS_LLA_VAL (re->lla))
    return false;
  return self_ep_exp_ok (re, our_lla);
}

static void
ent_strip_dir (AdvEnt *ent)
{
  if (!ent)
    return;
  memset (ent->ep_ip, 0, 16);
  ent->ep_port = 0;
  ent->mtu = 0;
  memset (ent->nhop_lla, 0, 16);
  ent->flags &= (uint8_t)~ADV_F_SEL_DIR;
}

static void
ent_mask_no_dir (AdvEnt *ent)
{
  if (!ent)
    return;
  ent_strip_dir (ent);
  ent->flags |= ADV_F_NO_DIR;
}

static bool
ent_bld (Rt *rt, const Re *re, const uint8_t our_lla[16],
             bool self_dir_ok, bool dst_no_dir, AdvEnt *out)
{
  static const uint8_t z[16] = { 0 };
  bool is_z = (memcmp (re->lla, z, 16) == 0);
  memcpy (out->lla, re->lla, 16);
  memcpy (out->ep_ip, re->ep_ip, 16);
  out->ep_port = re->ep_port;
  bool no_dir = false;
  if (!is_z && memcmp (re->lla, our_lla, 16) == 0)
    no_dir = !self_dir_ok;
  else if (!is_z)
    no_dir = rt_src_no_dir (rt, re->lla);
  bool is_self_ent = !is_z && memcmp (re->lla, our_lla, 16) == 0;
  out->flags
      = (!no_dir && (is_self_ent || rt_dir_is_sel (rt, re)))
            ? ADV_F_SEL_DIR
            : 0;
  if (no_dir)
    out->flags |= ADV_F_NO_DIR;
  if (tp_mask_has (re->tp_mask, TP_PROTO_UDP))
    out->flags |= ADV_F_TP_UDP;
  if (tp_mask_has (re->tp_mask, TP_PROTO_TCP))
    out->flags |= ADV_F_TP_TCP;
  bool dir_hint_ok = (out->flags & ADV_F_TP_UDP) != 0;
  out->state = (uint8_t)re->state;
  out->mtu
      = (re->state == RT_ACT) ? rt_dir_mtu_adv (rt, re) : 0;
  out->adv_m = re->rt_m;
  if (re->r2d > 0)
    {
      int32_t nh_m = RT_F_INF;
      for (uint32_t j = 0; j < rt->cnt; j++)
        {
          const Re *nh = &rt->re_arr[j];
          if (nh->r2d != 0)
            continue;
          if (memcmp (nh->lla, re->nhop_lla, 16) != 0)
            continue;
          if (nh->state != RT_ACT)
            continue;
          if (nh->rt_m < nh_m)
            nh_m = nh->rt_m;
        }
      if (nh_m != RT_F_INF && re->rt_m != RT_F_INF)
        {
          int64_t tot = (int64_t)nh_m + (int64_t)re->rt_m;
          if (tot >= RT_F_INF)
            tot = RT_F_INF - 1;
          if (tot <= -RT_F_INF)
            tot = -RT_F_INF + 1;
          out->adv_m = (int32_t)tot;
        }
      else
        out->adv_m = RT_F_INF;
    }
  {
    uint32_t loss_pct = 0;
    out->adv_loss = rt_loss_pct_get (re, &loss_pct) ? (uint8_t)loss_pct : 0;
  }
  if (memcmp (re->lla, our_lla, 16) == 0)
    out->adv_m = RT_F_INF;
  memcpy (out->nhop_lla, re->nhop_lla, 16);
  out->ver = re->ver;
  uint32_t self_id = lla_id (our_lla);
  if (memcmp (re->lla, our_lla, 16) == 0)
    {
      out->path_len = 1;
      out->path[0] = self_id;
    }
  else if (re->r2d == 0)
    {
      out->path_len = 2;
      out->path[0] = self_id;
      out->path[1] = lla_id (re->lla);
    }
  else
    {
      if (memcmp (re->nhop_lla, re->lla, 16) == 0)
        return false;
      if (re->path_len == 0 || re->path_len >= ADV_PATH_MAX)
        return false;
      out->path_len = (uint8_t)(re->path_len + 1);
      out->path[0] = self_id;
      memcpy (out->path + 1, re->path, (size_t)re->path_len * 4);
    }
  if (no_dir)
    ent_mask_no_dir (out);
  else if (dst_no_dir && memcmp (re->lla, our_lla, 16) != 0)
    ent_strip_dir (out);
  else if (!dir_hint_ok)
    ent_strip_dir (out);
  if (!is_z && !(out->flags & ADV_F_SEL_DIR))
    {
      memset (out->ep_ip, 0, 16);
      out->ep_port = 0;
    }
  return true;
}

uint32_t
adv_set_bld (Rt *rt, const uint8_t our_lla[16], bool self_dir_ok,
             bool dst_no_dir, bool is_p2p, const uint8_t tgt_lla[16],
             AdvEnt *out, uint32_t max_cnt)
{
  uint32_t n = 0;
  if (!rt)
    return 0;
  for (int re_idx = 0; re_idx < (int)rt->cnt && n < max_cnt; re_idx++)
    {
      const Re *re = &rt->re_arr[re_idx];
      if (tgt_lla && memcmp (re->lla, tgt_lla, 16) != 0)
        continue;
      if (!ent_exp_ok (re, our_lla))
        continue;
      if (memcmp (re->lla, our_lla, 16) != 0)
        {
          RtDec dec = rt_sel (rt, re->lla, is_p2p);
          bool is_sel = false;
          if (dec.type == RT_DIR && re->r2d == 0
              && memcmp (re->ep_ip, dec.dir.ip, 16) == 0
              && re->ep_port == dec.dir.port)
            is_sel = true;
          if (dec.type == RT_REL && re->r2d > 0
              && memcmp (re->ep_ip, dec.rel.relay_ip, 16) == 0
              && re->ep_port == dec.rel.relay_port
              && memcmp (re->nhop_lla, dec.rel.relay_lla, 16) == 0)
            is_sel = true;
          if (!is_sel)
            continue;
        }
      memset (&out[n], 0, sizeof (AdvEnt));
      if (!ent_bld (rt, re, our_lla, self_dir_ok, dst_no_dir, &out[n]))
        continue;
      n++;
    }
  return n;
}

int
adv_import (const uint8_t *pt, size_t pt_len, const uint8_t src_ip[16],
        uint16_t src_port, const uint8_t src_lla_hint[16],
        const uint8_t our_lla[16], Rt *rt, PPool *pool, bool allow_dir_hint,
        uint64_t sys_ts, bool *is_mod)
{
  if (!pt || pt_len < 2)
    return -1;
  uint16_t cnt = u16_rd (pt);
  uint32_t rt_c_old = rt->cnt;
  *is_mod = false;
  uint8_t src_lla[16] = { 0 };
  bool has_s_lla = false;
  if (src_lla_hint && IS_LLA_VAL (src_lla_hint))
    {
      memcpy (src_lla, src_lla_hint, 16);
      has_s_lla = true;
    }
  else
    {
      has_s_lla = lla_inf_s (rt, src_ip, src_port, src_lla);
    }
  bool saw_self_adv = false;
  bool saw_self_sel_dir = false;
  uint16_t self_sel_dir_mtu = 0;
  size_t rd_off = 2;
  for (uint16_t ent_i = 0; ent_i < cnt; ent_i++)
    {
      AdvEnt ent;
      int consumed = adv_ent_des (&ent, pt + rd_off, pt_len - rd_off);
      if (consumed < 0)
        break;
      rd_off += (size_t)consumed;
      static const uint8_t z_lla[16] = { 0 };
      bool is_z = (memcmp (ent.lla, z_lla, 16) == 0);
      if (!is_z && !IS_LLA_VAL (ent.lla))
        continue;
      if (is_z)
        {
          if (bogon_ip_match (ent.ep_ip))
            continue;
          if (has_mapped_ep (pt, pt_len, cnt, ent.ep_ip, ent.ep_port))
            continue;
          if (allow_dir_hint
              && !p_is_me (rt, our_lla, ent.ep_ip, ent.ep_port))
            {
              uint8_t tp_mask = 0;
              if ((ent.flags & ADV_F_TP_UDP) != 0)
                tp_mask |= TP_MASK_UDP;
              if ((ent.flags & ADV_F_TP_TCP) != 0)
                tp_mask |= TP_MASK_TCP;
              rt_ep_upd (rt, z_lla, ent.ep_ip, ent.ep_port, tp_mask,
                         sys_ts);
              if (pool)
                {
                  pp_add (pool, ent.ep_ip, ent.ep_port);
                }
            }
          continue;
        }
      int32_t adv_m = ent.adv_m;
      uint16_t ent_mtu = ent.mtu;
      bool no_dir = (ent.flags & ADV_F_NO_DIR) != 0;
      if (memcmp (ent.lla, our_lla, 16) == 0)
        {
          saw_self_adv = true;
          if ((ent.flags & ADV_F_SEL_DIR) != 0 && ent_mtu >= RT_MTU_MIN)
            {
              saw_self_sel_dir = true;
              self_sel_dir_mtu = ent_mtu;
            }
          continue;
        }
      bool has_dir_hint
          = !IS_LLA_VAL (ent.nhop_lla)
            || memcmp (ent.nhop_lla, ent.lla, 16) == 0;
      bool has_udp_hint = (ent.flags & ADV_F_TP_UDP) != 0;
      if (ent.path_len == 0)
        continue;
      if (ent.path[ent.path_len - 1] != lla_id (ent.lla))
        continue;
      if (has_s_lla && ent.path[0] != lla_id (src_lla))
        continue;
      {
        uint32_t own_id = lla_id (our_lla);
        bool has_own = false;
        for (uint8_t pi = 0; pi < ent.path_len; pi++)
          if (ent.path[pi] == own_id)
            has_own = true;
        if (has_own)
          {
            Re dead_re;
            memset (&dead_re, 0, sizeof (dead_re));
            memcpy (dead_re.lla, ent.lla, 16);
            memcpy (dead_re.ep_ip, src_ip, 16);
            dead_re.ep_port = src_port;
            dead_re.r2d = 1;
            dead_re.state = RT_DED;
            memcpy (dead_re.nhop_lla, src_lla, 16);
            rt_upd (rt, &dead_re, sys_ts);
            continue;
          }
      }
      bool is_s_owner
          = has_s_lla && memcmp (src_lla, ent.lla, 16) == 0;
      rt_src_upd_auth (rt, ent.lla, ent.ver, no_dir,
                       is_s_owner, sys_ts);
      bool eff_no_dir = no_dir || (!is_s_owner && rt_src_no_dir (rt, ent.lla));
      bool is_s_self = (memcmp (ent.ep_ip, src_ip, 16) == 0
                        && ent.ep_port == src_port);
      if (eff_no_dir && !is_s_self)
        rt_dir_hint_prune (rt, ent.lla);
      if (!is_s_self && !is_s_owner && has_s_lla)
        {
          Re rel_re;
          memset (&rel_re, 0, sizeof (rel_re));
          memcpy (rel_re.lla, ent.lla, 16);
          memcpy (rel_re.ep_ip, src_ip, 16);
          rel_re.ep_port = src_port;
          rel_re.ver = ent.ver;
          rel_re.adv_m = adv_m;
          rel_re.adv_loss = ent.adv_loss;
          rel_re.r2d = 1;
          rel_re.rt_m = adv_m;
          rel_re.path_len = ent.path_len;
          memcpy (rel_re.path, ent.path, sizeof (rel_re.path));
          if (ent_mtu > 0)
            {
              rel_re.mtu_lkg = ent_mtu;
              rel_re.mtu_ukb = ent_mtu;
            }
          rel_re.state = (RtSt)ent.state;
          rel_re.tp_mask = 0;
          if ((ent.flags & ADV_F_TP_UDP) != 0)
            rel_re.tp_mask |= TP_MASK_UDP;
          if ((ent.flags & ADV_F_TP_TCP) != 0)
            rel_re.tp_mask |= TP_MASK_TCP;
          memcpy (rel_re.nhop_lla, src_lla, 16);
          rt_upd (rt, &rel_re, sys_ts);
        }
      bool import_dir_hint
          = allow_dir_hint && !eff_no_dir && has_dir_hint
            && has_udp_hint
            && (!is_s_owner || is_s_self)
            && (is_s_self || (ent.flags & ADV_F_SEL_DIR) != 0);
      if (import_dir_hint)
        {
          if (bogon_ip_match (ent.ep_ip))
            continue;
          if (p_is_me (rt, our_lla, ent.ep_ip, ent.ep_port))
            continue;
          Re dir_re;
          memset (&dir_re, 0, sizeof (dir_re));
          memcpy (dir_re.lla, ent.lla, 16);
          memcpy (dir_re.ep_ip, ent.ep_ip, 16);
          dir_re.ep_port = ent.ep_port;
          dir_re.ver = ent.ver;
          dir_re.adv_m = adv_m;
          dir_re.adv_loss = ent.adv_loss;
          dir_re.r2d = 0;
          dir_re.rt_m = RT_F_INF;
          dir_re.sm_m = RT_M_INF;
          dir_re.state = (RtSt)ent.state;
          dir_re.tp_mask = 0;
          if ((ent.flags & ADV_F_TP_UDP) != 0)
            dir_re.tp_mask |= TP_MASK_UDP;
          if ((ent.flags & ADV_F_TP_TCP) != 0)
            dir_re.tp_mask |= TP_MASK_TCP;
          if (IS_LLA_VAL (ent.nhop_lla))
            memcpy (dir_re.nhop_lla, ent.nhop_lla, 16);
          else
            memcpy (dir_re.nhop_lla, ent.lla, 16);
          rt_upd (rt, &dir_re, sys_ts);
          if (pool
              && !p_is_me (rt, our_lla, ent.ep_ip, ent.ep_port))
            {
              pp_add (pool, ent.ep_ip, ent.ep_port);
            }
        }
    }
  if (has_s_lla && saw_self_adv)
    {
      rt_peer_rev_mtu_set (rt, src_lla, saw_self_sel_dir ? self_sel_dir_mtu : 0);
    }
  if (rt->cnt != rt_c_old || rt->adv_dirty)
    *is_mod = true;
  return 0;
}

