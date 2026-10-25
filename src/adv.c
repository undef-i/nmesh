#include "adv.h"
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

static void
id_lla (uint32_t id, uint8_t lla[16])
{
  memset (lla, 0, 16);
  lla[0] = 0xfe;
  lla[1] = 0x80;
  u32_wr (lla + 12, id);
}

static uint32_t
path_hash (const uint32_t *path, uint8_t path_len)
{
  uint32_t h = 2166136261U;
  for (uint8_t i = 0; i < path_len; i++)
    {
      uint32_t v = path[i];
      for (int b = 0; b < 4; b++)
        {
          h ^= (uint8_t)(v >> (8 * b));
          h *= 16777619U;
        }
    }
  return h;
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
  free (ses->sent);
  ses->sent = NULL;
  ses->sent_cnt = 0;
  ses->sent_cap = 0;
  free (ses->pend);
  ses->pend = NULL;
  ses->pend_cnt = 0;
  ses->inval_cnt = 0;
  ses->tx_nxt = 0;
  ses->rx_last = 0;
  ses->dgst_ts = 0;
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

void
adv_inval_dst (Adv *a, const uint8_t peer_lla[16], const uint8_t dst_lla[16])
{
  AdvSes *ses = ses_fnd (a, peer_lla);
  if (!ses)
    return;
  uint32_t did = lla_id (dst_lla);
  for (uint32_t i = 0; i < ses->inval_cnt; i++)
    if (ses->inval[i] == did)
      return;
  if (ses->inval_cnt < 64)
    ses->inval[ses->inval_cnt++] = did;
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
            size_t pt_len)
{
  if (!pt || pt_len < 4)
    return -1;
  uint32_t seq = u32_rd (pt);
  AdvSes *ses = ses_fnd (a, src_lla);
  if (!ses || ses->unack_seq == 0 || seq != ses->unack_seq)
    return -1;
  ses_apply_pend (ses);
  free (ses->unack_buf);
  ses->unack_buf = NULL;
  ses->unack_len = 0;
  ses->unack_seq = 0;
  ses->unack_ts = 0;
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
  if (ses && seq != 0 && seq <= ses->rx_last)
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

uint8_t *
adv_req_bld (Cry *s, const uint8_t *ids, uint32_t cnt,
             const uint8_t dst_lla[16], uint8_t *buf, size_t *out_len)
{
  uint8_t payload[2 + 4 * 64];
  if (cnt > 64)
    cnt = 64;
  u16_wr (payload, (uint16_t)cnt);
  memcpy (payload + 2, ids, (size_t)cnt * 4);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_ADV_REQ, 0, 32, hdr);
  return pkt_enc_to (s, dst_lla, hdr, payload, 2 + (size_t)cnt * 4, buf,
                     out_len);
}

int
adv_on_req (Adv *a, const uint8_t src_lla[16], const uint8_t *pt,
            size_t pt_len)
{
  if (!pt || pt_len < 2)
    return -1;
  uint16_t cnt = u16_rd (pt);
  size_t max_cnt = (pt_len - 2) / 4;
  if (cnt > max_cnt)
    cnt = (uint16_t)max_cnt;
  for (uint16_t i = 0; i < cnt; i++)
    {
      uint8_t dst_lla[16];
      id_lla (u32_rd (pt + 2 + (size_t)i * 4), dst_lla);
      adv_inval_dst (a, src_lla, dst_lla);
    }
  return 0;
}

int
adv_on_dgst (Adv *a, Rt *rt, const uint8_t src_lla[16],
             const uint8_t src_ip[16], uint16_t src_port, const uint8_t *pt,
             size_t pt_len, uint8_t *req_ids, uint32_t req_cap,
             uint32_t *req_cnt)
{
  if (!pt || pt_len < 2 || !req_ids || !req_cnt)
    return -1;
  uint16_t cnt = u16_rd (pt);
  size_t max_cnt = (pt_len - 2) / 16;
  if (cnt > max_cnt)
    cnt = (uint16_t)max_cnt;
  *req_cnt = 0;
  uint32_t src_id = lla_id (src_lla);
  for (uint16_t j = 0; j < cnt; j++)
    {
      const uint8_t *ln = pt + 2 + (size_t)j * 16;
      uint32_t did = u32_rd (ln);
      uint32_t dnhop = u32_rd (ln + 4);
      uint32_t dseq = u32_rd (ln + 8);
      uint32_t dhash = u32_rd (ln + 12);
      bool need = false;
      if (did == src_id)
        {
          Re dir_re;
          if (!rt_dir_fnd (rt, src_lla, &dir_re))
            need = true;
          else if (dir_re.seq != dseq)
            need = true;
        }
      else
        {
          uint8_t dst_lla[16];
          id_lla (did, dst_lla);
          const Re *held = NULL;
          for (uint32_t i = 0; i < rt->cnt; i++)
            {
              const Re *re = &rt->re_arr[i];
              if (re->r2d == 0)
                continue;
              if (memcmp (re->lla, dst_lla, 16) != 0)
                continue;
              if (memcmp (re->ep_ip, src_ip, 16) != 0
                  || re->ep_port != src_port)
                continue;
              if (lla_id (re->nhop_lla) != dnhop)
                continue;
              held = re;
              break;
            }
          if (!held)
            need = true;
          else if (held->seq != dseq
                   || path_hash (held->path, held->path_len) != dhash)
            need = true;
        }
      if (need && *req_cnt < req_cap)
        {
          u32_wr (req_ids + (size_t)*req_cnt * 4, did);
          (*req_cnt)++;
        }
    }
  (void)a;
  return 0;
}

static bool ent_exp_ok (const Re *re, const uint8_t our_lla[16]);

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
      if (!re->is_act || re->state == RT_DED)
        continue;
      if (memcmp (re->lla, cfg->addr, 16) == 0)
        continue;
      if (re->ep_port == 0)
        continue;
      AdvSes *ses = adv_ses_get (a, re->lla, re->sid);
      if (!ses)
        continue;
      bool peer_no_dir = false;
      (void)rt_src_no_dir_known (rt, re->lla, &peer_no_dir);
      bool self_dir_ok = cfg->p2p == P2P_EN && !peer_no_dir;
      bool need_set = rev_changed || ses->dgst_ts == 0
                      || (now - ses->dgst_ts >= ADV_DGST_INTV);
      AdvEnt *set = NULL;
      uint32_t set_cnt = 0;
      if (need_set)
        {
          set = malloc ((size_t)(rt->cnt ? rt->cnt : 1) * sizeof (AdvEnt));
          if (set)
            set_cnt = adv_set_bld (rt, cfg->addr, self_dir_ok, peer_no_dir,
                                   NULL, set, rt->cnt);
        }
      if (ses->unack_buf)
        {
          uint64_t rto = re->rto ? re->rto : RTO_INIT;
          if (now - ses->unack_ts >= rto)
            {
              if (adv_send (udp, cry_ctx, rt, cfg, re, PT_ADV_UPD,
                            ses->unack_buf, ses->unack_len, now))
                ses->unack_ts = now;
            }
        }
      else if (set)
        {
          for (uint32_t q = 0; q < ses->inval_cnt; q++)
            {
              for (uint32_t k = 0; k < ses->sent_cnt; k++)
                {
                  if (lla_id (ses->sent[k].lla) != ses->inval[q])
                    continue;
                  bool in_cur = false;
                  for (uint32_t m = 0; m < set_cnt; m++)
                    if (ent_key_eq (&set[m], &ses->sent[k]))
                      in_cur = true;
                  if (in_cur)
                    {
                      AdvEnt gone = ses->sent[k];
                      sent_del (ses, &gone);
                      k--;
                    }
                }
            }
          ses->inval_cnt = 0;
          uint32_t budget = rt_mtu_ub (rt);
          if (budget > 100U)
            budget -= 100U;
          size_t used = 6;
          uint32_t ch_cap = set_cnt + ses->sent_cnt;
          AdvEnt *ch = malloc ((size_t)(ch_cap ? ch_cap : 1)
                               * sizeof (AdvEnt));
          uint32_t ch_cnt = 0;
          if (ch)
            {
              for (uint32_t k = 0; k < set_cnt; k++)
                {
                  int si = sent_fnd (ses, &set[k]);
                  if (si >= 0 && ent_eq (&ses->sent[si], &set[k]))
                    continue;
                  size_t esz = ent_sz (&set[k]);
                  if (ch_cnt > 0 && used + esz > budget)
                    continue;
                  ch[ch_cnt++] = set[k];
                  used += esz;
                }
              for (uint32_t k = 0; k < ses->sent_cnt; k++)
                {
                  bool in_cur = false;
                  for (uint32_t m = 0; m < set_cnt; m++)
                    if (ent_key_eq (&set[m], &ses->sent[k]))
                      in_cur = true;
                  if (in_cur)
                    continue;
                  bool has_rec = false;
                  for (uint32_t m = 0; m < rt->cnt; m++)
                    {
                      const Re *re = &rt->re_arr[m];
                      if (memcmp (re->lla, ses->sent[k].lla, 16) == 0
                          && memcmp (re->nhop_lla, ses->sent[k].nhop_lla,
                                     16) == 0
                          && memcmp (re->ep_ip, ses->sent[k].ep_ip, 16) == 0
                          && re->ep_port == ses->sent[k].ep_port
                          && ent_exp_ok (re, cfg->addr))
                        has_rec = true;
                    }
                  if (has_rec)
                    continue;
                  AdvEnt wd = ses->sent[k];
                  wd.adv_m = RT_F_INF;
                  wd.state = (uint8_t)RT_DED;
                  size_t esz = ent_sz (&wd);
                  if (ch_cnt > 0 && used + esz > budget)
                    continue;
                  ch[ch_cnt++] = wd;
                  used += esz;
                }
            }
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
                      ses->unack_buf = pl;
                      ses->unack_len = off;
                      ses->unack_seq = seq;
                      ses->unack_ts = now;
                      free (ses->pend);
                      ses->pend = ch;
                      ses->pend_cnt = ch_cnt;
                      ch = NULL;
                    }
                  else
                    free (pl);
                }
            }
          free (ch);
        }
      if (set && (ses->dgst_ts == 0
                  || now - ses->dgst_ts >= ADV_DGST_INTV))
        {
          size_t pl_len = 2 + (size_t)set_cnt * 16;
          uint8_t *pl = malloc (pl_len);
          if (pl)
            {
              u16_wr (pl, (uint16_t)set_cnt);
              for (uint32_t k = 0; k < set_cnt; k++)
                {
                  uint8_t *ln = pl + 2 + (size_t)k * 16;
                  uint32_t pth[ADV_PATH_MAX];
                  uint8_t ent_nhop[16];
                  memcpy (pth, set[k].path, sizeof (pth));
                  memcpy (ent_nhop, set[k].nhop_lla, 16);
                  u32_wr (ln, lla_id (set[k].lla));
                  u32_wr (ln + 4, lla_id (ent_nhop));
                  u32_wr (ln + 8, set[k].seq);
                  u32_wr (ln + 12, path_hash (pth, set[k].path_len));
                }
              if (adv_send (udp, cry_ctx, rt, cfg, re, PT_ADV_DGST, pl,
                            pl_len, now))
                ses->dgst_ts = now;
              free (pl);
            }
        }
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
  u32_wr (dst + 38, src->seq);
  u32_wr (dst + 42, src->adv_m);
  dst[46] = src->adv_loss;
  memcpy (dst + 47, src->nhop_lla, 16);
  u64_wr (dst + 63, src->ver);
  dst[71] = src->path_len;
  for (uint8_t i = 0; i < src->path_len; i++)
    u32_wr (dst + 72 + (size_t)i * 4, src->path[i]);
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
  dst->seq = u32_rd (src + 38);
  dst->adv_m = u32_rd (src + 42);
  dst->adv_loss = src[46];
  memcpy (dst->nhop_lla, src + 47, 16);
  dst->ver = u64_rd (src + 63);
  dst->path_len = src[71];
  if (dst->path_len > ADV_PATH_MAX)
    return -1;
  size_t need = ADV_CORE_SZ + 1 + (size_t)dst->path_len * 4;
  if (avail < need)
    return -1;
  for (uint8_t i = 0; i < dst->path_len; i++)
    dst->path[i] = u32_rd (src + 72 + (size_t)i * 4);
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
  if (!re->is_act || re->state != RT_ACT)
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
  if (is_ip_bgn (re->ep_ip))
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
      = (re->is_act && re->state == RT_ACT) ? rt_dir_mtu_adv (rt, re) : 0;
  out->seq = re->seq;
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
          if (!nh->is_act || nh->state != RT_ACT)
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
  return true;
}

uint32_t
adv_set_bld (Rt *rt, const uint8_t our_lla[16], bool self_dir_ok,
             bool dst_no_dir, const uint8_t tgt_lla[16], AdvEnt *out,
             uint32_t max_cnt)
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
      memset (&out[n], 0, sizeof (AdvEnt));
      if (!ent_bld (rt, re, our_lla, self_dir_ok, dst_no_dir, &out[n]))
        continue;
      n++;
    }
  return n;
}

uint8_t *
seq_req_bld (Cry *s, const uint8_t tgt_lla[16], uint8_t *buf,
             const uint8_t dst_lla[16], size_t *out_len)
{
  uint8_t payload[16];
  memcpy (payload, tgt_lla, 16);
  uint8_t hdr[PKT_CH_SZ];
  hdr_bld (PT_SEQ_REQ, 0, 32, hdr);
  return pkt_enc_to (s, dst_lla, hdr, payload, sizeof (payload), buf, out_len);
}

int
adv_import (const uint8_t *pt, size_t pt_len, const uint8_t src_ip[16],
        uint16_t src_port, const uint8_t src_lla_hint[16],
        const uint8_t our_lla[16], Rt *rt, PPool *pool, bool allow_dir_hint,
        uint64_t sys_ts, bool *is_mod, bool *o_req_seq, uint8_t seq_tgt[16])
{
  if (!pt || pt_len < 2)
    return -1;
  uint16_t cnt = u16_rd (pt);
  uint32_t rt_c_old = rt->cnt;
  *is_mod = false;
  if (o_req_seq)
    *o_req_seq = false;
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
  uint16_t mtu_s = mtu_inf_s (rt, src_ip, src_port);
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
          if (is_ip_bgn (ent.ep_ip))
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
              if (tp_mask == 0)
                tp_mask = TP_MASK_UDP | TP_MASK_TCP;
              rt_ep_upd (rt, z_lla, ent.ep_ip, ent.ep_port, tp_mask,
                         sys_ts);
              if (pool)
                {
                  pp_add (pool, ent.ep_ip, ent.ep_port);
                }
            }
          continue;
        }
      uint32_t n_seq = ent.seq;
      int32_t adv_m = ent.adv_m;
      uint16_t ent_mtu = ent.mtu;
      bool no_dir = (ent.flags & ADV_F_NO_DIR) != 0;
      uint16_t rel_mtu = 0;
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
      if (mtu_s > 0 && ent_mtu > 0)
        {
          rel_mtu = (mtu_s < ent_mtu) ? mtu_s : ent_mtu;
        }
      else if (mtu_s > 0)
        {
          rel_mtu = mtu_s;
        }
      else
        {
          rel_mtu = ent_mtu;
        }
      bool is_s_alive = ((RtSt)ent.state != RT_DED);
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
          continue;
      }
      bool is_s_owner
          = has_s_lla && memcmp (src_lla, ent.lla, 16) == 0;
      SrcEnt *se = NULL;
      for (uint32_t si = 0; si < rt->src_cnt; si++)
        {
          if (memcmp (rt->sources[si].rt_id, ent.lla, 16) == 0)
            {
              se = &rt->sources[si];
              break;
            }
        }
      if (se && seq_lt (n_seq, se->seq) && o_req_seq && seq_tgt)
        {
          *o_req_seq = true;
          memcpy (seq_tgt, ent.lla, 16);
        }
      rt_src_upd_auth (rt, ent.lla, n_seq, ent.ver, no_dir,
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
          rel_re.seq = n_seq;
          rel_re.adv_m = adv_m;
          rel_re.adv_loss = ent.adv_loss;
          rel_re.r2d = 1;
          rel_re.rt_m = adv_m;
          rel_re.path_len = ent.path_len;
          memcpy (rel_re.path, ent.path, sizeof (rel_re.path));
          if (rel_mtu > 0)
            {
              rel_re.mtu = rel_mtu;
              rel_re.mtu_lkg = rel_mtu;
              rel_re.mtu_ukb = rel_mtu;
            }
          rel_re.state = is_s_alive ? RT_ACT : RT_DED;
          rel_re.is_act = is_s_alive;
          rel_re.tp_mask = 0;
          if ((ent.flags & ADV_F_TP_UDP) != 0)
            rel_re.tp_mask |= TP_MASK_UDP;
          if ((ent.flags & ADV_F_TP_TCP) != 0)
            rel_re.tp_mask |= TP_MASK_TCP;
          if (rel_re.tp_mask == 0)
            rel_re.tp_mask = TP_MASK_UDP | TP_MASK_TCP;
          rel_re.rto = RTO_INIT;
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
          if (is_ip_bgn (ent.ep_ip))
            continue;
          if (p_is_me (rt, our_lla, ent.ep_ip, ent.ep_port))
            continue;
          Re dir_re;
          memset (&dir_re, 0, sizeof (dir_re));
          memcpy (dir_re.lla, ent.lla, 16);
          memcpy (dir_re.ep_ip, ent.ep_ip, 16);
          dir_re.ep_port = ent.ep_port;
          dir_re.ver = ent.ver;
          dir_re.seq = n_seq;
          dir_re.adv_m = adv_m;
          dir_re.adv_loss = ent.adv_loss;
          dir_re.r2d = 0;
          dir_re.rt_m = RT_F_INF;
          dir_re.sm_m = RT_M_INF;
          dir_re.state = ((RtSt)ent.state == RT_DED) ? RT_DED : RT_PND;
          dir_re.is_act = false;
          dir_re.tp_mask = 0;
          if ((ent.flags & ADV_F_TP_UDP) != 0)
            dir_re.tp_mask |= TP_MASK_UDP;
          if ((ent.flags & ADV_F_TP_TCP) != 0)
            dir_re.tp_mask |= TP_MASK_TCP;
          if (dir_re.tp_mask == 0)
            dir_re.tp_mask = TP_MASK_UDP | TP_MASK_TCP;
          dir_re.rto = RTO_INIT;
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

int
on_seq_req (const uint8_t *pt, size_t pt_len, uint8_t tgt_lla[16])
{
  if (!pt)
    return -1;
  if (pt_len < 16)
    return -1;
  memcpy (tgt_lla, pt, 16);
  return 0;
}
