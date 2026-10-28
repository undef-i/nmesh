#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <stddef.h>
#include <stdint.h>


typedef struct
{
  uint8_t lla[16];
  uint64_t sid;
  uint32_t tx_nxt;
  uint32_t rx_last;
  uint32_t unack_seq;
  uint64_t unack_ts;
  uint8_t *unack_buf;
  size_t unack_len;
  bool unack_retx;
  uint64_t srtt_ms;
  uint64_t rttvar_ms;
  uint64_t rto_ms;
  AdvEnt *sent;
  uint32_t sent_cnt;
  uint32_t sent_cap;
  AdvEnt *pend;
  uint32_t pend_cnt;
  bool acc;
} AdvSes;

typedef struct Adv
{
  AdvSes *ses;
  uint32_t cnt;
  uint32_t cap;
  uint64_t last_rev;
} Adv;

void adv_init (Adv *a);
void adv_free (Adv *a);
AdvSes *adv_ses_get (Adv *a, const uint8_t lla[16], uint64_t sid);
void adv_ses_drop (Adv *a, const uint8_t lla[16]);
void adv_tick (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, Adv *a,
               uint64_t now);
int adv_on_upd (Adv *a, const uint8_t src_lla[16], const uint8_t *pt,
                size_t pt_len, uint32_t *ack_seq);
int adv_on_ack (Adv *a, const uint8_t src_lla[16], const uint8_t *pt,
                size_t pt_len, uint64_t now);
uint8_t *adv_ack_bld (Cry *s, uint32_t seq, const uint8_t dst_lla[16],
                      uint8_t *buf, size_t *out_len);

size_t adv_ent_ser (uint8_t *dst, const AdvEnt *src);
int adv_ent_des (AdvEnt *dst, const uint8_t *src, size_t avail);
uint32_t adv_set_bld (Rt *rt, const uint8_t our_lla[16], bool self_dir_ok,
                      bool dst_no_dir, bool is_p2p,
                      const uint8_t tgt_lla[16], AdvEnt *out,
                      uint32_t max_cnt);
int adv_import (const uint8_t *pt, size_t pt_len, const uint8_t src_ip[16],
                uint16_t src_port, const uint8_t src_lla_hint[16],
                const uint8_t our_lla[16], Rt *rt, PPool *pool,
                bool allow_dir_hint, uint64_t sys_ts, bool *is_mod);
