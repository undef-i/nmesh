#pragma once
#include "config.h"
#include "crypto.h"
#include "nbr.h"
#include "packet.h"
#include "route.h"
#include "udp.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct Adv Adv;

typedef enum
{
  ADM_UNKNOWN = 0,
  ADM_PROBING = 1,
  ADM_ADMITTED = 2,
  ADM_SUSPECT = 3,
  ADM_DEAD = 4
} AdmSt;

typedef struct
{
  uint8_t lla[16];
  AdmSt st;
  uint8_t ep_ip[16];
  uint16_t ep_port;
  bool ep_ok;
  uint8_t cand_ip[16];
  uint16_t cand_port;
  bool cand_ok;
  uint8_t seed_ip[16];
  uint16_t seed_port;
  uint64_t sid;
  bool sid_ok;
  bool kx_cur;
  bool tp_tcp;
  bool is_static;
  bool p2p_ok;
  uint8_t ckie_in[IBS_CKIE_SZ];
  bool ckie_in_ok;
  uint8_t ckie_src_ip[16];
  uint16_t ckie_src_port;
  bool chal_ok;
  uint64_t chal_buck;
  uint64_t tok_cur;
  uint64_t tok_prv;
  uint64_t tok_ts;
  uint64_t tok_wts;
  uint64_t ts_adm;
  uint64_t ts_pong;
  uint64_t ts_seen;
  uint64_t ts_dead;
  uint64_t chal_cnt;
  uint64_t drop_ibs;
  uint64_t drop_tok;
  uint64_t drop_ckie;
  uint64_t drop_state;
  uint64_t ep_sw;
} AdmEnt;

typedef struct Adm
{
  AdmEnt *arr;
  uint32_t cnt;
  uint32_t cap;
  uint64_t drop_oth;
  uint64_t chal_oth;
  uint64_t drop_ckie_oth;
  pthread_mutex_t mtx;
} Adm;

typedef enum
{
  ADJ_ADMIT = 0,
  ADJ_CHAL = 1,
  ADJ_DROP = 2
} AdjRes;

typedef struct
{
  AdjRes res;
  uint8_t lla[16];
  bool has_lla;
  uint8_t ckie_pl[IBS_CKIE_PL_SZ];
} AdjOut;

Adm *adm_glob (void);
void adm_init (Adm *a);
void adm_lock (Adm *a);
void adm_unlock (Adm *a);
AdmEnt *adm_fnd (Adm *a, const uint8_t lla[16]);
AdmEnt *adm_get (Adm *a, const Cfg *cfg, const uint8_t lla[16]);
void adm_seed (Adm *a, Rt *rt, const Cfg *cfg, PPool *pool);
void adm_tick (Adm *a, Rt *rt, Cry *cry, Adv *adv, const Cfg *cfg,
               uint64_t ts);
void adm_judge_ibs (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
                    uint8_t pt_type, const uint8_t *pl, size_t pl_sz,
                    const uint8_t *sig, const uint8_t src_ip[16],
                    uint16_t src_port, bool from_tcp, uint64_t ts,
                    AdjOut *out);
bool adm_judge_aead (Adm *a, Rt *rt, const Cfg *cfg,
                     const uint8_t lla[16], bool has_lla,
                     const uint8_t src_ip[16], uint16_t src_port,
                     uint64_t ts, AdjOut *out);
void adm_on_ckie (Adm *a, const uint8_t src_ip[16], uint16_t src_port,
                  const uint8_t *pl, size_t pl_len);
void adm_tcp_auth (Adm *a, Cry *cry, Rt *rt, Adv *adv, const Cfg *cfg,
                   const uint8_t lla[16], const uint8_t ip[16],
                   uint16_t port, uint64_t sid, uint64_t ts);
void adm_tcp_close (Adm *a, const uint8_t lla[16]);
void adm_evidence (Adm *a, const Cfg *cfg, const uint8_t lla[16],
                   const uint8_t ip[16], uint16_t port);
uint64_t adm_tok_next (AdmEnt *e, uint64_t sys_ts, uint64_t wall_ts_v);
const char *adm_st_name (AdmSt st);
