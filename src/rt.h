#pragma once
#include "uthash.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define RT_MAX 256
#define PEER_MAX 64
#define RTT_UNK UINT32_MAX
#define RTO_MIN 200U
#define RTO_MAX 30000U
#define RTO_INIT 1000U
#define RT_M_INF 0xFFFFU
#define RT_MTU_MIN 128U
#define RT_MTU_DEF 1280U
#define RT_MTU_MAX 65535U

typedef enum
{
  RT_ACT = 0,
  RT_PND = 1,
  RT_DED = 2,
} RtSt;

typedef enum
{
  MTU_ST_B = 0,
  MTU_ST_S = 1,
  MTU_ST_F = 2,
} MtuSt;

#define IS_LLA_VAL(ip) ((ip)[0] == 0xfe && ((ip)[1] & 0xc0) == 0x80)

typedef struct
{
  uint8_t lla[16];
  uint8_t ep_ip[16];
  uint16_t ep_port;
  uint64_t ver;
  uint64_t sid;
  uint32_t seq;
  uint32_t adv_m;
  uint32_t rt_m;
  uint8_t nhop_lla[16];
  RtSt state;
  bool is_act;
  bool is_static;
  uint64_t pong_ts;
  uint64_t rx_ts;
  uint64_t tx_ts;
  uint64_t rx_base;
  uint16_t rx_bmp;
  uint32_t srtt;
  uint32_t rttvar;
  uint32_t rto;
  uint32_t sm_m;
  uint32_t lat;
  uint32_t r2d;
  uint16_t mtu;
  uint16_t mtu_lkg;
  uint16_t mtu_ukb;
  MtuSt mtu_st;
  uint64_t prb_i_ts;
  uint16_t mtu_flr;
  uint16_t mtu_cel;
  uint16_t prb_mtu;
  uint32_t prb_id;
  uint8_t prb_tx;
  uint64_t prb_tx_ts;
  uint64_t prb_ddl;
  uint64_t ack_ts;
  uint64_t vfy_ts;
  uint64_t hld_ts;
  uint64_t prb_ts;
  uint8_t tnt_ip[16];
  uint16_t tnt_port;
  uint64_t tnt_sid;
} Re;

typedef struct Pth
{
  uint8_t ep_ip[16];
  uint16_t ep_port;
  uint64_t ver;
  uint64_t sid;
  uint32_t seq;
  uint32_t adv_m;
  uint32_t rt_m;
  uint8_t nhop_lla[16];
  RtSt state;
  bool is_act;
  bool is_static;
  uint64_t pong_ts;
  uint64_t rx_ts;
  uint64_t tx_ts;
  uint64_t rx_base;
  uint16_t rx_bmp;
  uint32_t srtt;
  uint32_t rttvar;
  uint32_t rto;
  uint32_t sm_m;
  uint32_t lat;
  uint32_t r2d;
  uint16_t mtu;
  uint16_t mtu_lkg;
  uint16_t mtu_ukb;
  MtuSt mtu_st;
  uint64_t prb_i_ts;
  uint16_t mtu_flr;
  uint16_t mtu_cel;
  uint16_t prb_mtu;
  uint32_t prb_id;
  uint8_t prb_tx;
  uint64_t prb_tx_ts;
  uint64_t prb_ddl;
  uint64_t ack_ts;
  uint64_t vfy_ts;
  uint64_t hld_ts;
  uint64_t prb_ts;
  uint8_t tnt_ip[16];
  uint16_t tnt_port;
  uint64_t tnt_sid;
  struct Pth *next;
} Pth;

typedef struct RtMap
{
  uint8_t lla[16];
  Pth *paths;
  Pth *sel_pth;
  UT_hash_handle hh;
} RtMap;

typedef struct EpIdx
{
  uint8_t key[18];
  uint8_t ep_ip[16];
  uint16_t ep_port;
  uint32_t b_dir_m;
  UT_hash_handle hh;
} EpIdx;

typedef struct
{
  uint8_t rt_id[16];
  uint32_t fwd_seq;
  uint32_t fwd_m;
  uint64_t last_ver;
  uint64_t gc_ts;
} SrcEnt;

typedef struct
{
  uint8_t ip[16];
  uint16_t port;
} PAnc;

typedef struct
{
  PAnc re_arr[PEER_MAX];
  int cnt;
  const char *persist_path;
  bool is_dirty;
} PPool;

typedef struct
{
  RtMap *map;
  EpIdx *dir_m_idx;
  Re *re_arr;
  uint32_t cnt;
  uint32_t cap;
  SrcEnt *sources;
  uint32_t src_cnt;
  uint32_t src_cap;
  uint8_t our_lla[16];
  uint32_t prb_nxt_id;
  uint16_t mtu_ub;
  bool map_dirty;
  bool has_trg;
  uint8_t trg_lla[16];
} Rt;

typedef enum
{
  RT_DIR = 0,
  RT_REL,
  RT_VP,
  RT_NONE,
} RtDecT;

typedef struct
{
  RtDecT type;

  union
  {
    struct
    {
      uint8_t ip[16];
      uint16_t port;
    } dir;

    struct
    {
      uint8_t relay_ip[16];
      uint16_t relay_port;
      uint8_t relay_lla[16];
    } rel;
  };
} RtDec;

void rt_init (Rt *t);
void rt_upd (Rt *t, const Re *re, uint64_t sys_ts);
bool rt_dir_fnd (Rt *t, const uint8_t dst_lla[16], Re *out);
void rt_rtt_upd (Rt *t, const uint8_t peer_lla[16], const uint8_t ip[16],
                 uint16_t port, uint32_t rtt_ms, uint64_t sys_ts);
void rt_ep_upd (Rt *t, const uint8_t lla[16], const uint8_t ip[16],
                uint16_t port, uint64_t sys_ts);
void rt_rx_ack (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts);
void rt_tx_ack (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts);
bool rt_trg_pop (Rt *t, uint8_t out_lla[16]);
RtDec rt_sel (Rt *t, const uint8_t dst_lla[16], bool is_p2p);
uint16_t rt_mtu (const Rt *t, const RtDec *sel);
bool rt_mprb_rdy (Rt *t, uint64_t sys_ts, Re *out_re, uint16_t *prb_mtu,
                  uint32_t *prb_id);
void rt_pmtu_ack_ep (Rt *t, const uint8_t ip[16], uint16_t port,
                     uint32_t probe_id, uint16_t probe_mtu, uint64_t sys_ts);
void rt_mtu_tk (Rt *t, uint64_t sys_ts);
void rt_pmtu_ub_set (Rt *t, uint16_t mtu);
void rt_emsg_hnd (Rt *t, const uint8_t ip[16], uint16_t port,
                  size_t atmpt_plen, uint64_t sys_ts);
void rt_unr_hnd (Rt *t, const uint8_t ip[16], uint16_t port, uint64_t sys_ts);
bool rt_pmtu_st (const Rt *t, const RtDec *sel, uint16_t *out_path_mtu,
                 uint16_t *prb_mtu, bool *out_is_searching,
                 bool *out_is_fixed);
bool rt_pmtu_lims (const Rt *t, const RtDec *sel, uint16_t *out_lkg,
                   uint16_t *out_ukb, MtuSt *state);
int rt_act_get (Rt *t, Re *buf, int buf_len, int s_off);
void rt_prn_st (Rt *t, uint64_t sys_ts);
void rt_src_gc (Rt *t, uint64_t sys_ts);
bool rt_fsb (Rt *t, const uint8_t rt_id[16], uint32_t n_seq, uint32_t n_metric,
             uint64_t n_ver, bool *req_seq);
void rt_src_upd (Rt *t, const uint8_t rt_id[16], uint32_t seq, uint32_t metric,
                 uint64_t ver, uint64_t sys_ts);
bool rt_peer_sess (Rt *t, const uint8_t rt_id[16], uint64_t peer_sid,
                   uint64_t sys_ts);
void rt_dad_stl (Rt *t, uint64_t sys_ts, PPool *pool, const char *peers_path);
void pp_init (PPool *p, const char *persist_path);
void pp_add (PPool *p, const uint8_t ip[16], uint16_t port);
