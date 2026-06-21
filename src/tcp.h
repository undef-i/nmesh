#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define TP_EV_LISTEN 7ULL
#define TP_EV_CONN_BASE (1ULL << 32)
#define TP_IDX_INV UINT32_MAX
#define TP_CONN_CAP_INIT 512U
#define TP_CONN_SYN_RETRIES 3U
#define TP_WARN_INTV RT_PRB_INTV
#define TP_FLOW_IDLE_TMO (KA_TMO * 2ULL)
#define TP_WIRE_SALT_SZ (CRY_NONCE_WIRE_SZ + sizeof (uint64_t))
#define TP_WIRE_KEY_SZ crypto_aead_aegis128l_KEYBYTES
#define TP_WIRE_NONCE_SZ crypto_aead_aegis128l_NPUBBYTES
#define TP_WIRE_MAC_SZ crypto_aead_aegis128l_ABYTES
#define TP_KX_PUB_SZ crypto_scalarmult_BYTES
#define TP_KX_SEC_SZ crypto_scalarmult_SCALARBYTES
#define TP_TXQ_FRAME_BYTES                                                    \
  ((uint32_t)(sizeof (uint32_t) + TP_PL_MAX + TP_WIRE_MAC_SZ))
#define TP_TXQ_STOP_MULT 4U
#define TP_CONN_TMO                                                           \
  (RTO_INIT * ((1ULL << (TP_CONN_SYN_RETRIES + 1U)) - 1ULL))

typedef struct
{
  bool is_tcp;
  int tcp_fd;
  uint8_t peer_lla[16];
  uint8_t route_ip[16];
  uint16_t route_port;
} TpSrc;

typedef enum
{
  TP_ST_NONE = 0,
  TP_ST_CONNECTING,
  TP_ST_ESTABLISHED,
} TpSt;

typedef struct
{
  uint8_t *buf;
  uint32_t cap;
  uint32_t head;
  uint32_t len;
} TpTxRing;

typedef struct
{
  uint8_t *buf;
  uint32_t cap;
  uint32_t len;
} TpPendQ;

typedef struct
{
  uint8_t route_ip[16];
  uint8_t peer_lla[16];
  uint16_t route_port;
  uint32_t flow_hash;
  uint32_t conn_idx;
  uint64_t ts;
  bool has_peer;
} TpFlowEnt;

typedef struct
{
  uint32_t slot_idx;
  int fd;
  TpSt st;
  bool inbound;
  bool auth;
  bool hello_tx;
  uint64_t auth_tok;
  uint64_t ts;
  uint8_t peer_lla[16];
  uint8_t sock_ip[16];
  uint16_t sock_port;
  uint8_t route_ip[16];
  uint16_t route_port;
  uint32_t lane_hash;
  uint8_t hdr_buf[sizeof (uint32_t)];
  uint8_t wire_salt[TP_WIRE_SALT_SZ];
  uint8_t wire_rx_key[TP_WIRE_KEY_SZ];
  uint8_t wire_tx_key[TP_WIRE_KEY_SZ];
  uint8_t wire_kx_pk[TP_KX_PUB_SZ];
  uint8_t wire_kx_sk[TP_KX_SEC_SZ];
  uint8_t wire_peer_pk[TP_KX_PUB_SZ];
  uint64_t wire_rx_seq;
  uint64_t wire_tx_seq;
  bool wire_ready;
  bool wire_salt_tx;
  bool wire_kx_ready;
  bool wire_peer_kx_ready;
  bool wire_fs_ready;
  bool drain;
  uint8_t *rx_in;
  uint8_t *rx_buf;
  uint32_t rx_in_cap;
  uint32_t rx_in_off;
  uint32_t rx_in_len;
  uint32_t rx_cap;
  uint32_t hdr_have;
  uint32_t rx_len;
  uint32_t rx_have;
  TpTxRing tx_hi;
  TpTxRing tx_lo;
  TpPendQ tx_pend;
  uint32_t tx_q_bytes;
  uint32_t sndbuf_bytes;
  bool tx_qd;
  bool tx_bp;
  bool tx_defer;
} TpConn;

typedef struct
{
  int listen_fd;
  pthread_mutex_t mtx;
  TpConn **conn_arr;
  uint32_t conn_cap;
  uint32_t *fd_idx_arr;
  uint32_t fd_idx_cap;
  uint32_t *peer_hot_idx;
  uint32_t peer_hot_cap;
  uint32_t *ep_hot_idx;
  uint32_t ep_hot_cap;
  TpFlowEnt *flow_arr;
  uint32_t flow_cnt;
  uint32_t flow_cap;
  uint32_t tx_qd_cnt;
  uint32_t tx_bp_cnt;
} TpRt;

typedef bool (*TpFrameFn) (const uint8_t *frame, size_t len, const TpSrc *src,
                           void *arg);

int tp_rt_init (TpRt *tp, uint16_t port);
void tp_rt_free (TpRt *tp);
int tp_rt_listen_fd_get (const TpRt *tp);
void tp_glb_bind (TpRt *tp, int epfd, Cry *cry_ctx, const Cfg *cfg,
                  uint64_t sid);
void tp_glb_unbind (void);
bool tp_rtt_get (const uint8_t ip[16], uint16_t port, uint32_t *out_rtt_ms);
bool tp_alive_get (const uint8_t peer_lla[16], const uint8_t ip[16],
                   uint16_t port);
bool tp_send (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len);
bool tp_send_flow (Udp *udp, const Rt *rt, const Cfg *cfg,
                   const uint8_t ip[16], uint16_t port, const uint8_t *data,
                   size_t len, uint32_t flow_hash);
bool tp_send_ctrl (Udp *udp, const Rt *rt, const Cfg *cfg,
                   const uint8_t ip[16], uint16_t port, const uint8_t *data,
                   size_t len);
bool tp_probe (const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
               uint16_t port);
bool tp_send_fd (int fd, const uint8_t *data, size_t len);
void tp_batch_begin (void);
void tp_batch_end (void);
bool tp_tx_pending (void);
bool tp_w_want (void);
void tp_rt_tick (TpRt *tp, Rt *rt, const Cfg *cfg);
void tp_rt_accept_ready (TpRt *tp, int epfd);
void tp_rt_conn_ready (TpRt *tp, int epfd, int fd, uint32_t events, Rt *rt,
                       const Cfg *cfg, TpFrameFn cb, void *cb_arg);
