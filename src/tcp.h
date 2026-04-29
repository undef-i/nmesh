#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
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
#define TP_TXQ_FRAME_BYTES ((uint32_t)(sizeof (uint32_t) + TP_PL_MAX))
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
  uint32_t slot_idx;
  int fd;
  TpSt st;
  bool inbound;
  bool auth;
  bool hello_tx;
  uint64_t ts;
  uint8_t peer_lla[16];
  uint8_t sock_ip[16];
  uint16_t sock_port;
  uint8_t route_ip[16];
  uint16_t route_port;
  uint8_t hdr_buf[sizeof (uint32_t)];
  uint32_t hdr_have;
  uint32_t rx_len;
  uint32_t rx_have;
  uint8_t rx_buf[TP_PL_MAX];
  TpTxRing tx_hi;
  TpTxRing tx_lo;
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
  uint32_t tx_qd_cnt;
  uint32_t tx_bp_cnt;
} TpRt;

typedef void (*TpFrameFn) (const uint8_t *frame, size_t len, const TpSrc *src,
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
void tp_rt_conn_ready (TpRt *tp, int epfd, int fd, uint32_t events,
                       const Rt *rt, const Cfg *cfg, TpFrameFn cb,
                       void *cb_arg);
