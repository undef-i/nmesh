#pragma once
#include "config.h"
#include "crypto.h"
#include "packet.h"
#include "route.h"
#include "udp.h"
#include "utils.h"
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

typedef struct
{
  size_t len;
  uint8_t buf[TAP_F_MAX + TAP_HR + TAP_TR];
} TapSlot;

typedef struct
{
  int tap_fd;
  int note_fd;
  int stop_fd;
  Udp *udp;
  Cry *cry_ctx;
  uint64_t sid;
  pthread_t tid_arr[2];
  bool tid_on[2];
  bool stop_req;
  pthread_rwlock_t snap_lk;
  bool snap_lk_init;
  pthread_mutex_t q_mtx;
  bool q_mtx_init;
  pthread_cond_t q_ne;
  bool q_ne_init;
  pthread_cond_t q_nf;
  bool q_nf_init;
  uint32_t q_head;
  uint32_t q_tail;
  uint32_t q_cnt;
  TapSlot q_arr[BATCH_MAX];
  Rt rt;
  Cfg cfg;
  uint64_t snap_ts;
} TapPipe;

typedef void (*LoopReadyFn) (void *arg);

void on_udp_emsg (const uint8_t dst_ip[16], uint16_t dst_port,
                  size_t atmpt_plen);
void on_udp_unr (const uint8_t dst_ip[16], uint16_t dst_port);
void udp_ep_upd (int epfd, int udp_fd, bool w_want, bool *w_watch);
int tap_pipe_init (TapPipe *tap_pipe, int tap_fd, Udp *udp, Cry *cry_ctx,
                   uint64_t sid);
int tap_pipe_note_fd_get (const TapPipe *tap_pipe);
void tap_pipe_note_hnd (TapPipe *tap_pipe);
void tap_pipe_sync (TapPipe *tap_pipe, const Rt *rt, const Cfg *cfg,
                    uint64_t now);
int tap_pipe_start (TapPipe *tap_pipe);
void tap_pipe_stop (TapPipe *tap_pipe);
void tap_pipe_join (TapPipe *tap_pipe);
void tap_pipe_free (TapPipe *tap_pipe);
void rt_loc_add (Rt *rt, const uint8_t our_lla[16], uint16_t port,
                 uint64_t now);
bool tap_frame_tx (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt,
                   const Cfg *cfg, uint64_t sid, uint64_t now,
                   uint8_t *vnet_frame, size_t vnet_len);
bool tap_frame_flush (Udp *udp);
void on_tap (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             uint64_t sid, uint64_t now);
void on_udp (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             uint64_t sid, PPool *pool);
void on_tmr (int timer_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             uint16_t act_port, uint64_t sid, PPool *pool);
size_t status_buf_bld (char *buf, size_t cap, Rt *rt, const Cfg *cfg,
                       PPool *pool);
void status_fd_emit (int fd, Rt *rt, const Cfg *cfg, PPool *pool);
void on_std (int fd, Rt *rt, const Cfg *cfg, PPool *pool);
void tty_raw (void);
void cfg_reload_apply (Cfg *cfg, Cry *cry_ctx, Rt *rt, PPool *pool,
                       const char *cfg_path, uint64_t ts);
void gsp_dirty_flush (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg);
int loop_run (const char *cfg_path, const Cfg *cfg_in, uint64_t sid,
              bool daemon_child, LoopReadyFn ready_fn, void *ready_arg);
