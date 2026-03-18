#pragma once
#include "config.h"
#include "crypto.h"
#include "route.h"
#include "udp.h"
#include <stdbool.h>
#include <stdint.h>

void on_udp_emsg (const uint8_t dst_ip[16], uint16_t dst_port,
                  size_t atmpt_plen);
void on_udp_unr (const uint8_t dst_ip[16], uint16_t dst_port);
void udp_ep_upd (int epfd, int udp_fd, bool w_want, bool *w_watch);
void rt_loc_add (Rt *rt, const uint8_t our_lla[16], uint16_t port,
                 uint64_t now);
void on_tap (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             uint64_t sid, uint64_t now);
void on_udp (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             uint64_t sid, PPool *pool);
void on_tmr (int timer_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             int *gsp_off, const char *peers_path, uint16_t act_port,
             uint64_t sid, PPool *pool);
void on_std (int fd, Rt *rt, const Cfg *cfg, PPool *pool);
void tty_raw (void);
void cfg_reload_apply (Cfg *cfg, Cry *cry_ctx, Rt *rt, PPool *pool,
                       const char *cfg_path, uint64_t ts);