#include "loop.h"
#include "bogon.h"
#include "config.h"
#include "crypto.h"
#include "forward.h"
#include "frag.h"
#include "gossip.h"
#include "gro.h"
#include "mss.h"
#include "packet.h"
#include "replay.h"
#include "route.h"
#include "tap.h"
#include "udp.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/virtio_net.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <termios.h>
#include <unistd.h>

void
on_udp_emsg (const uint8_t dst_ip[16], uint16_t dst_port, size_t atmpt_plen)
{
  if (!g_rt)
    return;
  rt_emsg_hnd (g_rt, dst_ip, dst_port, atmpt_plen, sys_ts ());
}

void
on_udp_unr (const uint8_t dst_ip[16], uint16_t dst_port)
{
  if (!g_rt)
    return;
  rt_unr_hnd (g_rt, dst_ip, dst_port, sys_ts ());
}

void
udp_ep_upd (int epfd, int udp_fd, bool w_want, bool *w_watch)
{
  if (!w_watch)
    return;
  if (*w_watch == w_want)
    return;
  struct epoll_event ev;
  ev.events = EPOLLIN | (w_want ? EPOLLOUT : 0);
  ev.data.u64 = ID_UDP;
  if (epoll_ctl (epfd, EPOLL_CTL_MOD, udp_fd, &ev) == 0)
    {
      *w_watch = w_want;
    }
}

#define TAP_Q_PROC_MAX 32

static void tap_note_tx (int note_fd);
static void tap_note_rx (int note_fd);
static void tap_pipe_stop_wake (TapPipe *tap_pipe);
static void *tap_read_loop (void *arg);
static void *tap_loop (void *arg);
static bool ctrl_pkt_is (uint8_t pkt_type);
static size_t tap_loop_stk_sz (void);

static int
cpu_aff_avail_cnt (void)
{
  cpu_set_t set;
  CPU_ZERO (&set);
  if (sched_getaffinity (0, sizeof (set), &set) != 0)
    {
      long cpu_cnt = sysconf (_SC_NPROCESSORS_ONLN);
      return (cpu_cnt > 0) ? (int)cpu_cnt : 1;
    }
  int cnt = 0;
  for (int i = 0; i < CPU_SETSIZE; i++)
    {
      if (CPU_ISSET (i, &set))
        cnt++;
    }
  return cnt > 0 ? cnt : 1;
}

static void
thr_aff_pin (pthread_t tid, int cpu_idx)
{
  long cpu_cnt = sysconf (_SC_NPROCESSORS_ONLN);
  if (cpu_cnt <= 1 || cpu_idx < 0)
    return;
  cpu_idx %= (int)cpu_cnt;
  cpu_set_t set;
  CPU_ZERO (&set);
  CPU_SET (cpu_idx, &set);
  (void)pthread_setaffinity_np (tid, sizeof (set), &set);
}

int
tap_pipe_init (TapPipe *tap_pipe, int tap_fd, Udp *udp, Cry *cry_ctx,
               uint64_t sid)
{
  if (!tap_pipe || tap_fd < 0 || !udp || !cry_ctx)
    return -1;
  memset (tap_pipe, 0, sizeof (*tap_pipe));
  rt_init (&tap_pipe->rt);
  tap_pipe->tap_fd = tap_fd;
  tap_pipe->note_fd = -1;
  tap_pipe->stop_fd = -1;
  tap_pipe->note_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  tap_pipe->stop_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  tap_pipe->udp = udp;
  tap_pipe->cry_ctx = cry_ctx;
  tap_pipe->sid = sid;
  if (tap_pipe->note_fd < 0 || tap_pipe->stop_fd < 0)
    {
      tap_pipe_free (tap_pipe);
      return -1;
    }
  if (pthread_rwlock_init (&tap_pipe->snap_lk, NULL) != 0)
    {
      tap_pipe_free (tap_pipe);
      return -1;
    }
  tap_pipe->snap_lk_init = true;
  if (pthread_mutex_init (&tap_pipe->q_mtx, NULL) != 0)
    {
      tap_pipe_free (tap_pipe);
      return -1;
    }
  tap_pipe->q_mtx_init = true;
  if (pthread_cond_init (&tap_pipe->q_ne, NULL) != 0)
    {
      tap_pipe_free (tap_pipe);
      return -1;
    }
  tap_pipe->q_ne_init = true;
  if (pthread_cond_init (&tap_pipe->q_nf, NULL) != 0)
    {
      tap_pipe_free (tap_pipe);
      return -1;
    }
  tap_pipe->q_nf_init = true;
  return 0;
}

int
tap_pipe_note_fd_get (const TapPipe *tap_pipe)
{
  return tap_pipe ? tap_pipe->note_fd : -1;
}

void
tap_pipe_note_hnd (TapPipe *tap_pipe)
{
  if (!tap_pipe)
    return;
  tap_note_rx (tap_pipe->note_fd);
  (void)udp_w_hnd (tap_pipe->udp);
}

void
tap_pipe_sync (TapPipe *tap_pipe, const Rt *rt, const Cfg *cfg, uint64_t now)
{
  if (!tap_pipe || !rt || !cfg)
    return;
  pthread_rwlock_wrlock (&tap_pipe->snap_lk);
  if (rt_cpy (&tap_pipe->rt, rt) == 0)
    {
      tap_pipe->cfg = *cfg;
      tap_pipe->snap_ts = now;
    }
  else
    {
      fprintf (stderr, "main: tap snapshot refresh failed\n");
    }
  pthread_rwlock_unlock (&tap_pipe->snap_lk);
}

int
tap_pipe_start (TapPipe *tap_pipe)
{
  if (!tap_pipe)
    return -1;
  if (pthread_create (&tap_pipe->tid_arr[0], NULL, tap_read_loop, tap_pipe)
      != 0)
    return -1;
  tap_pipe->tid_on[0] = true;
  pthread_attr_t attr;
  bool attr_on = false;
  bool stk_on = false;
  if (pthread_attr_init (&attr) == 0)
    {
      attr_on = true;
      if (pthread_attr_setstacksize (&attr, tap_loop_stk_sz ()) == 0)
        stk_on = true;
    }
  if (pthread_create (&tap_pipe->tid_arr[1], stk_on ? &attr : NULL, tap_loop,
                      tap_pipe)
      != 0)
    {
      if (attr_on)
        pthread_attr_destroy (&attr);
      tap_pipe_stop_wake (tap_pipe);
      pthread_join (tap_pipe->tid_arr[0], NULL);
      tap_pipe->tid_on[0] = false;
      return -1;
    }
  if (attr_on)
    pthread_attr_destroy (&attr);
  tap_pipe->tid_on[1] = true;
  thr_aff_pin (tap_pipe->tid_arr[0], 1);
  thr_aff_pin (tap_pipe->tid_arr[1], 2);
  return 0;
}

static void
tap_note_tx (int note_fd)
{
  uint64_t one = 1;
  if (note_fd >= 0)
    (void)write (note_fd, &one, sizeof (one));
}

static void
tap_note_rx (int note_fd)
{
  uint64_t val;
  while (note_fd >= 0 && read (note_fd, &val, sizeof (val)) > 0)
    {
    }
}

static void
tap_pipe_stop_wake (TapPipe *tap_pipe)
{
  uint64_t one = 1;
  if (!tap_pipe)
    return;
  if (tap_pipe->stop_fd >= 0)
    (void)write (tap_pipe->stop_fd, &one, sizeof (one));
  tap_note_tx (tap_pipe->note_fd);
}

void
tap_pipe_stop (TapPipe *tap_pipe)
{
  if (!tap_pipe)
    return;
  tap_pipe->stop_req = true;
  if (tap_pipe->q_mtx_init)
    {
      pthread_mutex_lock (&tap_pipe->q_mtx);
      pthread_cond_broadcast (&tap_pipe->q_ne);
      pthread_cond_broadcast (&tap_pipe->q_nf);
      pthread_mutex_unlock (&tap_pipe->q_mtx);
    }
  tap_pipe_stop_wake (tap_pipe);
}

void
tap_pipe_join (TapPipe *tap_pipe)
{
  if (!tap_pipe)
    return;
  for (int i = 0; i < 2; i++)
    {
      if (!tap_pipe->tid_on[i])
        continue;
      pthread_join (tap_pipe->tid_arr[i], NULL);
      tap_pipe->tid_on[i] = false;
    }
}

void
tap_pipe_free (TapPipe *tap_pipe)
{
  if (!tap_pipe)
    return;
  tap_pipe_stop (tap_pipe);
  tap_pipe_join (tap_pipe);
  rt_free (&tap_pipe->rt);
  if (tap_pipe->q_nf_init)
    {
      pthread_cond_destroy (&tap_pipe->q_nf);
      tap_pipe->q_nf_init = false;
    }
  if (tap_pipe->q_ne_init)
    {
      pthread_cond_destroy (&tap_pipe->q_ne);
      tap_pipe->q_ne_init = false;
    }
  if (tap_pipe->q_mtx_init)
    {
      pthread_mutex_destroy (&tap_pipe->q_mtx);
      tap_pipe->q_mtx_init = false;
    }
  if (tap_pipe->snap_lk_init)
    {
      pthread_rwlock_destroy (&tap_pipe->snap_lk);
      tap_pipe->snap_lk_init = false;
    }
  if (tap_pipe->stop_fd >= 0)
    {
      close (tap_pipe->stop_fd);
      tap_pipe->stop_fd = -1;
    }
  if (tap_pipe->note_fd >= 0)
    {
      close (tap_pipe->note_fd);
      tap_pipe->note_fd = -1;
    }
}

static void *
tap_read_loop (void *arg)
{
  TapPipe *tap_pipe = arg;
  struct pollfd pfd_arr[2];
  memset (pfd_arr, 0, sizeof (pfd_arr));
  pfd_arr[0].fd = tap_pipe->tap_fd;
  pfd_arr[0].events = POLLIN;
  pfd_arr[1].fd = tap_pipe->stop_fd;
  pfd_arr[1].events = POLLIN;
  for (;;)
    {
      int rc = poll (pfd_arr, 2, -1);
      if (rc < 0)
        {
          if (errno == EINTR)
            continue;
          break;
        }
      if ((pfd_arr[1].revents & POLLIN) != 0)
        {
          tap_note_rx (tap_pipe->stop_fd);
          break;
        }
      if ((pfd_arr[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        break;
      if ((pfd_arr[0].revents & POLLIN) == 0)
        continue;
      for (;;)
        {
          pthread_mutex_lock (&tap_pipe->q_mtx);
          while (!tap_pipe->stop_req && tap_pipe->q_cnt >= BATCH_MAX)
            pthread_cond_wait (&tap_pipe->q_nf, &tap_pipe->q_mtx);
          if (tap_pipe->stop_req)
            {
              pthread_mutex_unlock (&tap_pipe->q_mtx);
              return NULL;
            }
          uint32_t idx = tap_pipe->q_tail;
          pthread_mutex_unlock (&tap_pipe->q_mtx);

          ssize_t n = read (tap_pipe->tap_fd, tap_pipe->q_arr[idx].buf + TAP_HR,
                            TAP_F_MAX);
          if (n <= 0)
            {
              if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
              return NULL;
            }
          if (n <= VNET_HL)
            continue;

          pthread_mutex_lock (&tap_pipe->q_mtx);
          tap_pipe->q_arr[idx].len = (size_t)n;
          tap_pipe->q_tail = (tap_pipe->q_tail + 1U) % BATCH_MAX;
          tap_pipe->q_cnt++;
          pthread_cond_signal (&tap_pipe->q_ne);
          pthread_mutex_unlock (&tap_pipe->q_mtx);
        }
    }
  return NULL;
}

static void *
tap_loop (void *arg)
{
  TapPipe *tap_pipe = arg;
  uint32_t idx_arr[TAP_Q_PROC_MAX];
  for (;;)
    {
      pthread_mutex_lock (&tap_pipe->q_mtx);
      while (!tap_pipe->stop_req && tap_pipe->q_cnt == 0)
        pthread_cond_wait (&tap_pipe->q_ne, &tap_pipe->q_mtx);
      if (tap_pipe->stop_req && tap_pipe->q_cnt == 0)
        {
          pthread_mutex_unlock (&tap_pipe->q_mtx);
          break;
        }
      int take_cnt = (tap_pipe->q_cnt < TAP_Q_PROC_MAX) ? (int)tap_pipe->q_cnt
                                                        : TAP_Q_PROC_MAX;
      for (int i = 0; i < take_cnt; i++)
        idx_arr[i] = (tap_pipe->q_head + (uint32_t)i) % BATCH_MAX;
      pthread_mutex_unlock (&tap_pipe->q_mtx);

      pthread_rwlock_rdlock (&tap_pipe->snap_lk);
      uint64_t now = sys_ts ();
      bool tap_ok = true;
      int done_cnt = 0;
      while (done_cnt < take_cnt && !udp_w_want (tap_pipe->udp))
        {
          uint32_t idx = idx_arr[done_cnt];
          tap_ok = tap_frame_tx (tap_pipe->tap_fd, tap_pipe->udp,
                                 tap_pipe->cry_ctx, &tap_pipe->rt,
                                 &tap_pipe->cfg, tap_pipe->sid, now,
                                 tap_pipe->q_arr[idx].buf + TAP_HR,
                                 tap_pipe->q_arr[idx].len);
          if (!tap_ok)
            break;
          done_cnt++;
        }
      bool flush_ok = tap_frame_flush (tap_pipe->udp);
      bool want_w = udp_w_want (tap_pipe->udp);
      pthread_rwlock_unlock (&tap_pipe->snap_lk);

      if (done_cnt > 0)
        {
          pthread_mutex_lock (&tap_pipe->q_mtx);
          tap_pipe->q_head = (tap_pipe->q_head + (uint32_t)done_cnt) % BATCH_MAX;
          tap_pipe->q_cnt -= (uint32_t)done_cnt;
          pthread_cond_signal (&tap_pipe->q_nf);
          pthread_mutex_unlock (&tap_pipe->q_mtx);
        }
      if (want_w)
        tap_note_tx (tap_pipe->note_fd);
      if (!tap_ok || !flush_ok)
        {
        }
    }
  return NULL;
}

static uint64_t um_prb_intv (uint64_t age_ms);

typedef struct
{
  PktHdr hdr;
  uint8_t *pt;
  size_t pt_len;
  int dec_res;
} UdpDecRes;

static void
udp_dec_run (Cry *cry_ctx, UdpRxPkt pkt_arr[], UdpDecRes res_arr[],
             int pkt_cnt)
{
  for (int i = 0; i < pkt_cnt; i++)
    {
      res_arr[i].dec_res = pkt_dec (cry_ctx, pkt_arr[i].data,
                                    pkt_arr[i].data_len, NULL, 0,
                                    &res_arr[i].hdr, &res_arr[i].pt,
                                    &res_arr[i].pt_len);
    }
}

static bool
p_is_me (const Rt *rt, const uint8_t our_lla[16], const uint8_t ip[16],
         uint16_t port)
{
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
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
is_ip_loopback (const uint8_t ip[16])
{
  if (!ip)
    return false;
  if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
      && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0
      && ip[10] == 0xff && ip[11] == 0xff && ip[12] == 127)
    return true;
  for (int i = 0; i < 15; i++)
    {
      if (ip[i] != 0)
        return false;
    }
  return ip[15] == 1;
}

static bool
lla_is_z (const uint8_t lla[16])
{
  static const uint8_t z_lla[16] = { 0 };
  return memcmp (lla, z_lla, 16) == 0;
}

static Re *
rt_re_fnd (Rt *rt, const uint8_t lla[16])
{
  if (!rt || !lla)
    return NULL;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (memcmp (re->lla, lla, 16) != 0)
        continue;
      return re;
    }
  return NULL;
}

static bool
re_is_stdby (Rt *rt, const Re *re, bool is_p2p)
{
  if (!rt || !re || re->r2d != 0 || lla_is_z (re->lla))
    return false;
  RtDec dec = rt_sel (rt, re->lla, is_p2p);
  if (dec.type == RT_DIR)
    {
      if (memcmp (re->ep_ip, dec.dir.ip, 16) == 0 && re->ep_port == dec.dir.port)
        return false;
      return true;
    }
  if (dec.type == RT_REL)
    return true;
  return false;
}

static void
pulse_tx (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, Re *re, uint64_t ts,
          uint64_t sid, bool may_rel)
{
  if (!udp || !cry_ctx || !rt || !cfg || !re)
    return;
  if (!lla_is_z (re->lla) && may_rel && cfg->p2p == P2P_EN)
    {
      RtDec rd = rt_sel (rt, re->lla, true);
      if (rd.type == RT_REL)
        {
          uint64_t intv = (re->state == RT_ACT && re->rt_m < RT_M_INF)
                              ? KA_TMO
                              : um_prb_intv ((re->tx_ts > re->rx_ts
                                                  && ts > re->tx_ts)
                                                 ? (ts - re->tx_ts)
                                             : (ts > re->rx_ts)
                                                 ? (ts - re->rx_ts)
                                                 : 0);
          if (re->hp_ts != 0 && ts > re->hp_ts && (ts - re->hp_ts) < intv)
            return;
          uint8_t hp_buf[UDP_PL_MAX];
          size_t hp_len = 0;
          hp_bld (cry_ctx, cfg->addr, re->lla, hp_buf, &hp_len);
          udp_tx (udp, rd.rel.relay_ip, rd.rel.relay_port, hp_buf, hp_len);
          rt->ctrl_tx_b += (uint64_t)hp_len;
          re->hp_ts = ts;
        }
    }
  uint8_t p_buf[UDP_PL_MAX];
  size_t p_len = 0;
  uint64_t p_ts = sys_ts ();
  uint64_t p_tok = ((uint64_t)u32_rnd () << 32) | (uint64_t)u32_rnd ();
  ping_bld (cry_ctx, cfg->addr, p_ts, sid, p_tok, p_buf, &p_len);
  udp_tx (udp, re->ep_ip, re->ep_port, p_buf, p_len);
  rt->ping_tx_cnt++;
  rt->ctrl_tx_b += (uint64_t)p_len;
  re->prb_ts = p_ts;
  re->prb_tok = p_tok;
  rt_tx_ack (rt, re->ep_ip, re->ep_port, ts);
}

static struct termios g_tty_old;
static bool g_tty_sav = false;

static void
tty_rst (void)
{
  if (!g_tty_sav)
    return;
  tcsetattr (STDIN_FILENO, TCSANOW, &g_tty_old);
  g_tty_sav = false;
}

void
tty_raw (void)
{
  if (!isatty (STDIN_FILENO))
    return;
  struct termios t;
  if (tcgetattr (STDIN_FILENO, &g_tty_old) != 0)
    return;
  g_tty_sav = true;
  atexit (tty_rst);
  t = g_tty_old;
  t.c_lflag &= ~(ICANON | ECHO);
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 0;
  tcsetattr (STDIN_FILENO, TCSANOW, &t);
}

static uint32_t
re_show_m (const Re *re)
{
  if (!re)
    return RT_M_INF;
  if (re->dir_cost >= 0 && re->dir_cost < (int64_t)RT_M_INF)
    return (uint32_t)re->dir_cost;
  if (re->lat > 0 && re->lat < RTT_UNK)
    return re->lat;
  if (re->sm_m > 0 && re->sm_m < RT_M_INF && re->sm_m != RTT_UNK)
    return re->sm_m;
  return RT_M_INF;
}

static uint32_t
rt_show_m (const Rt *rt, const uint8_t dst_lla[16], const RtDec *sel)
{
  if (sel->type == RT_DIR)
    {
      uint32_t best = RT_M_INF;
      for (uint32_t i = 0; i < rt->cnt; i++)
        {
          const Re *re = &rt->re_arr[i];
          if (!re->is_act || re->state == RT_DED)
            continue;
          if (re->r2d != 0)
            continue;
          if (memcmp (re->lla, dst_lla, 16) != 0)
            continue;
          if (memcmp (re->ep_ip, sel->dir.ip, 16) != 0)
            continue;
          if (re->ep_port != sel->dir.port)
            continue;
          uint32_t m = re_show_m (re);
          if (m < best)
            best = m;
        }
      return best;
    }
  if (sel->type == RT_REL)
    {
      uint32_t m_rd = RT_M_INF;
      for (uint32_t i = 0; i < rt->cnt; i++)
        {
          const Re *re = &rt->re_arr[i];
          if (!re->is_act || re->state == RT_DED)
            continue;
          if (re->r2d == 0)
            continue;
          if (memcmp (re->lla, dst_lla, 16) != 0)
            continue;
          if (memcmp (re->ep_ip, sel->rel.relay_ip, 16) != 0)
            continue;
          if (re->ep_port != sel->rel.relay_port)
            continue;
          uint32_t m_adv = (re->r2d > 0) ? re->r2d : re->adv_m;
          if (m_adv == 0 || m_adv == RTT_UNK || m_adv >= RT_M_INF)
            m_adv = re->adv_m;
          if (m_adv == 0 || m_adv == RTT_UNK || m_adv >= RT_M_INF)
            continue;
          if (m_adv < m_rd)
            m_rd = m_adv;
        }
      uint32_t m_lr = RT_M_INF;
      for (uint32_t i = 0; i < rt->cnt; i++)
        {
          const Re *re = &rt->re_arr[i];
          if (!re->is_act || re->state == RT_DED)
            continue;
          if (re->r2d != 0)
            continue;
          if (memcmp (re->ep_ip, sel->rel.relay_ip, 16) != 0)
            continue;
          if (re->ep_port != sel->rel.relay_port)
            continue;
          uint32_t m = re_show_m (re);
          if (m < m_lr)
            m_lr = m;
        }
      if (m_rd >= RT_M_INF || m_lr >= RT_M_INF)
        return RT_M_INF;
      return m_lr + m_rd;
    }
  return RT_M_INF;
}

static bool
rt_key_get (const Rt *rt, const uint8_t *frame, const uint8_t our_lla[16],
            uint8_t out_lla[16])
{
  (void)rt;
  if (!frame || !out_lla || !our_lla)
    return false;
  const uint8_t *dst_mac = frame;
  if (dst_mac[0] != 0x02 || dst_mac[1] != 0x00)
    return false;
  memcpy (out_lla, our_lla, 16);
  out_lla[12] = dst_mac[2];
  out_lla[13] = dst_mac[3];
  out_lla[14] = dst_mac[4];
  out_lla[15] = dst_mac[5];
  return memcmp (out_lla, our_lla, 16) != 0;
}

static bool
mesh_dst_lla_from_frame (const uint8_t *frame, const uint8_t base_lla[16],
                         uint8_t out_lla[16])
{
  if (!frame || !base_lla || !out_lla)
    return false;
  const uint8_t *dst_mac = frame;
  if (dst_mac[0] != 0x02 || dst_mac[1] != 0x00)
    return false;
  memcpy (out_lla, base_lla, 16);
  out_lla[12] = dst_mac[2];
  out_lla[13] = dst_mac[3];
  out_lla[14] = dst_mac[4];
  out_lla[15] = dst_mac[5];
  return true;
}

static bool
mesh_src_lla_from_frame (const uint8_t *frame, const uint8_t base_lla[16],
                         uint8_t out_lla[16])
{
  if (!frame || !base_lla || !out_lla)
    return false;
  const uint8_t *src_mac = frame + ETH_ALEN;
  if (src_mac[0] != 0x02 || src_mac[1] != 0x00)
    return false;
  memcpy (out_lla, base_lla, 16);
  out_lla[12] = src_mac[2];
  out_lla[13] = src_mac[3];
  out_lla[14] = src_mac[4];
  out_lla[15] = src_mac[5];
  return true;
}

static bool
mesh_src_lla_from_ip6 (const uint8_t *frame, size_t frame_len,
                       uint8_t out_lla[16])
{
  if (!frame || !out_lla || frame_len < ETH_HLEN + 40U)
    return false;
  uint16_t eth_type = (uint16_t)(((uint16_t)frame[12] << 8) | frame[13]);
  if (eth_type != ETH_P_IPV6)
    return false;
  const uint8_t *ip6 = frame + ETH_HLEN;
  memcpy (out_lla, ip6 + 8, 16);
  return IS_LLA_VAL (out_lla);
}

void
rt_loc_add (Rt *rt, const uint8_t our_lla[16], uint16_t port, uint64_t now)
{
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs (&ifaddr) != 0)
    return;
  for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if (!ifa->ifa_addr)
        continue;
      if ((ifa->ifa_flags & IFF_LOOPBACK) != 0)
        continue;
      if ((ifa->ifa_flags & IFF_UP) == 0)
        continue;
      uint8_t ip[16] = { 0 };
      bool is_ok = false;
      if (ifa->ifa_addr->sa_family == AF_INET)
        {
          struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
          ip[10] = 0xff;
          ip[11] = 0xff;
          memcpy (ip + 12, &sa->sin_addr, 4);
          is_ok = true;
        }
      else if (ifa->ifa_addr->sa_family == AF_INET6)
        {
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
          memcpy (ip, &sa6->sin6_addr, 16);
          is_ok = true;
        }
      if (!is_ok)
        continue;
      if (!is_underlay_ip (ip))
        continue;
      Re s_re;
      memset (&s_re, 0, sizeof (s_re));
      memcpy (s_re.lla, our_lla, 16);
      memcpy (s_re.ep_ip, ip, 16);
      s_re.ep_port = port;
      s_re.is_act = true;
      s_re.state = RT_ACT;
      s_re.lat = 0;
      s_re.sm_m = 0;
      s_re.dir_cost = INT64_MAX;
      s_re.rt_m = 0;
      s_re.adv_m = 0;
      s_re.seq = 1;
      s_re.rto = RTO_INIT;
      memcpy (s_re.nhop_lla, our_lla, 16);
      rt_upd (rt, &s_re, now);
    }
  freeifaddrs (ifaddr);
}

static bool
pool_has_peer (const PPool *pool, const uint8_t ip[16], uint16_t port)
{
  for (int i = 0; i < pool->cnt; i++)
    {
      if (memcmp (pool->re_arr[i].ip, ip, 16) == 0
          && pool->re_arr[i].port == port)
        return true;
    }
  return false;
}

void
cfg_reload_apply (Cfg *cfg, Cry *cry_ctx, Rt *rt, PPool *pool,
                  const char *cfg_path, uint64_t ts)
{
  Cfg new_cfg;
  if (cfg_load (cfg_path, &new_cfg) != 0)
    return;
  bogon_cfg_apply (&new_cfg);
  if (memcmp (cfg->addr, new_cfg.addr, 16) != 0)
    fprintf (stderr, "main: address changed in config but not hot-applied\n");
  if (cfg->port != new_cfg.port || cfg->l_exp != new_cfg.l_exp)
    fprintf (stderr,
             "main: listen/port changed in config but not hot-applied\n");
  if (cfg->mtu != new_cfg.mtu)
    {
      cfg->mtu = new_cfg.mtu;
      tap_mtu_set (cfg->ifname, cfg->mtu);
      fprintf (stderr, "main: reloaded tap mtu to %u\n", (unsigned)cfg->mtu);
    }
  if (cfg->mtu_probe != new_cfg.mtu_probe)
    {
      cfg->mtu_probe = new_cfg.mtu_probe;
      rt_mtu_probe_set (rt, cfg->mtu_probe);
      if (!cfg->mtu_probe)
        rt_mtu_probe_idle (rt);
      fprintf (stderr, "main: reloaded mtu_probe mode\n");
    }
  if (cfg->p2p != new_cfg.p2p)
    {
      cfg->p2p = new_cfg.p2p;
      fprintf (stderr, "main: reloaded p2p mode\n");
    }
  if (cfg->bogon_cnt != new_cfg.bogon_cnt
      || memcmp (cfg->bogon_arr, new_cfg.bogon_arr, sizeof (cfg->bogon_arr)) != 0)
    {
      cfg->bogon_cnt = new_cfg.bogon_cnt;
      memcpy (cfg->bogon_arr, new_cfg.bogon_arr, sizeof (cfg->bogon_arr));
      bogon_cfg_apply (cfg);
      fprintf (stderr, "main: reloaded bogon filter\n");
    }
  if (memcmp (cfg->psk, new_cfg.psk, 32) != 0)
    {
      memcpy (cfg->psk, new_cfg.psk, 32);
      cry_init (cry_ctx, cfg->psk);
      fprintf (stderr, "main: reloaded psk\n");
    }
  P peers[RT_MAX];
  int peer_cnt = p_arr_ld (cfg_path, peers, RT_MAX);
  int add_cnt = 0;
  for (int i = 0; i < peer_cnt; i++)
    {
      Re ne;
      memset (&ne, 0, sizeof (ne));
      memcpy (ne.ep_ip, peers[i].ip, 16);
      ne.ep_port = peers[i].port;
      ne.is_act = false;
      ne.is_static = true;
      ne.state = RT_PND;
      ne.lat = RTT_UNK;
      ne.dir_cost = INT64_MAX;
      ne.rto = RTO_INIT;
      rt_upd (rt, &ne, ts);
      if (!pool_has_peer (pool, peers[i].ip, peers[i].port)
          && pool->cnt < PEER_MAX)
        {
          memcpy (pool->re_arr[pool->cnt].ip, peers[i].ip, 16);
          pool->re_arr[pool->cnt].port = peers[i].port;
          pool->cnt++;
          add_cnt++;
        }
    }
  fprintf (stderr, "main: config reloaded, peers loaded=%d, peers added=%d\n",
           peer_cnt, add_cnt);
}

int
loop_run (const char *cfg_path, const Cfg *cfg_in, uint64_t sid,
          bool daemon_child, LoopReadyFn ready_fn, void *ready_arg)
{
  if (!cfg_path || !cfg_in)
    return 1;

  int rc = 1;
  Cfg cfg = *cfg_in;
  static PPool pool;
  pp_init (&pool, cfg_path);
  Rt rt;
  rt_init (&rt);
  rt_mtu_probe_set (&rt, cfg.mtu_probe);
  memcpy (rt.our_lla, cfg.addr, 16);

  int tap_fd = -1;
  bool tap_created = false;
  static Udp udp;
  memset (&udp, 0, sizeof (udp));
  udp.fd = -1;
  bool udp_inited = false;
  static TapPipe tap_pipe;
  bool tap_pipe_inited = false;
  bool tap_inline = (cpu_aff_avail_cnt () <= 1);
  int epfd = -1;
  int timer_fd = -1;
  int cfg_ifd = -1;
  bool u_w_watch = false;
  bool stdin_watch = false;

  P peers[RT_MAX];
  int peer_cnt = p_arr_ld (cfg_path, peers, RT_MAX);
  for (int i = 0; i < peer_cnt; i++)
    {
      Re ne;
      memset (&ne, 0, sizeof (ne));
      memcpy (ne.ep_ip, peers[i].ip, 16);
      ne.ep_port = peers[i].port;
      ne.is_act = false;
      ne.is_static = true;
      ne.state = RT_PND;
      ne.lat = RTT_UNK;
      ne.dir_cost = INT64_MAX;
      ne.rto = RTO_INIT;
      rt_upd (&rt, &ne, 0);
      bool is_dup = false;
      for (int j = 0; j < pool.cnt; j++)
        {
          if (memcmp (pool.re_arr[j].ip, peers[i].ip, 16) == 0
              && pool.re_arr[j].port == peers[i].port)
            {
              is_dup = true;
              break;
            }
        }
      if (!is_dup && pool.cnt < PEER_MAX)
        {
          memcpy (pool.re_arr[pool.cnt].ip, peers[i].ip, 16);
          pool.re_arr[pool.cnt].port = peers[i].port;
          pool.cnt++;
        }
    }

  Cry cry_ctx;
  cry_init (&cry_ctx, cfg.psk);
  tap_stl_rm (cfg.ifname);
  tap_fd = tap_init (cfg.ifname);
  if (tap_fd < 0)
    {
      fprintf (stderr, "main: failed to create tap\n");
      goto out;
    }
  tap_created = true;
  if (tap_addr_set (cfg.ifname, cfg.addr) != 0)
    {
      fprintf (stderr, "main: failed to configure tap address\n");
      goto out;
    }
  if (tap_mtu_set (cfg.ifname, cfg.mtu) != 0)
    {
      fprintf (stderr, "main: failed to configure tap mtu\n");
      goto out;
    }
  printf ("main: tap device %s created (mtu=%u).\n", cfg.ifname,
          (unsigned)cfg.mtu);

  uint16_t act_port = cfg.port;
  if (udp_init (&udp, &act_port) != 0)
    {
      if (!cfg.l_exp)
        {
          act_port = 0;
          if (udp_init (&udp, &act_port) != 0)
            {
              fprintf (stderr, "main: failed to bind udp port\n");
              goto out;
            }
        }
      else
        {
          fprintf (stderr, "main: failed to bind explicit udp port %u\n",
                   cfg.port);
          goto out;
        }
    }
  udp_inited = true;
  g_rt = &rt;
  udp_emsg_cb_set (on_udp_emsg);
  udp_unr_cb_set (on_udp_unr);
  printf ("main: udp bound to port %u\n", act_port);
  {
    uint16_t hw_mtu = udp_mtu_get (&udp);
    rt_pmtu_ub_set (&rt, hw_mtu);
  }
  rt_loc_add (&rt, cfg.addr, act_port, sys_ts ());

  if (!tap_inline)
    {
      if (tap_pipe_init (&tap_pipe, tap_fd, &udp, &cry_ctx, sid) != 0)
        {
          fprintf (stderr, "main: failed to init tap pipeline\n");
          goto out;
        }
      tap_pipe_inited = true;
    }

  epfd = epoll_create1 (EPOLL_CLOEXEC);
  if (epfd < 0)
    {
      perror ("main: epoll_create1 failed");
      goto out;
    }

  struct epoll_event ev;
  memset (&ev, 0, sizeof (ev));
  ev.events = EPOLLIN;
  ev.data.u64 = tap_inline ? ID_TAP : ID_TAP_NOTE;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD,
                 tap_inline ? tap_fd : tap_pipe_note_fd_get (&tap_pipe), &ev)
      != 0)
    {
      perror (tap_inline ? "main: epoll add tap failed"
                         : "main: epoll add tap note failed");
      goto out;
    }
  ev.events = EPOLLIN | EPOLLERR;
  ev.data.u64 = ID_UDP;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, udp.fd, &ev) != 0)
    {
      perror ("main: epoll add udp failed");
      goto out;
    }

  timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (timer_fd < 0)
    {
      perror ("main: timerfd_create failed");
      goto out;
    }
  struct itimerspec its;
  memset (&its, 0, sizeof (its));
  its.it_value.tv_nsec = 1000000;
  its.it_interval.tv_sec = GSP_INTV;
  if (timerfd_settime (timer_fd, 0, &its, NULL) != 0)
    {
      perror ("main: timerfd_settime failed");
      goto out;
    }
  ev.events = EPOLLIN;
  ev.data.u64 = ID_TMR;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, timer_fd, &ev) != 0)
    {
      perror ("main: epoll add timer failed");
      goto out;
    }

  if (!daemon_child && isatty (STDIN_FILENO))
    {
      tty_raw ();
      int stdin_flg = fcntl (STDIN_FILENO, F_GETFL, 0);
      if (stdin_flg >= 0)
        (void)fcntl (STDIN_FILENO, F_SETFL, stdin_flg | O_NONBLOCK);
      ev.events = EPOLLIN;
      ev.data.u64 = ID_STD;
      if (epoll_ctl (epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == 0)
        stdin_watch = true;
    }

  char cfg_dir[PATH_MAX];
  char cfg_file[NAME_MAX];
  const char *cfg_name = cfg_path;
  const char *slash = strrchr (cfg_path, '/');
  if (slash)
    {
      size_t dlen = (size_t)(slash - cfg_path);
      if (dlen >= sizeof (cfg_dir))
        dlen = sizeof (cfg_dir) - 1;
      memcpy (cfg_dir, cfg_path, dlen);
      cfg_dir[dlen] = '\0';
      cfg_name = slash + 1;
    }
  else
    {
      snprintf (cfg_dir, sizeof (cfg_dir), ".");
    }
  size_t cfg_name_len = strlen (cfg_name);
  if (cfg_name_len >= sizeof (cfg_file))
    cfg_name_len = sizeof (cfg_file) - 1;
  memcpy (cfg_file, cfg_name, cfg_name_len);
  cfg_file[cfg_name_len] = '\0';

  cfg_ifd = inotify_init1 (IN_NONBLOCK | IN_CLOEXEC);
  if (cfg_ifd < 0)
    {
      fprintf (stderr, "main: inotify init failed; config reload disabled\n");
    }
  else
    {
      int wd
          = inotify_add_watch (cfg_ifd, cfg_dir, IN_CLOSE_WRITE | IN_MOVED_TO);
      if (wd < 0)
        {
          fprintf (stderr, "main: inotify watch failed for %s\n", cfg_dir);
          close (cfg_ifd);
          cfg_ifd = -1;
        }
      else
        {
          ev.events = EPOLLIN;
          ev.data.u64 = ID_CFG;
          if (epoll_ctl (epfd, EPOLL_CTL_ADD, cfg_ifd, &ev) != 0)
            {
              fprintf (stderr, "main: epoll add cfg watcher failed\n");
              close (cfg_ifd);
              cfg_ifd = -1;
            }
          else
            {
              fprintf (stderr, "main: config watcher active: %s\n", cfg_path);
            }
        }
    }

  printf ("main: nmesh running; entering epoll loop\n");
  if (stdin_watch)
    printf ("main: type 's' and press enter to view routing table\n");
  fflush (stdout);

  on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, act_port, sid, &pool);
  rt_gsp_dirty_set (&rt, "initial");
  if (!tap_inline)
    {
      tap_pipe_sync (&tap_pipe, &rt, &cfg, sys_ts ());
      if (tap_pipe_start (&tap_pipe) != 0)
        {
          fprintf (stderr, "main: failed to start tap pipeline threads\n");
          goto out;
        }
    }
  udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
  if (ready_fn)
    ready_fn (ready_arg);
  rc = 0;

  struct epoll_event ev_arr[EV_MAX];
  while (1)
    {
      int nev = epoll_wait (epfd, ev_arr, EV_MAX, -1);
      if (nev < 0)
        {
          if (errno == EINTR)
            continue;
          perror ("main: epoll_wait failed");
          rc = 1;
          break;
        }
      for (int i = 0; i < nev; i++)
        {
          uint64_t tok = ev_arr[i].data.u64;
          if (tok == ID_TAP)
            {
              on_tap (tap_fd, &udp, &cry_ctx, &rt, &cfg, sid, sys_ts ());
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_TAP_NOTE)
            {
              tap_pipe_note_hnd (&tap_pipe);
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_UDP)
            {
              if ((ev_arr[i].events & EPOLLIN) != 0)
                {
                  do
                    {
                      on_udp (tap_fd, &udp, &cry_ctx, &rt, &cfg, sid, &pool);
                    }
                  while (udp_rx_pending ());
                }
              if ((ev_arr[i].events & EPOLLERR) != 0)
                {
                  uint8_t dst_ip[16];
                  uint16_t dst_port = 0;
                  uint16_t pmtu = 0;
                  while (udp_err_rd (&udp, dst_ip, &dst_port, &pmtu) == 0)
                    rt_pmtu_ptb_ep (&rt, dst_ip, dst_port, pmtu, sys_ts ());
                }
              if ((ev_arr[i].events & EPOLLOUT) != 0)
                (void)udp_w_hnd (&udp);
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_TMR)
            {
              on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, act_port, sid,
                      &pool);
              if (!tap_inline)
                tap_pipe_sync (&tap_pipe, &rt, &cfg, sys_ts ());
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_STD)
            {
              on_std (STDIN_FILENO, &rt, &cfg, &pool);
            }
          else if (tok == ID_CFG && cfg_ifd >= 0)
            {
              char evbuf[4096];
              ssize_t n = read (cfg_ifd, evbuf, sizeof (evbuf));
              if (n > 0)
                {
                  bool need_reload = false;
                  for (ssize_t off = 0; off < n;)
                    {
                      struct inotify_event *ie
                          = (struct inotify_event *)(evbuf + off);
                      if (ie->len > 0 && strcmp (ie->name, cfg_file) == 0
                          && ((ie->mask & IN_CLOSE_WRITE)
                              || (ie->mask & IN_MOVED_TO)))
                        need_reload = true;
                      off += (ssize_t)sizeof (struct inotify_event)
                             + (ssize_t)ie->len;
                    }
                  if (need_reload)
                    {
                      uint64_t now = sys_ts ();
                      cfg_reload_apply (&cfg, &cry_ctx, &rt, &pool, cfg_path,
                                        now);
                      if (!tap_inline)
                        tap_pipe_sync (&tap_pipe, &rt, &cfg, now);
                    }
                }
            }
        }
      gsp_dirty_flush (&udp, &cry_ctx, &rt, &cfg);
      udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
    }

out:
  if (cfg_ifd >= 0)
    close (cfg_ifd);
  if (timer_fd >= 0)
    close (timer_fd);
  if (epfd >= 0)
    close (epfd);
  if (tap_pipe_inited)
    tap_pipe_free (&tap_pipe);
  if (udp_inited)
    udp_free (&udp);
  if (tap_fd >= 0)
    close (tap_fd);
  if (tap_created)
    tap_iface_cleanup (cfg.ifname);
  rt_free (&rt);
  g_rt = NULL;
  return rc;
}


typedef struct
{
  uint8_t rt_key[16];
  uint8_t tx_ip[16];
  uint16_t tx_port;
  uint16_t pmtu;
  RtDecT type;
  uint8_t rel_f;
  bool is_val;
} TapTxPath;

typedef struct
{
  uint8_t dest_lla[16];
  TapTxPath tx_path;
  uint64_t val_ts;
  bool is_val;
} TapFast;

typedef struct
{
  const uint8_t *frm;
  size_t frm_len;
  size_t mac_hl;
  size_t ip_hl;
  size_t udp_off;
  size_t pl_off;
  size_t pl_len;
  size_t pl_pos;
  size_t seg_pl;
  uint32_t sum_base;
  bool is_v6;
} TapUso;

typedef struct
{
  const uint8_t *frm;
  size_t frm_len;
  size_t mac_hl;
  size_t ip_hl;
  size_t tcp_off;
  size_t pl_off;
  size_t pl_len;
  size_t pl_pos;
  size_t seg_pl;
  uint8_t tcp_hl;
  uint8_t tcp_flags;
  uint16_t ip_id;
  uint32_t seq0;
  uint32_t sum_base;
  bool is_v6;
} TapTso;

#define TAP_TSO_PAR_MIN 12
#define TAP_TSO_PAR_MAX 64

typedef struct
{
  pthread_t tid;
  pthread_mutex_t mtx;
  pthread_cond_t cv;
  pthread_cond_t done_cv;
  bool is_on;
  bool is_busy;
  bool stop;
  bool ok;
  TapTso tso;
  int seg_bgn;
  int seg_end;
  uint8_t buf_arr[TAP_TSO_PAR_MAX][TAP_F_MAX + TAP_HR + TAP_TR]
      __attribute__ ((aligned (32)));
  size_t len_arr[TAP_TSO_PAR_MAX];
} TapTsoPar;

static TapTsoPar g_tso_par;
static pthread_once_t g_tso_par_once = PTHREAD_ONCE_INIT;

typedef struct
{
  uint64_t l_nh_ts;
  TapFast fast_path[256];
  uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR]
      __attribute__ ((aligned (32)));
  uint8_t uso_bufs[TAP_TSO_PAR_MAX][TAP_F_MAX + TAP_HR + TAP_TR]
      __attribute__ ((aligned (32)));
  UdpMsg batch_arr[BATCH_MAX];
  int bc;
} TapRun;

static _Thread_local TapRun g_tap_run;

static size_t
tap_loop_stk_sz (void)
{
  size_t stk_sz = (size_t)PTHREAD_STACK_MIN;
  stk_sz += sizeof (TapRun);
  stk_sz += sizeof (TapTso);
  stk_sz += sizeof (TapUso);
  stk_sz += sizeof (TapTxPath) * 4U;
  long pg_sz = sysconf (_SC_PAGESIZE);
  size_t pg = (pg_sz > 0) ? (size_t)pg_sz : 4096U;
  size_t rem = stk_sz % pg;
  if (rem != 0)
    stk_sz += pg - rem;
  return stk_sz;
}

static void tap_rel_pulse (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                           uint64_t now, uint64_t sid,
                           const TapTxPath *tx_path);
static void tap_tx_mark (Rt *rt, uint64_t now, const TapTxPath *tx_path);

static bool tap_data_tx (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                         uint64_t sid, uint64_t now, uint8_t *vnet_frame,
                         size_t vnet_len,
                         uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR],
                         UdpMsg batch_arr[BATCH_MAX], int *bc,
                         TapFast fast_path[256], uint64_t *l_nh_ts,
                         const TapTxPath *tx_path, bool pulse_apply,
                         bool tx_ack_apply, bool mss_apply);

static bool tap_data_fast (Udp *udp, Cry *cry_ctx, const TapTxPath *tx_path,
                           uint64_t now, uint8_t *vnet_frame, size_t vnet_len,
                           UdpMsg batch_arr[BATCH_MAX], int *bc);
static bool tap_data_fast_cnt (Udp *udp, Cry *cry_ctx,
                               const TapTxPath *tx_path, uint64_t now,
                               uint64_t cnt, uint8_t *vnet_frame,
                               size_t vnet_len, UdpMsg batch_arr[BATCH_MAX],
                               int *bc);
static bool tap_msg_add (Udp *udp, const UdpMsg *msg, uint64_t now,
                         UdpMsg batch_arr[BATCH_MAX], int *bc);

static uint16_t
tx_path_pmtu_get (const Cfg *cfg, const uint8_t tx_ip[16], uint16_t path_mtu)
{
  uint16_t pmtu = (path_mtu >= RT_MTU_MIN) ? path_mtu : RT_MTU_MIN;
  if (!cfg || cfg->mtu_probe)
    return pmtu;
  uint16_t local_mtu = udp_ep_mtu_get (tx_ip);
  if (local_mtu >= RT_MTU_MIN && local_mtu < pmtu)
    pmtu = local_mtu;
  return pmtu;
}

static inline uint16_t
tap_u16_rd (const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline void
tap_u16_wr (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xffU);
}

static inline uint32_t
tap_u32_rd (const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
tap_u32_wr (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v & 0xffU);
}

static uint32_t
tap_sum_add (uint32_t sum, const uint8_t *buf, size_t len)
{
  while (len > 1)
    {
      sum += ((uint32_t)buf[0] << 8) | buf[1];
      buf += 2;
      len -= 2;
    }
  if (len != 0)
    sum += (uint32_t)buf[0] << 8;
  return sum;
}

static uint16_t
tap_sum_fld (uint32_t sum)
{
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)(~sum & 0xffffU);
}

static uint16_t
tap_ip4_sum (const uint8_t *ip4, size_t ip_hl)
{
  uint32_t sum = 0;
  for (size_t i = 0; i < ip_hl; i += 2)
    {
      if (i == 10)
        continue;
      sum += ((uint32_t)ip4[i] << 8) | ip4[i + 1];
    }
  return tap_sum_fld (sum);
}

static uint32_t
tap_tcp_sum_base (const uint8_t *ip, const uint8_t *tcp, uint8_t tcp_hl,
                  bool is_v6)
{
  uint32_t sum = 0;
  if (is_v6)
    {
      sum = tap_sum_add (sum, ip + 8, 32);
    }
  else
    {
      sum = tap_sum_add (sum, ip + 12, 8);
    }
  sum += 6U;
  sum += tap_u16_rd (tcp + 0);
  sum += tap_u16_rd (tcp + 2);
  sum += tap_u16_rd (tcp + 8);
  sum += tap_u16_rd (tcp + 10);
  sum += tap_u16_rd (tcp + 14);
  sum += tap_u16_rd (tcp + 18);
  if (tcp_hl > 20U)
    sum = tap_sum_add (sum, tcp + 20, tcp_hl - 20U);
  return sum;
}

static uint32_t
tap_udp_sum_base (const uint8_t *ip, const uint8_t *udp, bool is_v6)
{
  uint32_t sum = 0;
  if (is_v6)
    {
      sum = tap_sum_add (sum, ip + 8, 32);
    }
  else
    {
      sum = tap_sum_add (sum, ip + 12, 8);
    }
  sum += 17U;
  sum += tap_u16_rd (udp + 0);
  sum += tap_u16_rd (udp + 2);
  return sum;
}

static bool
tap_tso_fit (const uint8_t *vnet_frm, size_t vnet_len, TapTso *tso)
{
  if (!vnet_frm || !tso || vnet_len <= VNET_HL + ETH_HLEN + 20U + 20U)
    return false;
  const struct virtio_net_hdr *vh = (const struct virtio_net_hdr *)vnet_frm;
  uint8_t gso_t = (uint8_t)(vh->gso_type & (uint8_t)~VIRTIO_NET_HDR_GSO_ECN);
  if (gso_t != VIRTIO_NET_HDR_GSO_TCPV4 && gso_t != VIRTIO_NET_HDR_GSO_TCPV6)
    return false;
  if (vh->gso_size == 0)
    return false;
  if ((vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) == 0)
    return false;
  if (vh->hdr_len < (uint16_t)(ETH_HLEN + 20U + 20U))
    return false;
  if (vh->hdr_len >= vnet_len)
    return false;
  if (vh->gso_size > 65535U / 4U)
    return false;

  const uint8_t *frm = vnet_frm + VNET_HL;
  size_t frm_len = vnet_len - VNET_HL;
  size_t mac_hl = ETH_HLEN;
  uint16_t eth_t = tap_u16_rd (frm + 12);
  if ((eth_t == 0x8100U || eth_t == 0x88A8U) && frm_len >= ETH_HLEN + 4U + 20U)
    {
      mac_hl = ETH_HLEN + 4U;
      eth_t = tap_u16_rd (frm + 16);
    }

  memset (tso, 0, sizeof (*tso));
  tso->frm = frm;
  tso->frm_len = frm_len;
  tso->mac_hl = mac_hl;
  tso->seg_pl = vh->gso_size;

  if (eth_t == 0x86DDU)
    {
      if (frm_len < mac_hl + 40U + 20U)
        return false;
      const uint8_t *ip6 = frm + mac_hl;
      if (ip6[6] != 6U)
        return false;
      tso->is_v6 = true;
      tso->ip_hl = 40U;
    }
  else if (eth_t == 0x0800U)
    {
      if (frm_len < mac_hl + 20U + 20U)
        return false;
      const uint8_t *ip4 = frm + mac_hl;
      size_t ip_hl = (size_t)((ip4[0] & 0x0fU) * 4U);
      if (ip_hl < 20U || frm_len < mac_hl + ip_hl + 20U)
        return false;
      if (ip4[9] != 6U)
        return false;
      tso->is_v6 = false;
      tso->ip_hl = ip_hl;
      tso->ip_id = tap_u16_rd (ip4 + 4);
    }
  else
    return false;

  tso->tcp_off = mac_hl + tso->ip_hl;
  tso->tcp_hl = (uint8_t)(((frm[tso->tcp_off + 12] >> 4) & 0x0fU) * 4U);
  if (tso->tcp_hl < 20U || tso->tcp_hl > 60U
      || frm_len < tso->tcp_off + tso->tcp_hl)
    return false;
  if (vh->hdr_len != (uint16_t)(tso->tcp_off + tso->tcp_hl))
    return false;
  if (vh->csum_start != tso->tcp_off || vh->csum_offset != 16)
    return false;
  tso->pl_off = tso->tcp_off + tso->tcp_hl;
  if (frm_len <= tso->pl_off)
    return false;
  tso->pl_len = frm_len - tso->pl_off;
  if (tso->pl_len <= tso->seg_pl)
    return false;
  if ((tso->pl_len / tso->seg_pl) > 256U)
    return false;
  tso->tcp_flags = frm[tso->tcp_off + 13];
  tso->seq0 = tap_u32_rd (frm + tso->tcp_off + 4);
  tso->sum_base = tap_tcp_sum_base (frm + tso->mac_hl, frm + tso->tcp_off,
                                    tso->tcp_hl, tso->is_v6);
  return true;
}

static bool
tap_tso_seg (TapTso *tso, uint8_t *dst_vnet, size_t *dst_len)
{
  if (!tso || !dst_vnet || !dst_len || tso->pl_pos >= tso->pl_len)
    return false;
  size_t chunk_len = tso->pl_len - tso->pl_pos;
  if (chunk_len > tso->seg_pl)
    chunk_len = tso->seg_pl;
  bool is_last = (tso->pl_pos + chunk_len) >= tso->pl_len;

  memset (dst_vnet, 0, VNET_HL);
  uint8_t *frm = dst_vnet + VNET_HL;
  memcpy (frm, tso->frm, tso->pl_off);
  memcpy (frm + tso->pl_off, tso->frm + tso->pl_off + tso->pl_pos, chunk_len);

  uint8_t *ip = frm + tso->mac_hl;
  uint8_t *tcp = frm + tso->tcp_off;
  uint32_t seq = tso->seq0 + (uint32_t)tso->pl_pos;
  tap_u32_wr (tcp + 4, seq);
  uint8_t flags = tso->tcp_flags;
  if (!is_last)
    flags &= (uint8_t)~(0x01U | 0x08U | 0x04U);
  if (tso->pl_pos > 0)
    flags &= (uint8_t)~0x80U;
  tcp[13] = flags;
  tcp[16] = 0;
  tcp[17] = 0;

  if (tso->is_v6)
    {
      uint16_t pl = (uint16_t)(tso->tcp_hl + chunk_len);
      tap_u16_wr (ip + 4, pl);
      uint32_t sum = tso->sum_base + (uint32_t)pl + (uint32_t)(seq >> 16)
                     + (uint32_t)(seq & 0xffffU)
                     + (uint32_t)(((uint16_t)tcp[12] << 8) | flags);
      sum = tap_sum_add (sum, frm + tso->pl_off, chunk_len);
      tap_u16_wr (tcp + 16, tap_sum_fld (sum));
    }
  else
    {
      uint16_t seg_idx = (uint16_t)(tso->pl_pos / tso->seg_pl);
      uint16_t tot_len = (uint16_t)(tso->ip_hl + tso->tcp_hl + chunk_len);
      tap_u16_wr (ip + 2, tot_len);
      tap_u16_wr (ip + 4, (uint16_t)(tso->ip_id + seg_idx));
      ip[10] = 0;
      ip[11] = 0;
      tap_u16_wr (ip + 10, tap_ip4_sum (ip, tso->ip_hl));
      uint16_t tcp_len = (uint16_t)(tso->tcp_hl + chunk_len);
      uint32_t sum = tso->sum_base + (uint32_t)tcp_len
                     + (uint32_t)(seq >> 16)
                     + (uint32_t)(seq & 0xffffU)
                     + (uint32_t)(((uint16_t)tcp[12] << 8) | flags);
      sum = tap_sum_add (sum, frm + tso->pl_off, chunk_len);
      tap_u16_wr (tcp + 16, tap_sum_fld (sum));
    }

  *dst_len = VNET_HL + tso->pl_off + chunk_len;
  tso->pl_pos += chunk_len;
  return true;
}

static bool
tap_uso_fit (const uint8_t *vnet_frm, size_t vnet_len, TapUso *uso)
{
  if (!vnet_frm || !uso || vnet_len <= VNET_HL + ETH_HLEN + 20U + 8U)
    return false;
  const struct virtio_net_hdr *vh = (const struct virtio_net_hdr *)vnet_frm;
  uint8_t gso_t = (uint8_t)(vh->gso_type & (uint8_t)~VIRTIO_NET_HDR_GSO_ECN);
  if (gso_t != VIRTIO_NET_HDR_GSO_UDP && gso_t != VIRTIO_NET_HDR_GSO_UDP_L4)
    return false;
  if (vh->gso_size == 0)
    return false;
  if ((vh->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) == 0)
    return false;
  if (vh->hdr_len < (uint16_t)(ETH_HLEN + 20U + 8U))
    return false;
  if (vh->hdr_len >= vnet_len)
    return false;

  const uint8_t *frm = vnet_frm + VNET_HL;
  size_t frm_len = vnet_len - VNET_HL;
  size_t mac_hl = ETH_HLEN;
  uint16_t eth_t = tap_u16_rd (frm + 12);
  if ((eth_t == 0x8100U || eth_t == 0x88A8U) && frm_len >= ETH_HLEN + 4U + 20U)
    {
      mac_hl = ETH_HLEN + 4U;
      eth_t = tap_u16_rd (frm + 16);
    }

  memset (uso, 0, sizeof (*uso));
  uso->frm = frm;
  uso->frm_len = frm_len;
  uso->mac_hl = mac_hl;
  uso->seg_pl = vh->gso_size;

  if (eth_t == 0x86DDU)
    {
      if (frm_len < mac_hl + 40U + 8U)
        return false;
      const uint8_t *ip6 = frm + mac_hl;
      if (ip6[6] != 17U)
        return false;
      uso->is_v6 = true;
      uso->ip_hl = 40U;
    }
  else if (eth_t == 0x0800U)
    {
      if (frm_len < mac_hl + 20U + 8U)
        return false;
      const uint8_t *ip4 = frm + mac_hl;
      size_t ip_hl = (size_t)((ip4[0] & 0x0fU) * 4U);
      if (ip_hl < 20U || frm_len < mac_hl + ip_hl + 8U)
        return false;
      if (ip4[9] != 17U)
        return false;
      uso->is_v6 = false;
      uso->ip_hl = ip_hl;
    }
  else
    return false;

  uso->udp_off = mac_hl + uso->ip_hl;
  uso->pl_off = uso->udp_off + 8U;
  if (vh->hdr_len != (uint16_t)uso->pl_off)
    return false;
  if (vh->csum_start != uso->udp_off || vh->csum_offset != 6)
    return false;
  if (frm_len <= uso->pl_off || uso->seg_pl == 0)
    return false;
  uso->pl_len = frm_len - uso->pl_off;
  if (uso->pl_len <= uso->seg_pl)
    return false;
  uso->sum_base
      = tap_udp_sum_base (frm + uso->mac_hl, frm + uso->udp_off, uso->is_v6);
  return true;
}

static bool
tap_uso_seg (TapUso *uso, uint8_t *dst_vnet, size_t *dst_len)
{
  if (!uso || !dst_vnet || !dst_len || uso->pl_pos >= uso->pl_len)
    return false;
  size_t chunk_len = uso->pl_len - uso->pl_pos;
  if (chunk_len > uso->seg_pl)
    chunk_len = uso->seg_pl;

  memset (dst_vnet, 0, VNET_HL);
  uint8_t *frm = dst_vnet + VNET_HL;
  memcpy (frm, uso->frm, uso->pl_off);
  memcpy (frm + uso->pl_off, uso->frm + uso->pl_off + uso->pl_pos, chunk_len);

  uint8_t *ip = frm + uso->mac_hl;
  uint8_t *udp = frm + uso->udp_off;
  uint16_t udp_len = (uint16_t)(8U + chunk_len);
  tap_u16_wr (udp + 4, udp_len);
  udp[6] = 0;
  udp[7] = 0;
  if (uso->is_v6)
    {
      tap_u16_wr (ip + 4, udp_len);
      uint32_t sum = uso->sum_base + (uint32_t)udp_len + (uint32_t)udp_len;
      sum = tap_sum_add (sum, frm + uso->pl_off, chunk_len);
      uint16_t chk = tap_sum_fld (sum);
      tap_u16_wr (udp + 6, (chk == 0) ? 0xffffU : chk);
    }
  else
    {
      uint16_t ip_len = (uint16_t)(uso->ip_hl + udp_len);
      tap_u16_wr (ip + 2, ip_len);
      ip[10] = 0;
      ip[11] = 0;
      tap_u16_wr (ip + 10, tap_ip4_sum (ip, uso->ip_hl));
      uint32_t sum = uso->sum_base + (uint32_t)udp_len + (uint32_t)udp_len;
      sum = tap_sum_add (sum, frm + uso->pl_off, chunk_len);
      uint16_t chk = tap_sum_fld (sum);
      tap_u16_wr (udp + 6, (chk == 0) ? 0xffffU : chk);
    }

  *dst_len = VNET_HL + uso->pl_off + chunk_len;
  uso->pl_pos += chunk_len;
  return true;
}

static bool
tap_tso_seg_idx (const TapTso *tso_src, int seg_idx, uint8_t *dst_vnet,
                 size_t *dst_len)
{
  if (!tso_src || seg_idx < 0)
    return false;
  TapTso tso = *tso_src;
  tso.pl_pos = (size_t)seg_idx * tso.seg_pl;
  return tap_tso_seg (&tso, dst_vnet, dst_len);
}

static void
tap_tso_par_job_run (TapTsoPar *par)
{
  if (!par)
    return;
  par->ok = false;
  for (int seg_idx = par->seg_bgn; seg_idx < par->seg_end; seg_idx++)
    {
      int out_idx = seg_idx - par->seg_bgn;
      if (out_idx < 0 || out_idx >= TAP_TSO_PAR_MAX)
        return;
      uint8_t *vnet = par->buf_arr[out_idx] + TAP_HR;
      size_t vnet_len = 0;
      if (!tap_tso_seg_idx (&par->tso, seg_idx, vnet, &vnet_len))
        return;
      par->len_arr[out_idx] = vnet_len;
    }
  par->ok = true;
}

static void *
tap_tso_par_loop (void *arg)
{
  TapTsoPar *par = arg;
  pthread_mutex_lock (&par->mtx);
  for (;;)
    {
      while (!par->is_busy && !par->stop)
        pthread_cond_wait (&par->cv, &par->mtx);
      if (par->stop)
        {
          pthread_mutex_unlock (&par->mtx);
          return NULL;
        }
      pthread_mutex_unlock (&par->mtx);
      tap_tso_par_job_run (par);
      pthread_mutex_lock (&par->mtx);
      par->is_busy = false;
      pthread_cond_signal (&par->done_cv);
    }
}

static void
tap_tso_par_boot (void)
{
  long cpu_cnt = sysconf (_SC_NPROCESSORS_ONLN);
  if (cpu_cnt <= 2)
    return;
  memset (&g_tso_par, 0, sizeof (g_tso_par));
  if (pthread_mutex_init (&g_tso_par.mtx, NULL) != 0)
    return;
  if (pthread_cond_init (&g_tso_par.cv, NULL) != 0)
    {
      pthread_mutex_destroy (&g_tso_par.mtx);
      return;
    }
  if (pthread_cond_init (&g_tso_par.done_cv, NULL) != 0)
    {
      pthread_cond_destroy (&g_tso_par.cv);
      pthread_mutex_destroy (&g_tso_par.mtx);
      return;
    }
  if (pthread_create (&g_tso_par.tid, NULL, tap_tso_par_loop, &g_tso_par) != 0)
    {
      pthread_cond_destroy (&g_tso_par.done_cv);
      pthread_cond_destroy (&g_tso_par.cv);
      pthread_mutex_destroy (&g_tso_par.mtx);
      return;
    }
  g_tso_par.is_on = true;
}

static int
tap_tso_tx_par (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, uint64_t sid,
                uint64_t now, const TapTso *tso, const TapTxPath *tx_path,
                uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR],
                UdpMsg batch_arr[BATCH_MAX], int *bc, TapFast fast_path[256],
                uint64_t *l_nh_ts,
                uint8_t local_bufs[TAP_TSO_PAR_MAX][TAP_F_MAX + TAP_HR + TAP_TR])
{
  pthread_once (&g_tso_par_once, tap_tso_par_boot);
  if (!g_tso_par.is_on || !udp || !cry_ctx || !rt || !cfg || !tso || !tx_path
      || !tx_path->is_val || tx_path->type == RT_NONE)
    return 0;
  uint16_t max_vnet = tnl_vnet_cap_get (tx_path->pmtu, tx_path->tx_ip);
  int seg_cnt = (int)((tso->pl_len + tso->seg_pl - 1U) / tso->seg_pl);
  if (seg_cnt < TAP_TSO_PAR_MIN || seg_cnt > (TAP_TSO_PAR_MAX * 2))
    return 0;
  int mid = seg_cnt / 2;
  int tail_cnt = seg_cnt - mid;
  if (mid <= 0 || mid > TAP_TSO_PAR_MAX || tail_cnt <= 0
      || tail_cnt > TAP_TSO_PAR_MAX)
    return 0;

  pthread_mutex_lock (&g_tso_par.mtx);
  if (g_tso_par.is_busy)
    {
      pthread_mutex_unlock (&g_tso_par.mtx);
      return 0;
    }
  g_tso_par.tso = *tso;
  g_tso_par.seg_bgn = mid;
  g_tso_par.seg_end = seg_cnt;
  g_tso_par.ok = false;
  g_tso_par.is_busy = true;
  pthread_cond_signal (&g_tso_par.cv);
  pthread_mutex_unlock (&g_tso_par.mtx);

  TapTso tso_head = *tso;
  int head_cnt = 0;
  size_t tso_len = 0;
  while (head_cnt < mid
         && tap_tso_seg (&tso_head, local_bufs[head_cnt] + TAP_HR, &tso_len))
    {
      if (max_vnet > 0 && tso_len <= max_vnet)
        {
          if (!tap_data_fast (udp, cry_ctx, tx_path, now,
                              local_bufs[head_cnt] + TAP_HR, tso_len,
                              batch_arr, bc))
            return -1;
        }
      else if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                             local_bufs[head_cnt] + TAP_HR, tso_len, frag_bufs,
                             batch_arr, bc, fast_path, l_nh_ts, tx_path, false,
                             false, false))
        return -1;
      head_cnt++;
    }

  pthread_mutex_lock (&g_tso_par.mtx);
  while (g_tso_par.is_busy)
    pthread_cond_wait (&g_tso_par.done_cv, &g_tso_par.mtx);
  bool worker_ok = g_tso_par.ok;
  pthread_mutex_unlock (&g_tso_par.mtx);

  if (!worker_ok || head_cnt != mid)
    return -1;
  for (int i = 0; i < tail_cnt; i++)
    {
      if (max_vnet > 0 && g_tso_par.len_arr[i] <= max_vnet)
        {
          if (!tap_data_fast (udp, cry_ctx, tx_path, now,
                              g_tso_par.buf_arr[i] + TAP_HR,
                              g_tso_par.len_arr[i], batch_arr, bc))
            return -1;
        }
      else if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                             g_tso_par.buf_arr[i] + TAP_HR,
                             g_tso_par.len_arr[i], frag_bufs, batch_arr, bc,
                             fast_path, l_nh_ts, tx_path, false, false,
                             false))
        return -1;
    }
  return 1;
}


static bool
tap_batch_fls (Udp *udp, UdpMsg batch_arr[BATCH_MAX], int *bc, const char *msg)
{
  if (!udp || !batch_arr || !bc || *bc <= 0)
    return true;
  int fl_bc = *bc;
  int tx_rc = udp_tx_arr (udp, batch_arr, *bc);
  if (tx_rc < 0)
    fprintf (stderr, "%s\n", msg);
  *bc = 0;
  return !(tx_rc < fl_bc || udp_w_want (udp));
}

static bool
tap_msg_add (Udp *udp, const UdpMsg *msg, uint64_t now,
             UdpMsg batch_arr[BATCH_MAX], int *bc)
{
  if (!udp || !msg || !batch_arr || !bc)
    return false;
  if (*bc >= BATCH_MAX
      && !tap_batch_fls (udp, batch_arr, bc,
                         "udp: batch send failed before enqueue tso data"))
    return false;
  batch_arr[*bc] = *msg;
  (*bc)++;
  g_tx_ts = now;
  if (*bc >= BATCH_MAX - 2
      && !tap_batch_fls (udp, batch_arr, bc,
                         "udp: batch send failed during tso fast flush"))
    return false;
  return true;
}

static bool
tap_data_fast_cnt (Udp *udp, Cry *cry_ctx, const TapTxPath *tx_path, uint64_t now,
                   uint64_t cnt, uint8_t *vnet_frame, size_t vnet_len,
                   UdpMsg batch_arr[BATCH_MAX], int *bc)
{
  if (!udp || !cry_ctx || !tx_path || !tx_path->is_val || tx_path->type == RT_NONE
      || !vnet_frame || !batch_arr || !bc)
    return false;
  size_t out_len = 0;
  uint8_t *out_ptr = data_bld_zc_cnt (cry_ctx, vnet_frame, vnet_len,
                                      tx_path->rel_f, 32, cnt, &out_len);
  UdpMsg msg;
  memcpy (msg.dst_ip, tx_path->tx_ip, 16);
  msg.dst_port = tx_path->tx_port;
  msg.data = out_ptr;
  msg.data_len = out_len;
  return tap_msg_add (udp, &msg, now, batch_arr, bc);
}

static bool
tap_data_fast (Udp *udp, Cry *cry_ctx, const TapTxPath *tx_path, uint64_t now,
               uint8_t *vnet_frame, size_t vnet_len,
               UdpMsg batch_arr[BATCH_MAX], int *bc)
{
  return tap_data_fast_cnt (udp, cry_ctx, tx_path, now, cry_cnt_take (cry_ctx, 1),
                            vnet_frame, vnet_len, batch_arr, bc);
}

static void
frame_l3_info_get (const uint8_t *frame_pkt, size_t frame_len, size_t *l3_off,
                   uint16_t *eth_type)
{
  if (!l3_off || !eth_type)
    return;
  *l3_off = ETH_HLEN;
  *eth_type = 0;
  if (!frame_pkt || frame_len < ETH_HLEN)
    return;
  *eth_type = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
  if ((*eth_type == 0x8100U || *eth_type == 0x88A8U)
      && frame_len >= ETH_HLEN + 4U + 20U)
    {
      *eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
      *l3_off = ETH_HLEN + 4U;
    }
}

static bool
tap_tx_path_fit (Rt *rt, const Cfg *cfg, uint64_t now, const uint8_t *frame_pkt,
                 TapFast fast_path[256], uint64_t *l_nh_ts, TapTxPath *tx_path)
{
  if (!rt || !cfg || !frame_pkt || !tx_path)
    return false;
  memset (tx_path, 0, sizeof (*tx_path));
  tx_path->is_val = true;
  tx_path->type = RT_NONE;
  if ((frame_pkt[0] & 0x01U) != 0U)
    return false;

  if (!rt_key_get (rt, frame_pkt, cfg->addr, tx_path->rt_key))
    {
      if (l_nh_ts && now - *l_nh_ts >= 2000ULL)
        {
          fprintf (stderr,
                   "routing: unresolved next-hop for dst-mac "
                   "%02x:%02x:%02x:%02x:%02x:%02x\n",
                   frame_pkt[0], frame_pkt[1], frame_pkt[2], frame_pkt[3],
                   frame_pkt[4], frame_pkt[5]);
          *l_nh_ts = now;
        }
      return true;
    }

  int fp_idx = (int)((tx_path->rt_key[12] ^ tx_path->rt_key[13]
                      ^ tx_path->rt_key[14] ^ tx_path->rt_key[15])
                     & 0xff);
  if (fast_path[fp_idx].is_val && now <= fast_path[fp_idx].val_ts
      && memcmp (fast_path[fp_idx].dest_lla, tx_path->rt_key, 16) == 0)
    {
      *tx_path = fast_path[fp_idx].tx_path;
      return true;
    }
  RtDec dec;
  memset (&dec, 0, sizeof (dec));
  if (memcmp (tx_path->rt_key, cfg->addr, 16) == 0)
    {
      dec.type = RT_NONE;
    }
  else
    {
      Re dir;
      if (cfg->p2p == P2P_EN && rt_dir_fnd (rt, tx_path->rt_key, &dir))
        {
          dec.type = RT_DIR;
          memcpy (dec.dir.ip, dir.ep_ip, 16);
          dec.dir.port = dir.ep_port;
        }
      else
        {
          dec = rt_sel (rt, tx_path->rt_key, cfg->p2p == P2P_EN);
        }
    }

  tx_path->type = dec.type;
  if (dec.type == RT_NONE)
    return true;
  if (dec.type == RT_DIR)
    {
      memcpy (tx_path->tx_ip, dec.dir.ip, 16);
      tx_path->tx_port = dec.dir.port;
    }
  else if (dec.type == RT_VP)
    {
      uint8_t gw_ip[16];
      uint16_t gw_port = 0;
      if (!rt_gw_fnd (rt, cfg->addr, gw_ip, &gw_port))
        {
          tx_path->type = RT_NONE;
          return true;
        }
      memcpy (tx_path->tx_ip, gw_ip, 16);
      tx_path->tx_port = gw_port;
      tx_path->rel_f = 1;
    }
  else if (dec.type == RT_REL)
    {
      memcpy (tx_path->tx_ip, dec.rel.relay_ip, 16);
      tx_path->tx_port = dec.rel.relay_port;
      tx_path->rel_f = 1;
    }
  if (tx_path->tx_port == 0)
    {
      tx_path->type = RT_NONE;
      fast_path[fp_idx].is_val = false;
      return true;
    }
  tx_path->pmtu = tx_path_pmtu_get (cfg, tx_path->tx_ip, rt_mtu (rt, &dec));
  memcpy (fast_path[fp_idx].dest_lla, tx_path->rt_key, 16);
  fast_path[fp_idx].tx_path = *tx_path;
  fast_path[fp_idx].val_ts = now + 200ULL;
  fast_path[fp_idx].is_val = true;
  return true;
}

static void
tap_rel_pulse (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, uint64_t now,
               uint64_t sid, const TapTxPath *tx_path)
{
  if (!udp || !cry_ctx || !rt || !cfg || !tx_path)
    return;
  if (cfg->p2p != P2P_EN || tx_path->type != RT_REL)
    return;
  Re *pulse_re = rt_re_fnd (rt, tx_path->rt_key);
  if (pulse_re)
    pulse_tx (udp, cry_ctx, rt, cfg, pulse_re, now, sid, true);
}

static void
tap_tx_mark (Rt *rt, uint64_t now, const TapTxPath *tx_path)
{
  if (!rt || !tx_path || !tx_path->is_val || tx_path->type == RT_NONE
      || tx_path->tx_port == 0)
    return;
  rt_tx_ack (rt, tx_path->tx_ip, tx_path->tx_port, now);
}

static bool
tap_data_tx (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg, uint64_t sid,
             uint64_t now, uint8_t *vnet_frame, size_t vnet_len,
             uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR],
             UdpMsg batch_arr[BATCH_MAX], int *bc, TapFast fast_path[256],
             uint64_t *l_nh_ts, const TapTxPath *tx_path, bool pulse_apply,
             bool tx_ack_apply, bool mss_apply)
{
  uint8_t *frame_pkt = vnet_frame + VNET_HL;
  size_t frame_len = vnet_len - VNET_HL;
  const uint8_t *dst_mac = frame_pkt;
  if ((dst_mac[0] & 0x01U) != 0U)
    {
      size_t out_len;
      uint8_t *out_ptr = data_bld_zc (cry_ctx, vnet_frame, vnet_len, 0, 32, &out_len);
      static const uint8_t z_lla[16] = { 0 };
      uint8_t uniq_lla[256][16];
      int u_cnt = 0;
      for (uint32_t ri = 0; ri < rt->cnt && u_cnt < 256; ri++)
        {
          Re *re = &rt->re_arr[ri];
          if (!re->is_act || re->state == RT_DED)
            continue;
          if (memcmp (re->lla, z_lla, 16) == 0)
            continue;
          if (memcmp (re->lla, cfg->addr, 16) == 0)
            continue;
          bool is_dup = false;
          for (int u = 0; u < u_cnt; u++)
            {
              if (memcmp (uniq_lla[u], re->lla, 16) == 0)
                {
                  is_dup = true;
                  break;
                }
            }
          if (!is_dup)
            memcpy (uniq_lla[u_cnt++], re->lla, 16);
        }
      typedef struct
      {
        uint8_t ip[16];
        uint16_t port;
      } FloodEp;
      FloodEp ep_arr[256];
      int ep_cnt = 0;
      for (int u = 0; u < u_cnt && ep_cnt < 256; u++)
        {
          RtDec sel = rt_sel (rt, uniq_lla[u], cfg->p2p == P2P_EN);
          uint8_t ep_ip[16] = { 0 };
          uint16_t ep_port = 0;
          bool is_ok = false;
          if (sel.type == RT_DIR)
            {
              memcpy (ep_ip, sel.dir.ip, 16);
              ep_port = sel.dir.port;
              is_ok = true;
            }
          else if (sel.type == RT_REL)
            {
              memcpy (ep_ip, sel.rel.relay_ip, 16);
              ep_port = sel.rel.relay_port;
              is_ok = true;
            }
          else if (sel.type == RT_VP)
            {
              uint8_t gw_ip[16];
              uint16_t gw_port = 0;
              if (rt_gw_fnd (rt, cfg->addr, gw_ip, &gw_port))
                {
                  memcpy (ep_ip, gw_ip, 16);
                  ep_port = gw_port;
                  is_ok = true;
                }
            }
          if (!is_ok || ep_port == 0)
            continue;
          bool is_dup = false;
          for (int re = 0; re < ep_cnt; re++)
            {
              if (memcmp (ep_arr[re].ip, ep_ip, 16) == 0
                  && ep_arr[re].port == ep_port)
                {
                  is_dup = true;
                  break;
                }
            }
          if (!is_dup)
            {
              memcpy (ep_arr[ep_cnt].ip, ep_ip, 16);
              ep_arr[ep_cnt].port = ep_port;
              ep_cnt++;
            }
        }
      for (int re = 0; re < ep_cnt; re++)
        {
          if (*bc >= BATCH_MAX
              && !tap_batch_fls (udp, batch_arr, bc,
                                 "udp: batch send failed before enqueue multicast"))
            return false;
          memcpy (batch_arr[*bc].dst_ip, ep_arr[re].ip, 16);
          batch_arr[*bc].dst_port = ep_arr[re].port;
          batch_arr[*bc].data = out_ptr;
          batch_arr[*bc].data_len = out_len;
          (*bc)++;
          rt_tx_ack (rt, ep_arr[re].ip, ep_arr[re].port, now);
          g_tx_ts = now;
        }
      return true;
    }

  TapTxPath tx_path_lcl;
  if (tx_path && tx_path->is_val)
    {
      tx_path_lcl = *tx_path;
    }
  else if (!tap_tx_path_fit (rt, cfg, now, frame_pkt, fast_path, l_nh_ts,
                             &tx_path_lcl))
    {
      return true;
    }
  if (tx_path_lcl.type == RT_NONE)
    return true;

  const uint8_t *tx_ip = tx_path_lcl.tx_ip;
  uint16_t tx_port = tx_path_lcl.tx_port;
  uint8_t rel_f = tx_path_lcl.rel_f;
  const uint8_t *rel_dst_lla = (rel_f != 0) ? tx_path_lcl.rt_key : NULL;
  uint16_t pmtu = tx_path_lcl.pmtu;
  uint16_t max_vnet = tnl_vnet_cap_get (pmtu, tx_ip);
  size_t l3_off = ETH_HLEN;
  uint16_t eth_type = 0;
  frame_l3_info_get (frame_pkt, frame_len, &l3_off, &eth_type);
  if (mss_apply && (eth_type == 0x0800U || eth_type == 0x86DDU)
      && frame_len > l3_off)
    {
      uint16_t max_in_l3 = tnl_inner_l3_cap_get (max_vnet, l3_off);
      if (max_in_l3 >= 88U)
        mss_clp (frame_pkt + l3_off, frame_len - l3_off, max_in_l3);
    }
  size_t chunk_max = tnl_frag_pl_cap_get (max_vnet, rel_f != 0);
  if (chunk_max == 0)
    {
      static uint64_t l_cr_ts = 0;
      uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
      if (now >= l_cr_ts + 1000ULL)
        {
          fprintf (stderr,
                   "main: physical mtu %u too small for tunnel overhead %u\n",
                   (unsigned)pmtu,
                   (unsigned)(oip_oh + 8U + PKT_HDR_SZ + sizeof (FragHdr)
                              + ((rel_f != 0) ? 4U : 0U)));
          l_cr_ts = now;
        }
      return true;
    }
  bool is_tiny = false;
  if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
    {
      is_tiny = (chunk_max < 64U)
                && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
    }
  if (!is_tiny && __builtin_expect ((size_t)vnet_len <= (size_t)max_vnet, 1))
    {
      size_t out_len;
      uint8_t *out_ptr = data_bld_zc (cry_ctx, vnet_frame, vnet_len, rel_f, 32, &out_len);
      if (*bc >= BATCH_MAX
          && !tap_batch_fls (udp, batch_arr, bc,
                             "udp: batch send failed before enqueue data"))
        return false;
      memcpy (batch_arr[*bc].dst_ip, tx_ip, 16);
      batch_arr[*bc].dst_port = tx_port;
      batch_arr[*bc].data = out_ptr;
      batch_arr[*bc].data_len = out_len;
      (*bc)++;
      if (tx_ack_apply)
        rt_tx_ack (rt, tx_ip, tx_port, now);
      g_tx_ts = now;
    }
  else
    {
      uint32_t n_frags = (uint32_t)((vnet_len + chunk_max - 1) / chunk_max);
      if (n_frags == 0)
        n_frags = 1;
      uint32_t msg_id = g_frag_mid++;
      if (g_frag_mid == 0)
        g_frag_mid = 1;
      uint8_t rel_dst_tail[4] = { 0 };
      if (rel_f != 0 && rel_dst_lla != NULL)
        memcpy (rel_dst_tail, rel_dst_lla + 12, 4);
      size_t off = 0;
      while (off < vnet_len)
        {
          if (*bc + 1 > BATCH_MAX
              && !tap_batch_fls (udp, batch_arr, bc,
                                 "udp: batch send failed during frag flush"))
            return false;
          size_t chunk_len = vnet_len - off;
          if (chunk_len > chunk_max)
            chunk_len = chunk_max;
          uint8_t *chunk_dst1 = frag_bufs[*bc] + TAP_HR + PKT_HDR_SZ
                                + sizeof (FragHdr) + ((rel_f != 0) ? 4U : 0U);
          memcpy (chunk_dst1, vnet_frame + off, chunk_len);
          if (off > 0x7fffU)
            break;
          size_t out_len = 0;
          bool mf = (off + chunk_len) < vnet_len;
          uint8_t *out_ptr = frag_bld_zc (cry_ctx, chunk_dst1, chunk_len, msg_id,
                                          (uint16_t)off, mf, rel_f,
                                          (rel_f != 0) ? rel_dst_tail : NULL, 32,
                                          &out_len);
          if (!out_ptr || out_len == 0)
            {
              off += chunk_len;
              continue;
            }
          memcpy (batch_arr[*bc].dst_ip, tx_ip, 16);
          batch_arr[*bc].dst_port = tx_port;
          batch_arr[*bc].data = out_ptr;
          batch_arr[*bc].data_len = out_len;
          (*bc)++;
          if (tx_ack_apply)
            rt_tx_ack (rt, tx_ip, tx_port, now);
          g_tx_ts = now;
          off += chunk_len;
        }
    }
  if (pulse_apply)
    tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path_lcl);
  if (*bc >= BATCH_MAX - 2
      && !tap_batch_fls (udp, batch_arr, bc,
                         "udp: batch send failed during near-full flush"))
    return false;
  return true;
}

static bool
tap_pkt_tx (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
            uint64_t sid, uint64_t now, uint8_t *vnet_frame, size_t vnet_len,
            uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR],
            UdpMsg batch_arr[BATCH_MAX], int *bc, TapFast fast_path[256],
            uint64_t *l_nh_ts)
{
  uint8_t *frame_pkt = vnet_frame + VNET_HL;
  size_t frame_len = vnet_len - VNET_HL;
  FRes result;
  tap_f_proc (frame_pkt, frame_len, cfg->addr, &result);
  if (result.res_type == FRAME_NS_INT)
    {
      uint8_t z_vnet[VNET_HL] = { 0 };
      struct iovec iov[2]
          = { { .iov_base = z_vnet, .iov_len = VNET_HL },
              { .iov_base = result.na_frame, .iov_len = result.na_len } };
      if (writev (tap_fd, iov, 2) < 0)
        perror ("loop: writev(tap) failed");
      return true;
    }
  if (result.res_type != FRAME_V6_DAT)
    return true;
  return tap_data_tx (udp, cry_ctx, rt, cfg, sid, now, vnet_frame, vnet_len,
                      frag_bufs, batch_arr, bc, fast_path, l_nh_ts, NULL, true,
                      true, true);
}

bool
tap_frame_tx (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
              uint64_t sid, uint64_t now, uint8_t *vnet_frame,
              size_t vnet_len)
{
  TapRun *tap_run = &g_tap_run;
  if (!vnet_frame || vnet_len <= VNET_HL)
    return true;
  TapTso tso;
  if (tap_tso_fit (vnet_frame, vnet_len, &tso))
    {
      TapTxPath tx_path;
      bool has_tx_path = tap_tx_path_fit (rt, cfg, now, vnet_frame + VNET_HL,
                                          tap_run->fast_path,
                                          &tap_run->l_nh_ts, &tx_path);
      if (has_tx_path)
        {
          int par_rc = tap_tso_tx_par (udp, cry_ctx, rt, cfg, sid, now, &tso,
                                       &tx_path, tap_run->frag_bufs,
                                       tap_run->batch_arr, &tap_run->bc,
                                       tap_run->fast_path, &tap_run->l_nh_ts,
                                       tap_run->uso_bufs);
          if (par_rc < 0)
            return false;
          if (par_rc > 0)
            {
              if (tap_run->bc > 0
                  && !tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                                     "udp: batch send failed during tso flush"))
                return false;
              tap_tx_mark (rt, now, &tx_path);
              tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path);
              return true;
            }
        }
      uint16_t max_vnet = has_tx_path
                             ? tnl_vnet_cap_get (tx_path.pmtu, tx_path.tx_ip)
                             : 0;
      int tso_i = 0;
      size_t tso_len = 0;
      while (tap_tso_seg (&tso, tap_run->uso_bufs[tso_i] + TAP_HR, &tso_len))
        {
          if (has_tx_path && max_vnet > 0 && tso_len <= max_vnet)
            {
              if (!tap_data_fast (udp, cry_ctx, &tx_path, now,
                                  tap_run->uso_bufs[tso_i] + TAP_HR, tso_len,
                                  tap_run->batch_arr, &tap_run->bc))
                return false;
            }
          else if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                                 tap_run->uso_bufs[tso_i] + TAP_HR, tso_len,
                                 tap_run->frag_bufs, tap_run->batch_arr,
                                 &tap_run->bc, tap_run->fast_path,
                                 &tap_run->l_nh_ts,
                                 has_tx_path ? &tx_path : NULL, false, false,
                                 false))
            return false;
          tso_i++;
          if (tso_i >= (int)(sizeof (tap_run->uso_bufs)
                             / sizeof (tap_run->uso_bufs[0])))
            {
              if (!tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                                  "udp: batch send failed during tso flush"))
                return false;
              tso_i = 0;
            }
        }
      if (tap_run->bc > 0
          && !tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                             "udp: batch send failed during tso flush"))
        return false;
      if (has_tx_path)
        {
          tap_tx_mark (rt, now, &tx_path);
          tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path);
        }
      return true;
    }
  TapUso uso;
  if (tap_uso_fit (vnet_frame, vnet_len, &uso))
    {
      TapTxPath tx_path;
      bool has_tx_path = tap_tx_path_fit (rt, cfg, now, vnet_frame + VNET_HL,
                                          tap_run->fast_path,
                                          &tap_run->l_nh_ts, &tx_path);
      uint16_t max_vnet = has_tx_path
                             ? tnl_vnet_cap_get (tx_path.pmtu, tx_path.tx_ip)
                             : 0;
      int uso_i = 0;
      size_t uso_len = 0;
      while (tap_uso_seg (&uso, tap_run->uso_bufs[uso_i] + TAP_HR, &uso_len))
        {
          if (has_tx_path && max_vnet > 0 && uso_len <= max_vnet)
            {
              if (!tap_data_fast (udp, cry_ctx, &tx_path, now,
                                  tap_run->uso_bufs[uso_i] + TAP_HR, uso_len,
                                  tap_run->batch_arr, &tap_run->bc))
                return false;
            }
          else if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                                 tap_run->uso_bufs[uso_i] + TAP_HR, uso_len,
                                 tap_run->frag_bufs, tap_run->batch_arr,
                                 &tap_run->bc, tap_run->fast_path,
                                 &tap_run->l_nh_ts,
                                 has_tx_path ? &tx_path : NULL, false, false,
                                 false))
            return false;
          uso_i++;
          if (uso_i >= (int)(sizeof (tap_run->uso_bufs)
                             / sizeof (tap_run->uso_bufs[0])))
            {
              if (!tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                                  "udp: batch send failed during uso flush"))
                return false;
              uso_i = 0;
            }
        }
      if (tap_run->bc > 0
          && !tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                             "udp: batch send failed during uso flush"))
        return false;
      if (has_tx_path)
        {
          tap_tx_mark (rt, now, &tx_path);
          tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path);
        }
      return true;
    }
  return tap_pkt_tx (tap_fd, udp, cry_ctx, rt, cfg, sid, now, vnet_frame,
                     vnet_len, tap_run->frag_bufs, tap_run->batch_arr,
                     &tap_run->bc, tap_run->fast_path, &tap_run->l_nh_ts);
}

bool
tap_frame_flush (Udp *udp)
{
  TapRun *tap_run = &g_tap_run;
  if (tap_run->bc <= 0)
    return true;
  return tap_batch_fls (udp, tap_run->batch_arr, &tap_run->bc,
                        "udp: batch send failed during final flush");
}

void
on_tap (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid, uint64_t now)
{
  static _Thread_local uint8_t frame_bufs[BATCH_MAX][TAP_F_MAX + TAP_HR + TAP_TR]
      __attribute__ ((aligned (32)));
  for (;;)
    {
      bool hit_eagain = false;
      int rd_cnt = 0;
      for (int i = 0; i < BATCH_MAX; i++)
        {
          if (udp_w_want (udp))
            break;
          uint8_t *pl_ptr = frame_bufs[i] + TAP_HR;
          ssize_t n = read (tap_fd, pl_ptr, TAP_F_MAX);
          if (n <= 0)
            {
              if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                hit_eagain = true;
              break;
            }
          rd_cnt++;
          if (!tap_frame_tx (tap_fd, udp, cry_ctx, rt, cfg, sid, now, pl_ptr,
                             (size_t)n))
            {
              rd_cnt = -1;
              break;
            }
        }
      if (!tap_frame_flush (udp))
        break;
      if (rd_cnt < 0 || udp_w_want (udp) || hit_eagain || rd_cnt < BATCH_MAX)
        break;
    }
}

void
on_udp (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid, PPool *pool)
{
  static UdpRxPkt pkt_arr[BATCH_MAX];
  static UdpDecRes dec_arr[BATCH_MAX];
  for (;;)
    {
      int rc = udp_rx_pkt_arr (udp, pkt_arr, BATCH_MAX);
      if (rc <= 0)
        return;
      udp_dec_run (cry_ctx, pkt_arr, dec_arr, rc);
      uint64_t ts = sys_ts ();

      static uint64_t l_reap_ts = 0;
      if (ts >= l_reap_ts + 50ULL)
        {
          frag_reap_tk (ts);
          l_reap_ts = ts;
        }

      uint8_t last_src_ip[16] = { 0 };
      uint16_t last_src_port = 0;
      bool has_last_src = false;

      for (int i = 0; i < rc; i++)
        {
          uint8_t *raw_buf = pkt_arr[i].data;
          uint8_t *src_ip = pkt_arr[i].src_ip;
          uint16_t src_port = pkt_arr[i].src_port;
          size_t pkt_len = pkt_arr[i].data_len;
          PktHdr *hdr = &dec_arr[i].hdr;
          uint8_t *pt = dec_arr[i].pt;
          size_t pt_len = dec_arr[i].pt_len;
          if (dec_arr[i].dec_res != 0)
            continue;
          bool bypass_replay
              = is_ip_loopback (src_ip) && hdr->pkt_type == PT_STAT_REQ;
          if (!bypass_replay
              && !rx_rp_chk (src_ip, src_port, raw_buf + PKT_CH_SZ))
            continue;

          if (!has_last_src || src_port != last_src_port
              || memcmp (src_ip, last_src_ip, 16) != 0)
            {
              rt_rx_ack (rt, src_ip, src_port, ts);
              memcpy (last_src_ip, src_ip, 16);
              last_src_port = src_port;
              has_last_src = true;
            }

          if (hdr->pkt_type == PT_DATA)
            {
              g_rx_ts = ts;
              if (pt_len < VNET_HL + ETH_HLEN)
                continue;
              if (hdr->rel_f == 0)
                {
                  if (rt_dat_upd (rt, src_ip, src_port, ts))
                    {
                      const uint8_t *frame = pt + VNET_HL;
                      uint8_t src_lla[16] = { 0 };
                      if ((mesh_src_lla_from_frame (frame, cfg->addr, src_lla)
                           || mesh_src_lla_from_ip6 (frame, pt_len - VNET_HL,
                                                     src_lla))
                          && memcmp (src_lla, cfg->addr, 16) != 0)
                        {
                          rt_ep_upd (rt, src_lla, src_ip, src_port, ts);
                        }
                    }
                  gro_fed (tap_fd, pt, pt_len);
                  continue;
                }
              if (hdr->hop_c <= 1)
                {
                  fprintf (stderr,
                           "routing: drop: ttl expired, routing loop detected\n");
                  continue;
                }
              uint8_t dest_lla[16] = { 0 };
              const uint8_t *frame = pt + VNET_HL;
              if (!mesh_dst_lla_from_frame (frame, cfg->addr, dest_lla))
                continue;
              if (memcmp (dest_lla, cfg->addr, 16) == 0)
                {
                  gro_fed (tap_fd, pt, pt_len);
                }
              else
                {
                  rel_fwd_dat (udp, cry_ctx, rt, cfg, dest_lla, pt, pt_len,
                               (uint8_t)(hdr->hop_c - 1), ts, src_ip,
                               src_port);
                }
              continue;
            }

          if (ctrl_pkt_is (hdr->pkt_type))
            rt->ctrl_rx_b += (uint64_t)pkt_len;

          switch (hdr->pkt_type)
            {
            case PT_FRAG:
              {
                g_rx_ts = ts;
                const uint8_t *payload = pt;
                size_t payload_len = pt_len;
                uint8_t dest_lla[16] = { 0 };
                if (hdr->rel_f != 0)
                  {
                    if (payload_len < 4 + sizeof (FragHdr))
                      break;
                    if (hdr->hop_c <= 1)
                      break;
                    memcpy (dest_lla, cfg->addr, 16);
                    memcpy (dest_lla + 12, payload, 4);
                    payload += 4;
                    payload_len -= 4;
                  }
                if (payload_len < sizeof (FragHdr))
                  break;
                uint32_t msg_id
                    = ((uint32_t)payload[0] << 24)
                      | ((uint32_t)payload[1] << 16)
                      | ((uint32_t)payload[2] << 8)
                      | (uint32_t)payload[3];
                uint16_t off_mf
                    = (uint16_t)(((uint16_t)payload[4] << 8) | payload[5]);
                uint16_t frag_off = (uint16_t)(off_mf & 0x7fffU);
                bool mf = (off_mf & 0x8000U) != 0;
                const uint8_t *chunk = payload + sizeof (FragHdr);
                size_t chunk_len = payload_len - sizeof (FragHdr);
                if (hdr->rel_f != 0 && memcmp (dest_lla, cfg->addr, 16) != 0)
                  {
                    relay_fwd_frag (udp, cry_ctx, rt, cfg, dest_lla, msg_id,
                                    frag_off, mf, chunk, chunk_len,
                                    (uint8_t)(hdr->hop_c - 1), ts, src_ip,
                                    src_port);
                    break;
                  }
                uint16_t full_len = 0;
                uint8_t *full_l3 = frag_asm (src_ip, msg_id, frag_off, mf,
                                             chunk, chunk_len, &full_len);
                if (!full_l3)
                  break;
                if (full_len < VNET_HL + ETH_HLEN)
                  break;
                if (rt_dat_upd (rt, src_ip, src_port, ts))
                  {
                    const uint8_t *frame = full_l3 + VNET_HL;
                    uint8_t src_lla[16] = { 0 };
                    if ((mesh_src_lla_from_frame (frame, cfg->addr, src_lla)
                         || mesh_src_lla_from_ip6 (frame, full_len - VNET_HL,
                                                   src_lla))
                        && memcmp (src_lla, cfg->addr, 16) != 0)
                      {
                        rt_ep_upd (rt, src_lla, src_ip, src_port, ts);
                      }
                  }
                gro_fed (tap_fd, full_l3, full_len);
                break;
              }
            case PT_MTU_PRB:
              {
                uint32_t probe_id = 0;
                uint16_t probe_mtu = 0;
                if (gsp_prs_mtu_prb (pt, pt_len, &probe_id, &probe_mtu) != 0)
                  break;
                static uint8_t ack_buf[UDP_PL_MAX];
                size_t ack_len = 0;
                mtu_ack_bld (cry_ctx, probe_id, probe_mtu, ack_buf, &ack_len);
                udp_tx (udp, src_ip, src_port, ack_buf, ack_len);
                rt_tx_ack (rt, src_ip, src_port, ts);
                break;
              }
            case PT_MTU_ACK:
              {
                uint32_t probe_id = 0;
                uint16_t probe_mtu = 0;
                if (gsp_prs_mtu_ack (pt, pt_len, &probe_id, &probe_mtu) != 0)
                  break;
                rt_pmtu_ack_ep (rt, src_ip, src_port, probe_id, probe_mtu, ts);
                break;
              }
            case PT_STAT_REQ:
              {
                if (!is_ip_loopback (src_ip))
                  break;
                uint32_t req_id = 0;
                if (gsp_prs_stat_req (pt, pt_len, &req_id) != 0)
                  break;
                uint16_t txt_cap = UINT16_MAX;
                char *txt = calloc (1, (size_t)txt_cap + 1U);
                if (!txt)
                  break;
                size_t txt_len = status_buf_bld (txt, (size_t)txt_cap + 1U, rt,
                                                 cfg, pool);
                if (txt_len > txt_cap)
                  txt_len = txt_cap;
                static uint8_t rsp_buf[UDP_PL_MAX];
                size_t chunk_cap = UDP_PL_MAX - PKT_HDR_SZ - sizeof (StatHdr);
                for (size_t off = 0; off < txt_len;)
                  {
                    size_t chunk_len = txt_len - off;
                    if (chunk_len > chunk_cap)
                      chunk_len = chunk_cap;
                    size_t rsp_len = 0;
                    if (!stat_rsp_bld (cry_ctx, req_id, (uint16_t)txt_len,
                                       (uint16_t)off, (const uint8_t *)txt + off,
                                       chunk_len, rsp_buf, &rsp_len))
                      break;
                    udp_tx (udp, src_ip, src_port, rsp_buf, rsp_len);
                    off += chunk_len;
                  }
                free (txt);
                break;
              }
            case PT_PING:
              {
                uint64_t req_ts, peer_sid;
                uint64_t prb_tok = 0;
                uint8_t peer_lla[16];
                if (on_ping (pt, pt_len, &req_ts, &peer_sid, peer_lla,
                             &prb_tok)
                    == 0)
                  {
                    if (rt_peer_sess (rt, peer_lla, peer_sid, ts))
                      rx_rp_rst_lla (rt, peer_lla);
                    if (hdr->rel_f == 0)
                      rt_ep_upd (rt, peer_lla, src_ip, src_port, ts);
                    if (hdr->rel_f == 0 && is_underlay_ip (src_ip)
                        && !p_is_me (rt, cfg->addr, src_ip, src_port))
                      {
                        pp_add (pool, src_ip, src_port);
                      }
                    static uint8_t pong_buf[UDP_PL_MAX];
                    size_t pong_len;
                    pong_bld (cry_ctx, cfg->addr, req_ts, sid, ts, prb_tok,
                              pong_buf, &pong_len);
                    udp_tx (udp, src_ip, src_port, pong_buf, pong_len);
                    rt->ctrl_tx_b += (uint64_t)pong_len;
                    rt_tx_ack (rt, src_ip, src_port, ts);
                  }
                break;
              }
            case PT_PONG:
              {
                uint64_t req_ts, peer_sid;
                uint64_t peer_rx_ts = 0;
                uint64_t prb_tok = 0;
                uint8_t peer_lla[16];
                if (on_pong (pt, pt_len, &req_ts, &peer_sid, peer_lla,
                             &peer_rx_ts, &prb_tok)
                    == 0)
                  {
                    if (rt_peer_sess (rt, peer_lla, peer_sid, ts))
                      rx_rp_rst_lla (rt, peer_lla);
                    if (hdr->rel_f == 0)
                      rt_ep_upd (rt, peer_lla, src_ip, src_port, ts);
                    uint32_t rtt = (uint32_t)(ts >= req_ts ? (ts - req_ts) : 0);
                    if (rtt == 0)
                      rtt = 1;
                    int64_t dir_cost = INT64_MAX;
                    if (peer_rx_ts > 0)
                      {
                        dir_cost = (int64_t)peer_rx_ts - (int64_t)req_ts;
                      }
                    if (!rt_ping_sample_upd (rt, peer_lla, prb_tok, rtt,
                                             dir_cost, ts))
                      {
                        rt_rtt_upd (rt, peer_lla, src_ip, src_port, rtt, ts);
                        if (dir_cost != INT64_MAX)
                          {
                            rt_dir_cost_upd (rt, peer_lla, src_ip, src_port,
                                             dir_cost);
                          }
                      }
                    if (hdr->rel_f == 0 && is_underlay_ip (src_ip)
                        && !p_is_me (rt, cfg->addr, src_ip, src_port))
                      {
                        pp_add (pool, src_ip, src_port);
                      }
                  }
                break;
              }
            case PT_GSP:
              {
                if (cfg->p2p == P2P_EN)
                  {
                    bool is_mod = false;
                    bool req_seq = false;
                    uint8_t seq_tgt[16] = { 0 };
                    on_gsp (pt, pt_len, src_ip, src_port, cfg->addr, rt, pool,
                            ts, &is_mod, &req_seq, seq_tgt);
                    if (is_mod)
                      {
                        rt_gsp_dirty_set (rt, "on_gsp (is_mod)");
                      }
                    if (req_seq)
                      {
                        static uint8_t req_buf[UDP_PL_MAX];
                        size_t req_len = 0;
                        seq_req_bld (cry_ctx, seq_tgt, req_buf, &req_len);
                        udp_tx (udp, src_ip, src_port, req_buf, req_len);
                        rt->ctrl_tx_b += (uint64_t)req_len;
                        rt_tx_ack (rt, src_ip, src_port, ts);
                      }
                  }
                break;
              }
            case PT_SEQ_REQ:
              {
                uint8_t tgt_lla[16];
                if (on_seq_req (pt, pt_len, tgt_lla) == 0)
                  {
                    if (memcmp (tgt_lla, cfg->addr, 16) == 0)
                      {
                        bool is_bump = false;
                        for (uint32_t j = 0; j < rt->cnt; j++)
                          {
                            if (memcmp (rt->re_arr[j].lla, cfg->addr, 16) == 0)
                              {
                                rt->re_arr[j].seq++;
                                is_bump = true;
                              }
                          }
                        if (is_bump)
                          {
                            static uint8_t dt_buf[UDP_PL_MAX];
                            size_t dt_len = 0;
                            gsp_dt_bld (cry_ctx, rt->re_arr, (int)rt->cnt,
                                        tgt_lla, cfg->addr, dt_buf, &dt_len);
                            if (dt_len > 0)
                              {
                                udp_tx (udp, src_ip, src_port, dt_buf, dt_len);
                                rt->ctrl_tx_b += (uint64_t)dt_len;
                                rt_tx_ack (rt, src_ip, src_port, ts);
                              }
                          }
                      }
                  }
                break;
              }
            case PT_HP:
              {
                if (cfg->p2p == P2P_EN)
                  {
                    on_hp (pt, pt_len, cry_ctx, udp, rt, cfg->addr, sid, ts);
                  }
                break;
              }
            }
        }
      gro_fls_all (tap_fd);
      if (rc < BATCH_MAX && !udp_rx_pending ())
        return;
    }
}

void
gsp_dirty_flush (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg)
{
  if (!rt->gsp_dirty)
    return;
  if (cfg->p2p != P2P_EN)
    {
      rt->gsp_dirty = false;
      printf ("gsp: flush: p2p disabled, clearing dirty\n");
      return;
    }
  uint64_t now = sys_ts ();
  if (rt->gsp_last_ts > 0 && now < rt->gsp_last_ts + 3000ULL)
    return;
  int peer_cnt = 0;
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
      peer_cnt++;
    }
  if (peer_cnt == 0)
    {
      rt->gsp_dirty = false;
      rt->gsp_last_ts = now;
      return;
    }
  /* printf ("gsp: flush: start (last %lu ms ago)\n",
             (unsigned long)(now - rt->gsp_last_ts)); */
  static uint8_t g_buf[UDP_PL_MAX];
  size_t gsp_len = 0;
  gsp_bld (cry_ctx, rt->re_arr, (int)rt->cnt, 0, cfg->addr, g_buf, &gsp_len);
  if (gsp_len == 0)
    {
      rt->gsp_dirty = false;
      rt->gsp_last_ts = now;
      return;
    }
  static UdpMsg batch_arr[BATCH_MAX];
  int bc = 0;
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
      if (bc >= BATCH_MAX)
        {
          udp_tx_arr (udp, batch_arr, bc);
          rt->gsp_tx_cnt += (uint64_t)bc;
          rt->ctrl_tx_b += (uint64_t)gsp_len * (uint64_t)bc;
          bc = 0;
        }
      memcpy (batch_arr[bc].dst_ip, re->ep_ip, 16);
      batch_arr[bc].dst_port = re->ep_port;
      batch_arr[bc].data = g_buf;
      batch_arr[bc].data_len = gsp_len;
      bc++;
    }
  if (bc > 0)
    {
      udp_tx_arr (udp, batch_arr, bc);
      rt->gsp_tx_cnt += (uint64_t)bc;
      rt->ctrl_tx_b += (uint64_t)gsp_len * (uint64_t)bc;
    }
  rt->gsp_dirty = false;
  rt->gsp_last_ts = now;
}

static uint64_t
um_prb_intv (uint64_t age_ms)
{
  if (age_ms < UM_PRB_A1)
    return UM_PRB_I1;
  if (age_ms < UM_PRB_A2)
    return UM_PRB_I2;
  if (age_ms < UM_PRB_A3)
    return UM_PRB_I3;
  if (age_ms < UM_PRB_A4)
    return UM_PRB_I4;
  if (age_ms < UM_PRB_A5)
    return UM_PRB_I5;
  if (age_ms < UM_PRB_A6)
    return UM_PRB_I6;
  return UM_PRB_IMAX;
}

static bool
re_has_dir_alt (const Rt *rt, const Re *re)
{
  if (!rt || !re || re->r2d != 0 || lla_is_z (re->lla))
    return false;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *alt = &rt->re_arr[i];
      if (alt == re || alt->r2d != 0)
        continue;
      if (!alt->is_act || alt->state != RT_ACT)
        continue;
      if (memcmp (alt->lla, re->lla, 16) != 0)
        continue;
      return true;
    }
  return false;
}

static void
ctrl_rate_upd (Rt *rt, uint64_t ts)
{
  if (!rt)
    return;
  uint64_t tot_b = rt->ctrl_tx_b + rt->ctrl_rx_b;
  if (rt->ctrl_last_ts == 0 || ts <= rt->ctrl_last_ts)
    {
      rt->ctrl_last_ts = ts;
      rt->ctrl_last_b = tot_b;
      return;
    }
  uint64_t diff_ms = ts - rt->ctrl_last_ts;
  if (diff_ms == 0)
    return;
  rt->ctrl_now_bps = ((tot_b - rt->ctrl_last_b) * 1000ULL) / diff_ms;
  rt->ctrl_last_ts = ts;
  rt->ctrl_last_b = tot_b;
}

void
on_tmr (int timer_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint16_t act_port, uint64_t sid, PPool *pool)
{
  uint8_t exp_buf[8];
  if (read (timer_fd, exp_buf, sizeof (exp_buf)) < 0)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        {
          perror ("loop: read(timer_fd) failed");
        }
    }
  uint64_t ts = sys_ts ();
  if (cfg->mtu_probe)
    rt_mtu_tk (rt, ts);
  else
    rt_mtu_probe_idle (rt);
  if (rt->loc_last_ts == 0 || ts < rt->loc_last_ts
      || (ts - rt->loc_last_ts) >= ((uint64_t)UPD_TK * 1000ULL))
    {
      rt_loc_add (rt, cfg->addr, act_port, ts);
      rt->loc_last_ts = ts;
    }
  rt_prn_st (rt, ts);
  rt_src_gc (rt, ts);
  {
    static const uint8_t z_lla[16] = { 0 };
    for (int i = 0; i < pool->cnt; i++)
      {
        if (!is_underlay_ip (pool->re_arr[i].ip))
          continue;
        rt_ep_upd (rt, z_lla, pool->re_arr[i].ip, pool->re_arr[i].port, ts);
      }
  }
  if (pool->is_dirty)
    pool->is_dirty = false;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (re->r2d != 0)
        continue;

      bool is_unmapped = lla_is_z (re->lla);
      bool needs_probe = is_unmapped || re->state == RT_PND
                         || re->rt_m >= RT_M_INF;
      if (needs_probe)
        {
          uint64_t base_ts = re->rx_ts;
          if (re->tx_ts > base_ts)
            base_ts = re->tx_ts;
          uint64_t age_ms = (base_ts > 0 && ts > base_ts) ? (ts - base_ts) : 0;
          uint64_t intv = um_prb_intv (age_ms);
          if (re->pnd_ts > 0 && ts > re->pnd_ts && (ts - re->pnd_ts) < intv)
            continue;
          pulse_tx (udp, cry_ctx, rt, cfg, re, ts, sid, true);
          re->pnd_ts = ts;
          continue;
        }

      if (!re->is_act || re->state != RT_ACT)
        continue;
      uint64_t prb_intv = (re_is_stdby (rt, re, cfg->p2p == P2P_EN)
                           || re_has_dir_alt (rt, re))
                              ? UM_PRB_I1
                              : KA_TMO;
      if (re->prb_ts > 0 && ts > re->prb_ts && (ts - re->prb_ts) < prb_intv)
        continue;
      pulse_tx (udp, cry_ctx, rt, cfg, re, ts, sid, false);
    }
  if (cfg->mtu_probe)
    {
      for (int burst = 0; burst < 3; burst++)
        {
          Re prb_re;
          uint16_t prb_mtu = 0;
          uint32_t probe_id = 0;
          if (!rt_mprb_rdy (rt, ts, &prb_re, &prb_mtu, &probe_id))
            break;
          if (prb_re.state != RT_ACT)
            continue;
          static uint8_t prb_buf[UDP_PL_MAX];
          size_t probe_len = 0;
          uint16_t prb_o_oh = is_ip_v4m (prb_re.ep_ip) ? 20U : 40U;
          uint16_t prb_u_oh = (uint16_t)(prb_o_oh + 8U);
          size_t t_pl_len
              = (prb_mtu > prb_u_oh) ? (size_t)(prb_mtu - prb_u_oh)
                                     : (size_t)PKT_HDR_SZ;
          mtu_prb_bld (cry_ctx, probe_id, prb_mtu, t_pl_len, prb_buf,
                       &probe_len);
          udp_tx (udp, prb_re.ep_ip, prb_re.ep_port, prb_buf, probe_len);
          rt_tx_ack (rt, prb_re.ep_ip, prb_re.ep_port, ts);
        }
    }
  ctrl_rate_upd (rt, ts);
}

static void
status_append (char *buf, size_t cap, size_t *len, const char *fmt, ...)
{
  if (!buf || !len || *len >= cap)
    return;
  va_list ap;
  va_start (ap, fmt);
  int rc = vsnprintf (buf + *len, cap - *len, fmt, ap);
  va_end (ap);
  if (rc <= 0)
    return;
  size_t add = (size_t)rc;
  if (add >= cap - *len)
    *len = cap - 1;
  else
    *len += add;
}

static bool
ctrl_pkt_is (uint8_t pkt_type)
{
  return pkt_type == PT_PING || pkt_type == PT_PONG || pkt_type == PT_GSP
         || pkt_type == PT_SEQ_REQ;
}

static void
fmt_rate (char *buf, size_t cap, uint64_t bps)
{
  static const char *u[] = { "B/s", "KiB/s", "MiB/s", "GiB/s" };
  double v = (double)bps;
  int idx = 0;
  while (v >= 1024.0 && idx < 3)
    {
      v /= 1024.0;
      idx++;
    }
  snprintf (buf, cap, "%.1f %s", v, u[idx]);
}

static void
fmt_size (char *buf, size_t cap, uint64_t bytes)
{
  static const char *u[] = { "B", "KiB", "MiB", "GiB" };
  double v = (double)bytes;
  int idx = 0;
  while (v >= 1024.0 && idx < 3)
    {
      v /= 1024.0;
      idx++;
    }
  snprintf (buf, cap, "%.1f %s", v, u[idx]);
}

static size_t
status_emit_core (int fd, char *buf, size_t cap, Rt *rt, const Cfg *cfg,
                  PPool *pool)
{
  size_t len = 0;
  if ((fd < 0 && (!buf || cap == 0)) || !rt || !cfg || !pool)
    return 0;
#define STATUS_PUT(...)                                                        \
  do                                                                           \
    {                                                                          \
      if (fd >= 0)                                                             \
        dprintf (fd, __VA_ARGS__);                                             \
      else                                                                     \
        status_append (buf, cap, &len, __VA_ARGS__);                           \
    }                                                                          \
  while (0)
  int um_cnt = 0;
  uint8_t z_lla[16] = { 0 };
  uint64_t now = sys_ts ();
  uint64_t ctrl_tot_b = rt->ctrl_tx_b + rt->ctrl_rx_b;
  uint64_t up_ms = (rt->boot_ts > 0 && now > rt->boot_ts) ? (now - rt->boot_ts)
                                                           : 0;
  uint64_t ctrl_avg_bps
      = (up_ms > 0) ? ((ctrl_tot_b * 1000ULL) / up_ms) : ctrl_tot_b;
  char ctrl_avg_str[32];
  char ctrl_now_str[32];
  char ctrl_tot_str[32];
  char ctrl_tx_str[32];
  char ctrl_rx_str[32];
  fmt_rate (ctrl_avg_str, sizeof (ctrl_avg_str), ctrl_avg_bps);
  fmt_rate (ctrl_now_str, sizeof (ctrl_now_str), rt->ctrl_now_bps);
  fmt_size (ctrl_tot_str, sizeof (ctrl_tot_str), ctrl_tot_b);
  fmt_size (ctrl_tx_str, sizeof (ctrl_tx_str), rt->ctrl_tx_b);
  fmt_size (ctrl_rx_str, sizeof (ctrl_rx_str), rt->ctrl_rx_b);

  typedef struct
  {
    uint8_t ip[16];
    uint16_t port;
  } UnmappedEp;
  UnmappedEp um_arr[256];

  for (uint32_t re_idx = 0; re_idx < rt->cnt; re_idx++)
    {
      Re *z_re = &rt->re_arr[re_idx];
      if (z_re->r2d != 0 || memcmp (z_re->lla, z_lla, 16) != 0
          || z_re->state == RT_DED)
        continue;
      bool is_mapped = false;
      for (uint32_t map_idx = 0; map_idx < rt->cnt; map_idx++)
        {
          Re *m_re = &rt->re_arr[map_idx];
          if (m_re->r2d != 0 || memcmp (m_re->lla, z_lla, 16) == 0
              || m_re->state == RT_DED)
            continue;
          if (memcmp (m_re->ep_ip, z_re->ep_ip, 16) == 0
              && m_re->ep_port == z_re->ep_port)
            {
              is_mapped = true;
              break;
            }
        }
      if (is_mapped)
        continue;
      bool is_dup = false;
      for (int um_idx = 0; um_idx < um_cnt; um_idx++)
        {
          if (memcmp (um_arr[um_idx].ip, z_re->ep_ip, 16) == 0
              && um_arr[um_idx].port == z_re->ep_port)
            {
              is_dup = true;
              break;
            }
        }
      if (!is_dup && um_cnt < 256)
        {
          memcpy (um_arr[um_cnt].ip, z_re->ep_ip, 16);
          um_arr[um_cnt].port = z_re->ep_port;
          um_cnt++;
        }
    }

  typedef struct
  {
    char dst[INET6_ADDRSTRLEN + 2];
    char nh[128];
    char rtt[32];
    char st[10];
    char mtu[64];
  } RRow;
  uint8_t uniq_lla[256][16];
  int u_cnt = 0;
  for (uint32_t j = 0; j < rt->cnt && u_cnt < 256; j++)
    {
      if (rt->re_arr[j].state == RT_DED
          || memcmp (rt->re_arr[j].lla, z_lla, 16) == 0
          || memcmp (rt->re_arr[j].lla, cfg->addr, 16) == 0)
        continue;
      bool is_dup = false;
      for (int u = 0; u < u_cnt; u++)
        {
          if (memcmp (uniq_lla[u], rt->re_arr[j].lla, 16) == 0)
            {
              is_dup = true;
              break;
            }
        }
      if (!is_dup)
        memcpy (uniq_lla[u_cnt++], rt->re_arr[j].lla, 16);
    }

  RRow rows[256];
  int r_cnt = 0, act_map_cnt = 0, m_dst = 3, m_nh = 7, m_st = 5, m_mtu = 3;
  for (int u = 0; u < u_cnt && r_cnt < 256; u++)
    {
      RtDec sel = rt_sel (rt, uniq_lla[u], cfg->p2p == P2P_EN);
      RRow *row = &rows[r_cnt++];
      inet_ntop (AF_INET6, uniq_lla[u], row->dst, sizeof (row->dst));
      if ((int)strlen (row->dst) > m_dst)
        m_dst = (int)strlen (row->dst);
      uint8_t sel_ip[16];
      uint16_t sel_port = 0;
      if (sel.type == RT_DIR)
        {
          memcpy (sel_ip, sel.dir.ip, 16);
          sel_port = sel.dir.port;
        }
      else if (sel.type == RT_REL)
        {
          memcpy (sel_ip, sel.rel.relay_ip, 16);
          sel_port = sel.rel.relay_port;
        }
      else
        {
          memset (sel_ip, 0, 16);
          sel_port = 0;
        }

      char ep_str[64] = "-";
      if (sel.type == RT_DIR || sel.type == RT_REL)
        {
          char ip_str[INET6_ADDRSTRLEN];
          if (sel_ip[0] == 0 && sel_ip[1] == 0 && sel_ip[10] == 0xff
              && sel_ip[11] == 0xff)
            inet_ntop (AF_INET, sel_ip + 12, ip_str, sizeof (ip_str));
          else
            inet_ntop (AF_INET6, sel_ip, ip_str, sizeof (ip_str));
          snprintf (ep_str, sizeof (ep_str), "%s:%u", ip_str, sel_port);
        }
      char nhop_str[INET6_ADDRSTRLEN] = "-";
      if (sel.type == RT_DIR)
        inet_ntop (AF_INET6, uniq_lla[u], nhop_str, sizeof (nhop_str));
      else if (sel.type == RT_REL && IS_LLA_VAL (sel.rel.relay_lla))
        inet_ntop (AF_INET6, sel.rel.relay_lla, nhop_str, sizeof (nhop_str));

      uint32_t show_m = rt_show_m (rt, uniq_lla[u], &sel);
      if (sel.type == RT_NONE || sel.type == RT_VP)
        {
          memset (sel_ip, 0, 16);
          sel_port = 0;
          snprintf (row->nh, sizeof (row->nh), "- (-)");
          strcpy (row->st, sel.type == RT_NONE ? "unmapped" : "via");
          strcpy (row->rtt, "-");
          strcpy (row->mtu, "-");
        }
      else
        {
          snprintf (row->nh, sizeof (row->nh), "%s (%s)", nhop_str, ep_str);
          if (show_m >= RT_M_INF)
            strcpy (row->rtt, "-");
          else
            snprintf (row->rtt, sizeof (row->rtt), "%ums", show_m);
          {
            uint16_t pmtu = rt_mtu (rt, &sel);
            uint16_t prb_mtu = 0, lkg = pmtu, ukb = pmtu;
            bool is_srch = false, is_fixed = true;
            MtuSt mtu_st = MTU_ST_B;
            rt_pmtu_st (rt, &sel, &pmtu, &prb_mtu, &is_srch, &is_fixed);
            rt_pmtu_lims (rt, &sel, &lkg, &ukb, &mtu_st);
            if (is_srch)
              {
                if (prb_mtu > 0)
                  snprintf (row->mtu, sizeof (row->mtu), "%u (%u-%u, %u)",
                            pmtu, lkg, ukb, prb_mtu);
                else
                  snprintf (row->mtu, sizeof (row->mtu), "%u (%u-%u)", pmtu,
                            lkg, ukb);
              }
            else
              {
                if (mtu_st == MTU_ST_F || is_fixed)
                  snprintf (row->mtu, sizeof (row->mtu), "%u", pmtu);
                else
                  snprintf (row->mtu, sizeof (row->mtu),
                            "%u (LKG:%u, UKB:%u, base)", pmtu, lkg, ukb);
              }
          }
          strcpy (row->st, "active");
        }
      if ((int)strlen (row->nh) > m_nh)
        m_nh = (int)strlen (row->nh);
      if (strcmp (row->st, "active") == 0)
        act_map_cnt++;
      if ((int)strlen (row->st) > m_st)
        m_st = (int)strlen (row->st);
      if ((int)strlen (row->mtu) > m_mtu)
        m_mtu = (int)strlen (row->mtu);
    }

  for (int um_idx = 0; um_idx < um_cnt && r_cnt < 256; um_idx++)
    {
      RRow *row = &rows[r_cnt++];
      strcpy (row->dst, "-");
      char ip_str[INET6_ADDRSTRLEN];
      const uint8_t *ep_ip = um_arr[um_idx].ip;
      if (ep_ip[0] == 0 && ep_ip[1] == 0 && ep_ip[10] == 0xff
          && ep_ip[11] == 0xff)
        inet_ntop (AF_INET, ep_ip + 12, ip_str, sizeof (ip_str));
      else
        inet_ntop (AF_INET6, ep_ip, ip_str, sizeof (ip_str));
      snprintf (row->nh, sizeof (row->nh), "- (%s:%u)", ip_str,
                um_arr[um_idx].port);
      strcpy (row->st, "unmapped");
      strcpy (row->rtt, "-");
      strcpy (row->mtu, "-");
      if ((int)strlen (row->dst) > m_dst)
        m_dst = (int)strlen (row->dst);
      if ((int)strlen (row->nh) > m_nh)
        m_nh = (int)strlen (row->nh);
      if ((int)strlen (row->st) > m_st)
        m_st = (int)strlen (row->st);
      if ((int)strlen (row->mtu) > m_mtu)
        m_mtu = (int)strlen (row->mtu);
    }

  STATUS_PUT ("fib: active: %d/%u, static: %d, unmapped: %d\n", act_map_cnt,
              (uint32_t)rt->cnt, pool->cnt, um_cnt);
  STATUS_PUT ("ctrl: gossip_tx=%llu ping_tx=%llu now=%s avg=%s total=%s tx=%s rx=%s\n",
              (unsigned long long)rt->gsp_tx_cnt,
              (unsigned long long)rt->ping_tx_cnt, ctrl_now_str, ctrl_avg_str,
              ctrl_tot_str, ctrl_tx_str, ctrl_rx_str);
  if (r_cnt > 0)
    {
      STATUS_PUT ("  %-*s  %-*s  %-*s  %-*s  rtt\n", m_dst, "dst", m_nh,
                  "nexthop", m_st, "state", m_mtu, "mtu");
      for (int k = 0; k < r_cnt; k++)
        {
          STATUS_PUT ("  %-*s  %-*s  %-*s  %-*s  %s\n", m_dst, rows[k].dst,
                      m_nh, rows[k].nh, m_st, rows[k].st, m_mtu, rows[k].mtu,
                      rows[k].rtt);
        }
    }
#undef STATUS_PUT
  return len;
}

size_t
status_buf_bld (char *buf, size_t cap, Rt *rt, const Cfg *cfg, PPool *pool)
{
  return status_emit_core (-1, buf, cap, rt, cfg, pool);
}

void
status_fd_emit (int fd, Rt *rt, const Cfg *cfg, PPool *pool)
{
  (void)status_emit_core (fd, NULL, 0, rt, cfg, pool);
}

void
on_std (int fd, Rt *rt, const Cfg *cfg, PPool *pool)
{
  char cmd_buf[128];
  int r_len = read (fd, cmd_buf, sizeof (cmd_buf) - 1);
  if (r_len <= 0)
    return;
  cmd_buf[r_len] = '\0';
  if (cmd_buf[0] == '\n' || cmd_buf[0] == '\r' || cmd_buf[0] == '\x1b')
    return;
  if (!(strchr (cmd_buf, 's') || strchr (cmd_buf, 'S')))
    return;
  status_fd_emit (STDOUT_FILENO, rt, cfg, pool);
}
