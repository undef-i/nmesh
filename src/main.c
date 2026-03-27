#include "config.h"
#include "crypto.h"
#include "forward.h"
#include "frag.h"
#include "gossip.h"
#include "gro.h"
#include "loop.h"
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
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

int
main (int argc, char **argv)
{
  const char *cfg_path = "nmesh.conf";
  for (int i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "-c") == 0 && i + 1 < argc)
        {
          cfg_path = argv[++i];
        }
    }
  Cfg cfg;
  if (cfg_load (cfg_path, &cfg) != 0)
    {
      fprintf (stderr, "main: failed to load config: %s\n", cfg_path);
      return 1;
    }
  printf ("main: loaded config from %s\n", cfg_path);
  uint64_t sid;
  {
    struct timespec t;
    clock_gettime (CLOCK_REALTIME, &t);
    sid = (uint64_t)t.tv_sec ^ ((uint64_t)t.tv_nsec << 32)
          ^ (uint64_t)getpid ();
  }
  g_rnd_st = (uint32_t)(sid ^ (sid >> 32));
  if (g_rnd_st == 0)
    g_rnd_st = 0x6d2b79f5U;
  printf ("main: session id: %016llx\n", (unsigned long long)sid);
  static PPool pool;
  pp_init (&pool, cfg_path);
  Rt rt;
  rt_init (&rt);
  memcpy (rt.our_lla, cfg.addr, 16);
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
  int tap_fd = tap_init (cfg.ifname);
  if (tap_fd < 0)
    {
      fprintf (stderr, "main: failed to create tap\n");
      return 1;
    }
  tap_addr_set (cfg.ifname, cfg.addr);
  tap_mtu_set (cfg.ifname, cfg.mtu);
  printf ("main: tap device %s created (mtu=%u).\n", cfg.ifname,
          (unsigned)cfg.mtu);
  static Udp udp;
  uint16_t act_port = cfg.port;
  if (udp_init (&udp, &act_port) != 0)
    {
      if (!cfg.l_exp)
        {
          act_port = 0;
          if (udp_init (&udp, &act_port) != 0)
            {
              fprintf (stderr, "main: failed to bind udp port\n");
              return 1;
            }
        }
      else
        {
          fprintf (stderr, "main: failed to bind explicit udp port %u\n",
                   cfg.port);
          return 1;
        }
    }
  g_rt = &rt;
  udp_emsg_cb_set (on_udp_emsg);
  udp_unr_cb_set (on_udp_unr);
  printf ("main: udp bound to port %u\n", act_port);
  {
    uint16_t hw_mtu = udp_mtu_get (&udp);
    rt_pmtu_ub_set (&rt, hw_mtu);
  }
  rt_loc_add (&rt, cfg.addr, act_port, sys_ts ());
  int epfd = epoll_create1 (0);
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.u64 = ID_TAP;
  epoll_ctl (epfd, EPOLL_CTL_ADD, tap_fd, &ev);
  ev.events = EPOLLIN | EPOLLERR;
  ev.data.u64 = ID_UDP;
  epoll_ctl (epfd, EPOLL_CTL_ADD, udp.fd, &ev);
  bool u_w_watch = false;
  int timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK);
  struct itimerspec its;
  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 1000000;
  its.it_interval.tv_sec = GSP_INTV;
  its.it_interval.tv_nsec = 0;
  timerfd_settime (timer_fd, 0, &its, NULL);
  ev.events = EPOLLIN;
  ev.data.u64 = ID_TMR;
  epoll_ctl (epfd, EPOLL_CTL_ADD, timer_fd, &ev);
  struct epoll_event ev_arr[EV_MAX];
  tty_raw ();
  int stdin_flg = fcntl (STDIN_FILENO, F_GETFL, 0);
  if (stdin_flg >= 0)
    fcntl (STDIN_FILENO, F_SETFL, stdin_flg | O_NONBLOCK);
  ev.events = EPOLLIN;
  ev.data.u64 = ID_STD;
  epoll_ctl (epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);
  char cfg_dir[512];
  char cfg_file[256];
  const char *slash = strrchr (cfg_path, '/');
  if (slash)
    {
      size_t dlen = (size_t)(slash - cfg_path);
      if (dlen >= sizeof (cfg_dir))
        dlen = sizeof (cfg_dir) - 1;
      memcpy (cfg_dir, cfg_path, dlen);
      cfg_dir[dlen] = '\0';
      snprintf (cfg_file, sizeof (cfg_file), "%s", slash + 1);
    }
  else
    {
      snprintf (cfg_dir, sizeof (cfg_dir), ".");
      snprintf (cfg_file, sizeof (cfg_file), "%s", cfg_path);
    }
  int cfg_ifd = inotify_init1 (IN_NONBLOCK | IN_CLOEXEC);
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
          epoll_ctl (epfd, EPOLL_CTL_ADD, cfg_ifd, &ev);
          fprintf (stderr, "main: config watcher active: %s/%s\n", cfg_dir,
                   cfg_file);
        }
    }
  printf ("main: nmesh running; entering epoll loop\n");
  printf ("main: type 's' and press enter to view routing table\n");
  fflush (stdout);
  on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, act_port, sid, &pool);
  rt_gsp_dirty_set (&rt, "initial");
  udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
  while (1)
    {
      int nev = epoll_wait (epfd, ev_arr, EV_MAX, -1);
      if (nev < 0)
        {
          if (errno == EINTR)
            continue;
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
                    {
                      rt_pmtu_ptb_ep (&rt, dst_ip, dst_port, pmtu, sys_ts ());
                    }
                }
              if ((ev_arr[i].events & EPOLLOUT) != 0)
                {
                  (void)udp_w_hnd (&udp);
                }
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_TMR)
            {
              on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, act_port, sid,
                      &pool);
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_STD)
            {
              on_std (STDIN_FILENO, &rt, &cfg, &pool);
            }
          else if (tok == ID_CFG)
            {
              if (cfg_ifd >= 0)
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
                          if (ie->len > 0
                              && strncmp (ie->name, cfg_file,
                                          sizeof (cfg_file))
                                     == 0)
                            {
                              if ((ie->mask & IN_CLOSE_WRITE)
                                  || (ie->mask & IN_MOVED_TO))
                                need_reload = true;
                            }
                          off += (ssize_t)sizeof (struct inotify_event)
                                 + (ssize_t)ie->len;
                        }
                      if (need_reload)
                        {
                          cfg_reload_apply (&cfg, &cry_ctx, &rt, &pool,
                                            cfg_path, sys_ts ());
                        }
                    }
                }
            }
        }
      gsp_dirty_flush (&udp, &cry_ctx, &rt, &cfg);
      udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
    }
  return 0;
}
