#include "cfg.h"
#include "cry.h"
#include "frag.h"
#include "gsp.h"
#include "mss.h"
#include "pkt.h"
#include "rt.h"
#include "tap.h"
#include "udp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
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
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define EV_MAX 10
#define ID_TAP 1
#define ID_UDP 2
#define ID_TMR 3
#define ID_STD 4
#define ID_CFG 5
#define GSP_INTV 4
#define UPD_TK 4
#define TAP_F_MAX 16384
#define PEER_FLS_TK 5
#define KA_TMO 25000ULL
#define RX_RP_MAX 512
#define RX_RP_W 16
#define RX_RP_B (RX_RP_W * 64)
static uint64_t g_tx_ts = 0;
static uint64_t g_rx_ts = 0;
static uint32_t g_frag_mid = 1;
static uint32_t g_rnd_st = 0;
static Rt *g_rt = NULL;

typedef struct
{
  bool is_act;
  uint8_t ip[16];
  uint16_t port;
  uint8_t sid[4];
  uint64_t max_cnt;
  uint64_t map[RX_RP_W];
} RxRp;

static RxRp g_rx_rp[RX_RP_MAX];

static uint64_t sys_ts (void);

static uint32_t
u32_rnd (void)
{
  if (g_rnd_st == 0)
    {
      uint64_t s = sys_ts ();
      g_rnd_st = (uint32_t)(s ^ (s >> 32) ^ 0x9e3779b9U);
      if (g_rnd_st == 0)
        g_rnd_st = 0x6d2b79f5U;
    }
  uint32_t x = g_rnd_st;
  x ^= (x << 13);
  x ^= (x >> 17);
  x ^= (x << 5);
  g_rnd_st = x;
  return x;
}

static uint64_t
nonce_cnt_rd (const uint8_t nonce[PKT_NONCE_SZ])
{
  return ((uint64_t)nonce[4] << 56) | ((uint64_t)nonce[5] << 48)
         | ((uint64_t)nonce[6] << 40) | ((uint64_t)nonce[7] << 32)
         | ((uint64_t)nonce[8] << 24) | ((uint64_t)nonce[9] << 16)
         | ((uint64_t)nonce[10] << 8) | (uint64_t)nonce[11];
}

static void
nonce_sid_rd (const uint8_t nonce[PKT_NONCE_SZ], uint8_t sid[4])
{
  memcpy (sid, nonce, 4);
}

static void
rx_rp_map_rst (uint64_t map[RX_RP_W])
{
  memset (map, 0, sizeof (uint64_t) * RX_RP_W);
}

static void
rx_rp_map_shl (uint64_t map[RX_RP_W], uint64_t sh)
{
  if (sh == 0)
    return;
  if (sh >= RX_RP_B)
    {
      rx_rp_map_rst (map);
      return;
    }
  uint64_t tmp[RX_RP_W] = { 0 };
  size_t w_sh = (size_t)(sh / 64);
  size_t b_sh = (size_t)(sh % 64);
  for (int i = RX_RP_W - 1; i >= 0; i--)
    {
      if ((size_t)i < w_sh)
        continue;
      size_t src = (size_t)i - w_sh;
      uint64_t v = map[src] << b_sh;
      if (b_sh != 0 && src > 0)
        {
          v |= (map[src - 1] >> (64 - b_sh));
        }
      tmp[i] = v;
    }
  memcpy (map, tmp, sizeof (tmp));
}

static bool
rx_rp_map_tst (const uint64_t map[RX_RP_W], uint64_t df)
{
  if (df >= RX_RP_B)
    return false;
  size_t wi = (size_t)(df / 64);
  size_t bi = (size_t)(df % 64);
  return (map[wi] & (1ULL << bi)) != 0;
}

static void
rx_rp_map_set (uint64_t map[RX_RP_W], uint64_t df)
{
  if (df >= RX_RP_B)
    return;
  size_t wi = (size_t)(df / 64);
  size_t bi = (size_t)(df % 64);
  map[wi] |= (1ULL << bi);
}

static bool
rx_rp_chk (const uint8_t ip[16], uint16_t port,
           const uint8_t nonce[PKT_NONCE_SZ])
{
  uint8_t sid[4];
  nonce_sid_rd (nonce, sid);
  uint64_t cnt = nonce_cnt_rd (nonce);
  RxRp *slot = NULL;
  RxRp *same_ep = NULL;
  for (size_t i = 0; i < RX_RP_MAX; i++)
    {
      if (!g_rx_rp[i].is_act)
        {
          if (!slot)
            slot = &g_rx_rp[i];
          continue;
        }
      if (memcmp (g_rx_rp[i].ip, ip, 16) != 0 || g_rx_rp[i].port != port)
        continue;
      if (memcmp (g_rx_rp[i].sid, sid, sizeof (sid)) == 0)
        {
          slot = &g_rx_rp[i];
          break;
        }
      if (!same_ep)
        same_ep = &g_rx_rp[i];
    }
  if (!slot)
    slot = same_ep;
  if (!slot)
    return false;
  if (!slot->is_act)
    {
      slot->is_act = true;
      memcpy (slot->ip, ip, 16);
      slot->port = port;
      memcpy (slot->sid, sid, sizeof (sid));
      slot->max_cnt = cnt;
      rx_rp_map_rst (slot->map);
      rx_rp_map_set (slot->map, 0);
      return true;
    }
  if (memcmp (slot->sid, sid, sizeof (sid)) != 0)
    {
      memcpy (slot->sid, sid, sizeof (sid));
      slot->max_cnt = cnt;
      rx_rp_map_rst (slot->map);
      rx_rp_map_set (slot->map, 0);
      return true;
    }
  if (cnt > slot->max_cnt)
    {
      uint64_t sh = cnt - slot->max_cnt;
      rx_rp_map_shl (slot->map, sh);
      rx_rp_map_set (slot->map, 0);
      slot->max_cnt = cnt;
      return true;
    }
  uint64_t df = slot->max_cnt - cnt;
  if (df >= RX_RP_B)
    return false;
  if (rx_rp_map_tst (slot->map, df))
    return false;
  rx_rp_map_set (slot->map, df);
  return true;
}

static void
rx_rp_rst_ep (const uint8_t ip[16], uint16_t port)
{
  for (size_t i = 0; i < RX_RP_MAX; i++)
    {
      if (!g_rx_rp[i].is_act)
        continue;
      if (memcmp (g_rx_rp[i].ip, ip, 16) != 0)
        continue;
      if (g_rx_rp[i].port != port)
        continue;
      memset (&g_rx_rp[i], 0, sizeof (g_rx_rp[i]));
    }
}

static void
rx_rp_rst_lla (Rt *rt, const uint8_t lla[16])
{
  if (!rt || !lla)
    return;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (memcmp (re->lla, lla, 16) != 0)
        continue;
      rx_rp_rst_ep (re->ep_ip, re->ep_port);
    }
}

static void
on_udp_emsg (const uint8_t dst_ip[16], uint16_t dst_port, size_t atmpt_plen)
{
  if (!g_rt)
    return;
  rt_emsg_hnd (g_rt, dst_ip, dst_port, atmpt_plen, sys_ts ());
}

static void
on_udp_unr (const uint8_t dst_ip[16], uint16_t dst_port)
{
  if (!g_rt)
    return;
  rt_unr_hnd (g_rt, dst_ip, dst_port, sys_ts ());
}

static void
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

static uint64_t
sys_ts (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static bool
is_tcp_syn (const uint8_t *l3, size_t l3_len)
{
  if (!l3 || l3_len < 20)
    return false;
  uint8_t v = (uint8_t)((l3[0] >> 4) & 0x0f);
  if (v == 4)
    {
      uint8_t ihl = (uint8_t)((l3[0] & 0x0f) * 4);
      if (ihl < 20 || ((size_t)ihl + 20U) > l3_len)
        return false;
      if (l3[9] != 6)
        return false;
      return (l3[ihl + 13] & 0x02U) != 0;
    }
  if (v == 6)
    {
      if (l3_len < 40 + 20)
        return false;
      if (l3[6] != 6)
        return false;
      return (l3[40 + 13] & 0x02U) != 0;
    }
  return false;
}

static bool
is_ip_v4m (const uint8_t ip[16])
{
  if (!ip)
    return false;
  return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
         && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0
         && ip[10] == 0xff && ip[11] == 0xff;
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

static void
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
re_m (const Re *re)
{
  if (re->lat > 0 && re->lat < RTT_UNK)
    return re->lat;
  if (re->sm_m > 0 && re->sm_m < RT_M_INF && re->sm_m != RTT_UNK)
    return re->sm_m;
  if (re->rt_m > 0 && re->rt_m < RT_M_INF && re->rt_m != RTT_UNK)
    return re->rt_m;
  return RT_M_INF;
}

static uint32_t
rt_e2e_m (const Rt *rt, const uint8_t dst_lla[16], const RtDec *sel)
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
          uint32_t m = re_m (re);
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
            m_adv = re->rt_m;
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
          uint32_t m = re_m (re);
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
rt_gw_fnd (const Rt *rt, const uint8_t our_lla[16], uint8_t out_ip[16],
           uint16_t *out_port)
{
  bool has_res = false;
  uint32_t best = RT_M_INF;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (!re->is_act || re->state == RT_DED)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->lla, our_lla, 16) == 0)
        continue;
      uint32_t m = re_m (re);
      if (m >= RT_M_INF)
        continue;
      if (!has_res || m < best)
        {
          memcpy (out_ip, re->ep_ip, 16);
          *out_port = re->ep_port;
          best = m;
          has_res = true;
        }
    }
  return has_res;
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

static void
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
      if (is_ip_bgn (ip))
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
      s_re.rt_m = 0;
      s_re.adv_m = 0;
      s_re.seq = 1;
      s_re.rto = RTO_INIT;
      memcpy (s_re.nhop_lla, our_lla, 16);
      rt_upd (rt, &s_re, now);
    }
  freeifaddrs (ifaddr);
}

static uint16_t
ep_mtu_get (const Rt *rt, const uint8_t ip[16], uint16_t port)
{
  uint16_t best = 0;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (!re->is_act || re->state == RT_DED)
        continue;
      if (re->r2d != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0)
        continue;
      if (re->ep_port != port)
        continue;
      uint16_t mtu = (re->mtu > 0) ? re->mtu : RT_MTU_DEF;
      if (best == 0 || mtu < best)
        best = mtu;
    }
  return (best > 0) ? best : RT_MTU_DEF;
}

static bool
rt_nh_get (Rt *rt, const Cfg *cfg, const uint8_t dest_lla[16], RtDec *out_dec,
           uint8_t out_ip[16], uint16_t *out_port)
{
  if (!rt || !cfg || !dest_lla || !out_dec || !out_ip || !out_port)
    return false;
  RtDec dec = rt_sel (rt, dest_lla, cfg->p2p == P2P_EN);
  if (dec.type == RT_DIR)
    {
      memcpy (out_ip, dec.dir.ip, 16);
      *out_port = dec.dir.port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  if (dec.type == RT_REL)
    {
      memcpy (out_ip, dec.rel.relay_ip, 16);
      *out_port = dec.rel.relay_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  if (dec.type == RT_VP)
    {
      uint8_t gw_ip[16] = { 0 };
      uint16_t gw_port = 0;
      if (!rt_gw_fnd (rt, cfg->addr, gw_ip, &gw_port))
        return false;
      memcpy (out_ip, gw_ip, 16);
      *out_port = gw_port;
      *out_dec = dec;
      return (*out_port != 0);
    }
  return false;
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

static void
cfg_reload_apply (Cfg *cfg, Cry *cry_ctx, Rt *rt, PPool *pool,
                  const char *cfg_path, uint64_t ts)
{
  Cfg new_cfg;
  if (cfg_load (cfg_path, &new_cfg) != 0)
    {
      return;
    }
  if (memcmp (cfg->addr, new_cfg.addr, 16) != 0)
    fprintf (stderr, "main: address changed in config but not hot-applied\n");
  if (cfg->port != new_cfg.port || cfg->l_exp != new_cfg.l_exp)
    fprintf (stderr, "main: listen/port changed in config but not "
                     "hot-applied\n");
  if (cfg->mtu != new_cfg.mtu)
    fprintf (stderr, "main: tap mtu changed in config but not hot-applied\n");
  if (cfg->p2p != new_cfg.p2p)
    {
      cfg->p2p = new_cfg.p2p;
      fprintf (stderr, "main: reloaded p2p mode\n");
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

static bool
rel_fwd_dat (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
             const uint8_t dest_lla[16], const uint8_t *frame,
             size_t frame_len, uint8_t hop_c, uint64_t ts,
             const uint8_t s_ip[16], uint16_t s_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !frame)
    return false;
  if (frame_len < ETH_HLEN || frame_len > TAP_F_MAX || frame_len > UINT16_MAX)
    return false;
  if (hop_c == 0)
    return false;
  RtDec dec;
  uint8_t tx_ip[16] = { 0 };
  uint16_t tx_port = 0;
  if (!rt_nh_get (rt, cfg, dest_lla, &dec, tx_ip, &tx_port))
    return false;
  if (s_ip && memcmp (tx_ip, s_ip, 16) == 0 && tx_port == s_port)
    return false;
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
  const uint16_t tnl_oh = (uint16_t)(oip_oh + 8U + PKT_HDR_SZ);
  int32_t frag_cap
      = (int32_t)pmtu - (int32_t)(tnl_oh + (uint16_t)sizeof (FragHdr) + 4U);
  if (frag_cap <= 0)
    return false;
  static uint8_t rel_f_buf[TAP_F_MAX + TAP_HR + TAP_TR] __attribute__ ((aligned (32)));
  uint8_t *frame_pkt = rel_f_buf + TAP_HR;
  memcpy (frame_pkt, frame, frame_len);
  uint16_t m_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
  {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type
        = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
        eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
        l3_off = ETH_HLEN + 4;
      }
    if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
      {
        uint16_t m_in_l3 = (m_tap_f > l3_off + 20U)
                               ? (uint16_t)(m_tap_f - l3_off - 20U)
                               : 0;
        if (m_in_l3 >= 88U)
          {
            mss_clp (frame_pkt + l3_off, frame_len - l3_off, m_in_l3);
          }
      }
  }
  bool is_tiny = false;
  {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type
        = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
        eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
        l3_off = ETH_HLEN + 4;
      }
    if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
      {
        is_tiny = (frag_cap < 64)
                  && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
      }
  }
  if (!is_tiny && ((size_t)frame_len + (size_t)tnl_oh) <= (size_t)pmtu)
    {
      static uint8_t rel_p_buf[UDP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
      uint8_t *pl_dst = rel_p_buf + TAP_HR + PKT_HDR_SZ;
      memcpy (pl_dst, frame_pkt, frame_len);
      size_t out_len = 0;
      uint8_t *out_ptr
          = data_bld_zc (cry_ctx, pl_dst, frame_len, 1, hop_c, &out_len);
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
    }
  else
    {
      size_t frag_pfx = sizeof (FragHdr) + 4U;
      if (m_tap_f <= frag_pfx)
        return false;
      size_t chunk_max = m_tap_f - frag_pfx;
      if (chunk_max == 0)
        return false;
      uint32_t mid = g_frag_mid++;
      if (g_frag_mid == 0)
        g_frag_mid = 1;
      uint8_t dst_tail[4];
      memcpy (dst_tail, dest_lla + 12, 4);
      static uint8_t rel_fg_buf[UDP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
      size_t off = 0;
      while (off < frame_len)
        {
          size_t chunk_len = frame_len - off;
          if (chunk_len > chunk_max)
            chunk_len = chunk_max;
          uint8_t *chunk_dst
              = rel_fg_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
          memcpy (chunk_dst, frame_pkt + off, chunk_len);
          size_t out_len = 0;
          bool mf = (off + chunk_len) < frame_len;
          uint8_t *out_ptr
              = frag_bld_zc (cry_ctx, chunk_dst, chunk_len, mid, (uint16_t)off,
                             mf, 1, dst_tail, hop_c, &out_len);
          udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
          rt_tx_ack (rt, tx_ip, tx_port, ts);
          g_tx_ts = ts;
          off += chunk_len;
        }
    }
  if (dec.type == RT_REL && cfg->p2p == P2P_EN)
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
    }
  return true;
}

static bool
relay_fwd_frag (Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
                const uint8_t dest_lla[16], uint32_t mid, uint16_t frag_off,
                bool mf_in, const uint8_t *chunk, size_t chunk_len,
                uint8_t hop_c, uint64_t ts, const uint8_t s_ip[16],
                uint16_t s_port)
{
  if (!udp || !cry_ctx || !rt || !cfg || !dest_lla || !chunk)
    return false;
  if (hop_c == 0)
    return false;
  RtDec dec;
  uint8_t tx_ip[16] = { 0 };
  uint16_t tx_port = 0;
  if (!rt_nh_get (rt, cfg, dest_lla, &dec, tx_ip, &tx_port))
    return false;
  if (s_ip && memcmp (tx_ip, s_ip, 16) == 0 && tx_port == s_port)
    return false;
  uint16_t pmtu = ep_mtu_get (rt, tx_ip, tx_port);
  if (dec.type == RT_REL)
    {
      uint16_t mtu = rt_mtu (rt, &dec);
      if (mtu < pmtu)
        pmtu = mtu;
    }
  uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
  const uint16_t tnl_oh = (uint16_t)(oip_oh + 8U + PKT_HDR_SZ);
  uint16_t m_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
  size_t frag_pfx = sizeof (FragHdr) + 4U;
  if (m_tap_f <= frag_pfx)
    return false;
  size_t chunk_max = m_tap_f - frag_pfx;
  if (chunk_max == 0)
    return false;
  uint8_t dst_tail[4];
  memcpy (dst_tail, dest_lla + 12, 4);
  bool is_tx = false;
  static uint8_t rel_fg_buf[UDP_PL_MAX + TAP_HR];
  for (size_t sub_off = 0; sub_off < chunk_len;)
    {
      size_t sub_len = chunk_len - sub_off;
      if (sub_len > chunk_max)
        sub_len = chunk_max;
      uint32_t abs_off = (uint32_t)frag_off + (uint32_t)sub_off;
      if (abs_off > UINT16_MAX)
        break;
      uint8_t *chunk_dst
          = rel_fg_buf + TAP_HR + PKT_HDR_SZ + sizeof (FragHdr) + 4U;
      memcpy (chunk_dst, chunk + sub_off, sub_len);
      size_t out_len = 0;
      bool is_last_sub = (sub_off + sub_len) == chunk_len;
      bool mf_out = mf_in || !is_last_sub;
      uint8_t *out_ptr
          = frag_bld_zc (cry_ctx, chunk_dst, sub_len, mid, (uint16_t)abs_off,
                         mf_out, 1, dst_tail, hop_c, &out_len);
      udp_tx (udp, tx_ip, tx_port, out_ptr, out_len);
      rt_tx_ack (rt, tx_ip, tx_port, ts);
      g_tx_ts = ts;
      is_tx = true;
      sub_off += sub_len;
    }
  if (is_tx && dec.type == RT_REL && cfg->p2p == P2P_EN)
    {
      static uint8_t hp_buf[UDP_PL_MAX];
      size_t hp_len = 0;
      hp_bld (cry_ctx, cfg->addr, dest_lla, hp_buf, &hp_len);
      udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
    }
  return is_tx;
}

static void
on_tap (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid)
{
  (void)sid;
  static uint64_t l_nh_ts = 0;

  static struct
  {
    uint8_t dest_lla[16];
    RtDec dec;
    uint64_t val_ts;
    bool is_val;
  } fast_path;

  static uint8_t frame_bufs[BATCH_MAX][TAP_F_MAX + TAP_HR + TAP_TR] __attribute__ ((aligned (32)));
  static uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR] __attribute__ ((aligned (32)));
  static UdpMsg batch_arr[BATCH_MAX];
  int bc = 0;
  for (int i = 0; i < BATCH_MAX; i++)
    {
      uint8_t *pl_ptr = frame_bufs[i] + TAP_HR;
      ssize_t n = read (tap_fd, pl_ptr, TAP_F_MAX);
      if (n <= 0)
        {
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          break;
        }
      FRes result;
      tap_f_proc (pl_ptr, (size_t)n, cfg->addr, &result);
      if (result.res_type == FRAME_NS_INT)
        {
          if (write (tap_fd, result.na_frame, result.na_len) < 0)
            {
            }
          continue;
        }
      if (result.res_type != FRAME_V6_DAT)
        continue;
      uint8_t *frame_pkt = pl_ptr + result.pl_start;
      size_t frame_len = result.payload_len;
      const uint8_t *dst_mac = pl_ptr;
      uint64_t now = sys_ts ();
      if ((dst_mac[0] & 0x01U) != 0U)
        {
          size_t out_len;
          uint8_t *out_ptr
              = data_bld_zc (cry_ctx, frame_pkt, frame_len, 0, 32, &out_len);
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
              if (bc >= BATCH_MAX)
                {
                  if (udp_tx_arr (udp, batch_arr, bc) < 0)
                    {
                      fprintf (stderr, "udp: batch send "
                                       "failed before enqueue "
                                       "multicast\n");
                    }
                  bc = 0;
                }
              memcpy (batch_arr[bc].dst_ip, ep_arr[re].ip, 16);
              batch_arr[bc].dst_port = ep_arr[re].port;
              batch_arr[bc].data = out_ptr;
              batch_arr[bc].data_len = out_len;
              bc++;
              rt_tx_ack (rt, ep_arr[re].ip, ep_arr[re].port, now);
              g_tx_ts = now;
            }
          continue;
        }
      uint8_t rt_key[16];
      if (!rt_key_get (rt, pl_ptr, cfg->addr, rt_key))
        {
          if (now - l_nh_ts >= 2000ULL)
            {
              fprintf (stderr,
                       "routing: unresolved next-hop for dst-mac "
                       "%02x:%02x:%02x:%02x:%02x:%02x\n",
                       pl_ptr[0], pl_ptr[1], pl_ptr[2], pl_ptr[3], pl_ptr[4],
                       pl_ptr[5]);
              l_nh_ts = now;
            }
          continue;
        }
      RtDec dec;
      memset (&dec, 0, sizeof (dec));
      if (fast_path.is_val && now <= fast_path.val_ts
          && memcmp (fast_path.dest_lla, rt_key, 16) == 0)
        {
          dec = fast_path.dec;
        }
      else
        {
          if (memcmp (rt_key, cfg->addr, 16) == 0)
            {
              dec.type = RT_NONE;
            }
          else
            {
              Re dir;
              if (cfg->p2p == P2P_EN && rt_dir_fnd (rt, rt_key, &dir))
                {
                  dec.type = RT_DIR;
                  memcpy (dec.dir.ip, dir.ep_ip, 16);
                  dec.dir.port = dir.ep_port;
                }
              else
                {
                  dec = rt_sel (rt, rt_key, cfg->p2p == P2P_EN);
                }
            }
          memcpy (fast_path.dest_lla, rt_key, 16);
          fast_path.dec = dec;
          fast_path.val_ts = now + 200ULL;
          fast_path.is_val = true;
        }
      if (dec.type == RT_NONE)
        continue;
      uint8_t tx_ip[16] = { 0 };
      uint16_t tx_port = 0;
      uint8_t rel_f = 0;
      const uint8_t *rel_dst_lla = NULL;
      if (dec.type == RT_DIR)
        {
          memcpy (tx_ip, dec.dir.ip, 16);
          tx_port = dec.dir.port;
        }
      else if (dec.type == RT_VP)
        {
          uint8_t gw_ip[16];
          uint16_t gw_port = 0;
          if (!rt_gw_fnd (rt, cfg->addr, gw_ip, &gw_port))
            {
              continue;
            }
          memcpy (tx_ip, gw_ip, 16);
          tx_port = gw_port;
          rel_f = 1;
          rel_dst_lla = rt_key;
        }
      else if (dec.type == RT_REL)
        {
          memcpy (tx_ip, dec.rel.relay_ip, 16);
          tx_port = dec.rel.relay_port;
          rel_f = 1;
          rel_dst_lla = rt_key;
        }
      uint16_t pmtu = rt_mtu (rt, &dec);
      uint16_t oip_oh = is_ip_v4m (tx_ip) ? 20U : 40U;
      const uint16_t tnl_oh = (uint16_t)(oip_oh + 8U + PKT_HDR_SZ);
      int32_t frag_cap = (int32_t)pmtu
                         - (int32_t)(tnl_oh + (uint16_t)sizeof (FragHdr)
                                     + ((rel_f != 0) ? 4U : 0U));
      if (frag_cap <= 0)
        {
          static uint64_t l_cr_ts = 0;
          if (now >= l_cr_ts + 1000ULL)
            {
              fprintf (stderr,
                       "main: physical mtu %u too small for "
                       "tunnel overhead %u\n",
                       (unsigned)pmtu,
                       (unsigned)(tnl_oh + (uint16_t)sizeof (FragHdr)
                                  + ((rel_f != 0) ? 4U : 0U)));
              l_cr_ts = now;
            }
          continue;
        }
      uint16_t max_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
      {
        size_t l3_off = ETH_HLEN;
        uint16_t eth_type
            = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
        if ((eth_type == 0x8100U || eth_type == 0x88A8U)
            && frame_len >= ETH_HLEN + 4 + 20)
          {
            eth_type
                = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
            l3_off = ETH_HLEN + 4;
          }
        if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
          {
            uint16_t max_in_l3 = (max_tap_f > l3_off + 20U)
                                     ? (uint16_t)(max_tap_f - l3_off - 20U)
                                     : 0;
            if (max_in_l3 >= 88U)
              {
                mss_clp (frame_pkt + l3_off, frame_len - l3_off, max_in_l3);
              }
          }
      }
      bool is_tiny = false;
      {
        size_t l3_off = ETH_HLEN;
        uint16_t eth_type
            = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
        if ((eth_type == 0x8100U || eth_type == 0x88A8U)
            && frame_len >= ETH_HLEN + 4 + 20)
          {
            eth_type
                = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
            l3_off = ETH_HLEN + 4;
          }
        if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
          {
            is_tiny = (frag_cap < 64)
                      && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
          }
      }
      if (!is_tiny
          && __builtin_expect (
              ((size_t)frame_len + (size_t)tnl_oh) <= (size_t)pmtu, 1))
        {
          size_t out_len;
          uint8_t *out_ptr = data_bld_zc (cry_ctx, frame_pkt, frame_len, rel_f,
                                          32, &out_len);
          if (bc >= BATCH_MAX)
            {
              if (udp_tx_arr (udp, batch_arr, bc) < 0)
                {
                  fprintf (stderr, "udp: batch send failed before "
                                   "enqueue data\n");
                }
              bc = 0;
            }
          memcpy (batch_arr[bc].dst_ip, tx_ip, 16);
          batch_arr[bc].dst_port = tx_port;
          batch_arr[bc].data = out_ptr;
          batch_arr[bc].data_len = out_len;
          bc++;
          rt_tx_ack (rt, tx_ip, tx_port, now);
          g_tx_ts = now;
        }
      else
        {
          size_t frag_pfx = sizeof (FragHdr) + ((rel_f != 0) ? 4U : 0U);
          if (max_tap_f <= frag_pfx)
            {
              continue;
            }
          size_t chunk_max = max_tap_f - frag_pfx;
          if (chunk_max == 0)
            continue;
          uint32_t n_frags
              = (uint32_t)((frame_len + chunk_max - 1) / chunk_max);
          if (n_frags == 0)
            n_frags = 1;
          uint32_t msg_id = g_frag_mid++;
          if (g_frag_mid == 0)
            g_frag_mid = 1;
          uint8_t rel_dst_tail[4] = { 0 };
          if (rel_f != 0 && rel_dst_lla != NULL)
            memcpy (rel_dst_tail, rel_dst_lla + 12, 4);
          size_t off = 0;
          while (off < frame_len)
            {
              bool is_dup_tx = (n_frags > 1) && ((u32_rnd () % n_frags) != 0);
              int need = is_dup_tx ? 2 : 1;
              if (bc + need > BATCH_MAX)
                {
                  if (udp_tx_arr (udp, batch_arr, bc) < 0)
                    {
                      fprintf (stderr, "udp: batch send failed "
                                       "during frag flush\n");
                    }
                  bc = 0;
                }
              size_t chunk_len = frame_len - off;
              if (chunk_len > chunk_max)
                chunk_len = chunk_max;
              uint8_t *chunk_dst1 = frag_bufs[bc] + TAP_HR + PKT_HDR_SZ
                                    + sizeof (FragHdr)
                                    + ((rel_f != 0) ? 4U : 0U);
              memcpy (chunk_dst1, frame_pkt + off, chunk_len);
              size_t out_len = 0;
              bool mf = (off + chunk_len) < frame_len;
              uint8_t *out_ptr = frag_bld_zc (
                  cry_ctx, chunk_dst1, chunk_len, msg_id, (uint16_t)off, mf,
                  rel_f, (rel_f != 0) ? rel_dst_tail : NULL, 32, &out_len);
              if (!out_ptr)
                {
                  off += chunk_len;
                  continue;
                }
              memcpy (batch_arr[bc].dst_ip, tx_ip, 16);
              batch_arr[bc].dst_port = tx_port;
              batch_arr[bc].data = out_ptr;
              batch_arr[bc].data_len = out_len;
              bc++;
              if (is_dup_tx)
                {
                  uint8_t *chunk_dst2 = frag_bufs[bc] + TAP_HR + PKT_HDR_SZ
                                        + sizeof (FragHdr)
                                        + ((rel_f != 0) ? 4U : 0U);
                  memcpy (chunk_dst2, frame_pkt + off, chunk_len);
                  size_t out_len2 = 0;
                  uint8_t *out_ptr2 = frag_bld_zc (
                      cry_ctx, chunk_dst2, chunk_len, msg_id, (uint16_t)off,
                      mf, rel_f, (rel_f != 0) ? rel_dst_tail : NULL, 32,
                      &out_len2);
                  if (!out_ptr2)
                    {
                      rt_tx_ack (rt, tx_ip, tx_port, now);
                      g_tx_ts = now;
                      off += chunk_len;
                      continue;
                    }
                  memcpy (batch_arr[bc].dst_ip, tx_ip, 16);
                  batch_arr[bc].dst_port = tx_port;
                  batch_arr[bc].data = out_ptr2;
                  batch_arr[bc].data_len = out_len2;
                  bc++;
                }
              rt_tx_ack (rt, tx_ip, tx_port, now);
              g_tx_ts = now;
              off += chunk_len;
            }
        }
      if (dec.type == RT_REL && cfg->p2p == P2P_EN && bc < BATCH_MAX)
        {
          static uint8_t hp_buf[UDP_PL_MAX];
          size_t hp_len;
          hp_bld (cry_ctx, cfg->addr, rt_key, hp_buf, &hp_len);
          udp_tx (udp, dec.rel.relay_ip, dec.rel.relay_port, hp_buf, hp_len);
        }
      if (bc >= BATCH_MAX - 2)
        {
          if (udp_tx_arr (udp, batch_arr, bc) < 0)
            {
              fprintf (stderr, "udp: batch send failed during "
                               "near-full flush\n");
            }
          bc = 0;
        }
    }
  if (bc > 0)
    {
      if (udp_tx_arr (udp, batch_arr, bc) < 0)
        {
          fprintf (stderr, "udp: batch send failed during final flush\n");
        }
    }
}

static void
on_udp (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid, PPool *pool)
{
  static uint8_t buf_arr[BATCH_MAX][UDP_PL_MAX] __attribute__ ((aligned (32)));
  static uint8_t ips[BATCH_MAX][16];
  static uint16_t ports[BATCH_MAX];
  static size_t len_arr[BATCH_MAX];
  int rc = udp_rx_arr (udp, buf_arr, ips, ports, len_arr, BATCH_MAX);
  if (rc <= 0)
    return;
  uint64_t ts = sys_ts ();
  frag_reap_tk (ts);
  for (int i = 0; i < rc; i++)
    {
      uint8_t *raw_buf = buf_arr[i];
      size_t raw_len = len_arr[i];
      uint8_t *src_ip = ips[i];
      uint16_t src_port = ports[i];
      if (raw_len < PKT_HDR_SZ)
        continue;
      PktHdr hdr;
      static uint8_t pt_store[TAP_HR + ETH_HLEN + UDP_PL_MAX] __attribute__ ((aligned (32)));
      uint8_t *pt_buf = pt_store + TAP_HR + ETH_HLEN;
      uint8_t *pt;
      size_t pt_len;
      int dec_res = pkt_dec (cry_ctx, raw_buf, raw_len, pt_buf,
                             sizeof (pt_store) - TAP_HR - ETH_HLEN, &hdr, &pt,
                             &pt_len);
      if (dec_res != 0)
        continue;
      if (!rx_rp_chk (src_ip, src_port, raw_buf + PKT_CH_SZ))
        continue;
      rt_rx_ack (rt, src_ip, src_port, ts);
      switch (hdr.pkt_type)
        {
        case PT_DATA:
          {
            g_rx_ts = ts;
            if (hdr.rel_f != 0)
              {
                if (pt_len < ETH_HLEN)
                  break;
                if (hdr.hop_c <= 1)
                  {
                    fprintf (stderr, "routing: drop: ttl expired, "
                                     "routing loop detected\n");
                    break;
                  }
                const uint8_t *fwd_frame = pt;
                size_t fwd_len = pt_len;
                uint8_t dest_lla[16] = { 0 };
                if (!mesh_dst_lla_from_frame (fwd_frame, cfg->addr, dest_lla))
                  break;
                if (memcmp (dest_lla, cfg->addr, 16) == 0)
                  {
                    if (fwd_len < ETH_HLEN)
                      break;
                    int retries = 10;
                    bool is_wr = false;
                    while (retries-- > 0)
                      {
                        if (write (tap_fd, fwd_frame, fwd_len) >= 0)
                          {
                            is_wr = true;
                            break;
                          }
                        if (errno == EAGAIN || errno == EWOULDBLOCK
                            || errno == ENOBUFS)
                          {
                            sched_yield ();
                            continue;
                          }
                        break;
                      }
                    if (!is_wr)
                      {
                        fprintf (stderr,
                                 "tap: queue full, drop "
                                 "packet len=%zu\n",
                                 fwd_len);
                      }
                  }
                else
                  {
                    rel_fwd_dat (udp, cry_ctx, rt, cfg, dest_lla, fwd_frame,
                                 fwd_len, (uint8_t)(hdr.hop_c - 1), ts, src_ip,
                                 src_port);
                  }
              }
            else
              {
                const uint8_t *frame_ptr = pt;
                size_t frame_len = pt_len;
                if (frame_len < ETH_HLEN)
                  break;
                int retries = 10;
                bool is_wr = false;
                while (retries-- > 0)
                  {
                    if (write (tap_fd, frame_ptr, frame_len) >= 0)
                      {
                        is_wr = true;
                        break;
                      }
                    if (errno == EAGAIN || errno == EWOULDBLOCK
                        || errno == ENOBUFS)
                      {
                        sched_yield ();
                        continue;
                      }
                    break;
                  }
                if (!is_wr)
                  {
                    fprintf (stderr,
                             "tap: queue full, drop packet "
                             "len=%zu\n",
                             frame_len);
                  }
              }
            break;
          }
        case PT_FRAG:
          {
            g_rx_ts = ts;
            const uint8_t *payload = pt;
            size_t payload_len = pt_len;
            uint8_t dest_lla[16] = { 0 };
            if (hdr.rel_f != 0)
              {
                if (payload_len < 4 + sizeof (FragHdr))
                  break;
                if (hdr.hop_c <= 1)
                  break;
                memcpy (dest_lla, cfg->addr, 16);
                memcpy (dest_lla + 12, payload, 4);
                payload += 4;
                payload_len -= 4;
              }
            if (payload_len < sizeof (FragHdr))
              break;
            uint32_t msg_id
                = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16)
                  | ((uint32_t)payload[2] << 8) | (uint32_t)payload[3];
            uint16_t off_mf
                = (uint16_t)(((uint16_t)payload[4] << 8) | payload[5]);
            uint16_t frag_off = (uint16_t)(off_mf & 0x7fffU);
            bool mf = (off_mf & 0x8000U) != 0;
            const uint8_t *chunk = payload + sizeof (FragHdr);
            size_t chunk_len = payload_len - sizeof (FragHdr);
            if (hdr.rel_f != 0 && memcmp (dest_lla, cfg->addr, 16) != 0)
              {
                relay_fwd_frag (udp, cry_ctx, rt, cfg, dest_lla, msg_id,
                                frag_off, mf, chunk, chunk_len,
                                (uint8_t)(hdr.hop_c - 1), ts, src_ip,
                                src_port);
                break;
              }
            uint16_t full_len = 0;
            uint8_t *full_l3
                = frag_asm (msg_id, frag_off, mf, chunk, chunk_len, &full_len);
            if (!full_l3)
              break;
            if (full_len < ETH_HLEN)
              break;
            int retries = 10;
            bool is_wr = false;
            while (retries-- > 0)
              {
                if (write (tap_fd, full_l3, full_len) >= 0)
                  {
                    is_wr = true;
                    break;
                  }
                if (errno == EAGAIN || errno == EWOULDBLOCK
                    || errno == ENOBUFS)
                  {
                    sched_yield ();
                    continue;
                  }
                break;
              }
            if (!is_wr)
              {
                fprintf (stderr,
                         "tap: queue full, drop reassembled "
                         "packet len=%u\n",
                         (unsigned)full_len);
              }
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
        case PT_PING:
          {
            uint64_t req_ts, peer_sid;
            uint8_t peer_lla[16];
            if (on_ping (pt, pt_len, &req_ts, &peer_sid, peer_lla) == 0)
              {
                if (rt_peer_sess (rt, peer_lla, peer_sid, ts))
                  rx_rp_rst_lla (rt, peer_lla);
                if (hdr.rel_f == 0)
                  rt_ep_upd (rt, peer_lla, src_ip, src_port, ts);
                if (hdr.rel_f == 0 && !is_ip_bgn (src_ip)
                    && !p_is_me (rt, cfg->addr, src_ip, src_port))
                  {
                    pp_add (pool, src_ip, src_port);
                  }
                static uint8_t pong_buf[UDP_PL_MAX];
                size_t pong_len;
                pong_bld (cry_ctx, cfg->addr, req_ts, sid, pong_buf,
                          &pong_len);
                udp_tx (udp, src_ip, src_port, pong_buf, pong_len);
                rt_tx_ack (rt, src_ip, src_port, ts);
              }
            break;
          }
        case PT_PONG:
          {
            uint64_t req_ts, peer_sid;
            uint8_t peer_lla[16];
            if (on_ping (pt, pt_len, &req_ts, &peer_sid, peer_lla) == 0)
              {
                if (rt_peer_sess (rt, peer_lla, peer_sid, ts))
                  rx_rp_rst_lla (rt, peer_lla);
                if (hdr.rel_f == 0)
                  rt_ep_upd (rt, peer_lla, src_ip, src_port, ts);
                uint32_t rtt = (uint32_t)(ts >= req_ts ? (ts - req_ts) : 0);
                rt_rtt_upd (rt, peer_lla, src_ip, src_port, rtt, ts);
                if (hdr.rel_f == 0 && !is_ip_bgn (src_ip)
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
                on_gsp (pt, pt_len, src_ip, src_port, cfg->addr, rt, pool, ts,
                        &is_mod, &req_seq, seq_tgt);
                if (req_seq)
                  {
                    static uint8_t req_buf[UDP_PL_MAX];
                    size_t req_len = 0;
                    seq_req_bld (cry_ctx, seq_tgt, req_buf, &req_len);
                    udp_tx (udp, src_ip, src_port, req_buf, req_len);
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
                    for (uint32_t j = 0; j < rt->cnt; j++)
                      {
                        if (memcmp (rt->re_arr[j].lla, cfg->addr, 16) == 0)
                          {
                            rt->re_arr[j].seq++;
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
}

static void
on_tmr (int timer_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        int *gsp_off, const char *peers_path, uint16_t act_port, uint64_t sid,
        PPool *pool)
{
  uint8_t exp_buf[8];
  if (read (timer_fd, exp_buf, sizeof (exp_buf)) < 0)
    {
    }
  (void)peers_path;
  uint64_t ts = sys_ts ();
  rt_mtu_tk (rt, ts);
  rt_loc_add (rt, cfg->addr, act_port, ts);
  rt_dad_stl (rt, ts, pool, peers_path);
  rt_prn_st (rt, ts);
  rt_src_gc (rt, ts);
  {
    static const uint8_t z_lla[16] = { 0 };
    for (int i = 0; i < pool->cnt; i++)
      {
        if (is_ip_bgn (pool->re_arr[i].ip))
          continue;
        rt_ep_upd (rt, z_lla, pool->re_arr[i].ip, pool->re_arr[i].port, ts);
      }
  }
  if (pool->is_dirty)
    pool->is_dirty = false;
  static uint32_t tk_cnt = 0;
  tk_cnt++;
  bool is_idle = false;
  uint64_t l_act = g_tx_ts > g_rx_ts ? g_tx_ts : g_rx_ts;
  if (l_act > 0 && ts > l_act && (ts - l_act) >= KA_TMO)
    is_idle = true;
  bool is_prb = ((tk_cnt % UPD_TK) == 0);
  static uint8_t p_buf[UDP_PL_MAX];
  size_t ping_len = 0;
  if (is_prb)
    {
      ping_bld (cry_ctx, cfg->addr, ts, sid, p_buf, &ping_len);
    }
  static uint8_t ka_buf[UDP_PL_MAX];
  size_t ka_len = 0;
  if (is_idle)
    {
      keep_bld (cry_ctx, ka_buf, &ka_len);
    }
  bool is_gsp = ((tk_cnt % UPD_TK) == 0);
  static uint8_t g_buf[UDP_PL_MAX];
  size_t gsp_len = 0;
  if (is_gsp)
    {
      gsp_bld (cry_ctx, rt->re_arr, (int)rt->cnt, *gsp_off, cfg->addr, g_buf,
               &gsp_len);
    }
  bool has_dt = false;
  uint8_t dt_lla[16] = { 0 };
  static uint8_t dt_buf[UDP_PL_MAX];
  size_t dt_len = 0;
  if (cfg->p2p == P2P_EN && rt_trg_pop (rt, dt_lla))
    {
      gsp_dt_bld (cry_ctx, rt->re_arr, (int)rt->cnt, dt_lla, cfg->addr, dt_buf,
                  &dt_len);
      has_dt = (dt_len > 0);
    }
  static UdpMsg batch_arr[BATCH_MAX];
  int bc = 0;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      if (!rt->re_arr[i].is_act && !rt->re_arr[i].is_static
          && rt->re_arr[i].state != RT_PND)
        continue;
      if (rt->re_arr[i].r2d != 0)
        continue;
      if (is_idle)
        {
          memcpy (batch_arr[bc].dst_ip, rt->re_arr[i].ep_ip, 16);
          batch_arr[bc].dst_port = rt->re_arr[i].ep_port;
          batch_arr[bc].data = ka_buf;
          batch_arr[bc].data_len = ka_len;
          bc++;
          rt_tx_ack (rt, rt->re_arr[i].ep_ip, rt->re_arr[i].ep_port, ts);
          g_tx_ts = ts;
          if (bc == BATCH_MAX)
            {
              udp_tx_arr (udp, batch_arr, bc);
              bc = 0;
            }
        }
      else if (is_prb || rt->re_arr[i].state == RT_PND)
        {
          if (ping_len == 0)
            {
              ping_bld (cry_ctx, cfg->addr, ts, sid, p_buf, &ping_len);
            }
          memcpy (batch_arr[bc].dst_ip, rt->re_arr[i].ep_ip, 16);
          batch_arr[bc].dst_port = rt->re_arr[i].ep_port;
          batch_arr[bc].data = p_buf;
          batch_arr[bc].data_len = ping_len;
          bc++;
          rt_tx_ack (rt, rt->re_arr[i].ep_ip, rt->re_arr[i].ep_port, ts);
          if (bc == BATCH_MAX)
            {
              udp_tx_arr (udp, batch_arr, bc);
              bc = 0;
            }
        }
      if (cfg->p2p == P2P_EN && is_gsp)
        {
          memcpy (batch_arr[bc].dst_ip, rt->re_arr[i].ep_ip, 16);
          batch_arr[bc].dst_port = rt->re_arr[i].ep_port;
          batch_arr[bc].data = g_buf;
          batch_arr[bc].data_len = gsp_len;
          bc++;
          if (bc == BATCH_MAX)
            {
              udp_tx_arr (udp, batch_arr, bc);
              bc = 0;
            }
        }
      if (cfg->p2p == P2P_EN && has_dt)
        {
          memcpy (batch_arr[bc].dst_ip, rt->re_arr[i].ep_ip, 16);
          batch_arr[bc].dst_port = rt->re_arr[i].ep_port;
          batch_arr[bc].data = dt_buf;
          batch_arr[bc].data_len = dt_len;
          bc++;
          if (bc == BATCH_MAX)
            {
              udp_tx_arr (udp, batch_arr, bc);
              bc = 0;
            }
        }
    }
  if (bc > 0)
    udp_tx_arr (udp, batch_arr, bc);
  {
    for (int burst = 0; burst < 3; burst++)
      {
        Re prb_re;
        uint16_t prb_mtu = 0;
        uint32_t probe_id = 0;
        if (!rt_mprb_rdy (rt, ts, &prb_re, &prb_mtu, &probe_id))
          break;
        static uint8_t prb_buf[UDP_PL_MAX];
        size_t probe_len = 0;
        uint16_t prb_o_oh = is_ip_v4m (prb_re.ep_ip) ? 20U : 40U;
        uint16_t prb_u_oh = (uint16_t)(prb_o_oh + 8U);
        size_t t_pl_len = (prb_mtu > prb_u_oh) ? (size_t)(prb_mtu - prb_u_oh)
                                               : (size_t)PKT_HDR_SZ;
        mtu_prb_bld (cry_ctx, probe_id, prb_mtu, t_pl_len, prb_buf,
                     &probe_len);
        udp_tx (udp, prb_re.ep_ip, prb_re.ep_port, prb_buf, probe_len);
        {
          static uint8_t prb_ping_buf[UDP_PL_MAX];
          size_t prb_ping_len = 0;
          ping_bld (cry_ctx, cfg->addr, ts, sid, prb_ping_buf, &prb_ping_len);
          udp_tx (udp, prb_re.ep_ip, prb_re.ep_port, prb_ping_buf,
                  prb_ping_len);
        }
        rt_tx_ack (rt, prb_re.ep_ip, prb_re.ep_port, ts);
      }
  }
  if (cfg->p2p == P2P_EN)
    {
      uint8_t z_lla[16] = { 0 };
      for (uint32_t i = 0; i < rt->cnt; i++)
        {
          Re *dec = &rt->re_arr[i];
          if (dec->r2d != 0)
            continue;
          if (dec->state != RT_PND)
            continue;
          if (memcmp (dec->lla, z_lla, 16) == 0)
            continue;
          RtDec rd = rt_sel (rt, dec->lla, true);
          if (rd.type != RT_REL)
            continue;
          static uint8_t hp_buf[UDP_PL_MAX];
          size_t hp_len = 0;
          hp_bld (cry_ctx, cfg->addr, dec->lla, hp_buf, &hp_len);
          udp_tx (udp, rd.rel.relay_ip, rd.rel.relay_port, hp_buf, hp_len);
        }
    }
  if (is_gsp)
    {
      *gsp_off = (*gsp_off + GSP_MAX) % (rt->cnt > 0 ? rt->cnt : 1);
    }
}

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
  printf ("main: tap device %s created.\n", cfg.ifname);
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
  if (udp_gso_set (&udp, 1200))
    {
      printf ("main: udp gso reserve enabled (segment=1200)\n");
    }
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
  its.it_value.tv_sec = GSP_INTV;
  its.it_value.tv_nsec = 0;
  its.it_interval.tv_sec = GSP_INTV;
  its.it_interval.tv_nsec = 0;
  timerfd_settime (timer_fd, 0, &its, NULL);
  ev.events = EPOLLIN;
  ev.data.u64 = ID_TMR;
  epoll_ctl (epfd, EPOLL_CTL_ADD, timer_fd, &ev);
  struct epoll_event ev_arr[EV_MAX];
  int gsp_off = 0;
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
  printf ("main: mesh running; entering epoll loop\n");
  printf ("main: type 's' and press enter to view routing table\n");
  fflush (stdout);
  on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, &gsp_off, cfg_path, act_port,
          sid, &pool);
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
              on_tap (tap_fd, &udp, &cry_ctx, &rt, &cfg, sid);
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_UDP)
            {
              if ((ev_arr[i].events & EPOLLIN) != 0)
                {
                  on_udp (tap_fd, &udp, &cry_ctx, &rt, &cfg, sid, &pool);
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
              on_tmr (timer_fd, &udp, &cry_ctx, &rt, &cfg, &gsp_off, cfg_path,
                      act_port, sid, &pool);
              udp_ep_upd (epfd, udp.fd, udp_w_want (&udp), &u_w_watch);
            }
          else if (tok == ID_STD)
            {
              char cmd_buf[128];
              int r_len = read (STDIN_FILENO, cmd_buf, sizeof (cmd_buf) - 1);
              if (r_len > 0)
                {
                  cmd_buf[r_len] = '\0';
                  if (cmd_buf[0] == '\n' || cmd_buf[0] == '\r'
                      || cmd_buf[0] == '\x1b')
                    {
                      continue;
                    }
                  if (strchr (cmd_buf, 's') || strchr (cmd_buf, 'S'))
                    {
                      int um_cnt = 0;
                      uint8_t z_lla[16] = { 0 };

                      typedef struct
                      {
                        uint8_t ip[16];
                        uint16_t port;
                      } UnmappedEp;

                      UnmappedEp um_arr[256];
                      for (uint32_t re_idx = 0; re_idx < rt.cnt; re_idx++)
                        {
                          Re *z_re = &rt.re_arr[re_idx];
                          if (z_re->r2d != 0)
                            continue;
                          if (memcmp (z_re->lla, z_lla, 16) != 0)
                            continue;
                          if (z_re->state == RT_DED)
                            continue;
                          bool is_mapped = false;
                          for (uint32_t map_idx = 0; map_idx < rt.cnt;
                               map_idx++)
                            {
                              Re *m_re = &rt.re_arr[map_idx];
                              if (m_re->r2d != 0)
                                continue;
                              if (memcmp (m_re->lla, z_lla, 16) == 0)
                                continue;
                              if (m_re->state == RT_DED)
                                continue;
                              if (memcmp (m_re->ep_ip, z_re->ep_ip, 16) != 0)
                                continue;
                              if (m_re->ep_port != z_re->ep_port)
                                continue;
                              is_mapped = true;
                              break;
                            }
                          if (is_mapped)
                            continue;
                          bool is_dup = false;
                          for (int um_idx = 0; um_idx < um_cnt; um_idx++)
                            {
                              if (memcmp (um_arr[um_idx].ip, z_re->ep_ip, 16)
                                      == 0
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
                      for (uint32_t j = 0; j < rt.cnt && u_cnt < 256; j++)
                        {
                          if (rt.re_arr[j].state == RT_DED)
                            continue;
                          if (memcmp (rt.re_arr[j].lla, z_lla, 16) == 0)
                            continue;
                          if (memcmp (rt.re_arr[j].lla, cfg.addr, 16) == 0)
                            continue;
                          bool is_dup = false;
                          for (int u = 0; u < u_cnt; u++)
                            {
                              if (memcmp (uniq_lla[u], rt.re_arr[j].lla, 16)
                                  == 0)
                                {
                                  is_dup = true;
                                  break;
                                }
                            }
                          if (!is_dup)
                            {
                              memcpy (uniq_lla[u_cnt++], rt.re_arr[j].lla, 16);
                            }
                        }
                      RRow rows[256];
                      int r_cnt = 0;
                      int act_map_cnt = 0;
                      int m_dst = 3;
                      int m_nh = 7;
                      int m_st = 5;
                      int m_mtu = 3;
                      for (int u = 0; u < u_cnt && r_cnt < 256; u++)
                        {
                          RtDec sel
                              = rt_sel (&rt, uniq_lla[u], cfg.p2p == P2P_EN);
                          RRow *row = &rows[r_cnt++];
                          inet_ntop (AF_INET6, uniq_lla[u], row->dst,
                                     sizeof (row->dst));
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
                              memset (sel_ip, 0, sizeof (sel_ip));
                              sel_port = 0;
                            }
                          char ep_str[64] = "-";
                          if (sel.type == RT_DIR || sel.type == RT_REL)
                            {
                              char ip_str[INET6_ADDRSTRLEN];
                              if (sel_ip[0] == 0 && sel_ip[1] == 0
                                  && sel_ip[10] == 0xff && sel_ip[11] == 0xff)
                                inet_ntop (AF_INET, sel_ip + 12, ip_str,
                                           sizeof (ip_str));
                              else
                                inet_ntop (AF_INET6, sel_ip, ip_str,
                                           sizeof (ip_str));
                              snprintf (ep_str, sizeof (ep_str), "%s:%u",
                                        ip_str, sel_port);
                            }
                          char nhop_str[INET6_ADDRSTRLEN] = "-";
                          if (sel.type == RT_DIR)
                            {
                              inet_ntop (AF_INET6, uniq_lla[u], nhop_str,
                                         sizeof (nhop_str));
                            }
                          else if (sel.type == RT_REL
                                   && IS_LLA_VAL (sel.rel.relay_lla))
                            {
                              inet_ntop (AF_INET6, sel.rel.relay_lla, nhop_str,
                                         sizeof (nhop_str));
                            }
                          uint32_t show_m = rt_e2e_m (&rt, uniq_lla[u], &sel);
                          if (sel.type == RT_NONE || sel.type == RT_VP)
                            {
                              memset (sel_ip, 0, sizeof (sel_ip));
                              sel_port = 0;
                              snprintf (row->nh, sizeof (row->nh), "- (-)");
                              if (sel.type == RT_NONE)
                                strcpy (row->st, "u"
                                                 "n"
                                                 "m"
                                                 "a"
                                                 "p"
                                                 "p"
                                                 "e"
                                                 "d");
                              else
                                strcpy (row->st, "v"
                                                 "i"
                                                 "a");
                              strcpy (row->rtt, "-");
                              strcpy (row->mtu, "-");
                            }
                          else
                            {
                              snprintf (row->nh, sizeof (row->nh), "%s (%s)",
                                        nhop_str, ep_str);
                              if (show_m >= RT_M_INF)
                                strcpy (row->rtt, "-");
                              else
                                snprintf (row->rtt, sizeof (row->rtt),
                                          "%"
                                          "u"
                                          "m"
                                          "s",
                                          show_m);
                              {
                                uint16_t pmtu = rt_mtu (&rt, &sel);
                                uint16_t prb_mtu = 0;
                                uint16_t lkg = pmtu;
                                uint16_t ukb = pmtu;
                                bool is_srch = false;
                                bool is_fixed = true;
                                MtuSt mtu_st = MTU_ST_B;
                                rt_pmtu_st (&rt, &sel, &pmtu, &prb_mtu,
                                            &is_srch, &is_fixed);
                                rt_pmtu_lims (&rt, &sel, &lkg, &ukb, &mtu_st);
                                if (is_srch)
                                  {
                                    if (prb_mtu > 0)
                                      snprintf (row->mtu, sizeof (row->mtu),
                                                "%u (%u-%u, %u)",
                                                (unsigned)pmtu, (unsigned)lkg,
                                                (unsigned)ukb,
                                                (unsigned)prb_mtu);
                                    else
                                      snprintf (row->mtu, sizeof (row->mtu),
                                                "%u (%u-%u)", (unsigned)pmtu,
                                                (unsigned)lkg, (unsigned)ukb);
                                  }
                                else
                                  {
                                    if (mtu_st == MTU_ST_F || is_fixed)
                                      {
                                        snprintf (row->mtu, sizeof (row->mtu),
                                                  "%u", (unsigned)pmtu);
                                      }
                                    else
                                      {
                                        snprintf (row->mtu, sizeof (row->mtu),
                                                  "%u (LKG:%u, UKB:%u, base)",
                                                  (unsigned)pmtu,
                                                  (unsigned)lkg,
                                                  (unsigned)ukb);
                                      }
                                  }
                              }
                              if (show_m >= RT_M_INF)
                                {
                                  strcpy (row->st, "p"
                                                   "e"
                                                   "n"
                                                   "d"
                                                   "i"
                                                   "n"
                                                   "g");
                                }
                              else
                                {
                                  strcpy (row->st, "a"
                                                   "c"
                                                   "t"
                                                   "i"
                                                   "v"
                                                   "e");
                                }
                            }
                          if ((int)strlen (row->nh) > m_nh)
                            m_nh = (int)strlen (row->nh);
                          if (sel.type != RT_NONE && sel.type != RT_VP
                              && show_m >= RT_M_INF)
                            {
                              strcpy (row->st, "pending");
                            }
                          if (strcmp (row->st, "active") == 0)
                            {
                              act_map_cnt++;
                            }
                          if ((int)strlen (row->st) > m_st)
                            m_st = (int)strlen (row->st);
                          if ((int)strlen (row->mtu) > m_mtu)
                            m_mtu = (int)strlen (row->mtu);
                        }
                      for (int um_idx = 0; um_idx < um_cnt && r_cnt < 256;
                           um_idx++)
                        {
                          RRow *row = &rows[r_cnt++];
                          strcpy (row->dst, "-");
                          char ip_str[INET6_ADDRSTRLEN];
                          const uint8_t *ep_ip = um_arr[um_idx].ip;
                          if (ep_ip[0] == 0 && ep_ip[1] == 0
                              && ep_ip[10] == 0xff && ep_ip[11] == 0xff)
                            inet_ntop (AF_INET, ep_ip + 12, ip_str,
                                       sizeof (ip_str));
                          else
                            inet_ntop (AF_INET6, ep_ip, ip_str,
                                       sizeof (ip_str));
                          snprintf (row->nh, sizeof (row->nh), "- (%s:%u)",
                                    ip_str, um_arr[um_idx].port);
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
                      printf ("fib: active: %d/%u, "
                              "static: %d, unmapped: "
                              "%d\n",
                              act_map_cnt, (uint32_t)rt.cnt, pool.cnt, um_cnt);
                      if (r_cnt > 0)
                        {
                          printf ("  %-*s  %-*s  "
                                  "%-*s  %-*s  "
                                  "rtt\n",
                                  m_dst, "dst", m_nh, "nexthop", m_st, "state",
                                  m_mtu, "mtu");
                          for (int k = 0; k < r_cnt; k++)
                            {
                              printf ("  %-*s  "
                                      "%-*s  "
                                      "%-*s  "
                                      "%-*s  "
                                      "%s\n",
                                      m_dst, rows[k].dst, m_nh, rows[k].nh,
                                      m_st, rows[k].st, m_mtu, rows[k].mtu,
                                      rows[k].rtt);
                            }
                        }
                    }
                }
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
    }
  return 0;
}
