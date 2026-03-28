#include "loop.h"
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
#include <ifaddrs.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
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

static uint64_t um_prb_intv (uint64_t age_ms);

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
          re->hp_ts = ts;
          return;
        }
    }
  uint8_t p_buf[UDP_PL_MAX];
  size_t p_len = 0;
  ping_bld (cry_ctx, cfg->addr, ts, sid, p_buf, &p_len);
  udp_tx (udp, re->ep_ip, re->ep_port, p_buf, p_len);
  rt->ping_tx_cnt++;
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


typedef struct
{
  uint8_t dest_lla[16];
  RtDec dec;
  uint64_t val_ts;
  bool is_val;
} TapFast;

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

  RtDec dec;
  memset (&dec, 0, sizeof (dec));
  int fp_idx = (int)((tx_path->rt_key[12] ^ tx_path->rt_key[13]
                      ^ tx_path->rt_key[14] ^ tx_path->rt_key[15])
                     & 0xff);
  if (fast_path[fp_idx].is_val && now <= fast_path[fp_idx].val_ts
      && memcmp (fast_path[fp_idx].dest_lla, tx_path->rt_key, 16) == 0)
    {
      dec = fast_path[fp_idx].dec;
    }
  else
    {
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
      memcpy (fast_path[fp_idx].dest_lla, tx_path->rt_key, 16);
      fast_path[fp_idx].dec = dec;
      fast_path[fp_idx].val_ts = now + 200ULL;
      fast_path[fp_idx].is_val = true;
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
      return true;
    }
  tx_path->pmtu = rt_mtu (rt, &dec);
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

  if (!cfg->mtu_probe)
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
      if (mss_apply && (eth_type == 0x0800U || eth_type == 0x86DDU)
          && frame_len > l3_off && cfg->mtu >= 88U)
        {
          mss_clp (frame_pkt + l3_off, frame_len - l3_off, cfg->mtu);
        }
      size_t out_len;
      uint8_t *out_ptr
          = data_bld_zc (cry_ctx, vnet_frame, vnet_len, rel_f, 32, &out_len);
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
      if (pulse_apply)
        tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path_lcl);
      if (*bc >= BATCH_MAX - 2
          && !tap_batch_fls (udp, batch_arr, bc,
                             "udp: batch send failed during near-full flush"))
        return false;
      return true;
    }
  uint16_t pmtu = tx_path_lcl.pmtu;
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
                   "main: physical mtu %u too small for tunnel overhead %u\n",
                   (unsigned)pmtu,
                   (unsigned)(tnl_oh + (uint16_t)sizeof (FragHdr)
                              + ((rel_f != 0) ? 4U : 0U)));
          l_cr_ts = now;
        }
      return true;
    }
  uint16_t max_tap_f = (pmtu > tnl_oh) ? (uint16_t)(pmtu - tnl_oh) : 0;
  {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
          eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
          l3_off = ETH_HLEN + 4;
        }
    if (mss_apply && (eth_type == 0x0800U || eth_type == 0x86DDU)
        && frame_len > l3_off)
      {
        uint16_t max_in_l3 = (max_tap_f > l3_off + 20U)
                                 ? (uint16_t)(max_tap_f - l3_off - 20U)
                                 : 0;
        if (max_in_l3 >= 88U)
          mss_clp (frame_pkt + l3_off, frame_len - l3_off, max_in_l3);
      }
  }
  bool is_tiny = false;
  if (mss_apply)
    {
    size_t l3_off = ETH_HLEN;
    uint16_t eth_type = (uint16_t)(((uint16_t)frame_pkt[12] << 8) | frame_pkt[13]);
    if ((eth_type == 0x8100U || eth_type == 0x88A8U)
        && frame_len >= ETH_HLEN + 4 + 20)
      {
        eth_type = (uint16_t)(((uint16_t)frame_pkt[16] << 8) | frame_pkt[17]);
        l3_off = ETH_HLEN + 4;
      }
    if ((eth_type == 0x0800U || eth_type == 0x86DDU) && frame_len > l3_off)
      is_tiny = (frag_cap < 64)
                && is_tcp_syn (frame_pkt + l3_off, frame_len - l3_off);
    }
  if (!is_tiny && __builtin_expect (((size_t)vnet_len + (size_t)tnl_oh) <= (size_t)pmtu, 1))
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
      size_t frag_pfx = sizeof (FragHdr) + ((rel_f != 0) ? 4U : 0U);
      if (max_tap_f <= frag_pfx)
        return true;
      size_t chunk_max = max_tap_f - frag_pfx;
      if (chunk_max == 0)
        return true;
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
          bool is_dup_tx = (n_frags > 1) && ((u32_rnd () % n_frags) != 0);
          int need = is_dup_tx ? 2 : 1;
          if (*bc + need > BATCH_MAX
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
          if (is_dup_tx)
            {
              uint8_t *chunk_dst2 = frag_bufs[*bc] + TAP_HR + PKT_HDR_SZ
                                    + sizeof (FragHdr) + ((rel_f != 0) ? 4U : 0U);
              memcpy (chunk_dst2, vnet_frame + off, chunk_len);
              size_t out_len2 = 0;
              uint8_t *out_ptr2 = frag_bld_zc (cry_ctx, chunk_dst2, chunk_len,
                                               msg_id, (uint16_t)off, mf, rel_f,
                                               (rel_f != 0) ? rel_dst_tail : NULL,
                                               32, &out_len2);
              if (!out_ptr2 || out_len2 == 0)
                {
                  if (tx_ack_apply)
                    rt_tx_ack (rt, tx_ip, tx_port, now);
                  g_tx_ts = now;
                  off += chunk_len;
                  continue;
                }
              memcpy (batch_arr[*bc].dst_ip, tx_ip, 16);
              batch_arr[*bc].dst_port = tx_port;
              batch_arr[*bc].data = out_ptr2;
              batch_arr[*bc].data_len = out_len2;
              (*bc)++;
            }
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

void
on_tap (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid, uint64_t now)
{
  (void)sid;
  static uint64_t l_nh_ts = 0;
  static TapFast fast_path[256];
  static uint8_t frame_bufs[BATCH_MAX][TAP_F_MAX + TAP_HR + TAP_TR]
      __attribute__ ((aligned (32)));
  static uint8_t frag_bufs[BATCH_MAX][UDP_PL_MAX + TAP_HR]
      __attribute__ ((aligned (32)));
  static uint8_t uso_bufs[64][TAP_F_MAX + TAP_HR + TAP_TR]
      __attribute__ ((aligned (32)));
  static UdpMsg batch_arr[BATCH_MAX];
  int bc = 0;
  for (int i = 0; i < BATCH_MAX; i++)
    {
      if (udp_w_want (udp))
        break;
      uint8_t *pl_ptr = frame_bufs[i] + TAP_HR;
      ssize_t n = read (tap_fd, pl_ptr, TAP_F_MAX);
      if (n <= 0)
        {
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          break;
        }
      if (n <= VNET_HL)
        continue;
      TapTso tso;
      if (tap_tso_fit (pl_ptr, (size_t)n, &tso))
        {
          TapTxPath tx_path;
          bool has_tx_path = tap_tx_path_fit (rt, cfg, now, pl_ptr + VNET_HL,
                                              fast_path, &l_nh_ts, &tx_path);
          int tso_i = 0;
          size_t tso_len = 0;
          while (tap_tso_seg (&tso, uso_bufs[tso_i] + TAP_HR, &tso_len))
            {
              if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                                uso_bufs[tso_i] + TAP_HR, tso_len, frag_bufs,
                                batch_arr, &bc, fast_path, &l_nh_ts,
                                has_tx_path ? &tx_path : NULL, false, false,
                                false))
                goto out;
              tso_i++;
              if (tso_i >= (int)(sizeof (uso_bufs) / sizeof (uso_bufs[0])))
                {
                  if (!tap_batch_fls (udp, batch_arr, &bc,
                                      "udp: batch send failed during tso flush"))
                    goto out;
                  tso_i = 0;
                }
            }
          if (bc > 0
              && !tap_batch_fls (udp, batch_arr, &bc,
                                 "udp: batch send failed during tso flush"))
            goto out;
          if (has_tx_path)
            {
              tap_tx_mark (rt, now, &tx_path);
              tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path);
            }
          continue;
        }
      TapUso uso;
      if (tap_uso_fit (pl_ptr, (size_t)n, &uso))
        {
          TapTxPath tx_path;
          bool has_tx_path = tap_tx_path_fit (rt, cfg, now, pl_ptr + VNET_HL,
                                              fast_path, &l_nh_ts, &tx_path);
          int uso_i = 0;
          size_t uso_len = 0;
          while (tap_uso_seg (&uso, uso_bufs[uso_i] + TAP_HR, &uso_len))
            {
              if (!tap_data_tx (udp, cry_ctx, rt, cfg, sid, now,
                                uso_bufs[uso_i] + TAP_HR, uso_len, frag_bufs,
                                batch_arr, &bc, fast_path, &l_nh_ts,
                                has_tx_path ? &tx_path : NULL, false, false,
                                false))
                goto out;
              uso_i++;
              if (uso_i >= (int)(sizeof (uso_bufs) / sizeof (uso_bufs[0])))
                {
                  if (!tap_batch_fls (udp, batch_arr, &bc,
                                      "udp: batch send failed during uso flush"))
                    goto out;
                  uso_i = 0;
                }
            }
          if (bc > 0
              && !tap_batch_fls (udp, batch_arr, &bc,
                                 "udp: batch send failed during uso flush"))
            goto out;
          if (has_tx_path)
            {
              tap_tx_mark (rt, now, &tx_path);
              tap_rel_pulse (udp, cry_ctx, rt, cfg, now, sid, &tx_path);
            }
          continue;
        }
      if (!tap_pkt_tx (tap_fd, udp, cry_ctx, rt, cfg, sid, now, pl_ptr, (size_t)n,
                       frag_bufs, batch_arr, &bc, fast_path, &l_nh_ts))
        goto out;
    }
out:
  if (bc > 0)
    {
      if (!tap_batch_fls (udp, batch_arr, &bc,
                          "udp: batch send failed during final flush"))
        return;
    }
}

void
on_udp (int tap_fd, Udp *udp, Cry *cry_ctx, Rt *rt, const Cfg *cfg,
        uint64_t sid, PPool *pool)
{
  static uint8_t buf_arr[BATCH_MAX][UDP_PL_MAX] __attribute__ ((aligned (32)));
  static uint8_t ips[BATCH_MAX][16];
  static uint16_t ports[BATCH_MAX];
  static size_t len_arr[BATCH_MAX];
  for (;;)
    {
      int rc = udp_rx_arr (udp, buf_arr, ips, ports, len_arr, BATCH_MAX);
      if (rc <= 0)
        return;
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
      uint8_t *raw_buf = buf_arr[i];
      size_t raw_len = len_arr[i];
      uint8_t *src_ip = ips[i];
      uint16_t src_port = ports[i];
      if (raw_len < PKT_HDR_SZ)
        continue;
      PktHdr hdr;
      uint8_t *pt;
      size_t pt_len;
      int dec_res
          = pkt_dec (cry_ctx, raw_buf, raw_len, NULL, 0, &hdr, &pt, &pt_len);
      if (dec_res != 0)
        continue;
      if (!rx_rp_chk (src_ip, src_port, raw_buf + PKT_CH_SZ))
        continue;

      if (!has_last_src || src_port != last_src_port
          || memcmp (src_ip, last_src_ip, 16) != 0)
        {
          rt_rx_ack (rt, src_ip, src_port, ts);
          memcpy (last_src_ip, src_ip, 16);
          last_src_port = src_port;
          has_last_src = true;
        }

      if (hdr.pkt_type == PT_DATA)
        {
          g_rx_ts = ts;
          if (pt_len < VNET_HL + ETH_HLEN)
            continue;
          if (hdr.rel_f == 0)
            {
              gro_fed (tap_fd, pt, pt_len);
              continue;
            }
          if (hdr.hop_c <= 1)
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
                           (uint8_t)(hdr.hop_c - 1), ts, src_ip, src_port);
            }
          continue;
        }

      switch (hdr.pkt_type)
        {
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
            uint8_t *full_l3 = frag_asm (src_ip, msg_id, frag_off, mf, chunk,
                                         chunk_len, &full_len);
            if (!full_l3)
              break;
            if (full_len < VNET_HL + ETH_HLEN)
              break;
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
                if (rtt == 0)
                  rtt = 1;
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
                        gsp_dt_bld (cry_ctx, rt->re_arr, (int)rt->cnt, tgt_lla,
                                    cfg->addr, dt_buf, &dt_len);
                        if (dt_len > 0)
                          {
                            udp_tx (udp, src_ip, src_port, dt_buf, dt_len);
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
  rt_loc_add (rt, cfg->addr, act_port, ts);
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
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      Re *re = &rt->re_arr[i];
      if (re->r2d != 0)
        continue;
      if (re_is_stdby (rt, re, cfg->p2p == P2P_EN))
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
      if (re->tx_ts > 0 && ts > re->tx_ts && (ts - re->tx_ts) < KA_TMO)
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

  int um_cnt = 0;
  uint8_t z_lla[16] = { 0 };

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

      uint32_t show_m = rt_e2e_m (rt, uniq_lla[u], &sel);
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
          strcpy (row->st, show_m >= RT_M_INF ? "pending" : "active");
        }
      if ((int)strlen (row->nh) > m_nh)
        m_nh = (int)strlen (row->nh);
      if (sel.type != RT_NONE && sel.type != RT_VP && show_m >= RT_M_INF)
        strcpy (row->st, "pending");
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

  printf ("fib: active: %d/%u, static: %d, unmapped: %d\n", act_map_cnt,
          (uint32_t)rt->cnt, pool->cnt, um_cnt);
  printf ("ctrl: gossip_tx=%llu ping_tx=%llu\n",
          (unsigned long long)rt->gsp_tx_cnt,
          (unsigned long long)rt->ping_tx_cnt);
  if (r_cnt > 0)
    {
      printf ("  %-*s  %-*s  %-*s  %-*s  rtt\n", m_dst, "dst", m_nh,
              "nexthop", m_st, "state", m_mtu, "mtu");
      for (int k = 0; k < r_cnt; k++)
        {
          printf ("  %-*s  %-*s  %-*s  %-*s  %s\n", m_dst, rows[k].dst, m_nh,
                  rows[k].nh, m_st, rows[k].st, m_mtu, rows[k].mtu,
                  rows[k].rtt);
        }
    }
}
