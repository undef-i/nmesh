#include "config.h"
#include "route.h"
#include "utils.h"

#include "../include/nm_nl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef GENL_HDRLEN
#define GENL_HDRLEN NLMSG_ALIGN(sizeof(struct genlmsghdr))
#endif

#define DCO_NL_BUFSZ 8192
#define DCO_KEY_LEN 32

typedef struct
{
  int fd;
  uint32_t seq;
  uint16_t fam_id;
} DcoNl;

typedef struct
{
  uint32_t peer_id;
  uint8_t overlay_v6[16];
  uint8_t ep_ip4[4];
  uint16_t ep_port;
  uint8_t key[DCO_KEY_LEN];
} DcoPeerAdd;

typedef struct
{
  uint32_t peer_id;
  uint8_t overlay_v6[16];
  uint8_t ep_ip4[4];
  uint16_t ep_port;
  uint8_t key[DCO_KEY_LEN];
  bool is_val;
} DcoPeerCacheEnt;

static DcoPeerCacheEnt g_dco_peer_cache[RT_MAX];
static int g_dco_peer_cache_cnt = 0;

typedef struct
{
  uint8_t dst_lla[16];
  uint32_t peer_id;
} DcoRouteEnt;

static DcoRouteEnt g_dco_route_cache[RT_MAX];
static int g_dco_route_cache_cnt = -1;

static int
nl_open (DcoNl *nl)
{
  memset (nl, 0, sizeof (*nl));
  nl->fd = socket (AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (nl->fd < 0)
    return -1;

  struct sockaddr_nl addr;
  memset (&addr, 0, sizeof (addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_pid = (uint32_t)getpid ();

  if (bind (nl->fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      close (nl->fd);
      nl->fd = -1;
      return -1;
    }

  nl->seq = 1;
  return 0;
}

static void
nl_close (DcoNl *nl)
{
  if (nl && nl->fd >= 0)
    {
      close (nl->fd);
      nl->fd = -1;
    }
}

static int
nla_put (uint8_t *buf, size_t buf_sz, size_t *off, uint16_t type,
         const void *data, uint16_t len)
{
  size_t need = (size_t)NLA_HDRLEN + (size_t)len;
  size_t need_al = (size_t)NLA_ALIGN ((int)need);
  if (*off + need_al > buf_sz)
    return -1;

  struct nlattr *a = (struct nlattr *)(buf + *off);
  a->nla_type = type;
  a->nla_len = (uint16_t)need;

  if (len > 0 && data)
    memcpy ((uint8_t *)a + NLA_HDRLEN, data, len);

  size_t pad = need_al - need;
  if (pad)
    memset ((uint8_t *)a + need, 0, pad);

  *off += need_al;
  return 0;
}

static int
genl_req (DcoNl *nl, uint16_t cmd, const uint8_t *attrs, size_t attrs_len,
          uint16_t *out_ctrl_family_id)
{
  uint8_t tx[DCO_NL_BUFSZ];
  memset (tx, 0, sizeof (tx));

  struct nlmsghdr *nlh = (struct nlmsghdr *)tx;
  struct genlmsghdr *gh = (struct genlmsghdr *)(tx + NLMSG_HDRLEN);

  nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + (uint32_t)attrs_len;
  nlh->nlmsg_type = nl->fam_id;
  nlh->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | NLM_F_ACK);
  nlh->nlmsg_seq = nl->seq++;
  nlh->nlmsg_pid = (uint32_t)getpid ();

  gh->cmd = (uint8_t)cmd;
  gh->version = NM_NL_VER;
  gh->reserved = 0;

  if (attrs_len > 0 && attrs)
    memcpy ((uint8_t *)gh + GENL_HDRLEN, attrs, attrs_len);

  struct sockaddr_nl dst;
  memset (&dst, 0, sizeof (dst));
  dst.nl_family = AF_NETLINK;

  ssize_t wr = sendto (nl->fd, tx, nlh->nlmsg_len, 0, (struct sockaddr *)&dst,
                       sizeof (dst));
  if (wr < 0)
    return -1;

  for (;;)
    {
      uint8_t rx[DCO_NL_BUFSZ];
      ssize_t rd = recv (nl->fd, rx, sizeof (rx), 0);
      if (rd < 0)
        {
          if (errno == EINTR)
            continue;
          return -1;
        }

      for (struct nlmsghdr *rh = (struct nlmsghdr *)rx; NLMSG_OK (rh, rd);
           rh = NLMSG_NEXT (rh, rd))
        {
          if (rh->nlmsg_type == NLMSG_DONE)
            continue;

          if (rh->nlmsg_type >= NLMSG_MIN_TYPE && out_ctrl_family_id)
            {
              struct genlmsghdr *rgh = (struct genlmsghdr *)NLMSG_DATA (rh);
              uint8_t *ab = (uint8_t *)rgh + GENL_HDRLEN;
              int alen = rh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

              for (size_t pos = 0; pos + (size_t)NLA_HDRLEN <= (size_t)alen;)
                {
                  struct nlattr *a = (struct nlattr *)(ab + pos);
                  uint16_t nlen = a->nla_len;
                  size_t nlen_al = (size_t)NLA_ALIGN ((int)nlen);

                  if (nlen < (uint16_t)NLA_HDRLEN)
                    break;
                  if (pos + nlen > (size_t)alen)
                    break;

                  if (a->nla_type == CTRL_ATTR_FAMILY_ID
                      && (int)nlen >= NLA_HDRLEN + (int)sizeof (uint16_t))
                    {
                      uint16_t id;
                      memcpy (&id, (uint8_t *)a + NLA_HDRLEN, sizeof (id));
                      *out_ctrl_family_id = id;
                    }

                  if (nlen_al == 0)
                    break;
                  pos += nlen_al;
                }
            }

          if (rh->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA (rh);
              if (e->error == 0)
                return 0;
              errno = -e->error;
              return -1;
            }
        }
    }
}

static int
genl_resolve_family (DcoNl *nl, const char *name)
{
  nl->fam_id = GENL_ID_CTRL;

  uint8_t attrs[256];
  size_t off = 0;
  if (nla_put (attrs, sizeof (attrs), &off, CTRL_ATTR_FAMILY_NAME, name,
               (uint16_t)(strlen (name) + 1))
      != 0)
    return -1;

  uint16_t fid = 0;
  if (genl_req (nl, CTRL_CMD_GETFAMILY, attrs, off, &fid) != 0)
    return -1;
  if (fid == 0)
    {
      errno = ENOENT;
      return -1;
    }

  nl->fam_id = fid;
  return 0;
}

static int
dco_peer_add (DcoNl *nl, const DcoPeerAdd *pa)
{
  uint8_t attrs[512];
  size_t off = 0;

  if (nla_put (attrs, sizeof (attrs), &off, NM_A_P_ID, &pa->peer_id,
               sizeof (pa->peer_id))
      != 0)
    return -1;
  if (nla_put (attrs, sizeof (attrs), &off, NM_A_V6_IP, pa->overlay_v6, 16)
      != 0)
    return -1;
  if (nla_put (attrs, sizeof (attrs), &off, NM_A_EP_IP, pa->ep_ip4, 4) != 0)
    return -1;
  if (nla_put (attrs, sizeof (attrs), &off, NM_A_EP_PORT, &pa->ep_port,
               sizeof (pa->ep_port))
      != 0)
    return -1;
  if (nla_put (attrs, sizeof (attrs), &off, NM_A_K_DAT, pa->key, DCO_KEY_LEN)
      != 0)
    return -1;

  return genl_req (nl, NM_C_P_ADD, attrs, off, NULL);
}

static int
dco_route_flush (DcoNl *nl)
{
  return genl_req (nl, NM_C_R_FLUSH, NULL, 0, NULL);
}

static int
dco_route_set (DcoNl *nl, const uint8_t dst_lla[16], uint32_t peer_id)
{
  uint8_t attrs[128];
  size_t off = 0;

  if (nla_put (attrs, sizeof (attrs), &off, NM_A_V6_IP, dst_lla, 16) != 0)
    return -1;
  if (nla_put (attrs, sizeof (attrs), &off, NM_A_P_ID, &peer_id,
               sizeof (peer_id))
      != 0)
    return -1;

  return genl_req (nl, NM_C_R_SET, attrs, off, NULL);
}

static int
dco_if_del (DcoNl *nl, int ifindex)
{
  uint8_t attrs[32];
  size_t off = 0;

  if (ifindex > 0)
    {
      uint32_t idx = (uint32_t)ifindex;
      if (nla_put (attrs, sizeof (attrs), &off, NM_A_IF_IDX, &idx,
                   sizeof (idx))
          != 0)
        return -1;
    }

  return genl_req (nl, NM_C_IF_DEL, attrs, off, NULL);
}

static int
peer_cache_fnd (uint32_t peer_id)
{
  for (int i = 0; i < g_dco_peer_cache_cnt; i++)
    {
      if (g_dco_peer_cache[i].is_val && g_dco_peer_cache[i].peer_id == peer_id)
        return i;
    }
  return -1;
}

static int
peer_cache_put (const DcoPeerAdd *pa)
{
  if (!pa)
    return -1;
  int idx = peer_cache_fnd (pa->peer_id);
  if (idx < 0)
    {
      if (g_dco_peer_cache_cnt >= RT_MAX)
        return -1;
      idx = g_dco_peer_cache_cnt++;
    }
  g_dco_peer_cache[idx].peer_id = pa->peer_id;
  memcpy (g_dco_peer_cache[idx].overlay_v6, pa->overlay_v6, 16);
  memcpy (g_dco_peer_cache[idx].ep_ip4, pa->ep_ip4, 4);
  g_dco_peer_cache[idx].ep_port = pa->ep_port;
  memcpy (g_dco_peer_cache[idx].key, pa->key, DCO_KEY_LEN);
  g_dco_peer_cache[idx].is_val = true;
  return 0;
}

static uint32_t
peer_id_from_ip_port (const uint8_t ip[16], uint16_t port)
{
  uint32_t v = 2166136261u;
  for (int i = 0; i < 16; i++)
    {
      v ^= ip[i];
      v *= 16777619u;
    }
  v ^= (uint8_t)(port >> 8);
  v *= 16777619u;
  v ^= (uint8_t)port;
  v *= 16777619u;
  if (v == 0)
    v = 1;
  return v;
}

static int
ipv6_mapped_v4_extract (const uint8_t ip[16], uint8_t out4[4])
{
  if (!(ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
        && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0
        && ip[10] == 0xff && ip[11] == 0xff))
    return -1;
  memcpy (out4, ip + 12, 4);
  return 0;
}

static bool
route_cache_equal (const DcoRouteEnt *new_arr, int new_cnt)
{
  if (g_dco_route_cache_cnt < 0)
    return false;
  if (new_cnt != g_dco_route_cache_cnt)
    return false;

  for (int i = 0; i < new_cnt; i++)
    {
      if (memcmp (g_dco_route_cache[i].dst_lla, new_arr[i].dst_lla, 16) != 0)
        return false;
      if (g_dco_route_cache[i].peer_id != new_arr[i].peer_id)
        return false;
    }

  return true;
}

static void
route_cache_store (const DcoRouteEnt *arr, int cnt)
{
  if (cnt < 0)
    cnt = 0;
  if (cnt > RT_MAX)
    cnt = RT_MAX;

  for (int i = 0; i < cnt; i++)
    g_dco_route_cache[i] = arr[i];

  g_dco_route_cache_cnt = cnt;
}



int
dco_ctl_apply_cfg (const Cfg *cfg, const char *cfg_path, int udp_fd)
{
  if (!cfg || !cfg_path)
    return -1;

  P peers[RT_MAX];
  int peer_cnt = p_arr_ld (cfg_path, peers, RT_MAX);

  DcoNl nl;
  bool nl_ready = false;

  if (nl_open (&nl) != 0)
    {
      perror ("dco_ctl: netlink open failed");
      fprintf (stderr,
               "dco_ctl: startup diagnostic: cannot open NETLINK_GENERIC socket\n");
    }
  else if (genl_resolve_family (&nl, NM_NL_FAM) != 0)
    {
      perror ("dco_ctl: resolve nmesh genetlink family failed");
      fprintf (stderr,
               "dco_ctl: startup diagnostic: genetlink family '%s' unavailable\n",
               NM_NL_FAM);
      nl_close (&nl);
    }
  else
    {
      nl_ready = true;
      int ifindex = if_nametoindex (cfg->ifname);
      {
        uint8_t attrs[64];
        size_t off = 0;
        uint16_t lport = cfg->port;
        if (lport == 0)
          lport = 11451;
	        if (ifindex > 0)
	          (void)nla_put (attrs, sizeof (attrs), &off, NM_A_IF_IDX, &ifindex,
	                         sizeof (ifindex));
	        (void)nla_put (attrs, sizeof (attrs), &off, NM_A_EP_PORT, &lport,
	                       sizeof (lport));
	        if (udp_fd >= 0)
	          {
	            uint32_t fd = (uint32_t)udp_fd;
	            (void)nla_put (attrs, sizeof (attrs), &off, NM_A_UDP_FD, &fd,
	                           sizeof (fd));
	          }
	        if (genl_req (&nl, NM_C_IF_NEW, attrs, off, NULL) != 0)
          {
            perror ("dco_ctl: NM_C_IF_NEW failed");
            fprintf (stderr,
                     "dco_ctl: IF_NEW failed; aborting peer apply for this namespace\n");
            nl_close (&nl);
            return -1;
          }
      }
    }

  int ok_cnt = 0;

  for (int i = 0; i < peer_cnt; i++)
    {
      DcoPeerAdd pa;
      memset (&pa, 0, sizeof (pa));
      pa.peer_id = peer_id_from_ip_port (peers[i].ip, peers[i].port);
      memcpy (pa.overlay_v6, peers[i].ip, 16);
      pa.ep_port = peers[i].port;
      memcpy (pa.key, cfg->psk, DCO_KEY_LEN);

      if (ipv6_mapped_v4_extract (peers[i].ip, pa.ep_ip4) != 0)
        {
          char ipbuf[INET6_ADDRSTRLEN];
          inet_ntop (AF_INET6, peers[i].ip, ipbuf, sizeof (ipbuf));
          fprintf (stderr,
                   "dco_ctl: skip peer [%s]:%u (kernel dco currently ipv4-underlay only)\n",
                   ipbuf, (unsigned)peers[i].port);
          continue;
        }

      if (peer_cache_put (&pa) != 0)
        {
          fprintf (stderr, "dco_ctl: peer cache full, skip peer id=%u\n",
                   (unsigned)pa.peer_id);
        }

      if (!nl_ready)
        continue;

      if (dco_peer_add (&nl, &pa) != 0)
        {
          perror ("dco_ctl: NM_C_P_ADD failed");
          continue;
        }

      ok_cnt++;
    }

  if (nl_ready)
    {
      if (ok_cnt < peer_cnt && g_dco_peer_cache_cnt > 0)
        {
          int replay_ok = 0;
          for (int i = 0; i < g_dco_peer_cache_cnt; i++)
            {
              if (!g_dco_peer_cache[i].is_val)
                continue;
              DcoPeerAdd pa;
              memset (&pa, 0, sizeof (pa));
              pa.peer_id = g_dco_peer_cache[i].peer_id;
              memcpy (pa.overlay_v6, g_dco_peer_cache[i].overlay_v6, 16);
              memcpy (pa.ep_ip4, g_dco_peer_cache[i].ep_ip4, 4);
              pa.ep_port = g_dco_peer_cache[i].ep_port;
              memcpy (pa.key, g_dco_peer_cache[i].key, DCO_KEY_LEN);
              if (dco_peer_add (&nl, &pa) == 0)
                replay_ok++;
            }
          if (replay_ok > ok_cnt)
            ok_cnt = replay_ok;
        }
      fprintf (stderr, "dco_ctl: applied peers %d/%d\n", ok_cnt, peer_cnt);
      g_dco_route_cache_cnt = -1;
      nl_close (&nl);
      return (ok_cnt > 0 || peer_cnt == 0) ? 0 : -1;
    }

  fprintf (stderr,
           "dco_ctl: kernel peer preload cached %d entries; will retry on next apply\n",
           g_dco_peer_cache_cnt);
  return (peer_cnt == 0) ? 0 : -1;
}

int
dco_ctl_sync_fib (const Cfg *cfg, Rt *rt)
{
  if (!cfg || !rt)
    return -1;

  DcoRouteEnt routes[RT_MAX];
  int route_cnt = 0;

  for (uint32_t i = 0; i < rt->cnt && route_cnt < RT_MAX; i++)
    {
      uint8_t z_lla[16] = { 0 };
      uint8_t dst_lla[16];
      RtDec sel;
      uint8_t sel_ip[16];
      uint16_t sel_port = 0;
      uint32_t peer_id = 0;
      bool dup = false;
      bool peer_known = false;

      if (rt->re_arr[i].state == RT_DED)
        continue;
      if (memcmp (rt->re_arr[i].lla, z_lla, 16) == 0)
        continue;
      if (memcmp (rt->re_arr[i].lla, cfg->addr, 16) == 0)
        continue;

      memcpy (dst_lla, rt->re_arr[i].lla, 16);
      for (int j = 0; j < route_cnt; j++)
        {
          if (memcmp (routes[j].dst_lla, dst_lla, 16) == 0)
            {
              dup = true;
              break;
            }
        }
      if (dup)
        continue;

      sel = rt_sel (rt, dst_lla, cfg->p2p == P2P_EN);
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
          continue;
        }

      if (sel_port == 0)
        continue;

      peer_id = peer_id_from_ip_port (sel_ip, sel_port);
      for (int k = 0; k < g_dco_peer_cache_cnt; k++)
        {
          if (!g_dco_peer_cache[k].is_val)
            continue;
          if (g_dco_peer_cache[k].peer_id == peer_id)
            {
              peer_known = true;
              break;
            }
        }
      if (!peer_known)
        continue;

      memcpy (routes[route_cnt].dst_lla, dst_lla, 16);
      routes[route_cnt].peer_id = peer_id;
      route_cnt++;
    }

  if (route_cache_equal (routes, route_cnt))
    return 0;

  DcoNl nl;
  if (nl_open (&nl) != 0)
    return -1;
  if (genl_resolve_family (&nl, NM_NL_FAM) != 0)
    {
      nl_close (&nl);
      return -1;
    }

  if (dco_route_flush (&nl) != 0)
    {
      perror ("dco_ctl: NM_C_R_FLUSH failed");
      nl_close (&nl);
      return -1;
    }

  for (int i = 0; i < route_cnt; i++)
    {
      if (dco_route_set (&nl, routes[i].dst_lla, routes[i].peer_id) != 0)
        {
          perror ("dco_ctl: NM_C_R_SET failed");
          nl_close (&nl);
          return -1;
        }
    }

  nl_close (&nl);
  route_cache_store (routes, route_cnt);
  return 0;
}

int
dco_ctl_cleanup_stale (const Cfg *cfg)
{
  DcoNl nl;
  int ifindex;

  if (!cfg)
    return -1;

  if (nl_open (&nl) != 0)
    return -1;
  if (genl_resolve_family (&nl, NM_NL_FAM) != 0)
    {
      nl_close (&nl);
      return -1;
    }

  ifindex = if_nametoindex (cfg->ifname);
  if (dco_if_del (&nl, ifindex) != 0)
    {
      nl_close (&nl);
      return -1;
    }

  nl_close (&nl);
  g_dco_route_cache_cnt = -1;
  return 0;
}
