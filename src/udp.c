#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "udp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/udp.h>
#endif
static UdpEmsgsizeCallback g_emsg_cb = NULL;
static UdpUnreachCallback g_unr_cb = NULL;

static void
ip_to_v6m (const uint8_t ip[16], uint8_t out[16])
{
  int is_v4m
      = (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
         && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0
         && ip[10] == 0xff && ip[11] == 0xff);
  memcpy (out, ip, 16);
  if (!is_v4m)
    return;
}

static bool
is_err_tns (int re)
{
  return (re == EAGAIN || re == EWOULDBLOCK || re == ENOBUFS);
}

static bool
is_err_unr (int re)
{
  return (re == ENETUNREACH || re == EHOSTUNREACH || re == EINVAL);
}

static bool
udp_pend_add (Udp *s, const UdpMsg *m)
{
  if (s->pend_cnt >= UDP_PND_MAX)
    return false;
  if (m->data_len > UDP_PL_MAX)
    return false;
  uint32_t idx = (s->pend_head + s->pend_cnt) % UDP_PND_MAX;
  UdpPMsg *pm = &s->pend[idx];
  memcpy (pm->dst_ip, m->dst_ip, 16);
  pm->dst_port = m->dst_port;
  pm->data_len = m->data_len;
  memcpy (pm->data, m->data, m->data_len);
  s->pend_cnt++;
  return true;
}

static int
udp_pend_fls (Udp *s)
{
  int flush_cnt = 0;
  while (s->pend_cnt > 0)
    {
      UdpPMsg *pm = &s->pend[s->pend_head];
      struct sockaddr_in6 addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons (pm->dst_port);
      ip_to_v6m (pm->dst_ip, addr.sin6_addr.s6_addr);
      ssize_t rc = sendto (s->fd, pm->data, pm->data_len, 0,
                           (struct sockaddr *)&addr, sizeof (addr));
      if (rc < 0)
        {
          if (is_err_tns (errno))
            break;
          if (errno == EMSGSIZE)
            {
              if (g_emsg_cb)
                g_emsg_cb (pm->dst_ip, pm->dst_port, pm->data_len);
              s->pend_head = (s->pend_head + 1) % UDP_PND_MAX;
              s->pend_cnt--;
              continue;
            }
          if (is_err_unr (errno))
            {
              if (g_unr_cb)
                g_unr_cb (pm->dst_ip, pm->dst_port);
              s->pend_head = (s->pend_head + 1) % UDP_PND_MAX;
              s->pend_cnt--;
              continue;
            }
          fprintf (stderr, "udp: sendto pending drop errno=%d\n", errno);
          s->pend_head = (s->pend_head + 1) % UDP_PND_MAX;
          s->pend_cnt--;
          continue;
        }
      s->pend_head = (s->pend_head + 1) % UDP_PND_MAX;
      s->pend_cnt--;
      flush_cnt++;
    }
  return flush_cnt;
}

int
udp_init (Udp *s, uint16_t *port)
{
  memset (s, 0, sizeof (*s));
  s->fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (s->fd < 0)
    return -1;
  const char *rmem = "/proc/sys/net/core/rmem_max";
  const char *wmem = "/proc/sys/net/core/wmem_max";
  const char *v16m = "16777216\n";
  int fd;
  if ((fd = open (rmem, O_WRONLY)) >= 0)
    {
      if (write (fd, v16m, strlen (v16m)) < 0)
        {
        }
      close (fd);
    }
  if ((fd = open (wmem, O_WRONLY)) >= 0)
    {
      if (write (fd, v16m, strlen (v16m)) < 0)
        {
        }
      close (fd);
    }
  int rx_buf = 8388608;
  int sndbuf = 8388608;
  if (setsockopt (s->fd, SOL_SOCKET, SO_RCVBUF, &rx_buf, sizeof (rx_buf)) < 0)
    {
      perror ("udp: setsockopt so_rcvbuf 8mb failed");
    }
  if (setsockopt (s->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof (sndbuf)) < 0)
    {
      perror ("udp: setsockopt so_sndbuf 8mb failed");
    }
  int off = 0;
  if (setsockopt (s->fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof (off)) < 0)
    {
      perror ("udp: setsockopt ipv6_v6only failed");
    }
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_WANT)
  {
    int pmtu4 = IP_PMTUDISC_WANT;
    if (setsockopt (s->fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu4, sizeof (pmtu4))
        < 0)
      {
        perror ("udp: setsockopt ip_mtu_discover failed");
      }
  }
#endif
#if defined(IP_RECVERR)
  {
    int on = 1;
    if (setsockopt (s->fd, IPPROTO_IP, IP_RECVERR, &on, sizeof (on)) < 0)
      {
        perror ("udp: setsockopt ip_recverr failed");
      }
  }
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_WANT)
  {
    int pmtu6 = IPV6_PMTUDISC_WANT;
    if (setsockopt (s->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu6,
                    sizeof (pmtu6))
        < 0)
      {
        perror ("udp: setsockopt ipv6_mtu_discover failed");
      }
  }
#endif
#if defined(IPV6_RECVERR)
  {
    int on = 1;
    if (setsockopt (s->fd, IPPROTO_IPV6, IPV6_RECVERR, &on, sizeof (on)) < 0)
      {
        perror ("udp: setsockopt ipv6_recverr failed");
      }
  }
#endif
#if defined(IPV6_DONTFRAG)
  {
    int df = 1;
    if (setsockopt (s->fd, IPPROTO_IPV6, IPV6_DONTFRAG, &df, sizeof (df)) < 0)
      {
        perror ("udp: setsockopt ipv6_dontfrag failed");
      }
  }
#endif
  struct sockaddr_in6 addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (*port);
  addr.sin6_addr = in6addr_any;
  if (bind (s->fd, (struct sockaddr *)&addr, sizeof (addr)) < 0)
    {
      close (s->fd);
      s->fd = -1;
      return -1;
    }
  int flags = fcntl (s->fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl (s->fd, F_SETFL, flags | O_NONBLOCK);
  socklen_t len = sizeof (addr);
  if (getsockname (s->fd, (struct sockaddr *)&addr, &len) == 0)
    {
      *port = ntohs (addr.sin6_port);
    }
  return 0;
}

void
udp_free (Udp *s)
{
  if (s->fd >= 0)
    {
      close (s->fd);
      s->fd = -1;
    }
}

int
udp_tx_arr (Udp *s, UdpMsg *msgs, int cnt)
{
  if (cnt <= 0)
    return 0;
  if (cnt > BATCH_MAX)
    cnt = BATCH_MAX;
  (void)udp_pend_fls (s);
  if (s->pend_cnt > 0)
    {
      int acc_cnt = 0;
      for (int i = 0; i < cnt; i++)
        {
          if (!udp_pend_add (s, &msgs[i]))
            {
              fprintf (stderr, "udp: pending queue full, drop "
                               "outgoing packet\n");
              continue;
            }
          acc_cnt++;
        }
      return acc_cnt;
    }
  static struct mmsghdr msg_arr[BATCH_MAX];
  static struct sockaddr_in6 addr_arr[BATCH_MAX];
  static struct iovec iovs[BATCH_MAX];
  for (int i = 0; i < cnt; i++)
    {
      memset (&addr_arr[i], 0, sizeof (addr_arr[i]));
      addr_arr[i].sin6_family = AF_INET6;
      addr_arr[i].sin6_port = htons (msgs[i].dst_port);
      ip_to_v6m (msgs[i].dst_ip, addr_arr[i].sin6_addr.s6_addr);
      iovs[i].iov_base = msgs[i].data;
      iovs[i].iov_len = msgs[i].data_len;
      memset (&msg_arr[i], 0, sizeof (msg_arr[i]));
      msg_arr[i].msg_hdr.msg_name = &addr_arr[i];
      msg_arr[i].msg_hdr.msg_namelen = sizeof (addr_arr[i]);
      msg_arr[i].msg_hdr.msg_iov = &iovs[i];
      msg_arr[i].msg_hdr.msg_iovlen = 1;
    }
  int tx_cnt = 0;
  while (tx_cnt < cnt)
    {
      int rc = sendmmsg (s->fd, msg_arr + tx_cnt, cnt - tx_cnt, 0);
      if (rc < 0)
        {
          if (is_err_tns (errno))
            break;
          int acc_cnt = tx_cnt;
          for (int i = tx_cnt; i < cnt; i++)
            {
              struct sockaddr_in6 addr;
              memset (&addr, 0, sizeof (addr));
              addr.sin6_family = AF_INET6;
              addr.sin6_port = htons (msgs[i].dst_port);
              ip_to_v6m (msgs[i].dst_ip, addr.sin6_addr.s6_addr);
              ssize_t tx1 = sendto (s->fd, msgs[i].data, msgs[i].data_len, 0,
                                    (struct sockaddr *)&addr, sizeof (addr));
              if (tx1 >= 0)
                {
                  acc_cnt++;
                  continue;
                }
              if (is_err_tns (errno))
                {
                  if (udp_pend_add (s, &msgs[i]))
                    {
                      acc_cnt++;
                    }
                  else
                    {
                      fprintf (stderr, "udp: pending queue full, "
                                       "drop outgoing packet\n");
                    }
                  continue;
                }
              if (errno == EMSGSIZE)
                {
                  if (g_emsg_cb)
                    {
                      g_emsg_cb (msgs[i].dst_ip, msgs[i].dst_port,
                                 msgs[i].data_len);
                    }
                  continue;
                }
              if (is_err_unr (errno))
                {
                  if (g_unr_cb)
                    {
                      g_unr_cb (msgs[i].dst_ip, msgs[i].dst_port);
                    }
                  continue;
                }
              fprintf (stderr, "udp: sendto fallback drop errno=%d\n", errno);
            }
          return acc_cnt;
        }
      if (rc == 0)
        break;
      tx_cnt += rc;
    }
  for (int i = tx_cnt; i < cnt; i++)
    {
      if (!udp_pend_add (s, &msgs[i]))
        {
          fprintf (stderr, "udp: pending queue full, drop outgoing packet\n");
        }
    }
  return cnt;
}

int
udp_rx_arr (Udp *s, uint8_t buf_arr[][UDP_PL_MAX], uint8_t src_ips[][16],
            uint16_t src_ports[], size_t len_arr[], int m_cnt)
{
  if (m_cnt <= 0)
    return 0;
  if (m_cnt > BATCH_MAX)
    m_cnt = BATCH_MAX;
  static struct mmsghdr msg_arr[BATCH_MAX];
  static struct sockaddr_in6 addr_arr[BATCH_MAX];
  static struct iovec iovs[BATCH_MAX];
  for (int i = 0; i < m_cnt; i++)
    {
      iovs[i].iov_base = buf_arr[i];
      iovs[i].iov_len = UDP_PL_MAX;
      memset (&addr_arr[i], 0, sizeof (addr_arr[i]));
      memset (&msg_arr[i], 0, sizeof (msg_arr[i]));
      msg_arr[i].msg_hdr.msg_name = &addr_arr[i];
      msg_arr[i].msg_hdr.msg_namelen = sizeof (addr_arr[i]);
      msg_arr[i].msg_hdr.msg_iov = &iovs[i];
      msg_arr[i].msg_hdr.msg_iovlen = 1;
    }
  int rx_cnt = recvmmsg (s->fd, msg_arr, m_cnt, MSG_DONTWAIT, NULL);
  if (rx_cnt < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return -1;
    }
  for (int i = 0; i < rx_cnt; i++)
    {
      memcpy (src_ips[i], addr_arr[i].sin6_addr.s6_addr, 16);
      src_ports[i] = ntohs (addr_arr[i].sin6_port);
      len_arr[i] = msg_arr[i].msg_len;
    }
  return rx_cnt;
}

int
udp_tx (Udp *s, const uint8_t dst_ip[16], uint16_t dst_port,
        const uint8_t *data, size_t data_len)
{
  UdpMsg msg;
  memcpy (msg.dst_ip, dst_ip, 16);
  msg.dst_port = dst_port;
  msg.data = (uint8_t *)data;
  msg.data_len = data_len;
  return udp_tx_arr (s, &msg, 1);
}

bool
udp_gso_set (Udp *s, uint16_t seg_sz)
{
#if defined(__linux__) && defined(UDP_SEGMENT)
  if (setsockopt (s->fd, IPPROTO_UDP, UDP_SEGMENT, &seg_sz, sizeof (seg_sz))
      == 0)
    return true;
  return false;
#else
  (void)s;
  (void)seg_sz;
  return false;
#endif
}

void
udp_emsg_cb_set (UdpEmsgsizeCallback cb)
{
  g_emsg_cb = cb;
}

void
udp_unr_cb_set (UdpUnreachCallback cb)
{
  g_unr_cb = cb;
}

bool
udp_w_want (const Udp *s)
{
  return s && s->pend_cnt > 0;
}

int
udp_w_hnd (Udp *s)
{
  if (!s)
    return -1;
  return udp_pend_fls (s);
}

uint16_t
udp_mtu_get (const Udp *s)
{
  if (!s || s->fd < 0)
    return 1500;
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, "eth0", IFNAMSIZ - 1);
  if (ioctl (s->fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0)
    return (uint16_t)ifr.ifr_mtu;
  return 1500;
}

int
udp_err_rd (Udp *s, uint8_t dst_ip[16], uint16_t *dst_port, uint16_t *mtu)
{
#if defined(__linux__) && defined(MSG_ERRQUEUE)
  if (!s || s->fd < 0 || !dst_ip || !dst_port || !mtu)
    return -1;
  uint8_t data[1];
  struct iovec iov;
  memset (&iov, 0, sizeof (iov));
  iov.iov_base = data;
  iov.iov_len = sizeof (data);
  uint8_t cbuf[512];
  struct sockaddr_storage name;
  memset (&name, 0, sizeof (name));
  struct msghdr msg;
  memset (&msg, 0, sizeof (msg));
  msg.msg_name = &name;
  msg.msg_namelen = sizeof (name);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof (cbuf);
  ssize_t rc = recvmsg (s->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
  if (rc < 0)
    return -1;
  uint16_t m = 0;
  bool has_mtu = false;
  for (struct cmsghdr *c = CMSG_FIRSTHDR (&msg); c; c = CMSG_NXTHDR (&msg, c))
    {
      if (c->cmsg_level != IPPROTO_IP && c->cmsg_level != IPPROTO_IPV6)
        continue;
#if defined(IP_RECVERR)
      if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_RECVERR)
        {
          struct sock_extended_err *e
              = (struct sock_extended_err *)CMSG_DATA (c);
          if (e && e->ee_info > 0)
            {
              m = (uint16_t)e->ee_info;
              has_mtu = true;
            }
        }
#endif
#if defined(IPV6_RECVERR)
      if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_RECVERR)
        {
          struct sock_extended_err *e
              = (struct sock_extended_err *)CMSG_DATA (c);
          if (e && e->ee_info > 0)
            {
              m = (uint16_t)e->ee_info;
              has_mtu = true;
            }
        }
#endif
    }
  if (!has_mtu)
    return -1;
  if (name.ss_family == AF_INET6)
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&name;
      memcpy (dst_ip, sa6->sin6_addr.s6_addr, 16);
      *dst_port = ntohs (sa6->sin6_port);
    }
  else if (name.ss_family == AF_INET)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&name;
      memset (dst_ip, 0, 16);
      dst_ip[10] = 0xff;
      dst_ip[11] = 0xff;
      memcpy (dst_ip + 12, &sa4->sin_addr, 4);
      *dst_port = ntohs (sa4->sin_port);
    }
  else
    {
      return -1;
    }
  *mtu = m;
  return 0;
#else
  (void)s;
  (void)dst_ip;
  (void)dst_port;
  (void)mtu;
  return -1;
#endif
}
