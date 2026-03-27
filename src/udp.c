#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "udp.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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
#if defined(__linux__) && defined(UDP_SEGMENT)
#define UDP_GSO_MAX_SEGS 8
#define UDP_GSO_MAX_BYTES 65535U
#ifndef SOL_UDP
#define SOL_UDP IPPROTO_UDP
#endif
#else
#define UDP_GSO_MAX_SEGS 8
#endif
#define UDP_RX_BUF_MAX 65535U
#define UDP_RX_SPLIT_MAX (BATCH_MAX * 64)

static void ip_fmt (const uint8_t ip[16], char out[INET6_ADDRSTRLEN]);
static bool udp_pend_add (Udp *s, const UdpMsg *m);

typedef struct
{
  uint8_t src_ip[16];
  uint16_t src_port;
  size_t data_len;
  uint8_t data[UDP_PL_MAX];
} UdpRxSeg;

static UdpRxSeg g_rx_split_arr[UDP_RX_SPLIT_MAX];
static uint32_t g_rx_split_head = 0;
static uint32_t g_rx_split_cnt = 0;

static void
ip_to_v6m (const uint8_t ip[16], uint8_t out[16])
{
  memcpy (out, ip, 16);
}

static bool
is_err_tns (int re)
{
  return (re == EAGAIN || re == EWOULDBLOCK || re == ENOBUFS);
}

static bool
is_err_unr (int re)
{
  return (re == ENETUNREACH || re == EHOSTUNREACH || re == ECONNREFUSED);
}

static int
udp_tx_1 (Udp *s, const UdpMsg *m)
{
  struct sockaddr_in6 addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (m->dst_port);
  ip_to_v6m (m->dst_ip, addr.sin6_addr.s6_addr);
  ssize_t tx1 = sendto (s->fd, m->data, m->data_len, 0,
                        (struct sockaddr *)&addr, sizeof (addr));
  if (tx1 >= 0)
    return 1;
  if (is_err_tns (errno))
    {
      if (udp_pend_add (s, m))
        return 1;
      fprintf (stderr, "udp: pending queue full, drop outgoing packet\n");
      return 0;
    }
  if (errno == EMSGSIZE)
    {
      if (g_emsg_cb)
        g_emsg_cb (m->dst_ip, m->dst_port, m->data_len);
      return 0;
    }
  if (is_err_unr (errno))
    {
      char ip_str[INET6_ADDRSTRLEN] = { 0 };
      ip_fmt (m->dst_ip, ip_str);
      fprintf (stderr,
               "udp: unreachable on sendto errno=%d dst=%s:%u "
               "len=%zu\n",
               errno, ip_str, m->dst_port, m->data_len);
      if (g_unr_cb)
        g_unr_cb (m->dst_ip, m->dst_port);
      return 0;
    }
  fprintf (stderr, "udp: sendto fallback drop errno=%d\n", errno);
  return 0;
}

static bool
udp_rx_split_add (const uint8_t src_ip[16], uint16_t src_port,
                  const uint8_t *data, size_t data_len)
{
  static uint64_t ovf_log_ts = 0;
  if (!src_ip || !data || data_len > UDP_PL_MAX || g_rx_split_cnt >= UDP_RX_SPLIT_MAX)
    {
      uint64_t now = sys_ts ();
      if (now - ovf_log_ts >= 1000ULL)
        {
          fprintf (stderr,
                   "udp: rx split backlog overflow cnt=%u max=%u len=%zu\n",
                   (unsigned)g_rx_split_cnt, (unsigned)UDP_RX_SPLIT_MAX,
                   data_len);
          ovf_log_ts = now;
        }
      return false;
    }
  uint32_t idx = (g_rx_split_head + g_rx_split_cnt) % UDP_RX_SPLIT_MAX;
  memcpy (g_rx_split_arr[idx].src_ip, src_ip, 16);
  g_rx_split_arr[idx].src_port = src_port;
  g_rx_split_arr[idx].data_len = data_len;
  memcpy (g_rx_split_arr[idx].data, data, data_len);
  g_rx_split_cnt++;
  return true;
}

static int
udp_rx_split_drn (uint8_t buf_arr[][UDP_PL_MAX], uint8_t src_ips[][16],
                  uint16_t src_ports[], size_t len_arr[], int max_cnt)
{
  int out_cnt = 0;
  while (out_cnt < max_cnt && g_rx_split_cnt > 0)
    {
      UdpRxSeg *seg = &g_rx_split_arr[g_rx_split_head];
      memcpy (buf_arr[out_cnt], seg->data, seg->data_len);
      memcpy (src_ips[out_cnt], seg->src_ip, 16);
      src_ports[out_cnt] = seg->src_port;
      len_arr[out_cnt] = seg->data_len;
      g_rx_split_head = (g_rx_split_head + 1) % UDP_RX_SPLIT_MAX;
      g_rx_split_cnt--;
      out_cnt++;
    }
  return out_cnt;
}

#if defined(__linux__) && defined(UDP_SEGMENT)
static bool
udp_gso_grp_fit (const UdpMsg *head, const UdpMsg *msg, size_t seg_len,
                 size_t tot_len, int seg_cnt)
{
  if (!head || !msg || seg_len == 0 || seg_cnt >= UDP_GSO_MAX_SEGS)
    return false;
  if (msg->data_len != seg_len)
    return false;
  if (msg->dst_port != head->dst_port)
    return false;
  if (memcmp (msg->dst_ip, head->dst_ip, 16) != 0)
    return false;
  if (tot_len + msg->data_len > UDP_GSO_MAX_BYTES)
    return false;
  return true;
}

static bool
udp_gso_has_run (UdpMsg *msgs, int cnt)
{
  for (int i = 1; i < cnt; i++)
    {
      if (msgs[i].data_len == msgs[i - 1].data_len
          && msgs[i].dst_port == msgs[i - 1].dst_port
          && memcmp (msgs[i].dst_ip, msgs[i - 1].dst_ip, 16) == 0)
        return true;
    }
  return false;
}

static int
udp_gso_tx (Udp *s, UdpMsg *msgs, int cnt)
{
  static uint8_t gso_buf[UDP_GSO_MAX_BYTES];
  int acc_cnt = 0;
  for (int i = 0; i < cnt;)
    {
      int grp_cnt = 1;
      size_t seg_len = msgs[i].data_len;
      size_t tot_len = seg_len;
      while ((i + grp_cnt) < cnt
             && udp_gso_grp_fit (&msgs[i], &msgs[i + grp_cnt], seg_len,
                                 tot_len, grp_cnt))
        {
          tot_len += msgs[i + grp_cnt].data_len;
          grp_cnt++;
        }
      if (grp_cnt < 2 || seg_len == 0)
        {
          int rc = udp_tx_1 (s, &msgs[i]);
          acc_cnt += rc;
          i++;
          continue;
        }

      size_t off = 0;
      for (int j = 0; j < grp_cnt; j++)
        {
          memcpy (gso_buf + off, msgs[i + j].data, msgs[i + j].data_len);
          off += msgs[i + j].data_len;
        }

      struct sockaddr_in6 addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons (msgs[i].dst_port);
      ip_to_v6m (msgs[i].dst_ip, addr.sin6_addr.s6_addr);

      struct iovec iov = { .iov_base = gso_buf, .iov_len = off };
      char cmsg_buf[CMSG_SPACE (sizeof (uint16_t))];
      memset (cmsg_buf, 0, sizeof (cmsg_buf));
      struct msghdr msg;
      memset (&msg, 0, sizeof (msg));
      msg.msg_name = &addr;
      msg.msg_namelen = sizeof (addr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = cmsg_buf;
      msg.msg_controllen = sizeof (cmsg_buf);

      struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
      cmsg->cmsg_level = SOL_UDP;
      cmsg->cmsg_type = UDP_SEGMENT;
      cmsg->cmsg_len = CMSG_LEN (sizeof (uint16_t));
      *((uint16_t *)CMSG_DATA (cmsg)) = (uint16_t)seg_len;
      msg.msg_controllen = CMSG_SPACE (sizeof (uint16_t));

      ssize_t rc = sendmsg (s->fd, &msg, 0);
      if (rc >= 0)
        {
          acc_cnt += grp_cnt;
          i += grp_cnt;
          continue;
        }

      if (errno == EINVAL || errno == ENOPROTOOPT || errno == EOPNOTSUPP
          || errno == ENOTSUP)
        {
          s->gso_en = false;
          for (int j = 0; j < grp_cnt; j++)
            acc_cnt += udp_tx_1 (s, &msgs[i + j]);
          i += grp_cnt;
          continue;
        }
      if (is_err_tns (errno))
        {
          for (int j = 0; j < grp_cnt; j++)
            {
              if (udp_pend_add (s, &msgs[i + j]))
                acc_cnt++;
              else
                fprintf (stderr,
                         "udp: pending queue full, drop outgoing packet\n");
            }
          i += grp_cnt;
          continue;
        }
      if (errno == EMSGSIZE)
        {
          if (g_emsg_cb)
            g_emsg_cb (msgs[i].dst_ip, msgs[i].dst_port, seg_len);
          i += grp_cnt;
          continue;
        }
      if (is_err_unr (errno))
        {
          char ip_str[INET6_ADDRSTRLEN] = { 0 };
          ip_fmt (msgs[i].dst_ip, ip_str);
          fprintf (stderr,
                   "udp: unreachable on gso send errno=%d dst=%s:%u "
                   "seg=%zu cnt=%d\n",
                   errno, ip_str, msgs[i].dst_port, seg_len, grp_cnt);
          if (g_unr_cb)
            g_unr_cb (msgs[i].dst_ip, msgs[i].dst_port);
        }
      else
        {
          fprintf (stderr, "udp: gso send drop errno=%d seg=%zu cnt=%d\n",
                   errno, seg_len, grp_cnt);
        }
      i += grp_cnt;
    }
  return acc_cnt;
}
#endif

static void
ip_fmt (const uint8_t ip[16], char out[INET6_ADDRSTRLEN])
{
  if (!ip || !out)
    return;
  if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 && ip[4] == 0
      && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0
      && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff)
    inet_ntop (AF_INET, ip + 12, out, INET6_ADDRSTRLEN);
  else
    inet_ntop (AF_INET6, ip, out, INET6_ADDRSTRLEN);
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
              char ip_str[INET6_ADDRSTRLEN] = { 0 };
              ip_fmt (pm->dst_ip, ip_str);
              fprintf (stderr,
                       "udp: unreachable on pending flush errno=%d dst=%s:%u "
                       "len=%zu\n",
                       errno, ip_str, pm->dst_port, pm->data_len);
              if (g_unr_cb)
                g_unr_cb (pm->dst_ip, pm->dst_port);
              s->pend_head = (s->pend_head + 1) % UDP_PND_MAX;
              s->pend_cnt--;
              continue;
            }
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
  s->gso_en = true;
  s->gro_en = false;
  s->fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (s->fd < 0)
    return -1;
  /*
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
  */
  int rx_buf = 67108864;
  int sndbuf = 67108864;
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
#if defined(__linux__) && defined(UDP_GRO)
  {
    int gro = 1;
    if (setsockopt (s->fd, IPPROTO_UDP, UDP_GRO, &gro, sizeof (gro)) == 0)
      s->gro_en = true;
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
#if defined(__linux__) && defined(UDP_SEGMENT)
  if (s->gso_en && udp_gso_has_run (msgs, cnt))
    return udp_gso_tx (s, msgs, cnt);
#endif
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
              acc_cnt += udp_tx_1 (s, &msgs[i]);
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
  if (!s)
    return -1;
  if (m_cnt <= 0)
    return 0;
  if (m_cnt > BATCH_MAX)
    m_cnt = BATCH_MAX;
  int out_cnt = udp_rx_split_drn (buf_arr, src_ips, src_ports, len_arr, m_cnt);
  if (out_cnt >= m_cnt)
    return out_cnt;
  if (!s->gro_en)
    {
      static struct mmsghdr msg_arr[BATCH_MAX];
      static struct sockaddr_in6 addr_arr[BATCH_MAX];
      static struct iovec iovs[BATCH_MAX];
      static bool is_init = false;
      if (!is_init)
        {
          for (int i = 0; i < BATCH_MAX; i++)
            {
              memset (&addr_arr[i], 0, sizeof (addr_arr[i]));
              memset (&msg_arr[i], 0, sizeof (msg_arr[i]));
              msg_arr[i].msg_hdr.msg_name = &addr_arr[i];
              msg_arr[i].msg_hdr.msg_namelen = sizeof (addr_arr[i]);
              msg_arr[i].msg_hdr.msg_iov = &iovs[i];
              msg_arr[i].msg_hdr.msg_iovlen = 1;
            }
          is_init = true;
        }
      for (int i = out_cnt; i < m_cnt; i++)
        {
          iovs[i].iov_base = buf_arr[i];
          iovs[i].iov_len = UDP_PL_MAX;
          msg_arr[i].msg_hdr.msg_namelen = sizeof (addr_arr[i]);
          msg_arr[i].msg_hdr.msg_flags = 0;
          msg_arr[i].msg_len = 0;
        }
      int rx_cnt = recvmmsg (s->fd, msg_arr + out_cnt, m_cnt - out_cnt,
                             MSG_DONTWAIT, NULL);
      if (rx_cnt < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return out_cnt;
          return (out_cnt > 0) ? out_cnt : -1;
        }
      for (int i = 0; i < rx_cnt; i++)
        {
          int idx = out_cnt + i;
          memcpy (src_ips[idx], addr_arr[idx].sin6_addr.s6_addr, 16);
          src_ports[idx] = ntohs (addr_arr[idx].sin6_port);
          len_arr[idx] = msg_arr[idx].msg_len;
        }
      return out_cnt + rx_cnt;
    }

  static struct mmsghdr gro_msg_arr[BATCH_MAX];
  static struct sockaddr_in6 gro_addr_arr[BATCH_MAX];
  static struct iovec gro_iovs[BATCH_MAX];
  static uint8_t gro_buf_arr[BATCH_MAX][UDP_RX_BUF_MAX];
  static char gro_cmsg_arr[BATCH_MAX][CMSG_SPACE (sizeof (uint16_t))];
  static bool gro_init = false;
  if (!gro_init)
    {
      for (int i = 0; i < BATCH_MAX; i++)
        {
          memset (&gro_addr_arr[i], 0, sizeof (gro_addr_arr[i]));
          memset (&gro_msg_arr[i], 0, sizeof (gro_msg_arr[i]));
          gro_msg_arr[i].msg_hdr.msg_name = &gro_addr_arr[i];
          gro_msg_arr[i].msg_hdr.msg_namelen = sizeof (gro_addr_arr[i]);
          gro_msg_arr[i].msg_hdr.msg_iov = &gro_iovs[i];
          gro_msg_arr[i].msg_hdr.msg_iovlen = 1;
        }
      gro_init = true;
    }
  for (int i = 0; i < (m_cnt - out_cnt); i++)
    {
      gro_iovs[i].iov_base = gro_buf_arr[i];
      gro_iovs[i].iov_len = sizeof (gro_buf_arr[i]);
      gro_msg_arr[i].msg_hdr.msg_namelen = sizeof (gro_addr_arr[i]);
      gro_msg_arr[i].msg_hdr.msg_flags = 0;
      gro_msg_arr[i].msg_hdr.msg_control = gro_cmsg_arr[i];
      gro_msg_arr[i].msg_hdr.msg_controllen = sizeof (gro_cmsg_arr[i]);
      gro_msg_arr[i].msg_len = 0;
    }
  int rx_cnt = recvmmsg (s->fd, gro_msg_arr, m_cnt - out_cnt, MSG_DONTWAIT, NULL);
  if (rx_cnt < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return out_cnt;
      return (out_cnt > 0) ? out_cnt : -1;
    }
  for (int i = 0; i < rx_cnt; i++)
    {
      size_t pkt_len = gro_msg_arr[i].msg_len;
      uint16_t seg_len = 0;
      for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&gro_msg_arr[i].msg_hdr);
           cmsg != NULL; cmsg = CMSG_NXTHDR (&gro_msg_arr[i].msg_hdr, cmsg))
        {
#if defined(__linux__) && defined(UDP_GRO)
          if (cmsg->cmsg_level == IPPROTO_UDP && cmsg->cmsg_type == UDP_GRO
              && cmsg->cmsg_len >= CMSG_LEN (sizeof (uint16_t)))
            {
              seg_len = *((uint16_t *)CMSG_DATA (cmsg));
            }
#endif
        }
      uint8_t src_ip[16];
      memcpy (src_ip, gro_addr_arr[i].sin6_addr.s6_addr, 16);
      uint16_t src_port = ntohs (gro_addr_arr[i].sin6_port);
      if (seg_len == 0)
        {
          if (pkt_len > UDP_PL_MAX)
            continue;
          if (out_cnt < m_cnt)
            {
              memcpy (buf_arr[out_cnt], gro_buf_arr[i], pkt_len);
              memcpy (src_ips[out_cnt], src_ip, 16);
              src_ports[out_cnt] = src_port;
              len_arr[out_cnt] = pkt_len;
              out_cnt++;
            }
          else
            {
              (void)udp_rx_split_add (src_ip, src_port, gro_buf_arr[i],
                                      pkt_len);
            }
          continue;
        }
      if (seg_len > UDP_PL_MAX)
        continue;
      for (size_t off = 0; off < pkt_len;)
        {
          size_t chunk_len = pkt_len - off;
          if (chunk_len > seg_len)
            chunk_len = seg_len;
          if (out_cnt < m_cnt)
            {
              memcpy (buf_arr[out_cnt], gro_buf_arr[i] + off, chunk_len);
              memcpy (src_ips[out_cnt], src_ip, 16);
              src_ports[out_cnt] = src_port;
              len_arr[out_cnt] = chunk_len;
              out_cnt++;
            }
          else
            {
              if (!udp_rx_split_add (src_ip, src_port, gro_buf_arr[i] + off,
                                     chunk_len))
                break;
            }
          off += chunk_len;
        }
    }
  return out_cnt;
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

bool
udp_rx_pending (void)
{
  return g_rx_split_cnt > 0;
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
  (void)s;
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs (&ifaddr) != 0)
    return 1500;
  int max_mtu = 1280;
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0)
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (!ifa->ifa_addr)
            continue;
          if ((ifa->ifa_flags & IFF_UP) == 0)
            continue;
          if ((ifa->ifa_flags & IFF_LOOPBACK) != 0)
            continue;
          if (ifa->ifa_addr->sa_family == AF_INET
              || ifa->ifa_addr->sa_family == AF_INET6)
            {
              struct ifreq ifr;
              memset (&ifr, 0, sizeof (ifr));
              strncpy (ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
              if (ioctl (fd, SIOCGIFMTU, &ifr) == 0)
                {
                  if (ifr.ifr_mtu > max_mtu)
                    max_mtu = ifr.ifr_mtu;
                }
            }
        }
      close (fd);
    }
  freeifaddrs (ifaddr);
  return (uint16_t)max_mtu;
}

uint16_t
udp_ep_mtu_get (const uint8_t dst_ip[16])
{
  if (!dst_ip)
    return 1500;
  int is_v4m = (dst_ip[0] == 0 && dst_ip[1] == 0 && dst_ip[2] == 0
                && dst_ip[3] == 0 && dst_ip[4] == 0 && dst_ip[5] == 0
                && dst_ip[6] == 0 && dst_ip[7] == 0 && dst_ip[8] == 0
                && dst_ip[9] == 0 && dst_ip[10] == 0xff && dst_ip[11] == 0xff);
  if (is_v4m)
    {
      int fd4 = socket (AF_INET, SOCK_DGRAM, 0);
      if (fd4 < 0)
        return 1500;
      struct sockaddr_in sa4;
      memset (&sa4, 0, sizeof (sa4));
      sa4.sin_family = AF_INET;
      sa4.sin_port = htons (53);
      memcpy (&sa4.sin_addr, dst_ip + 12, 4);
      if (connect (fd4, (struct sockaddr *)&sa4, sizeof (sa4)) == 0)
        {
          int mtu4 = 0;
          socklen_t len4 = sizeof (mtu4);
          if (getsockopt (fd4, IPPROTO_IP, IP_MTU, &mtu4, &len4) == 0
              && mtu4 > 0)
            {
              close (fd4);
              return (uint16_t)mtu4;
            }
        }
      close (fd4);
      return 1500;
    }

  int fd6 = socket (AF_INET6, SOCK_DGRAM, 0);
  if (fd6 < 0)
    return 1500;
  struct sockaddr_in6 sa6;
  memset (&sa6, 0, sizeof (sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons (53);
  memcpy (sa6.sin6_addr.s6_addr, dst_ip, 16);
  if (connect (fd6, (struct sockaddr *)&sa6, sizeof (sa6)) == 0)
    {
      int mtu6 = 0;
      socklen_t len6 = sizeof (mtu6);
      if (getsockopt (fd6, IPPROTO_IPV6, IPV6_MTU, &mtu6, &len6) == 0
          && mtu6 > 0)
        {
          close (fd6);
          return (uint16_t)mtu6;
        }
    }
  close (fd6);
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
