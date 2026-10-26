#include "tap.h"
#include "config.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_addr.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef TUNSETIFF
#define TUNSETIFF 0x400454caU
#endif
#ifndef TUNSETSNDBUF
#define TUNSETSNDBUF 0x400454d4U
#endif
#ifndef SIOCSIFTXQLEN
#define SIOCSIFTXQLEN 0x8943U
#endif
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000
#define IFF_VNET_HDR 0x4000
#define TAP_TXQ_LEN 1024
#define TAP_SND_BUF (4 * 1024 * 1024)
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86ddU
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800U
#endif
#define ICMP6_T_NS 135
#define ICMP6_T_NA 136
#define V6_NX_ICMP6 58
#define V6_HDR_LEN 40
#define NA_F_SOL 0x40
#define NA_F_OVR 0x20
#define ICMP6_OPT_TLL 2

static TapCaps g_tap_caps;

static int
tap_ip_run (char *const argv[], const char *what, const char *name,
            char *out, size_t out_cap)
{
  int pipefd[2] = { -1, -1 };
  if (out && pipe (pipefd) != 0)
    return -1;
  pid_t pid = fork ();
  if (pid < 0)
    {
      if (pipefd[0] >= 0)
        {
          close (pipefd[0]);
          close (pipefd[1]);
        }
      return -1;
    }
  if (pid == 0)
    {
      if (out)
        {
          close (pipefd[0]);
          if (dup2 (pipefd[1], STDOUT_FILENO) < 0)
            _exit (127);
          close (pipefd[1]);
        }
      execvp (argv[0], argv);
      _exit (127);
    }
  if (out)
    {
      close (pipefd[1]);
      size_t used = 0;
      ssize_t r;
      char buf[256];
      while ((r = read (pipefd[0], buf, sizeof (buf))) > 0)
        {
          if (out_cap > 0 && used < out_cap - 1)
            {
              size_t take = (size_t)r;
              if (take > out_cap - 1 - used)
                take = out_cap - 1 - used;
              memcpy (out + used, buf, take);
              used += take;
            }
        }
      close (pipefd[0]);
      if (out_cap > 0)
        out[used] = '\0';
    }
  int status = 0;
  if (waitpid (pid, &status, 0) < 0)
    return -1;
  if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
    return 0;
  if (what)
    {
      if (WIFEXITED (status))
        fprintf (stderr, "tap: %s failed for %s (exit=%d)\n", what, name,
                 WEXITSTATUS (status));
      else
        fprintf (stderr, "tap: %s failed for %s\n", what, name);
    }
  return -1;
}

static int
tap_txq_set (const char *name)
{
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return -1;
  struct ifreq q;
  memset (&q, 0, sizeof (q));
  strncpy (q.ifr_name, name, IFNAMSIZ - 1);
  q.ifr_qlen = TAP_TXQ_LEN;
  int rc = ioctl (sock, SIOCSIFTXQLEN, &q);
  if (rc < 0)
    perror ("tap: ioctl(SIOCSIFTXQLEN) failed");
  close (sock);
  return rc < 0 ? -1 : 0;
}

const TapCaps *
tap_caps (void)
{
  return &g_tap_caps;
}

static int
tap_down_flush (const char *name)
{
  char *down_argv[]
      = { "ip", "link", "set", "dev", (char *)name, "down", NULL };
  if (tap_ip_run (down_argv, "set link down", name, NULL, 0) != 0)
    return -1;
  char *flush_argv[] = { "ip",  "-6",   "addr", "flush", "dev",
                         (char *)name, "scope", "link", NULL };
  return tap_ip_run (flush_argv, "flush addresses", name, NULL, 0);
}

void
tap_stl_rm (const char *name)
{
  unsigned int ifidx = if_nametoindex (name);
  if (ifidx == 0)
    return;
  FILE *f = fopen ("/proc/net/if_inet6", "r");
  if (!f)
    return;
  bool stale = false;
  char line[160];
  while (fgets (line, sizeof (line), f))
    {
      unsigned int idx = 0, plen = 0, scope = 0, flags = 0;
      if (sscanf (line, "%*s %x %x %x %x", &idx, &plen, &scope, &flags)
          != 4)
        continue;
      if (idx != ifidx)
        continue;
      if (flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED))
        stale = true;
    }
  fclose (f);
  if (!stale)
    return;
  (void)tap_down_flush (name);
}

void
tap_iface_cleanup (const char *name)
{
  if (!name || !name[0] || if_nametoindex (name) == 0)
    return;
  char *del_argv[] = { "ip", "link", "del", "dev", (char *)name, NULL };
  (void)tap_down_flush (name);
  (void)tap_ip_run (del_argv, "delete link", name, NULL, 0);
}

int
tap_init (const char *name)
{
  int fd = open ("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return -1;
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, name, IFNAMSIZ - 1);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
  if (ioctl (fd, TUNSETIFF, &ifr) < 0)
    {
      perror ("tap: ioctl(TUNSETIFF) failed");
      close (fd);
      return -1;
    }
  {
    int vnet_hdr_sz = 10;
    if (ioctl (fd, TUNSETVNETHDRSZ, &vnet_hdr_sz) < 0)
      {
        perror ("tap: ioctl(TUNSETVNETHDRSZ) failed");
        close (fd);
        return -1;
      }
    int tcp_offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
    int udp_offload = TUN_F_UFO | TUN_F_USO4 | TUN_F_USO6;
    int offload = tcp_offload | udp_offload;
    memset (&g_tap_caps, 0, sizeof (g_tap_caps));
    if (ioctl (fd, TUNSETOFFLOAD, offload) == 0)
      {
        g_tap_caps.tcp_gso = true;
        g_tap_caps.udp_gso = true;
      }
    else if (ioctl (fd, TUNSETOFFLOAD, tcp_offload) == 0)
      {
        g_tap_caps.tcp_gso = true;
        fprintf (stderr,
                 "tap: UDP segmentation offload unavailable; "
                 "software segmentation is the UDP write path\n");
      }
    else
      {
        fprintf (stderr,
                 "tap: no segmentation offload available; "
                 "software segmentation is the write path\n");
      }
  }
  {
    int sndbuf = TAP_SND_BUF;
    if (ioctl (fd, TUNSETSNDBUF, &sndbuf) == 0)
      g_tap_caps.sndbuf_ok = true;
    else
      perror ("tap: ioctl(TUNSETSNDBUF) failed");
  }
  g_tap_caps.txq_ok = tap_txq_set (name) == 0;
  {
    char *up_argv[]
        = { "ip", "link", "set", "dev", (char *)name, "up", NULL };
    if (tap_ip_run (up_argv, "set link up", name, NULL, 0) != 0)
      {
        close (fd);
        return -1;
      }
  }
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl (fd, F_SETFL, flags | O_NONBLOCK);
  return fd;
}

int
tap_addr_set (const char *name, const uint8_t lla[16])
{
  char addr_str[64];
  snprintf (addr_str, sizeof (addr_str),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x/96",
            lla[0], lla[1], lla[2], lla[3], lla[4], lla[5], lla[6], lla[7],
            lla[8], lla[9], lla[10], lla[11], lla[12], lla[13], lla[14],
            lla[15]);
  uint8_t mac[6];
  lla_to_mac (lla, mac);
  char mac_str[24];
  snprintf (mac_str, sizeof (mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  char *addr_argv[] = { "ip",   "link", "set",     "dev",
                        (char *)name, "address", mac_str, NULL };
  if (tap_ip_run (addr_argv, "set address", name, NULL, 0) != 0)
    return -1;
  char *mc_argv[] = { "ip",   "link",      "set", "dev",
                      (char *)name, "multicast", "on",  NULL };
  if (tap_ip_run (mc_argv, "enable multicast", name, NULL, 0) != 0)
    return -1;
  char *ag_argv[] = { "ip",   "link", "set",        "dev",
                      (char *)name, "addrgenmode", "none", NULL };
  if (tap_ip_run (ag_argv, "set addrgenmode", name, NULL, 0) != 0)
    return -1;
  char *flush_argv[] = { "ip",  "-6",   "addr", "flush", "dev",
                         (char *)name, "scope", "link", NULL };
  if (tap_ip_run (flush_argv, "flush addresses", name, NULL, 0) != 0)
    return -1;
  char *add_argv[] = { "ip",  "-6",     "addr",    "add",  addr_str,
                       "dev", (char *)name, "scope", "link", NULL };
  if (tap_ip_run (add_argv, "add link-local address", name, NULL, 0) != 0)
    return -1;
  return 0;
}

int
tap_mtu_set (const char *name, uint16_t mtu)
{
  if (!name)
    return -1;
  if (mtu < CFG_MTU_MIN || mtu > CFG_MTU_MAX)
    return -1;
  char mtu_str[16];
  snprintf (mtu_str, sizeof (mtu_str), "%u", (unsigned)mtu);
  char *mtu_argv[] = { "ip",   "link", "set", "dev",
                       (char *)name, "mtu",  mtu_str, NULL };
  return tap_ip_run (mtu_argv, "set mtu", name, NULL, 0);
}

void
lla_to_mac (const uint8_t lla[16], uint8_t mac[6])
{
  mac[0] = 0x02;
  mac[1] = 0x00;
  mac[2] = lla[12];
  mac[3] = lla[13];
  mac[4] = lla[14];
  mac[5] = lla[15];
}

static uint16_t
icmp6_csum (const uint8_t src[16], const uint8_t dst[16],
            const uint8_t *payload, size_t plen)
{
  uint32_t sum = 0;
  for (int i = 0; i < 16; i += 2)
    {
      sum += ((uint32_t)src[i] << 8) | src[i + 1];
      sum += ((uint32_t)dst[i] << 8) | dst[i + 1];
    }
  sum += (uint32_t)(plen >> 16);
  sum += (uint32_t)(plen & 0xffff);
  sum += V6_NX_ICMP6;
  for (size_t i = 0; i + 1 < plen; i += 2)
    sum += ((uint32_t)payload[i] << 8) | payload[i + 1];
  if (plen & 1)
    sum += (uint32_t)payload[plen - 1] << 8;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return (uint16_t)(~sum & 0xffff);
}

void
tap_f_proc (uint8_t *frame, size_t n, const uint8_t our_lla[16], FRes *r)
{
  r->res_type = FRAME_OTH;
  r->na_len = 0;
  r->pl_start = 0;
  r->payload_len = 0;
  if (n < ETH_HLEN)
    return;
  uint16_t eth_type = ((uint16_t)frame[12] << 8) | frame[13];
  if (eth_type != ETH_P_IPV6)
    {
      r->res_type = FRAME_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  if (n < ETH_HLEN + V6_HDR_LEN)
    return;
  uint8_t *pl_ptr = frame + ETH_HLEN;
  uint8_t nh = pl_ptr[6];
  if (nh != V6_NX_ICMP6)
    {
      r->res_type = FRAME_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  if (n < ETH_HLEN + V6_HDR_LEN + 8)
    {
      r->res_type = FRAME_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  uint8_t *icmp = pl_ptr + V6_HDR_LEN;
  if (icmp[0] != ICMP6_T_NS)
    {
      r->res_type = FRAME_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  if (n < ETH_HLEN + V6_HDR_LEN + 24)
    return;
  uint8_t target[16];
  memcpy (target, icmp + 8, 16);
  if (our_lla && memcmp (target, our_lla, 16) == 0)
    {
      return;
    }
  uint8_t src_mac[6];
  memcpy (src_mac, frame + 6, 6);
  uint8_t src_ip[16], dst_ip[16];
  memcpy (src_ip, pl_ptr + 8, 16);
  memcpy (dst_ip, pl_ptr + 24, 16);
  (void)dst_ip;
  int is_z = 1;
  for (int i = 0; i < 16; i++)
    {
      if (src_ip[i] != 0)
        {
          is_z = 0;
          break;
        }
    }
  if (is_z)
    {
      src_ip[0] = 0xff;
      src_ip[1] = 0x02;
      memset (src_ip + 2, 0, 13);
      src_ip[15] = 0x01;
      src_mac[0] = 0x33;
      src_mac[1] = 0x33;
      src_mac[2] = 0x00;
      src_mac[3] = 0x00;
      src_mac[4] = 0x00;
      src_mac[5] = 0x01;
    }
  uint8_t tgt_mac[6];
  lla_to_mac (target, tgt_mac);
  uint8_t na_icmp[32] = { 0 };
  na_icmp[0] = ICMP6_T_NA;
  na_icmp[4] = 0x80 | NA_F_OVR | (is_z ? 0 : NA_F_SOL);
  memcpy (na_icmp + 8, target, 16);
  na_icmp[24] = ICMP6_OPT_TLL;
  na_icmp[25] = 1;
  memcpy (na_icmp + 26, tgt_mac, 6);
  uint16_t csum = icmp6_csum (target, src_ip, na_icmp, sizeof (na_icmp));
  if (csum == 0)
    csum = 0xffff;
  na_icmp[2] = (uint8_t)(csum >> 8);
  na_icmp[3] = (uint8_t)(csum & 0xff);
  uint8_t *buf = r->na_frame;
  memcpy (buf, src_mac, 6);
  memcpy (buf + 6, tgt_mac, 6);
  buf[12] = 0x86;
  buf[13] = 0xdd;
  uint16_t plen = (uint16_t)sizeof (na_icmp);
  buf[ETH_HLEN + 0] = 0x60;
  buf[ETH_HLEN + 1] = 0;
  buf[ETH_HLEN + 2] = 0;
  buf[ETH_HLEN + 3] = 0;
  buf[ETH_HLEN + 4] = (uint8_t)(plen >> 8);
  buf[ETH_HLEN + 5] = (uint8_t)(plen & 0xff);
  buf[ETH_HLEN + 6] = V6_NX_ICMP6;
  buf[ETH_HLEN + 7] = 255;
  memcpy (buf + ETH_HLEN + 8, target, 16);
  memcpy (buf + ETH_HLEN + 24, src_ip, 16);
  memcpy (buf + ETH_HLEN + 40, na_icmp, sizeof (na_icmp));
  r->na_len = ETH_HLEN + V6_HDR_LEN + sizeof (na_icmp);
  r->res_type = FRAME_NS_INT;
}
