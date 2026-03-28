#include "tap.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef TUNSETIFF
#define TUNSETIFF 0x400454caU
#endif
#ifndef TUNSETSNDBUF
#define TUNSETSNDBUF 0x400454d4U
#endif
#ifndef SIOCSIFFLAGS
#define SIOCSIFFLAGS 0x8914U
#endif
#ifndef SIOCGIFFLAGS
#define SIOCGIFFLAGS 0x8913U
#endif
#ifndef SIOCSIFTXQLEN
#define SIOCSIFTXQLEN 0x8943U
#endif
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000
#define IFF_VNET_HDR 0x4000
#define TAP_TXQ_LEN 500000
#define TAP_SND_BUF (256 * 1024 * 1024)
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

static bool g_tap_udp_gso = false;

static void
tap_txq_set (const char *name)
{
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return;
  struct ifreq q;
  memset (&q, 0, sizeof (q));
  strncpy (q.ifr_name, name, IFNAMSIZ - 1);
  q.ifr_qlen = TAP_TXQ_LEN;
  if (ioctl (sock, SIOCSIFTXQLEN, &q) < 0)
    {
      perror ("tap: ioctl(SIOCSIFTXQLEN) failed");
    }
  close (sock);
}

bool
tap_udp_gso_ok (void)
{
  return g_tap_udp_gso;
}

void
tap_stl_rm (const char *name)
{
  char chk_cmd[256];
  snprintf (chk_cmd, sizeof (chk_cmd),
            "ip -6 addr show dev %s 2>/dev/null | grep -Eq "
            "'dadfailed|tentative'",
            name);
  int rc = system (chk_cmd);
  if (rc != 0)
    return;
  char cmd[256];
  snprintf (cmd, sizeof (cmd), "ip link set dev %s down", name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to set link %s down\n", name);
    }
  snprintf (cmd, sizeof (cmd), "ip -6 addr flush dev %s scope link", name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to flush addresses for %s\n", name);
    }
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
      }
    int tcp_offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
    int udp_offload = TUN_F_UFO | TUN_F_USO4 | TUN_F_USO6;
    int offload = tcp_offload | udp_offload;
    g_tap_udp_gso = false;
    if (ioctl (fd, TUNSETOFFLOAD, offload) == 0)
      {
        g_tap_udp_gso = true;
      }
    else if (ioctl (fd, TUNSETOFFLOAD, tcp_offload) < 0)
      {
        perror ("tap: ioctl(TUNSETOFFLOAD) failed");
      }
    else
      {
        fprintf (stderr,
                 "tap: UDP segmentation offload unavailable; "
                 "falling back to plain UDP delivery\n");
      }
  }
  {
    int sndbuf = TAP_SND_BUF;
    if (ioctl (fd, TUNSETSNDBUF, &sndbuf) < 0)
      {
        perror ("tap: ioctl(TUNSETSNDBUF) failed");
      }
  }
  tap_txq_set (name);
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock >= 0)
    {
      struct ifreq grp;
      memset (&grp, 0, sizeof (grp));
      strncpy (grp.ifr_name, name, IFNAMSIZ - 1);
      if (ioctl (sock, SIOCGIFFLAGS, &grp) < 0)
        {
          perror ("tap: ioctl(SIOCGIFFLAGS) failed");
        }
      grp.ifr_flags |= (IFF_UP | IFF_MULTICAST);
      if (ioctl (sock, SIOCSIFFLAGS, &grp) < 0)
        {
          perror ("tap: ioctl(SIOCSIFFLAGS) failed");
        }
      close (sock);
    }
  {
    char cmd[256];
    snprintf (cmd, sizeof (cmd), "ip link set dev %s up", name);
    if (system (cmd) < 0)
      {
        fprintf (stderr, "tap: system(ip link set up) failed\n");
      }
  }
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl (fd, F_SETFL, flags | O_NONBLOCK);
  return fd;
}

void
tap_addr_set (const char *name, const uint8_t lla[16])
{
  tap_txq_set (name);
  char addr_str[64];
  snprintf (addr_str, sizeof (addr_str),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x/96",
            lla[0], lla[1], lla[2], lla[3], lla[4], lla[5], lla[6], lla[7],
            lla[8], lla[9], lla[10], lla[11], lla[12], lla[13], lla[14],
            lla[15]);
  uint8_t mac[6];
  lla_to_mac (lla, mac);
  char cmd[256];
  snprintf (cmd, sizeof (cmd),
            "ip link set dev %s address %02x:%02x:%02x:%02x:%02x:%02x", name,
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to set address for %s\n", name);
    }
  snprintf (cmd, sizeof (cmd), "ip link set dev %s multicast on", name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to set multicast for %s\n", name);
    }
  snprintf (cmd, sizeof (cmd), "ip link set dev %s addrgenmode none", name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to set addrgenmode for %s\n", name);
    }
  snprintf (cmd, sizeof (cmd), "ip -6 addr flush dev %s scope link", name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to flush addresses for %s\n", name);
    }
  snprintf (cmd, sizeof (cmd), "ip -6 addr add %s dev %s scope link", addr_str,
            name);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: failed to add link-local address for %s\n", name);
    }
}

void
tap_mtu_set (const char *name, uint16_t mtu)
{
  if (!name)
    return;
  if (mtu < 128)
    mtu = 128;
  char cmd[256];
  snprintf (cmd, sizeof (cmd), "ip link set dev %s mtu %u", name,
            (unsigned)mtu);
  if (system (cmd) < 0)
    {
      fprintf (stderr, "tap: system(ip link set mtu) failed\n");
    }
}

int
tap_mtu_get (const char *name, uint16_t *mtu)
{
  if (!name || !mtu)
    return -1;
  int sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return -1;
  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, name, IFNAMSIZ - 1);
  if (ioctl (sock, SIOCGIFMTU, &ifr) < 0)
    {
      close (sock);
      return -1;
    }
  close (sock);
  if (ifr.ifr_mtu < 0)
    return -1;
  *mtu = (uint16_t)ifr.ifr_mtu;
  return 0;
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
  if (eth_type == ETH_P_IP)
    {
      r->res_type = FRAME_V6_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  if (eth_type != ETH_P_IPV6)
    {
      r->res_type = FRAME_V6_DAT;
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
      r->res_type = FRAME_V6_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  if (n < ETH_HLEN + V6_HDR_LEN + 8)
    {
      r->res_type = FRAME_V6_DAT;
      r->pl_start = 0;
      r->payload_len = n;
      return;
    }
  uint8_t *icmp = pl_ptr + V6_HDR_LEN;
  if (icmp[0] != ICMP6_T_NS)
    {
      r->res_type = FRAME_V6_DAT;
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

uint8_t *
eth_bld (const uint8_t src_lla[16], const uint8_t dst_lla[16],
         const uint8_t *ipv6, size_t ipv6_len, uint8_t *buf, size_t *out_len)
{
  uint8_t src_mac[6], dst_mac[6];
  lla_to_mac (src_lla, src_mac);
  lla_to_mac (dst_lla, dst_mac);
  memcpy (buf, dst_mac, 6);
  memcpy (buf + 6, src_mac, 6);
  uint16_t eth_type = ETH_P_IPV6;
  if (ipv6_len >= 1)
    {
      uint8_t ver = (uint8_t)((ipv6[0] >> 4) & 0x0f);
      if (ver == 4)
        eth_type = ETH_P_IP;
      else if (ver == 6)
        eth_type = ETH_P_IPV6;
    }
  buf[12] = (uint8_t)(eth_type >> 8);
  buf[13] = (uint8_t)(eth_type & 0xff);
  memcpy (buf + ETH_HLEN, ipv6, ipv6_len);
  *out_len = ETH_HLEN + ipv6_len;
  return buf;
}

uint8_t *
eth_bld_ip (const uint8_t src_lla[16], const uint8_t dst_lla[16],
            uint8_t *ipv6_ptr, size_t ipv6_len, size_t *out_len)
{
  uint8_t *eth_ptr = ipv6_ptr - ETH_HLEN;
  uint8_t src_mac[6], dst_mac[6];
  lla_to_mac (src_lla, src_mac);
  lla_to_mac (dst_lla, dst_mac);
  memcpy (eth_ptr, dst_mac, 6);
  memcpy (eth_ptr + 6, src_mac, 6);
  uint16_t eth_type = ETH_P_IPV6;
  if (ipv6_len >= 1)
    {
      uint8_t ver = (uint8_t)((ipv6_ptr[0] >> 4) & 0x0f);
      if (ver == 4)
        eth_type = ETH_P_IP;
      else if (ver == 6)
        eth_type = ETH_P_IPV6;
    }
  eth_ptr[12] = (uint8_t)(eth_type >> 8);
  eth_ptr[13] = (uint8_t)(eth_type & 0xff);
  *out_len = ETH_HLEN + ipv6_len;
  return eth_ptr;
}
