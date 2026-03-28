#include "gro.h"
#include "tap.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/virtio_net.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define GRO_MAX_SZ 65535U
#define GRO_SLOTS 32
#define GRO_PROTO_TCP 6
#define GRO_PROTO_UDP 17

typedef struct
{
  uint8_t buf[GRO_MAX_SZ + 256];
  size_t len;
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  uint16_t sport;
  uint16_t dport;
  uint32_t nxt_seq;
  uint16_t gso_sz;
  uint8_t mac_hl;
  uint8_t ip_hl;
  uint8_t l4_hl;
  uint8_t proto;
  bool is_v6;
  bool act;
} GroEnt;

static GroEnt g_gro[GRO_SLOTS];
static bool g_udp_gso_bad = false;

static inline uint16_t
u16_be_rd (const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline void
u16_be_wr (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xffU);
}

static inline uint32_t
u32_be_rd (const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
u32_be_wr (uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v & 0xffU);
}

static uint32_t
csum_add (uint32_t sum, const uint8_t *buf, size_t len)
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
csum_fold (uint32_t sum)
{
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)(~sum & 0xffffU);
}

static uint16_t
ip4_hdr_sum (const uint8_t *ip4, size_t ip_hl)
{
  uint32_t sum = 0;
  for (size_t i = 0; i < ip_hl; i += 2)
    {
      if (i == 10)
        continue;
      sum += ((uint32_t)ip4[i] << 8) | ip4[i + 1];
    }
  return csum_fold (sum);
}

static uint16_t
l4_sum_v4 (const uint8_t *ip4, uint8_t proto, const uint8_t *l4, size_t l4_len)
{
  uint32_t sum = 0;
  sum = csum_add (sum, ip4 + 12, 8);
  sum += proto;
  sum += (uint16_t)l4_len;
  sum = csum_add (sum, l4, l4_len);
  return csum_fold (sum);
}

static uint16_t
l4_sum_v6 (const uint8_t *ip6, uint8_t proto, const uint8_t *l4, size_t l4_len)
{
  uint32_t sum = 0;
  sum = csum_add (sum, ip6 + 8, 32);
  sum += (uint32_t)((l4_len >> 16) & 0xffffU);
  sum += (uint32_t)(l4_len & 0xffffU);
  sum += proto;
  sum = csum_add (sum, l4, l4_len);
  return csum_fold (sum);
}

static void
gro_sum_prep (GroEnt *gro)
{
  uint8_t *l3 = gro->buf + gro->mac_hl;
  uint8_t *l4 = l3 + gro->ip_hl;
  size_t l4_len = gro->len - gro->mac_hl - gro->ip_hl;
  if (gro->is_v6)
    {
      u16_be_wr (l3 + 4, (uint16_t)l4_len);
      if (gro->proto == GRO_PROTO_TCP)
        {
          l4[16] = 0;
          l4[17] = 0;
          u16_be_wr (l4 + 16, l4_sum_v6 (l3, GRO_PROTO_TCP, l4, l4_len));
        }
      else
        {
          u16_be_wr (l4 + 4, (uint16_t)l4_len);
          l4[6] = 0;
          l4[7] = 0;
          u16_be_wr (l4 + 6, l4_sum_v6 (l3, GRO_PROTO_UDP, l4, l4_len));
        }
      return;
    }

  u16_be_wr (l3 + 2, (uint16_t)(gro->ip_hl + l4_len));
  l3[10] = 0;
  l3[11] = 0;
  u16_be_wr (l3 + 10, ip4_hdr_sum (l3, gro->ip_hl));
  if (gro->proto == GRO_PROTO_TCP)
    {
      l4[16] = 0;
      l4[17] = 0;
      u16_be_wr (l4 + 16, l4_sum_v4 (l3, GRO_PROTO_TCP, l4, l4_len));
    }
  else
    {
      u16_be_wr (l4 + 4, (uint16_t)l4_len);
      l4[6] = 0;
      l4[7] = 0;
      u16_be_wr (l4 + 6, l4_sum_v4 (l3, GRO_PROTO_UDP, l4, l4_len));
    }
}

static void
gro_ent_fls (int tap_fd, GroEnt *gro)
{
  if (!gro->act)
    return;
  if (gro->proto == GRO_PROTO_UDP
      && (!tap_udp_gso_ok () || g_udp_gso_bad))
    {
      static uint8_t seg_buf[GRO_MAX_SZ + 256];
      static const uint8_t z_vnet[VNET_HL] = { 0 };
      size_t hdr_len = gro->mac_hl + gro->ip_hl + 8U;
      if (gro->gso_sz == 0 || gro->len < hdr_len)
        {
          fprintf (stderr, "gro: invalid udp gso frame, drop\n");
          gro->act = false;
          return;
        }
      size_t pl_len = gro->len - hdr_len;
      for (size_t off = 0; off < pl_len;)
        {
          size_t seg_pl = pl_len - off;
          if (seg_pl > gro->gso_sz)
            seg_pl = gro->gso_sz;
          memcpy (seg_buf, gro->buf, hdr_len);
          memcpy (seg_buf + hdr_len, gro->buf + hdr_len + off, seg_pl);
          uint8_t *l3 = seg_buf + gro->mac_hl;
          uint8_t *udp = l3 + gro->ip_hl;
          size_t l4_len = 8U + seg_pl;
          if (gro->is_v6)
            {
              u16_be_wr (l3 + 4, (uint16_t)l4_len);
              u16_be_wr (udp + 4, (uint16_t)l4_len);
              udp[6] = 0;
              udp[7] = 0;
              u16_be_wr (udp + 6,
                         l4_sum_v6 (l3, GRO_PROTO_UDP, udp, l4_len));
            }
          else
            {
              u16_be_wr (l3 + 2, (uint16_t)(gro->ip_hl + l4_len));
              l3[10] = 0;
              l3[11] = 0;
              u16_be_wr (l3 + 10, ip4_hdr_sum (l3, gro->ip_hl));
              u16_be_wr (udp + 4, (uint16_t)l4_len);
              udp[6] = 0;
              udp[7] = 0;
              u16_be_wr (udp + 6,
                         l4_sum_v4 (l3, GRO_PROTO_UDP, udp, l4_len));
            }
          struct iovec iov[2] = { { .iov_base = (void *)z_vnet,
                                    .iov_len = sizeof (z_vnet) },
                                  { .iov_base = seg_buf,
                                    .iov_len = hdr_len + seg_pl } };
          if (writev (tap_fd, iov, 2) < 0)
            {
              fprintf (stderr,
                       "gro: udp plain write fallback failed errno=%d\n",
                       errno);
              gro->act = false;
              return;
            }
          off += seg_pl;
        }
      gro->act = false;
      return;
    }
  gro_sum_prep (gro);

  struct virtio_net_hdr vh;
  memset (&vh, 0, sizeof (vh));
  vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
  if (gro->proto == GRO_PROTO_TCP)
    {
      vh.gso_type = gro->is_v6 ? VIRTIO_NET_HDR_GSO_TCPV6
                               : VIRTIO_NET_HDR_GSO_TCPV4;
      vh.csum_offset = 16;
    }
  else
    {
      vh.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
      vh.csum_offset = 6;
    }
  vh.hdr_len = (uint16_t)(gro->mac_hl + gro->ip_hl + gro->l4_hl);
  vh.gso_size = gro->gso_sz;
  vh.csum_start = (uint16_t)(gro->mac_hl + gro->ip_hl);

  struct iovec iov[2] = { { .iov_base = &vh, .iov_len = sizeof (vh) },
                          { .iov_base = gro->buf, .iov_len = gro->len } };
  if (writev (tap_fd, iov, 2) < 0)
    {
      if (gro->proto == GRO_PROTO_UDP)
        {
          fprintf (stderr,
                   "gro: udp gso write failed errno=%d; "
                   "disabling udp gso to tap\n",
                   errno);
          g_udp_gso_bad = true;
          gro_ent_fls (tap_fd, gro);
          return;
        }
      fprintf (stderr, "gro: tcp gso write failed errno=%d\n", errno);
    }
  gro->act = false;
}

static void
gro_fls_all_kind (int tap_fd, uint8_t proto, bool is_v6)
{
  for (int i = 0; i < GRO_SLOTS; i++)
    {
      if (!g_gro[i].act)
        continue;
      if (g_gro[i].proto != proto || g_gro[i].is_v6 != is_v6)
        continue;
      gro_ent_fls (tap_fd, &g_gro[i]);
    }
}

void
gro_fls_all (int tap_fd)
{
  for (int i = 0; i < GRO_SLOTS; i++)
    gro_ent_fls (tap_fd, &g_gro[i]);
}

static bool
gro_tcp_try (int tap_fd, const uint8_t *frm, size_t len, size_t mac_hl,
             bool is_v6)
{
  size_t ip_hl = is_v6 ? 40U : (size_t)((frm[mac_hl] & 0x0fU) * 4U);
  if (ip_hl < (is_v6 ? 40U : 20U) || len < mac_hl + ip_hl + 20U)
    return false;
  const uint8_t *ip = frm + mac_hl;
  const uint8_t *tcp = ip + ip_hl;
  size_t tcp_hl = (size_t)(((tcp[12] >> 4) & 0x0fU) * 4U);
  if (tcp_hl < 20U || len < mac_hl + ip_hl + tcp_hl + 1U)
    return false;
  size_t pl_len = len - mac_hl - ip_hl - tcp_hl;
  uint32_t seq = u32_be_rd (tcp + 4);
  uint16_t sp = u16_be_rd (tcp + 0);
  uint16_t dp = u16_be_rd (tcp + 2);
  int slot = (int)((sp ^ dp ^ ip[15]) % GRO_SLOTS);
  GroEnt *gro = &g_gro[slot];

  if (gro->act)
    {
      uint8_t *gro_ip = gro->buf + gro->mac_hl;
      uint8_t *gro_tcp = gro_ip + gro->ip_hl;
      if (gro->proto == GRO_PROTO_TCP && gro->is_v6 == is_v6
          && gro->sport == sp && gro->dport == dp
          && gro->ip_hl == ip_hl && gro->l4_hl == tcp_hl
          && memcmp (gro->src_ip, is_v6 ? ip + 8 : ip + 12, is_v6 ? 16 : 4) == 0
          && memcmp (gro->dst_ip, is_v6 ? ip + 24 : ip + 16, is_v6 ? 16 : 4) == 0
          && memcmp (gro_tcp, tcp, 4) == 0
          && memcmp (gro_tcp + 8, tcp + 8, 8) == 0
          && seq == gro->nxt_seq && (gro->len + pl_len) <= GRO_MAX_SZ)
        {
          memcpy (gro->buf + gro->len, tcp + tcp_hl, pl_len);
          gro->len += pl_len;
          gro->nxt_seq += (uint32_t)pl_len;
          memcpy ((uint8_t *)gro_tcp + 8, tcp + 8, 8);
          gro_tcp[13] |= tcp[13];
          if ((tcp[13] & 0x09U) != 0)
            gro_ent_fls (tap_fd, gro);
          return true;
        }
      gro_ent_fls (tap_fd, gro);
    }

  memcpy (gro->buf, frm, len);
  gro->len = len;
  memset (gro->src_ip, 0, sizeof (gro->src_ip));
  memset (gro->dst_ip, 0, sizeof (gro->dst_ip));
  memcpy (gro->src_ip, is_v6 ? ip + 8 : ip + 12, is_v6 ? 16 : 4);
  memcpy (gro->dst_ip, is_v6 ? ip + 24 : ip + 16, is_v6 ? 16 : 4);
  gro->sport = sp;
  gro->dport = dp;
  gro->nxt_seq = seq + (uint32_t)pl_len;
  gro->gso_sz = (uint16_t)pl_len;
  gro->mac_hl = (uint8_t)mac_hl;
  gro->ip_hl = (uint8_t)ip_hl;
  gro->l4_hl = (uint8_t)tcp_hl;
  gro->proto = GRO_PROTO_TCP;
  gro->is_v6 = is_v6;
  gro->act = true;
  if ((tcp[13] & 0x09U) != 0)
    gro_ent_fls (tap_fd, gro);
  return true;
}

static bool
gro_udp_try (int tap_fd, const uint8_t *frm, size_t len, size_t mac_hl,
             bool is_v6)
{
  if (!tap_udp_gso_ok () || g_udp_gso_bad)
    return false;
  size_t ip_hl = is_v6 ? 40U : (size_t)((frm[mac_hl] & 0x0fU) * 4U);
  if (ip_hl < (is_v6 ? 40U : 20U) || len < mac_hl + ip_hl + 8U)
    return false;
  const uint8_t *ip = frm + mac_hl;
  const uint8_t *udp = ip + ip_hl;
  size_t pl_len = len - mac_hl - ip_hl - 8U;
  if (pl_len == 0)
    return false;
  uint16_t sp = u16_be_rd (udp + 0);
  uint16_t dp = u16_be_rd (udp + 2);
  int slot = (int)((sp ^ dp ^ ip[15] ^ 0x5aU) % GRO_SLOTS);
  GroEnt *gro = &g_gro[slot];

  if (gro->act)
    {
      const uint8_t *gro_ip = gro->buf + gro->mac_hl;
      const uint8_t *gro_udp = gro_ip + gro->ip_hl;
      if (gro->proto == GRO_PROTO_UDP && gro->is_v6 == is_v6
          && gro->sport == sp && gro->dport == dp
          && gro->ip_hl == ip_hl
          && memcmp (gro->src_ip, is_v6 ? ip + 8 : ip + 12, is_v6 ? 16 : 4) == 0
          && memcmp (gro->dst_ip, is_v6 ? ip + 24 : ip + 16, is_v6 ? 16 : 4) == 0
          && memcmp (gro_udp, udp, 4) == 0 && gro->gso_sz == pl_len
          && (gro->len + pl_len) <= GRO_MAX_SZ)
        {
          memcpy (gro->buf + gro->len, udp + 8, pl_len);
          gro->len += pl_len;
          return true;
        }
      gro_ent_fls (tap_fd, gro);
    }

  memcpy (gro->buf, frm, len);
  gro->len = len;
  memset (gro->src_ip, 0, sizeof (gro->src_ip));
  memset (gro->dst_ip, 0, sizeof (gro->dst_ip));
  memcpy (gro->src_ip, is_v6 ? ip + 8 : ip + 12, is_v6 ? 16 : 4);
  memcpy (gro->dst_ip, is_v6 ? ip + 24 : ip + 16, is_v6 ? 16 : 4);
  gro->sport = sp;
  gro->dport = dp;
  gro->nxt_seq = 0;
  gro->gso_sz = (uint16_t)pl_len;
  gro->mac_hl = (uint8_t)mac_hl;
  gro->ip_hl = (uint8_t)ip_hl;
  gro->l4_hl = 8;
  gro->proto = GRO_PROTO_UDP;
  gro->is_v6 = is_v6;
  gro->act = true;
  return true;
}

void
gro_fed (int tap_fd, const uint8_t *vnet_frm, size_t vnet_len)
{
  if (!vnet_frm || vnet_len <= VNET_HL + ETH_HLEN)
    return;
  const uint8_t *frm = vnet_frm + VNET_HL;
  size_t len = vnet_len - VNET_HL;
  size_t mac_hl = ETH_HLEN;
  if (len < mac_hl + 20U)
    goto bypass;
  uint16_t eth_type = u16_be_rd (frm + 12);
  if ((eth_type == 0x8100U || eth_type == 0x88A8U) && len >= ETH_HLEN + 4U + 20U)
    {
      mac_hl = ETH_HLEN + 4U;
      eth_type = u16_be_rd (frm + 16);
    }

  if (eth_type == 0x86DDU)
    {
      const uint8_t *ip6 = frm + mac_hl;
      if (len < mac_hl + 40U)
        goto bypass;
      if (ip6[6] == GRO_PROTO_TCP)
        {
          gro_fls_all_kind (tap_fd, GRO_PROTO_UDP, true);
          if (gro_tcp_try (tap_fd, frm, len, mac_hl, true))
            return;
        }
      else if (ip6[6] == GRO_PROTO_UDP)
        {
          gro_fls_all_kind (tap_fd, GRO_PROTO_TCP, true);
          if (gro_udp_try (tap_fd, frm, len, mac_hl, true))
            return;
        }
      goto bypass;
    }

  if (eth_type == 0x0800U)
    {
      const uint8_t *ip4 = frm + mac_hl;
      if (len < mac_hl + 20U)
        goto bypass;
      uint8_t ihl = (uint8_t)((ip4[0] & 0x0fU) * 4U);
      if (ihl < 20U || len < mac_hl + ihl + 8U)
        goto bypass;
      if (ip4[9] == GRO_PROTO_TCP)
        {
          gro_fls_all_kind (tap_fd, GRO_PROTO_UDP, false);
          if (gro_tcp_try (tap_fd, frm, len, mac_hl, false))
            return;
        }
      else if (ip4[9] == GRO_PROTO_UDP)
        {
          gro_fls_all_kind (tap_fd, GRO_PROTO_TCP, false);
          if (gro_udp_try (tap_fd, frm, len, mac_hl, false))
            return;
        }
      goto bypass;
    }

bypass:
  gro_fls_all (tap_fd);
  if (write (tap_fd, vnet_frm, vnet_len) < 0)
    {
    }
}
