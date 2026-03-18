#include "gro.h"
#include "utils.h"
#include <arpa/inet.h>
#include <linux/virtio_net.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define GRO_MAX_SZ 65535
#define GRO_SLOTS 16
typedef struct
{
  uint8_t buf[GRO_MAX_SZ + 256];
  size_t len;
  uint32_t saddr[4];
  uint16_t sport;
  uint16_t dport;
  uint32_t nxt_seq;
  uint16_t mss;
  uint8_t mac_hl;
  uint8_t ip_hl;
  uint8_t tcp_hl;
  bool act;
} GroSt;

static GroSt g_gro[GRO_SLOTS];

static void
gro_fls (int tap_fd, GroSt *gro)
{
  if (!gro->act)
    return;

  uint16_t l3_plen = gro->len - gro->mac_hl - gro->ip_hl;
  uint8_t *ip6 = gro->buf + gro->mac_hl;
  ip6[4] = (l3_plen >> 8) & 0xff;
  ip6[5] = l3_plen & 0xff;

  uint32_t sum = 0;
  for (int i = 0; i < 32; i += 2)
    {
      uint16_t word;
      memcpy (&word, ip6 + 8 + i, 2);
      sum += word;
    }
  sum += htons (6);
  sum += htons (l3_plen);
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  uint16_t final_sum = ~sum;
  uint8_t *tcp = ip6 + gro->ip_hl;
  memcpy (tcp + 16, &final_sum, 2);

  struct virtio_net_hdr vh = { 0 };
  vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
  vh.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
  vh.hdr_len = gro->mac_hl + gro->ip_hl + gro->tcp_hl;
  vh.gso_size = gro->mss;
  vh.csum_start = gro->mac_hl + gro->ip_hl;
  vh.csum_offset = 16;

  struct iovec iov[2] = { { &vh, sizeof (vh) }, { gro->buf, gro->len } };
  writev (tap_fd, iov, 2);
  gro->act = false;
}

void
gro_fls_all (int tap_fd)
{
  for (int i = 0; i < GRO_SLOTS; i++)
    gro_fls (tap_fd, &g_gro[i]);
}

void
gro_fed (int tap_fd, const uint8_t *vnet_frm, size_t vnet_len)
{
  if (vnet_len < VNET_HL + 14 + 40 + 20)
    goto bypass;
  const uint8_t *frm = vnet_frm + VNET_HL;
  size_t len = vnet_len - VNET_HL;

  if (frm[12] != 0x86 || frm[13] != 0xdd)
    goto bypass;
  const uint8_t *ip6 = frm + 14;
  if (ip6[6] != 6)
    goto bypass;

  const uint8_t *tcp = ip6 + 40;
  uint8_t tcp_hl = (tcp[12] >> 4) * 4;
  if (14 + 40 + (size_t)tcp_hl > len)
    goto bypass;

  size_t pl_len = len - 14 - 40 - tcp_hl;
  if (pl_len == 0)
    goto bypass;

  uint32_t seq_net;
  memcpy (&seq_net, tcp + 4, 4);
  uint32_t seq = ntohl (seq_net);

  uint16_t sp, dp;
  memcpy (&sp, tcp + 0, 2);
  memcpy (&dp, tcp + 2, 2);
  bool psh = (tcp[13] & 0x08) != 0;

  int slot_idx = (sp ^ dp ^ ip6[23]) % GRO_SLOTS;
  GroSt *gro = &g_gro[slot_idx];

  if (gro->act)
    {
      if (sp == gro->sport && dp == gro->dport
          && memcmp (ip6 + 8, gro->saddr, 16) == 0 && seq == gro->nxt_seq
          && gro->len + pl_len <= GRO_MAX_SZ)
        {
          memcpy (gro->buf + gro->len, tcp + tcp_hl, pl_len);
          gro->len += pl_len;
          gro->nxt_seq += pl_len;

          uint8_t *g_tcp = gro->buf + gro->mac_hl + gro->ip_hl;
          memcpy (g_tcp + 8, tcp + 8, 4);
          memcpy (g_tcp + 14, tcp + 14, 2);
          g_tcp[13] |= tcp[13];

          if (psh)
            gro_fls (tap_fd, gro);
          return;
        }
      gro_fls (tap_fd, gro);
    }

  memcpy (gro->buf, frm, len);
  gro->len = len;
  memcpy (gro->saddr, ip6 + 8, 16);
  gro->sport = sp;
  gro->dport = dp;
  gro->nxt_seq = seq + pl_len;
  gro->mss = pl_len;
  gro->mac_hl = 14;
  gro->ip_hl = 40;
  gro->tcp_hl = tcp_hl;
  gro->act = true;
  return;

bypass:
  gro_fls_all (tap_fd);
  if (write (tap_fd, vnet_frm, vnet_len) < 0)
    {
    }
}