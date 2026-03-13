#include "mss.h"
#include <stdbool.h>

static uint16_t
u16_rd (const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void
u16_wr (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xff);
}

static uint16_t
csum_upd_16 (uint16_t o_chk, uint16_t old_word, uint16_t n_word)
{
  uint32_t sum = (uint32_t)(~o_chk & 0xffffU);
  sum += (uint32_t)(~old_word & 0xffffU);
  sum += (uint32_t)n_word;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t)(~sum & 0xffffU);
}

static bool
ip6_tcp_off_get (const uint8_t *pkt, size_t len, size_t *ip_hl)
{
  if (!pkt || !ip_hl)
    return false;
  if (len < 40)
    return false;
  uint8_t nh = pkt[6];
  size_t off = 40;
  while (off < len)
    {
      if (nh == 6)
        {
          *ip_hl = off;
          return true;
        }
      if (nh == 0 || nh == 43 || nh == 60)
        {
          if (off + 2 > len)
            return false;
          uint8_t n_nh = pkt[off];
          uint8_t ext_len = pkt[off + 1];
          size_t step = 8U + ((size_t)ext_len * 8U);
          if (step == 0 || off + step > len)
            return false;
          nh = n_nh;
          off += step;
          continue;
        }
      if (nh == 44)
        {
          if (off + 8 > len)
            return false;
          nh = pkt[off];
          off += 8;
          continue;
        }
      return false;
    }
  return false;
}

void
mss_clp (uint8_t *l3_pkt, size_t len, uint16_t max_l3_pl)
{
  if (!l3_pkt || len < 20)
    return;
  if (max_l3_pl == 0)
    return;
  uint8_t ver = (uint8_t)((l3_pkt[0] >> 4) & 0x0f);
  size_t ip_hl = 0;
  if (ver == 4)
    {
      if (len < 20)
        return;
      uint8_t ihl = (uint8_t)((l3_pkt[0] & 0x0f) * 4);
      if (ihl < 20 || ihl > len)
        return;
      if (l3_pkt[9] != 6)
        return;
      ip_hl = ihl;
    }
  else if (ver == 6)
    {
      if (!ip6_tcp_off_get (l3_pkt, len, &ip_hl))
        return;
    }
  else
    {
      return;
    }
  if (len < ip_hl + 20)
    return;
  uint8_t *tcp = l3_pkt + ip_hl;
  size_t tcp_len = len - ip_hl;
  if ((tcp[13] & 0x02U) == 0)
    return;
  uint8_t data_off = (uint8_t)((tcp[12] >> 4) * 4);
  if (data_off < 20 || data_off > tcp_len)
    return;
  uint16_t in_hl = (ver == 6) ? 60U : 40U;
  if (max_l3_pl <= in_hl)
    return;
  uint16_t t_mss = (uint16_t)(max_l3_pl - in_hl);
  if (t_mss < 88U)
    return;
  size_t opt_off = 20;
  while (opt_off < data_off)
    {
      uint8_t kind = tcp[opt_off];
      if (kind == 0)
        break;
      if (kind == 1)
        {
          opt_off++;
          continue;
        }
      if (opt_off + 1 >= data_off)
        break;
      uint8_t olen = tcp[opt_off + 1];
      if (olen < 2 || opt_off + olen > data_off)
        break;
      if (kind == 2 && olen == 4)
        {
          uint16_t o_mss = u16_rd (tcp + opt_off + 2);
          if (o_mss > t_mss)
            {
              uint16_t o_chk = u16_rd (tcp + 16);
              uint16_t n_chk = csum_upd_16 (o_chk, o_mss, t_mss);
              u16_wr (tcp + opt_off + 2, t_mss);
              u16_wr (tcp + 16, n_chk);
            }
          return;
        }
      opt_off += olen;
    }
}
