#include "config.h"
#include "bogon.h"
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <limits.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void
cfg_init (Cfg *cfg)
{
  if (!cfg)
    return;
  memset (cfg, 0, sizeof (*cfg));
  cfg->port = 50000;
  cfg->mtu = 1280;
  cfg->mtu_probe = false;
  cfg->p2p = P2P_EN;
  cfg->tap_mode = TAP_MODE_AUTO;
  strcpy (cfg->ifname, "nmesh");
}

void
cfg_free (Cfg *cfg)
{
  if (!cfg)
    return;
  free (cfg->tp_pref);
  free (cfg->bogon_arr);
  memset (cfg, 0, sizeof (*cfg));
}

static int
cfg_tp_rsv (Cfg *cfg, uint8_t need)
{
  if (!cfg)
    return -1;
  if (need <= cfg->tp_pref_cap)
    return 0;
  uint8_t new_cap = cfg->tp_pref_cap ? cfg->tp_pref_cap : TP_PREF_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (uint8_t)(UINT8_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap = (uint8_t)(new_cap * 2U);
    }
  uint8_t *new_arr = realloc (cfg->tp_pref, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    return -1;
  cfg->tp_pref = new_arr;
  cfg->tp_pref_cap = new_cap;
  return 0;
}

static int
cfg_bogon_rsv (Cfg *cfg, size_t need)
{
  if (!cfg)
    return -1;
  if (need <= cfg->bogon_cap)
    return 0;
  size_t new_cap = cfg->bogon_cap ? cfg->bogon_cap : BOGON_RULE_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (SIZE_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  BogonRule *new_arr = realloc (cfg->bogon_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    return -1;
  cfg->bogon_arr = new_arr;
  cfg->bogon_cap = new_cap;
  return 0;
}

int
cfg_cpy (Cfg *dst, const Cfg *src)
{
  if (!dst || !src)
    return -1;
  cfg_init (dst);
  *dst = *src;
  dst->tp_pref = NULL;
  dst->tp_pref_cap = 0;
  dst->bogon_arr = NULL;
  dst->bogon_cap = 0;
  if (src->tp_pref_len > 0)
    {
      if (cfg_tp_rsv (dst, src->tp_pref_len) != 0)
        {
          cfg_free (dst);
          return -1;
        }
      memcpy (dst->tp_pref, src->tp_pref, src->tp_pref_len);
    }
  if (src->bogon_cnt > 0)
    {
      if (cfg_bogon_rsv (dst, src->bogon_cnt) != 0)
        {
          cfg_free (dst);
          return -1;
        }
      memcpy (dst->bogon_arr, src->bogon_arr,
              sizeof (*dst->bogon_arr) * src->bogon_cnt);
    }
  return 0;
}

static char *
str_trm (char *s)
{
  while (*s && isspace ((unsigned char)*s))
    s++;
  char *end_ptr = s + strlen (s);
  while (end_ptr > s && isspace ((unsigned char)*(end_ptr - 1)))
    end_ptr--;
  *end_ptr = '\0';
  return s;
}

static int
char_to_hex (char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

int
str_to_v6 (const char *s, uint8_t out[16])
{
  char buf[128];
  if (s[0] == '[')
    {
      const char *r_bkt = strchr (s, ']');
      if (!r_bkt)
        return -1;
      size_t t_len = (size_t)(r_bkt - s - 1);
      if (t_len >= sizeof (buf))
        return -1;
      memcpy (buf, s + 1, t_len);
      buf[t_len] = '\0';
      s = buf;
    }
  memset (out, 0, 16);
  if (strcmp (s, "::1") == 0)
    {
      out[15] = 1;
      return 0;
    }
  if (strcmp (s, "::") == 0)
    return 0;
  const char *dbl_col = strstr (s, "::");
  const char *l_str = s;
  const char *r_s = NULL;
  char l_buf[64] = { 0 };
  char r_b[64] = { 0 };
  if (dbl_col)
    {
      size_t l_len = (size_t)(dbl_col - s);
      size_t r_len = strlen (dbl_col + 2);
      if (l_len >= sizeof (l_buf) || r_len >= sizeof (r_b))
        return -1;
      memcpy (l_buf, l_str, l_len);
      memcpy (r_b, dbl_col + 2, r_len);
      l_str = l_buf;
      r_s = r_b;
    }
  uint16_t l_grp[8] = { 0 };
  int l_cnt = 0;
  uint16_t r_grp[8] = { 0 };
  int r_cnt = 0;
  if (l_str && l_str[0])
    {
      char tmp[64];
      strncpy (tmp, l_str, sizeof (tmp) - 1);
      tmp[sizeof (tmp) - 1] = '\0';
      char *seg = strtok (tmp, ":");
      while (seg)
        {
          if (l_cnt >= 8)
            return -1;
          l_grp[l_cnt++] = (uint16_t)strtoul (seg, NULL, 16);
          seg = strtok (NULL, ":");
        }
    }
  if (r_s && r_s[0])
    {
      char tmp[64];
      strncpy (tmp, r_s, sizeof (tmp) - 1);
      tmp[sizeof (tmp) - 1] = '\0';
      char *seg = strtok (tmp, ":");
      while (seg)
        {
          if (r_cnt >= 8)
            return -1;
          r_grp[r_cnt++] = (uint16_t)strtoul (seg, NULL, 16);
          seg = strtok (NULL, ":");
        }
    }
  if (!dbl_col && l_cnt != 8)
    return -1;
  uint16_t grp_arr[8] = { 0 };
  for (int g_idx = 0; g_idx < l_cnt; g_idx++)
    grp_arr[g_idx] = l_grp[g_idx];
  int gap = 8 - l_cnt - r_cnt;
  for (int g_idx = 0; g_idx < r_cnt; g_idx++)
    grp_arr[l_cnt + gap + g_idx] = r_grp[g_idx];
  for (int g_idx = 0; g_idx < 8; g_idx++)
    {
      out[g_idx * 2] = (uint8_t)(grp_arr[g_idx] >> 8);
      out[g_idx * 2 + 1] = (uint8_t)(grp_arr[g_idx] & 0xff);
    }
  return 0;
}

static int
str_to_v4 (const char *s, uint8_t out[16])
{
  memset (out, 0, 16);
  out[10] = 0xff;
  out[11] = 0xff;
  unsigned int o1, o2, o3, o4;
  if (sscanf (s, "%u.%u.%u.%u", &o1, &o2, &o3, &o4) != 4)
    return -1;
  if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255)
    return -1;
  out[12] = (uint8_t)o1;
  out[13] = (uint8_t)o2;
  out[14] = (uint8_t)o3;
  out[15] = (uint8_t)o4;
  return 0;
}

static int
str_to_p (const char *s, P *p)
{
  memset (p, 0, sizeof (*p));
  const char *p_str;
  if (s[0] == '[')
    {
      const char *r_bkt = strchr (s, ']');
      if (!r_bkt)
        return -1;
      const char *sep = strchr (r_bkt, ':');
      if (!sep)
        return -1;
      p_str = sep + 1;
      char addr_buf[64];
      size_t addr_len = (size_t)(r_bkt - s - 1);
      if (addr_len >= sizeof (addr_buf))
        return -1;
      memcpy (addr_buf, s + 1, addr_len);
      addr_buf[addr_len] = '\0';
      if (str_to_v6 (addr_buf, p->ip) != 0)
        return -1;
    }
  else
    {
      const char *last_sep = strrchr (s, ':');
      if (!last_sep)
        return -1;
      p_str = last_sep + 1;
      char addr_buf[64];
      size_t addr_len = (size_t)(last_sep - s);
      if (addr_len >= sizeof (addr_buf))
        return -1;
      memcpy (addr_buf, s, addr_len);
      addr_buf[addr_len] = '\0';
      if (strchr (addr_buf, ':'))
        {
          if (str_to_v6 (addr_buf, p->ip) != 0)
            return -1;
        }
      else
        {
          if (str_to_v4 (addr_buf, p->ip) != 0)
            {
              struct addrinfo hints;
              memset (&hints, 0, sizeof (hints));
              hints.ai_family = AF_UNSPEC;
              hints.ai_socktype = SOCK_DGRAM;
              struct addrinfo *res = NULL;
              if (getaddrinfo (addr_buf, NULL, &hints, &res) != 0)
                return -1;
              bool ok = false;
              for (struct addrinfo *it = res; it != NULL; it = it->ai_next)
                {
                  if (it->ai_family == AF_INET)
                    {
                      struct sockaddr_in *sa4
                          = (struct sockaddr_in *)it->ai_addr;
                      memset (p->ip, 0, 16);
                      p->ip[10] = 0xff;
                      p->ip[11] = 0xff;
                      memcpy (p->ip + 12, &sa4->sin_addr, 4);
                      ok = true;
                      break;
                    }
                  if (it->ai_family == AF_INET6)
                    {
                      struct sockaddr_in6 *sa6
                          = (struct sockaddr_in6 *)it->ai_addr;
                      memcpy (p->ip, &sa6->sin6_addr, 16);
                      ok = true;
                      break;
                    }
                }
              freeaddrinfo (res);
              if (!ok)
                return -1;
            }
        }
    }
  unsigned long p_v = strtoul (p_str, NULL, 10);
  if (p_v == 0 || p_v > 65535)
    return -1;
  p->port = (uint16_t)p_v;
  return 0;
}

static int
psk_prs (const char *s, uint8_t out[32])
{
  size_t s_len = strlen (s);
  if (s_len == 0)
    return -1;
  if (s_len == 64)
    {
      for (int idx = 0; idx < 32; idx++)
        {
          int h_nib = char_to_hex (s[idx * 2]);
          int l_nib = char_to_hex (s[idx * 2 + 1]);
          if (h_nib < 0 || l_nib < 0)
            return -1;
          out[idx] = (uint8_t)(h_nib * 16 + l_nib);
        }
      return 0;
    }
  return crypto_generichash (out, 32, (const uint8_t *)s, s_len, NULL, 0);
}

static int
bool_prs (const char *s, bool *out)
{
  if (!s || !out)
    return -1;
  if (strcmp (s, "enable") == 0)
    {
      *out = true;
      return 0;
    }
  if (strcmp (s, "disable") == 0)
    {
      *out = false;
      return 0;
    }
  return -1;
}

static int
tp_defaults_set (Cfg *cfg)
{
  if (!cfg)
    return -1;
  cfg->tp_mask = TP_MASK_UDP | TP_MASK_TCP;
  cfg->tp_pref_len = 2;
  if (cfg_tp_rsv (cfg, cfg->tp_pref_len) != 0)
    return -1;
  cfg->tp_pref[0] = TP_PROTO_UDP;
  cfg->tp_pref[1] = TP_PROTO_TCP;
  return 0;
}

static int
tp_proto_prs (const char *s, TpProto *out)
{
  if (!s || !out)
    return -1;
  if (strcmp (s, "udp") == 0)
    {
      *out = TP_PROTO_UDP;
      return 0;
    }
  if (strcmp (s, "tcp") == 0)
    {
      *out = TP_PROTO_TCP;
      return 0;
    }
  return -1;
}

static int
tp_cfg_prs (const char *s, Cfg *cfg)
{
  if (!s || !cfg)
    return -1;
  char buf[128];
  if (strlen (s) >= sizeof (buf))
    return -1;
  snprintf (buf, sizeof (buf), "%s", s);

  uint8_t mask = 0;
  uint8_t *pref = NULL;
  uint8_t pref_cap = 0;
  uint8_t pref_len = 0;
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok != NULL;
       tok = strtok_r (NULL, ",", &save))
    {
      tok = str_trm (tok);
      TpProto proto;
      if (tp_proto_prs (tok, &proto) != 0)
        return -1;
      uint8_t bit = tp_proto_mask (proto);
      if ((mask & bit) != 0)
        continue;
      if (pref_len >= pref_cap)
        {
          uint8_t new_cap = pref_cap ? (uint8_t)(pref_cap * 2U)
                                     : TP_PREF_CAP_INIT;
          uint8_t *new_pref = realloc (pref, sizeof (*pref) * new_cap);
          if (!new_pref)
            {
              free (pref);
              return -1;
            }
          pref = new_pref;
          pref_cap = new_cap;
        }
      mask |= bit;
      pref[pref_len++] = (uint8_t)proto;
    }
  if (mask == 0 || pref_len == 0)
    {
      free (pref);
      return -1;
    }

  free (cfg->tp_pref);
  cfg->tp_mask = mask;
  cfg->tp_pref_len = pref_len;
  cfg->tp_pref_cap = pref_cap;
  cfg->tp_pref = pref;
  return 0;
}

int
cfg_load (const char *path, Cfg *cfg)
{
  cfg_init (cfg);
  if (tp_defaults_set (cfg) != 0)
    {
      cfg_free (cfg);
      return -1;
    }
  FILE *fp = fopen (path, "r");
  if (!fp)
    {
      cfg_free (cfg);
      return -1;
    }
  char line[512];
  while (fgets (line, sizeof (line), fp))
    {
      char *l_trm = str_trm (line);
      if (!l_trm[0] || l_trm[0] == '#')
        continue;
      char *sep = strchr (l_trm, '=');
      if (!sep)
        continue;
      *sep = '\0';
      char *k = str_trm (l_trm);
      char *v = str_trm (sep + 1);
      if (strcmp (k, "address") == 0)
        {
          if (str_to_v6 (v, cfg->addr) != 0)
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "port") == 0)
        {
          cfg->port = (uint16_t)strtoul (v, NULL, 10);
          cfg->l_exp = true;
        }
      else if (strcmp (k, "mtu") == 0)
        {
          unsigned long m_v = strtoul (v, NULL, 10);
          if (m_v < 128UL || m_v > 65535UL)
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
          cfg->mtu = (uint16_t)m_v;
        }
      else if (strcmp (k, "p2p") == 0)
        {
          cfg->p2p = (strcmp (v, "enable") == 0) ? P2P_EN : P2P_DIS;
        }
      else if (strcmp (k, "tap_mode") == 0)
        {
          if (strcmp (v, "auto") == 0)
            cfg->tap_mode = TAP_MODE_AUTO;
          else if (strcmp (v, "inline") == 0)
            cfg->tap_mode = TAP_MODE_INLINE;
          else if (strcmp (v, "pipe") == 0)
            cfg->tap_mode = TAP_MODE_PIPE;
          else
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "mtu_probe") == 0)
        {
          if (bool_prs (v, &cfg->mtu_probe) != 0)
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "transport") == 0)
        {
          if (tp_cfg_prs (v, cfg) != 0)
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "bogon") == 0)
        {
          if (cfg_bogon_rsv (cfg, cfg->bogon_cnt + 1U) != 0)
            {
              fprintf (stderr,
                       "config: out of memory while expanding bogon rules\n");
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
          if (!bogon_rule_parse (v, &cfg->bogon_arr[cfg->bogon_cnt]))
            {
              fprintf (stderr, "config: invalid bogon rule: %s\n", v);
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
          cfg->bogon_cnt++;
        }
      else if (strcmp (k, "ifname") == 0)
        {
          strncpy (cfg->ifname, v, sizeof (cfg->ifname) - 1);
          cfg->ifname[sizeof (cfg->ifname) - 1] = '\0';
        }
      else if (strcmp (k, "psk") == 0)
        {
          if (psk_prs (v, cfg->psk) != 0)
            {
              cfg_free (cfg);
              fclose (fp);
              return -1;
            }
        }
    }
  fclose (fp);
  uint8_t z16[16] = { 0 };
  if (memcmp (cfg->addr, z16, 16) == 0)
    {
      cfg_free (cfg);
      return -1;
    }
  uint8_t z32[32] = { 0 };
  if (memcmp (cfg->psk, z32, 32) == 0)
    {
      cfg_free (cfg);
      return -1;
    }
  return 0;
}

int
p_arr_ld (const char *path, P *p_arr, int max_cnt)
{
  P *tmp = NULL;
  int cnt = 0;
  if (p_arr_load (path, &tmp, &cnt) != 0)
    return 0;
  if (cnt > max_cnt)
    cnt = max_cnt;
  for (int i = 0; i < cnt; i++)
    p_arr[i] = tmp[i];
  free (tmp);
  return cnt;
}

int
p_arr_load (const char *path, P **out_arr, int *out_cnt)
{
  if (out_arr)
    *out_arr = NULL;
  if (out_cnt)
    *out_cnt = 0;
  FILE *fp = fopen (path, "r");
  if (!fp)
    return 0;
  P *arr = NULL;
  int p_cnt = 0;
  int p_cap = 0;
  char line[512];
  while (fgets (line, sizeof (line), fp))
    {
      char *l_trm = str_trm (line);
      if (!l_trm[0] || l_trm[0] == '#')
        continue;
      char *sep = strchr (l_trm, '=');
      if (!sep)
        continue;
      *sep = '\0';
      char *k = str_trm (l_trm);
      char *v = str_trm (sep + 1);
      if (strcmp (k, "peer") != 0)
        continue;
      P p;
      if (str_to_p (v, &p) == 0)
        {
          if (p_cnt >= p_cap)
            {
              int new_cap = (p_cap > 0) ? (p_cap * 2) : PEER_CAP_INIT;
              P *new_arr = realloc (arr, sizeof (*arr) * (size_t)new_cap);
              if (!new_arr)
                {
                  fprintf (stderr,
                           "config: out of memory while expanding peer list\n");
                  free (arr);
                  fclose (fp);
                  return -1;
                }
              arr = new_arr;
              p_cap = new_cap;
            }
          arr[p_cnt++] = p;
        }
      else
        {
          fprintf (stderr, "config: invalid peer entry ignored: %s\n", v);
        }
    }
  fclose (fp);
  if (out_arr)
    *out_arr = arr;
  else
    free (arr);
  if (out_cnt)
    *out_cnt = p_cnt;
  return 0;
}
