#include "config.h"
#include <stdarg.h>
#include <arpa/inet.h>
#include <errno.h>
#include "bogon.h"
#include "ibs.h"
#include "tap.h"
#include "utils.h"
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
  cfg->mtu = (uint16_t) (FRAG_DATA_MAX - VNET_HL - ETH_HLEN);
  cfg->mtu_probe = false;
  cfg->p2p = true;
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
  free (cfg->peer_arr);
  memset (cfg, 0, sizeof (*cfg));
}

static int
cfg_tp_rsv (Cfg *cfg, size_t need)
{
  if (!cfg)
    return -1;
  if (need <= cfg->tp_pref_cap)
    return 0;
  size_t new_cap = cfg->tp_pref_cap ? cfg->tp_pref_cap : TP_PREF_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (SIZE_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
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

static int
cfg_peer_rsv (Cfg *cfg, size_t need)
{
  if (!cfg)
    return -1;
  if (need <= cfg->peer_cap)
    return 0;
  size_t new_cap = cfg->peer_cap ? cfg->peer_cap : PEER_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (SIZE_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  P *new_arr = realloc (cfg->peer_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    return -1;
  cfg->peer_arr = new_arr;
  cfg->peer_cap = new_cap;
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
  dst->peer_arr = NULL;
  dst->peer_cap = 0;
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
  if (src->peer_cnt > 0)
    {
      if (cfg_peer_rsv (dst, src->peer_cnt) != 0)
        {
          cfg_free (dst);
          return -1;
        }
      memcpy (dst->peer_arr, src->peer_arr,
              sizeof (*dst->peer_arr) * src->peer_cnt);
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

static int
hex_dec (const char *s, uint8_t *out, size_t n)
{
  for (size_t i = 0; i < n; i++)
    {
      int hi = char_to_hex (s[i * 2]);
      int lo = char_to_hex (s[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return -1;
      out[i] = (uint8_t)((hi << 4) | lo);
    }
  return 0;
}

static int cfg_u32_prs (const char *v, unsigned long *out);

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
  return inet_pton (AF_INET6, s, out) == 1 ? 0 : -1;
}

static int
str_to_v4 (const char *s, uint8_t out[16])
{
  uint8_t v4[4];
  if (inet_pton (AF_INET, s, v4) != 1)
    return -1;
  memset (out, 0, 16);
  out[10] = 0xff;
  out[11] = 0xff;
  memcpy (out + 12, v4, 4);
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
              if (getaddrinfo (addr_buf, NULL, &hints, &res) != 0 || !res)
                return -1;
              bool ok = false;
              if (res->ai_family == AF_INET)
                {
                  struct sockaddr_in *sa4 = (struct sockaddr_in *)res->ai_addr;
                  memset (p->ip, 0, 16);
                  p->ip[10] = 0xff;
                  p->ip[11] = 0xff;
                  memcpy (p->ip + 12, &sa4->sin_addr, 4);
                  ok = true;
                }
              else if (res->ai_family == AF_INET6)
                {
                  struct sockaddr_in6 *sa6
                      = (struct sockaddr_in6 *)res->ai_addr;
                  memcpy (p->ip, &sa6->sin6_addr, 16);
                  ok = true;
                }
              freeaddrinfo (res);
              if (!ok)
                return -1;
            }
        }
    }
  unsigned long p_v = 0;
  if (cfg_u32_prs (p_str, &p_v) != 0 || p_v < 1 || p_v > 65535)
    return -1;
  p->port = (uint16_t)p_v;
  return 0;
}

static int
psk_prs (const char *s, uint8_t out[32])
{
  if (strlen (s) != 64)
    return -1;
  return hex_dec (s, out, 32);
}

static int
psk_pass_prs (const char *s, uint8_t out[32])
{
  size_t s_len = strlen (s);
  if (s_len == 0)
    return -1;
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
  char *buf = strdup (s);
  if (!buf)
    return -1;

  uint8_t mask = 0;
  uint8_t *pref = NULL;
  size_t pref_cap = 0;
  size_t pref_len = 0;
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok != NULL;
       tok = strtok_r (NULL, ",", &save))
    {
      tok = str_trm (tok);
      TpProto proto;
      if (tp_proto_prs (tok, &proto) != 0)
        {
          free (buf);
          free (pref);
          return -1;
        }
      uint8_t bit = tp_proto_mask (proto);
      if ((mask & bit) != 0)
        continue;
      if (pref_len >= pref_cap)
        {
          size_t new_cap = pref_cap ? (pref_cap * 2U) : TP_PREF_CAP_INIT;
          uint8_t *new_pref = realloc (pref, sizeof (*pref) * new_cap);
          if (!new_pref)
            {
              free (buf);
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
      free (buf);
      free (pref);
      return -1;
    }

  free (buf);
  free (cfg->tp_pref);
  cfg->tp_mask = mask;
  cfg->tp_pref_len = pref_len;
  cfg->tp_pref_cap = pref_cap;
  cfg->tp_pref = pref;
  return 0;
}

static void
cfg_ln_err (const char *path, int line_no, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  fprintf (stderr, "config: %s:%d: ", path, line_no);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fputc ('\n', stderr);
}

static int
cfg_u32_prs (const char *v, unsigned long *out)
{
  if (!v || !*v)
    return -1;
  char *end = NULL;
  errno = 0;
  unsigned long val = strtoul (v, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return -1;
  *out = val;
  return 0;
}

static const char *const cfg_scalar_keys[] = {
  "address", "port", "mtu", "p2p", "tap_mode", "mtu_probe",
  "default_phys_mtu", "transport", "ifname", "psk", "psk_passphrase",
  "auth", "ibs_mpk", "ibs_sk",
};

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
  char *line = NULL;
  size_t line_cap = 0;
  int line_no = 0;
  unsigned seen = 0;
  while (getline (&line, &line_cap, fp) >= 0)
    {
      line_no++;
      char *l_trm = str_trm (line);
      if (!l_trm[0] || l_trm[0] == '#')
        continue;
      char *sep = strchr (l_trm, '=');
      if (!sep)
        {
          cfg_ln_err (path, line_no, "expected key = value");
          cfg_free (cfg);
          free (line);
          fclose (fp);
          return -1;
        }
      *sep = '\0';
      char *k = str_trm (l_trm);
      char *v = str_trm (sep + 1);
      for (size_t si = 0;
           si < sizeof (cfg_scalar_keys) / sizeof (cfg_scalar_keys[0]);
           si++)
        {
          if (strcmp (k, cfg_scalar_keys[si]) != 0)
            continue;
          if (seen & (1U << si))
            {
              cfg_ln_err (path, line_no, "duplicate key: %s", k);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          seen |= (1U << si);
          break;
        }
      if (strcmp (k, "address") == 0)
        {
          if (str_to_v6 (v, cfg->addr) != 0)
            {
              cfg_ln_err (path, line_no, "invalid address: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "port") == 0)
        {
          unsigned long p_v = 0;
          if (cfg_u32_prs (v, &p_v) != 0 || p_v < 1 || p_v > 65535)
            {
              cfg_ln_err (path, line_no, "invalid port: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->port = (uint16_t)p_v;
          cfg->l_exp = true;
        }
      else if (strcmp (k, "mtu") == 0)
        {
          unsigned long m_v = 0;
          if (cfg_u32_prs (v, &m_v) != 0 || m_v < CFG_MTU_MIN
              || m_v > CFG_MTU_MAX)
            {
              cfg_ln_err (path, line_no, "invalid mtu: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->mtu = (uint16_t)m_v;
        }
      else if (strcmp (k, "p2p") == 0)
        {
          bool en = false;
          if (bool_prs (v, &en) != 0)
            {
              cfg_ln_err (path, line_no, "invalid p2p value: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->p2p = en;
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
              cfg_ln_err (path, line_no, "invalid tap_mode: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "mtu_probe") == 0)
        {
          if (bool_prs (v, &cfg->mtu_probe) != 0)
            {
              cfg_ln_err (path, line_no, "invalid mtu_probe value: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "default_phys_mtu") == 0)
        {
          unsigned long d_v = 0;
          if (cfg_u32_prs (v, &d_v) != 0 || d_v < CFG_MTU_MIN
              || d_v > CFG_MTU_MAX)
            {
              cfg_ln_err (path, line_no, "invalid default_phys_mtu: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->default_phys_mtu = (uint16_t)d_v;
        }
      else if (strcmp (k, "transport") == 0)
        {
          if (tp_cfg_prs (v, cfg) != 0)
            {
              cfg_ln_err (path, line_no, "invalid transport: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "bogon") == 0)
        {
          if (cfg_bogon_rsv (cfg, cfg->bogon_cnt + 1U) != 0)
            {
              cfg_ln_err (path, line_no,
                          "out of memory while expanding bogon rules");
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          if (!bogon_rule_parse (v, &cfg->bogon_arr[cfg->bogon_cnt]))
            {
              cfg_ln_err (path, line_no, "invalid bogon rule: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->bogon_cnt++;
        }
      else if (strcmp (k, "ifname") == 0)
        {
          if (!v[0] || strlen (v) >= sizeof (cfg->ifname))
            {
              cfg_ln_err (path, line_no, "invalid ifname: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          strcpy (cfg->ifname, v);
        }
      else if (strcmp (k, "psk") == 0)
        {
          if (psk_prs (v, cfg->psk) != 0)
            {
              cfg_ln_err (path, line_no,
                          "invalid psk value (want 64 hex characters)");
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "psk_passphrase") == 0)
        {
          if (psk_pass_prs (v, cfg->psk) != 0)
            {
              cfg_ln_err (path, line_no, "invalid psk_passphrase value");
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "auth") == 0)
        {
          if (strcmp (v, "ibs") == 0)
            cfg->auth_ibs = true;
          else if (strcmp (v, "psk") == 0)
            cfg->auth_ibs = false;
          else
            {
              cfg_ln_err (path, line_no, "invalid auth mode: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
        }
      else if (strcmp (k, "ibs_mpk") == 0)
        {
          if (strlen (v) != IBS_MPK_SZ * 2
              || hex_dec (v, cfg->ibs_mpk, IBS_MPK_SZ) != 0)
            {
              cfg_ln_err (path, line_no, "invalid ibs_mpk value");
              cfg_free (cfg); free (line); fclose (fp); return -1;
            }
        }
      else if (strcmp (k, "ibs_sk") == 0)
        {
          if (strlen (v) != IBS_SK_SZ * 2
              || hex_dec (v, cfg->ibs_sk, IBS_SK_SZ) != 0)
            {
              cfg_ln_err (path, line_no, "invalid ibs_sk value");
              cfg_free (cfg); free (line); fclose (fp); return -1;
            }
        }
      else if (strcmp (k, "peer") == 0)
        {
          P p;
          if (str_to_p (v, &p) != 0)
            {
              cfg_ln_err (path, line_no, "invalid peer entry: %s", v);
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          if (cfg_peer_rsv (cfg, cfg->peer_cnt + 1U) != 0)
            {
              cfg_ln_err (path, line_no,
                          "out of memory while expanding peer list");
              cfg_free (cfg);
              free (line);
              fclose (fp);
              return -1;
            }
          cfg->peer_arr[cfg->peer_cnt++] = p;
        }
      else
        {
          cfg_ln_err (path, line_no, "unknown key: %s", k);
          cfg_free (cfg);
          free (line);
          fclose (fp);
          return -1;
        }
    }
  free (line);
  fclose (fp);
  uint8_t z16[16] = { 0 };
  if (memcmp (cfg->addr, z16, 16) == 0)
    {
      fprintf (stderr, "config: %s: address is required\n", path);
      cfg_free (cfg);
      return -1;
    }
  if (cfg->addr[0] != 0xfe || (cfg->addr[1] & 0xc0) != 0x80)
    {
      fprintf (stderr,
               "config: %s: address must be link-local (fe80::/10)\n",
               path);
      cfg_free (cfg);
      return -1;
    }
  uint8_t z32[32] = { 0 };
  if (cfg->auth_ibs)
    {
      uint8_t z_mpk[IBS_MPK_SZ] = { 0 };
      uint8_t z_sk[IBS_SK_SZ] = { 0 };
      if (memcmp (cfg->ibs_mpk, z_mpk, IBS_MPK_SZ) == 0
          || memcmp (cfg->ibs_sk, z_sk, IBS_SK_SZ) == 0)
        {
          fprintf (stderr,
                   "config: %s: auth = ibs requires ibs_mpk and ibs_sk\n",
                   path);
          cfg_free (cfg);
          return -1;
        }
    }
  else if (memcmp (cfg->psk, z32, 32) == 0)
    {
      fprintf (stderr, "config: %s: psk is required\n", path);
      cfg_free (cfg);
      return -1;
    }
  return 0;
}
