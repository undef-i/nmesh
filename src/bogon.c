#include "bogon.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BogonRule *g_rule_arr = NULL;
static size_t g_rule_cnt = 0;
static size_t g_rule_cap = 0;

static bool
prefix_match (const uint8_t a[16], const uint8_t b[16], uint8_t prefix_len)
{
  if (prefix_len > 128)
    return false;
  size_t full_len = (size_t)(prefix_len / 8U);
  uint8_t rem_len = (uint8_t)(prefix_len % 8U);
  if (full_len > 0 && memcmp (a, b, full_len) != 0)
    return false;
  if (rem_len == 0)
    return true;
  uint8_t mask = (uint8_t)(0xffU << (8U - rem_len));
  return (a[full_len] & mask) == (b[full_len] & mask);
}

static bool
bogon_rule_add (const BogonRule *rule)
{
  if (!rule || !rule->is_set || rule->prefix_len > 128)
    return false;
  for (size_t i = 0; i < g_rule_cnt; i++)
    {
      if (!g_rule_arr[i].is_set)
        continue;
      if (g_rule_arr[i].prefix_len != rule->prefix_len)
        continue;
      if (memcmp (g_rule_arr[i].ip, rule->ip, 16) != 0)
        continue;
      return true;
    }
  if (g_rule_cnt >= g_rule_cap)
    {
      size_t new_cap = g_rule_cap ? (g_rule_cap * 2U) : BOGON_RULE_CAP_INIT;
      BogonRule *new_arr = realloc (g_rule_arr, sizeof (*new_arr) * new_cap);
      if (!new_arr)
        return false;
      g_rule_arr = new_arr;
      g_rule_cap = new_cap;
    }
  g_rule_arr[g_rule_cnt++] = *rule;
  return true;
}

bool
bogon_rule_parse (const char *s, BogonRule *out)
{
  if (!s || !out)
    return false;
  char buf[128];
  snprintf (buf, sizeof (buf), "%s", s);
  char *slash = strchr (buf, '/');
  memset (out, 0, sizeof (*out));
  if (strchr (buf, ':'))
    {
      struct in6_addr sa6;
      unsigned long prefix_len = 128;
      if (slash)
        {
          *slash = '\0';
          char *end = NULL;
          prefix_len = strtoul (slash + 1, &end, 10);
          if (!end || *end != '\0')
            return false;
        }
      if (prefix_len > 128 || inet_pton (AF_INET6, buf, &sa6) != 1)
        return false;
      memcpy (out->ip, &sa6, 16);
      out->prefix_len = (uint8_t)prefix_len;
    }
  else
    {
      struct in_addr sa4;
      unsigned long prefix_len = 32;
      if (slash)
        {
          *slash = '\0';
          char *end = NULL;
          prefix_len = strtoul (slash + 1, &end, 10);
          if (!end || *end != '\0')
            return false;
        }
      if (prefix_len > 32 || inet_pton (AF_INET, buf, &sa4) != 1)
        return false;
      out->ip[10] = 0xff;
      out->ip[11] = 0xff;
      memcpy (out->ip + 12, &sa4, 4);
      out->prefix_len = (uint8_t)(96U + prefix_len);
    }
  out->is_set = true;
  return true;
}

void
bogon_cfg_apply (const Cfg *cfg)
{
  g_rule_cnt = 0;
  if (!cfg || cfg->bogon_cnt == 0)
    return;
  for (size_t i = 0; i < cfg->bogon_cnt; i++)
    {
      if (cfg->bogon_arr[i].is_set)
        bogon_rule_add (&cfg->bogon_arr[i]);
    }
}

bool
bogon_ip_match (const uint8_t ip[16])
{
  if (!ip)
    return true;
  for (size_t i = 0; i < g_rule_cnt; i++)
    {
      if (g_rule_arr[i].is_set
          && prefix_match (ip, g_rule_arr[i].ip, g_rule_arr[i].prefix_len))
        return true;
    }
  return false;
}
