#include "bogon.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const BogonRule g_default_rule_arr[] = {
  { .ip = { [10] = 0xff, [11] = 0xff }, .prefix_len = 104, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 10 }, .prefix_len = 104, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 100, [13] = 64 }, .prefix_len = 106, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 172, [13] = 16 }, .prefix_len = 108, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 192, [13] = 0, [14] = 0 }, .prefix_len = 120, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 192, [13] = 0, [14] = 2 }, .prefix_len = 120, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 192, [13] = 88, [14] = 99 }, .prefix_len = 120, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 192, [13] = 168 }, .prefix_len = 112, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 198, [13] = 18 }, .prefix_len = 111, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 198, [13] = 51, [14] = 100 }, .prefix_len = 120, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 203, [13] = 0, [14] = 113 }, .prefix_len = 120, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 127 }, .prefix_len = 104, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 169, [13] = 254 }, .prefix_len = 112, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 224 }, .prefix_len = 100, .is_set = true },
  { .ip = { [10] = 0xff, [11] = 0xff, [12] = 240 }, .prefix_len = 100, .is_set = true },
  { .ip = { 0 }, .prefix_len = 128, .is_set = true },
  { .ip = { [15] = 1 }, .prefix_len = 128, .is_set = true },
  { .ip = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, .prefix_len = 64, .is_set = true },
  { .ip = { 0x20, 0x01, 0x00, 0x02 }, .prefix_len = 48, .is_set = true },
  { .ip = { 0x20, 0x01, 0x10 }, .prefix_len = 28, .is_set = true },
  { .ip = { 0x20, 0x01, 0x0d, 0xb8 }, .prefix_len = 32, .is_set = true },
  { .ip = { 0x20, 0x02 }, .prefix_len = 16, .is_set = true },
  { .ip = { 0x20, 0x01, 0x00, 0x00, 0x0a, 0x00 }, .prefix_len = 40, .is_set = true },
  { .ip = { 0x20, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x02 }, .prefix_len = 56, .is_set = true },
  { .ip = { 0x20, 0x01, 0x00, 0x00, 0xc0, 0xa8 }, .prefix_len = 48, .is_set = true },
  { .ip = { 0xff }, .prefix_len = 8, .is_set = true },
  { .ip = { 0xfe, 0x80 }, .prefix_len = 10, .is_set = true },
  { .ip = { 0xfe, 0xc0 }, .prefix_len = 10, .is_set = true },
  { .ip = { 0xfc }, .prefix_len = 7, .is_set = true },
};

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
    {
      for (size_t i = 0;
           i < sizeof (g_default_rule_arr) / sizeof (g_default_rule_arr[0]);
           i++)
        bogon_rule_add (&g_default_rule_arr[i]);
      return;
    }
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
