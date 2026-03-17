#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum
{
  P2P_EN = 0,
  P2P_DIS
} P2pMode;

typedef struct
{
  char ifname[16];
  uint8_t addr[16];
  uint16_t port;
  uint16_t mtu;
  bool l_exp;
  P2pMode p2p;
  uint8_t psk[32];
} Cfg;

typedef struct
{
  uint8_t ip[16];
  uint16_t port;
} P;

int cfg_load (const char *path, Cfg *out);
int p_arr_ld (const char *path, P *p_arr, int max_cnt);
int str_to_v6 (const char *s, uint8_t out[16]);
