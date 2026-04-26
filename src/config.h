#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PEER_CAP_INIT 64
#define TP_PREF_CAP_INIT 4U
#define BOGON_RULE_CAP_INIT 16U

typedef enum
{
  P2P_EN = 0,
  P2P_DIS
} P2pMode;

typedef enum
{
  TAP_MODE_AUTO = 0,
  TAP_MODE_INLINE,
  TAP_MODE_PIPE
} TapMode;

typedef enum
{
  TP_PROTO_NONE = 0,
  TP_PROTO_UDP = 1,
  TP_PROTO_TCP = 2,
} TpProto;

#define TP_MASK_UDP 0x01U
#define TP_MASK_TCP 0x02U

static inline uint8_t
tp_proto_mask (TpProto proto)
{
  switch (proto)
    {
    case TP_PROTO_UDP:
      return TP_MASK_UDP;
    case TP_PROTO_TCP:
      return TP_MASK_TCP;
    default:
      return 0;
    }
}

static inline bool
tp_mask_has (uint8_t mask, TpProto proto)
{
  return (mask & tp_proto_mask (proto)) != 0;
}

typedef struct
{
  uint8_t ip[16];
  uint8_t prefix_len;
  bool is_set;
} BogonRule;

typedef struct
{
  char ifname[16];
  uint8_t addr[16];
  uint16_t port;
  uint16_t mtu;
  bool mtu_probe;
  uint8_t tp_mask;
  size_t tp_pref_len;
  size_t tp_pref_cap;
  uint8_t *tp_pref;
  bool l_exp;
  size_t bogon_cnt;
  size_t bogon_cap;
  BogonRule *bogon_arr;
  P2pMode p2p;
  TapMode tap_mode;
  uint8_t psk[32];
} Cfg;

typedef struct
{
  uint8_t ip[16];
  uint16_t port;
} P;

int cfg_load (const char *path, Cfg *out);
void cfg_init (Cfg *cfg);
void cfg_free (Cfg *cfg);
int cfg_cpy (Cfg *dst, const Cfg *src);
int p_arr_load (const char *path, P **out_arr, int *out_cnt);
int str_to_v6 (const char *s, uint8_t out[16]);

static inline TpProto
cfg_tp_pick (const Cfg *cfg, uint8_t peer_mask)
{
  if (!cfg)
    return TP_PROTO_NONE;
  for (size_t i = 0; i < cfg->tp_pref_len; i++)
    {
      TpProto proto = (TpProto)cfg->tp_pref[i];
      if (tp_mask_has (cfg->tp_mask, proto) && tp_mask_has (peer_mask, proto))
        return proto;
    }
  return TP_PROTO_NONE;
}
