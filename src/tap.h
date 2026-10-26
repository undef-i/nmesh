#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define ETH_HLEN 14

typedef enum
{
  FRAME_NS_INT = 0,
  FRAME_DAT,
  FRAME_OTH,
} FResT;

typedef struct
{
  FResT res_type;
  uint8_t na_frame[128];
  size_t na_len;
  size_t pl_start;
  size_t payload_len;
} FRes;

typedef struct
{
  bool tcp_gso;
  bool udp_gso;
  bool sndbuf_ok;
  bool txq_ok;
} TapCaps;

int tap_init (const char *name);
const TapCaps *tap_caps (void);
void tap_stl_rm (const char *name);
void tap_iface_cleanup (const char *name);
int tap_addr_set (const char *name, const uint8_t lla[16]);
int tap_mtu_set (const char *name, uint16_t mtu);
void lla_to_mac (const uint8_t lla[16], uint8_t mac[6]);
void tap_f_proc (uint8_t *frame, size_t n, const uint8_t our_lla[16], FRes *r);
