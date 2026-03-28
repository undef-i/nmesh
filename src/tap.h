#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define ETH_HLEN 14

typedef enum
{
  FRAME_NS_INT = 0,
  FRAME_V6_DAT,
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

int tap_init (const char *name);
bool tap_udp_gso_ok (void);
void tap_stl_rm (const char *name);
void tap_addr_set (const char *name, const uint8_t lla[16]);
void tap_mtu_set (const char *name, uint16_t mtu);
int tap_mtu_get (const char *name, uint16_t *mtu);
void lla_to_mac (const uint8_t lla[16], uint8_t mac[6]);
void tap_f_proc (uint8_t *frame, size_t n, const uint8_t our_lla[16], FRes *r);
uint8_t *eth_bld (const uint8_t src_lla[16], const uint8_t dst_lla[16],
                  const uint8_t *ipv6, size_t ipv6_len, uint8_t *buf,
                  size_t *out_len);
uint8_t *eth_bld_ip (const uint8_t src_lla[16], const uint8_t dst_lla[16],
                     uint8_t *ipv6_ptr, size_t ipv6_len, size_t *out_len);
