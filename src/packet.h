#pragma once
#include <stddef.h>
#include <stdint.h>
#define PT_DATA 0
#define PT_PING 1
#define PT_PONG 2
#define PT_GSP 3
#define PT_HP 4
#define PT_SEQ_REQ 5
#define PT_FRAG 7
#define PT_MTU_PRB 8
#define PT_MTU_ACK 9

typedef struct __attribute__ ((packed))
{
  uint8_t pkt_type;
  uint8_t rel_f;
  uint8_t hop_c;
} PktHdr;

#define PKT_TF_REL 0x80
#define PKT_TF_TYPE_MASK 0x7f
#define PKT_CH_SZ 2
#define PKT_NONCE_SZ 12
#define PKT_HDR_SZ (PKT_CH_SZ + PKT_NONCE_SZ + 16)
#define V6_PL_MAX 9000
#define UDP_PL_MAX (PKT_HDR_SZ + 16 + V6_PL_MAX)
#define TAP_HR 128
#define TAP_TR 64
#define PING_PL_SZ 32

typedef struct __attribute__ ((packed))
{
  uint8_t lla[16];
  uint8_t ep_ip[16];
  uint16_t ep_port;
  uint8_t flags;
  uint8_t state;
  uint16_t mtu;
  uint32_t seq;
  uint32_t adv_m;
  uint8_t nhop_lla[16];
  uint64_t ver;
} GspEnt;

typedef struct __attribute__ ((packed))
{
  uint32_t mid;
  uint16_t off_mf;
} FragHdr;

typedef struct __attribute__ ((packed))
{
  uint32_t prb_id;
  uint16_t prb_mtu;
} ProbeHdr;

#define GSP_SZ sizeof (GspEnt)
_Static_assert (sizeof (PktHdr) == 3, "PktHdr size");
_Static_assert (sizeof (GspEnt) == 70, "GspEnt size");
_Static_assert (sizeof (FragHdr) == 6, "FragHdr size");
_Static_assert (sizeof (ProbeHdr) == 6, "ProbeHdr size");
_Static_assert (PKT_HDR_SZ == 30, "PKT_HDR_SZ");
_Static_assert (UDP_PL_MAX == (PKT_HDR_SZ + 16 + V6_PL_MAX), "UDP_PL_MAX");