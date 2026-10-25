#pragma once
#include <stddef.h>
#include <stdint.h>
#define PT_DATA 0
#define PT_PING 1
#define PT_PONG 2
#define PT_GSP 3
#define PT_ADV_UPD 14
#define PT_ADV_ACK 15
#define PT_ADV_DGST 16
#define PT_ADV_REQ 17
#define PT_HP 4
#define PT_SEQ_REQ 5
#define PT_FRAG 7
#define PT_MTU_PRB 8
#define PT_MTU_ACK 9
#define PT_STAT_REQ 10
#define PT_STAT_RSP 11
#define PT_IBS_PING 12
#define PT_IBS_PONG 13
#define PT_IBS_CKIE 18
#define IBS_CKIE_SZ 32

typedef struct __attribute__ ((packed))
{
  uint8_t pkt_type;
  uint8_t rel_f;
  uint8_t hop_c;
} PktHdr;

#define PKT_TF_REL 0x80
#define PKT_TF_TYPE_MASK 0x7f
#define PKT_CH_SZ 2
#define PKT_NONCE_SZ 32
#define PKT_MAC_SZ 32
#define PKT_NONCE_CNT_SZ sizeof (uint64_t)
#define PKT_NONCE_SID_SZ (PKT_NONCE_SZ - PKT_NONCE_CNT_SZ)
#define PKT_HDR_SZ (PKT_CH_SZ + PKT_NONCE_SZ + PKT_MAC_SZ)
/* Largest UDP payload in a largest IP packet: 65535 - 20
   (IPv4 header) - 8 (UDP header); IPv6 needs less. */
#define UDP_PL_MAX (65535U - 20U - 8U)
#define PKT_PT_MAX (UDP_PL_MAX - PKT_HDR_SZ)
#define TP_VNET_MAX UINT16_MAX
#define TP_PL_MAX (PKT_HDR_SZ + TP_VNET_MAX)
#define TAP_HR 128
#define TAP_TR 64
#define PING_PL_SZ 42
#define PONG_PL_SZ 50
#define FRAG_MF_MASK 0x8000U
#define FRAG_OFF_MASK 0x7fffU
/* Fragment offsets count 8-byte units, as in IP (RFC 791):
   the 15-bit field reaches 32767 * 8 = 262136 bytes. */
#define FRAG_OFF_UNIT 8U
#define FRAG_DATA_MAX 65535U

#define ADV_PATH_MAX 32U

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
  uint8_t adv_loss;
  uint8_t nhop_lla[16];
  uint64_t ver;
  uint8_t path_len;
  uint32_t path[ADV_PATH_MAX];
} AdvEnt;

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

typedef struct __attribute__ ((packed))
{
  uint32_t req_id;
  uint64_t off;
  uint64_t total_len;
} StatHdr;

#define STAT_RSP_CHUNK_MAX (PKT_PT_MAX - sizeof (StatHdr))

static inline size_t
frag_vnet_len_max (size_t chunk_max)
{
  if (chunk_max == 0)
    return 0;
  return FRAG_DATA_MAX;
}

#define ADV_CORE_SZ 71U
#define ADV_F_SEL_DIR 0x01U
#define ADV_F_NO_DIR 0x02U
#define ADV_F_TP_UDP 0x04U
#define ADV_F_TP_TCP 0x08U
#define ADV_SZ ADV_CORE_SZ
_Static_assert (sizeof (PktHdr) == 3, "PktHdr size");
_Static_assert (sizeof (AdvEnt)
                == ADV_CORE_SZ + 1U + 4U * ADV_PATH_MAX, "AdvEnt size");
_Static_assert (sizeof (FragHdr) == 6, "FragHdr size");
_Static_assert (sizeof (ProbeHdr) == 6, "ProbeHdr size");
_Static_assert (sizeof (StatHdr) == 20, "StatHdr size");
_Static_assert (PKT_HDR_SZ == 66, "PKT_HDR_SZ");
_Static_assert (UDP_PL_MAX == 65535U - 20U - 8U, "UDP_PL_MAX");
