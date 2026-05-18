#pragma once
#include "packet.h"
#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#define CRY_NONCE_WIRE_SZ PKT_NONCE_SZ
#define CRY_NONCE_SID_SZ PKT_NONCE_SID_SZ
#define CRY_MAC_SZ PKT_MAC_SZ
#define CRY_KX_PUB_SZ 32
#define CRY_KX_SEC_SZ 32

typedef struct
{
  uint8_t lla[16];
  uint8_t peer_pk[CRY_KX_PUB_SZ];
  uint8_t tx_key[32];
  uint8_t rx_key[32];
  uint8_t tx_sid[CRY_NONCE_SID_SZ];
  uint8_t rx_sid[CRY_NONCE_SID_SZ];
  bool ready;
} CryPeer;

typedef struct
{
  uint8_t key[32];
  uint8_t n_sid[CRY_NONCE_SID_SZ];
  uint8_t kx_pk[CRY_KX_PUB_SZ];
  uint8_t kx_sk[CRY_KX_SEC_SZ];
  CryPeer *peer_arr;
  uint32_t peer_cnt;
  uint32_t peer_cap;
  pthread_mutex_t mtx;
  _Atomic uint64_t cnt;
} Cry;

int cry_init (Cry *s, const uint8_t psk[32]);
void cry_free (Cry *s);
uint64_t cry_cnt_take (Cry *s, uint64_t n);
const uint8_t *cry_kx_pub (Cry *s);
bool cry_peer_rekey (Cry *s, const uint8_t our_lla[16],
                     const uint8_t peer_lla[16],
                     const uint8_t peer_pk[CRY_KX_PUB_SZ]);
bool cry_peer_ready (Cry *s, const uint8_t peer_lla[16]);
void cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
              size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ],
              uint8_t mac[CRY_MAC_SZ], uint8_t *ct);
int cry_enc_to (Cry *s, const uint8_t dst_lla[16], const uint8_t *pt,
                size_t pt_len, const uint8_t *ad, size_t ad_len,
                uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
                uint8_t *ct);
void cry_enc_cnt (const Cry *s, uint64_t cnt, const uint8_t *pt, size_t pt_len,
                  const uint8_t *ad, size_t ad_len,
                  uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
                  uint8_t *ct);
int cry_enc_cnt_to (Cry *s, const uint8_t dst_lla[16], uint64_t cnt,
                    const uint8_t *pt, size_t pt_len, const uint8_t *ad,
                    size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ],
                    uint8_t mac[CRY_MAC_SZ], uint8_t *ct);
int cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
             size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
             const uint8_t mac[CRY_MAC_SZ], uint8_t *pt);
int cry_dec_from (Cry *s, const uint8_t src_lla[16], const uint8_t *ct,
                  size_t ct_len, const uint8_t *ad, size_t ad_len,
                  const uint8_t nonce[CRY_NONCE_WIRE_SZ],
                  const uint8_t mac[CRY_MAC_SZ], uint8_t *pt,
                  bool *used_psk, uint8_t matched_lla[16]);
