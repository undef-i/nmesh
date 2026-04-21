#pragma once
#include "packet.h"
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>

#define CRY_NONCE_WIRE_SZ PKT_NONCE_SZ
#define CRY_NONCE_SID_SZ (CRY_NONCE_WIRE_SZ - sizeof (uint64_t))
#define CRY_MAC_SZ PKT_MAC_SZ

typedef struct
{
  uint8_t key[32];
  uint8_t n_sid[CRY_NONCE_SID_SZ];
  _Atomic uint64_t cnt;
} Cry;

int cry_init (Cry *s, const uint8_t psk[32]);
uint64_t cry_cnt_take (Cry *s, uint64_t n);
void cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
              size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ],
              uint8_t mac[CRY_MAC_SZ], uint8_t *ct);
void cry_enc_cnt (const Cry *s, uint64_t cnt, const uint8_t *pt, size_t pt_len,
                  const uint8_t *ad, size_t ad_len,
                  uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
                  uint8_t *ct);
int cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
             size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
             const uint8_t mac[CRY_MAC_SZ], uint8_t *pt);
