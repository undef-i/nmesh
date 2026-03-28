#pragma once
#include <stddef.h>
#include <stdint.h>

#define CRY_NONCE_WIRE_SZ 12
#define CRY_NONCE_FULL_SZ 24
#define CRY_NONCE_SID_SZ 4

typedef struct
{
  uint8_t alg;
  uint8_t key[32];
  uint8_t n_sid[CRY_NONCE_SID_SZ];
  uint64_t cnt;
} Cry;

int cry_init (Cry *s, const uint8_t psk[32]);
void cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
              size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[16],
              uint8_t *ct);
int cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
             size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
             const uint8_t mac[16], uint8_t *pt);
