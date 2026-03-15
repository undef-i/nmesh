#include "cry.h"
#include <sodium.h>
#include <string.h>

static void
nonce_full_bld (const uint8_t wire_nonce[CRY_NONCE_WIRE_SZ],
                uint8_t full_nonce[CRY_NONCE_FULL_SZ])
{
  memset (full_nonce, 0, CRY_NONCE_FULL_SZ);
  memcpy (full_nonce + (CRY_NONCE_FULL_SZ - CRY_NONCE_WIRE_SZ), wire_nonce,
          CRY_NONCE_WIRE_SZ);
}

int
cry_init (Cry *s, const uint8_t psk[32])
{
  if (sodium_init () < 0)
    return -1;
  memcpy (s->key, psk, 32);
  s->cnt = 1;
  randombytes_buf (s->n_sid, CRY_NONCE_SID_SZ);
  return 0;
}

void
cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
         size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[16],
         uint8_t *ct)
{
  uint64_t cnt = s->cnt++;
  memcpy (nonce, s->n_sid, CRY_NONCE_SID_SZ);
  nonce[4] = (uint8_t)(cnt >> 56);
  nonce[5] = (uint8_t)(cnt >> 48);
  nonce[6] = (uint8_t)(cnt >> 40);
  nonce[7] = (uint8_t)(cnt >> 32);
  nonce[8] = (uint8_t)(cnt >> 24);
  nonce[9] = (uint8_t)(cnt >> 16);
  nonce[10] = (uint8_t)(cnt >> 8);
  nonce[11] = (uint8_t)(cnt);
  crypto_aead_chacha20poly1305_ietf_encrypt_detached (
    ct, mac, NULL, pt, pt_len, ad, ad_len, NULL, nonce, s->key);
}

int
cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
         size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
         const uint8_t mac[16], uint8_t *pt)
{
  int rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached (
    pt, NULL, ct, ct_len, mac, ad, ad_len, nonce, s->key);
  return (rc == 0) ? 0 : -1;
}
