#include "crypto.h"
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

enum
{
  CRY_ALG_CHACHA20P1305 = 0,
  CRY_ALG_AES256GCM = 1,
};

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
  int has_aesni = sodium_runtime_has_aesni ();
  int has_pclmul = sodium_runtime_has_pclmul ();
  int has_avx = sodium_runtime_has_avx ();
  int aes_gcm_ok = crypto_aead_aes256gcm_is_available ();
  s->alg = aes_gcm_ok ? CRY_ALG_AES256GCM : CRY_ALG_CHACHA20P1305;
  memcpy (s->key, psk, 32);
  atomic_store_explicit (&s->cnt, 1, memory_order_relaxed);
  randombytes_buf (s->n_sid, CRY_NONCE_SID_SZ);
  fprintf (stderr, "crypto: aead=%s aesni=%d pclmul=%d avx=%d aes256gcm=%d\n",
           s->alg == CRY_ALG_AES256GCM ? "aes256gcm" : "chacha20poly1305",
           has_aesni, has_pclmul, has_avx, aes_gcm_ok);
  return 0;
}

uint64_t
cry_cnt_take (Cry *s, uint64_t n)
{
  return atomic_fetch_add_explicit (&s->cnt, n, memory_order_relaxed);
}

void
cry_enc_cnt (const Cry *s, uint64_t cnt, const uint8_t *pt, size_t pt_len,
             const uint8_t *ad, size_t ad_len,
             uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[16], uint8_t *ct)
{
  memcpy (nonce, s->n_sid, CRY_NONCE_SID_SZ);
  nonce[4] = (uint8_t)(cnt >> 56);
  nonce[5] = (uint8_t)(cnt >> 48);
  nonce[6] = (uint8_t)(cnt >> 40);
  nonce[7] = (uint8_t)(cnt >> 32);
  nonce[8] = (uint8_t)(cnt >> 24);
  nonce[9] = (uint8_t)(cnt >> 16);
  nonce[10] = (uint8_t)(cnt >> 8);
  nonce[11] = (uint8_t)(cnt);
  if (s->alg == CRY_ALG_AES256GCM)
    {
      crypto_aead_aes256gcm_encrypt_detached (ct, mac, NULL, pt, pt_len, ad,
                                              ad_len, NULL, nonce, s->key);
      return;
    }
  crypto_aead_chacha20poly1305_ietf_encrypt_detached (
      ct, mac, NULL, pt, pt_len, ad, ad_len, NULL, nonce, s->key);
}

void
cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
         size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[16],
         uint8_t *ct)
{
  cry_enc_cnt (s, cry_cnt_take (s, 1), pt, pt_len, ad, ad_len, nonce, mac,
               ct);
}

int
cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
         size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
         const uint8_t mac[16], uint8_t *pt)
{
  int rc;
  if (s->alg == CRY_ALG_AES256GCM)
    {
      rc = crypto_aead_aes256gcm_decrypt_detached (pt, NULL, ct, ct_len, mac,
                                                   ad, ad_len, nonce, s->key);
    }
  else
    {
      rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached (
          pt, NULL, ct, ct_len, mac, ad, ad_len, nonce, s->key);
    }
  return (rc == 0) ? 0 : -1;
}
