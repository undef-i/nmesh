#include "crypto.h"
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

int
cry_init (Cry *s, const uint8_t psk[32])
{
  if (sodium_init () < 0)
    return -1;
  int has_aesni = sodium_runtime_has_aesni ();
  int has_pclmul = sodium_runtime_has_pclmul ();
  int has_avx = sodium_runtime_has_avx ();
  memcpy (s->key, psk, 32);
  atomic_store_explicit (&s->cnt, 1, memory_order_relaxed);
  randombytes_buf (s->n_sid, CRY_NONCE_SID_SZ);
  fprintf (stderr, "crypto: aead=aegis128l aesni=%d pclmul=%d avx=%d\n",
           has_aesni, has_pclmul, has_avx);
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
             uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
             uint8_t *ct)
{
  memcpy (nonce, s->n_sid, CRY_NONCE_SID_SZ);
  for (size_t i = 0; i < sizeof (cnt); i++)
    nonce[CRY_NONCE_SID_SZ + i] = (uint8_t)(cnt >> (56U - (i * 8U)));
  crypto_aead_aegis128l_encrypt_detached (ct, mac, NULL, pt, pt_len, ad,
                                          ad_len, NULL, nonce, s->key);
}

void
cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
         size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ],
         uint8_t mac[CRY_MAC_SZ], uint8_t *ct)
{
  cry_enc_cnt (s, cry_cnt_take (s, 1), pt, pt_len, ad, ad_len, nonce, mac,
               ct);
}

int
cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
         size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
         const uint8_t mac[CRY_MAC_SZ], uint8_t *pt)
{
  int rc = crypto_aead_aegis128l_decrypt_detached (
      pt, NULL, ct, ct_len, mac, ad, ad_len, nonce, s->key);
  return (rc == 0) ? 0 : -1;
}
