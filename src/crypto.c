#include "crypto.h"
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert (CRY_KX_PUB_SZ == crypto_scalarmult_BYTES,
                "x25519 public key size");
_Static_assert (CRY_KX_SEC_SZ == crypto_scalarmult_SCALARBYTES,
                "x25519 secret key size");

static bool
cry_lla_ok (const uint8_t lla[16])
{
  return lla && lla[0] == 0xfe && ((lla[1] & 0xc0) == 0x80);
}

static CryPeer *
cry_peer_fnd_locked (Cry *s, const uint8_t lla[16])
{
  if (!s || !cry_lla_ok (lla))
    return NULL;
  for (uint32_t i = 0; i < s->peer_cnt; i++)
    {
      if (memcmp (s->peer_arr[i].lla, lla, 16) == 0)
        return &s->peer_arr[i];
    }
  return NULL;
}

static CryPeer *
cry_peer_fnd_rx_sid_locked (Cry *s, const uint8_t sid[CRY_NONCE_SID_SZ])
{
  if (!s || !sid)
    return NULL;
  for (uint32_t i = 0; i < s->peer_cnt; i++)
    {
      CryPeer *p = &s->peer_arr[i];
      if (p->ready && memcmp (p->rx_sid, sid, CRY_NONCE_SID_SZ) == 0)
        return p;
    }
  return NULL;
}

static CryPeer *
cry_peer_get_locked (Cry *s, const uint8_t lla[16])
{
  CryPeer *p = cry_peer_fnd_locked (s, lla);
  if (p)
    return p;
  if (!s || !cry_lla_ok (lla))
    return NULL;
  if (s->peer_cnt == s->peer_cap)
    {
      uint32_t new_cap = s->peer_cap ? s->peer_cap * 2U : 64U;
      CryPeer *new_arr = realloc (s->peer_arr, sizeof (*new_arr) * new_cap);
      if (!new_arr)
        return NULL;
      memset (new_arr + s->peer_cap, 0,
              sizeof (*new_arr) * (new_cap - s->peer_cap));
      s->peer_arr = new_arr;
      s->peer_cap = new_cap;
    }
  p = &s->peer_arr[s->peer_cnt++];
  memset (p, 0, sizeof (*p));
  memcpy (p->lla, lla, 16);
  return p;
}

static void
cry_enc_cnt_key (const uint8_t key[32], const uint8_t sid[CRY_NONCE_SID_SZ],
                 uint64_t cnt, const uint8_t *pt, size_t pt_len,
                 const uint8_t *ad, size_t ad_len,
                 uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
                 uint8_t *ct)
{
  memcpy (nonce, sid, CRY_NONCE_SID_SZ);
  for (size_t i = 0; i < sizeof (cnt); i++)
    nonce[CRY_NONCE_SID_SZ + i] = (uint8_t)(cnt >> (56U - (i * 8U)));
  crypto_aead_aegis128l_encrypt_detached (ct, mac, NULL, pt, pt_len, ad,
                                          ad_len, NULL, nonce, key);
}

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
  randombytes_buf (s->kx_sk, CRY_KX_SEC_SZ);
  crypto_scalarmult_base (s->kx_pk, s->kx_sk);
  s->peer_arr = NULL;
  s->peer_cnt = 0;
  s->peer_cap = 0;
  pthread_mutex_init (&s->mtx, NULL);
  fprintf (stderr, "crypto: aead=aegis128l aesni=%d pclmul=%d avx=%d\n",
           has_aesni, has_pclmul, has_avx);
  return 0;
}

void
cry_free (Cry *s)
{
  if (!s)
    return;
  pthread_mutex_lock (&s->mtx);
  if (s->peer_arr)
    sodium_memzero (s->peer_arr, sizeof (*s->peer_arr) * s->peer_cap);
  free (s->peer_arr);
  s->peer_arr = NULL;
  s->peer_cnt = 0;
  s->peer_cap = 0;
  sodium_memzero (s->kx_sk, sizeof (s->kx_sk));
  pthread_mutex_unlock (&s->mtx);
  pthread_mutex_destroy (&s->mtx);
}

uint64_t
cry_cnt_take (Cry *s, uint64_t n)
{
  return atomic_fetch_add_explicit (&s->cnt, n, memory_order_relaxed);
}

const uint8_t *
cry_kx_pub (Cry *s)
{
  return s ? s->kx_pk : NULL;
}

bool
cry_peer_rekey (Cry *s, const uint8_t our_lla[16],
                const uint8_t peer_lla[16],
                const uint8_t peer_pk[CRY_KX_PUB_SZ])
{
  if (!s || !cry_lla_ok (our_lla) || !cry_lla_ok (peer_lla) || !peer_pk
      || memcmp (our_lla, peer_lla, 16) == 0)
    return false;
  uint8_t shared[crypto_scalarmult_BYTES];
  if (crypto_scalarmult (shared, s->kx_sk, peer_pk) != 0)
    return false;
  bool our_low = memcmp (our_lla, peer_lla, 16) < 0;
  const uint8_t *low_lla = our_low ? our_lla : peer_lla;
  const uint8_t *high_lla = our_low ? peer_lla : our_lla;
  const uint8_t *low_pk = our_low ? s->kx_pk : peer_pk;
  const uint8_t *high_pk = our_low ? peer_pk : s->kx_pk;
  uint8_t seed[1U + crypto_scalarmult_BYTES + 32U + 2U * CRY_KX_PUB_SZ];
  uint8_t low_to_high[32];
  uint8_t high_to_low[32];
  uint8_t low_to_high_sid[CRY_NONCE_SID_SZ];
  uint8_t high_to_low_sid[CRY_NONCE_SID_SZ];
  seed[0] = 4;
  memcpy (seed + 1U, shared, sizeof (shared));
  memcpy (seed + 1U + sizeof (shared), low_lla, 16);
  memcpy (seed + 1U + sizeof (shared) + 16U, high_lla, 16);
  memcpy (seed + 1U + sizeof (shared) + 32U, low_pk, CRY_KX_PUB_SZ);
  memcpy (seed + 1U + sizeof (shared) + 32U + CRY_KX_PUB_SZ, high_pk,
          CRY_KX_PUB_SZ);
  crypto_generichash (low_to_high, sizeof (low_to_high), seed, sizeof (seed),
                      s->key, sizeof (s->key));
  seed[0] = 5;
  crypto_generichash (high_to_low, sizeof (high_to_low), seed, sizeof (seed),
                      s->key, sizeof (s->key));
  seed[0] = 6;
  crypto_generichash (low_to_high_sid, sizeof (low_to_high_sid), seed,
                      sizeof (seed), s->key, sizeof (s->key));
  seed[0] = 7;
  crypto_generichash (high_to_low_sid, sizeof (high_to_low_sid), seed,
                      sizeof (seed), s->key, sizeof (s->key));

  pthread_mutex_lock (&s->mtx);
  CryPeer *p = cry_peer_get_locked (s, peer_lla);
  if (p)
    {
      memcpy (p->peer_pk, peer_pk, CRY_KX_PUB_SZ);
      if (our_low)
        {
          memcpy (p->tx_key, low_to_high, 32);
          memcpy (p->rx_key, high_to_low, 32);
          memcpy (p->tx_sid, low_to_high_sid, sizeof (p->tx_sid));
          memcpy (p->rx_sid, high_to_low_sid, sizeof (p->rx_sid));
        }
      else
        {
          memcpy (p->tx_key, high_to_low, 32);
          memcpy (p->rx_key, low_to_high, 32);
          memcpy (p->tx_sid, high_to_low_sid, sizeof (p->tx_sid));
          memcpy (p->rx_sid, low_to_high_sid, sizeof (p->rx_sid));
        }
      p->ready = true;
    }
  pthread_mutex_unlock (&s->mtx);

  sodium_memzero (shared, sizeof (shared));
  sodium_memzero (seed, sizeof (seed));
  sodium_memzero (low_to_high, sizeof (low_to_high));
  sodium_memzero (high_to_low, sizeof (high_to_low));
  sodium_memzero (low_to_high_sid, sizeof (low_to_high_sid));
  sodium_memzero (high_to_low_sid, sizeof (high_to_low_sid));
  return p != NULL;
}

bool
cry_peer_ready (Cry *s, const uint8_t peer_lla[16])
{
  bool ok = false;
  if (!s || !cry_lla_ok (peer_lla))
    return false;
  pthread_mutex_lock (&s->mtx);
  CryPeer *p = cry_peer_fnd_locked (s, peer_lla);
  ok = p && p->ready;
  pthread_mutex_unlock (&s->mtx);
  return ok;
}

void
cry_enc_cnt (const Cry *s, uint64_t cnt, const uint8_t *pt, size_t pt_len,
             const uint8_t *ad, size_t ad_len,
             uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
             uint8_t *ct)
{
  cry_enc_cnt_key (s->key, s->n_sid, cnt, pt, pt_len, ad, ad_len, nonce, mac,
                   ct);
}

int
cry_enc_cnt_to (Cry *s, const uint8_t dst_lla[16], uint64_t cnt,
                const uint8_t *pt, size_t pt_len, const uint8_t *ad,
                size_t ad_len, uint8_t nonce[CRY_NONCE_WIRE_SZ],
                uint8_t mac[CRY_MAC_SZ], uint8_t *ct)
{
  uint8_t key[32];
  uint8_t sid[CRY_NONCE_SID_SZ];
  bool keyed = false;
  if (s && cry_lla_ok (dst_lla))
    {
      pthread_mutex_lock (&s->mtx);
      CryPeer *p = cry_peer_fnd_locked (s, dst_lla);
      if (p && p->ready)
        {
          memcpy (key, p->tx_key, sizeof (key));
          memcpy (sid, p->tx_sid, sizeof (sid));
          keyed = true;
        }
      pthread_mutex_unlock (&s->mtx);
    }
  if (!keyed)
    return -1;
  cry_enc_cnt_key (key, sid, cnt, pt, pt_len, ad, ad_len, nonce, mac,
                   ct);
  sodium_memzero (key, sizeof (key));
  sodium_memzero (sid, sizeof (sid));
  return 0;
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
cry_enc_to (Cry *s, const uint8_t dst_lla[16], const uint8_t *pt,
            size_t pt_len, const uint8_t *ad, size_t ad_len,
            uint8_t nonce[CRY_NONCE_WIRE_SZ], uint8_t mac[CRY_MAC_SZ],
            uint8_t *ct)
{
  return cry_enc_cnt_to (s, dst_lla, cry_cnt_take (s, 1), pt, pt_len, ad,
                         ad_len, nonce, mac, ct);
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

int
cry_dec_from (Cry *s, const uint8_t src_lla[16], const uint8_t *ct,
              size_t ct_len, const uint8_t *ad, size_t ad_len,
              const uint8_t nonce[CRY_NONCE_WIRE_SZ],
              const uint8_t mac[CRY_MAC_SZ], uint8_t *pt, bool *used_psk,
              uint8_t matched_lla[16])
{
  if (used_psk)
    *used_psk = false;
  if (matched_lla)
    memset (matched_lla, 0, 16);
  if (s)
    {
      uint8_t key[32];
      uint8_t lla[16];
      bool keyed = false;
      memset (key, 0, sizeof (key));
      memset (lla, 0, sizeof (lla));
      pthread_mutex_lock (&s->mtx);
      CryPeer *p = cry_peer_fnd_rx_sid_locked (s, nonce);
      if (!p && cry_lla_ok (src_lla))
        {
          p = cry_peer_fnd_locked (s, src_lla);
          if (p && memcmp (p->rx_sid, nonce, CRY_NONCE_SID_SZ) != 0)
            p = NULL;
        }
      if (p && p->ready)
        {
          memcpy (key, p->rx_key, sizeof (key));
          memcpy (lla, p->lla, sizeof (lla));
          keyed = true;
        }
      pthread_mutex_unlock (&s->mtx);
      if (keyed)
        {
          int rc = crypto_aead_aegis128l_decrypt_detached (
              pt, NULL, ct, ct_len, mac, ad, ad_len, nonce, key);
          sodium_memzero (key, sizeof (key));
          if (rc == 0)
            {
              if (used_psk)
                *used_psk = false;
              if (matched_lla)
                memcpy (matched_lla, lla, 16);
              sodium_memzero (lla, sizeof (lla));
              return 0;
            }
          sodium_memzero (lla, sizeof (lla));
        }
    }
  return -1;
}
