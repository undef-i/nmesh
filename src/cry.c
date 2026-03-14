#include "cry.h"
#include "monocypher.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

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
  memcpy (s->key, psk, 32);
  s->cnt = 1;
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read (fd, s->n_sid, CRY_NONCE_SID_SZ);
  close (fd);
  if (n != CRY_NONCE_SID_SZ)
    return -1;
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
  uint8_t full_nonce[CRY_NONCE_FULL_SZ];
  nonce_full_bld (nonce, full_nonce);
  uint8_t *ct_ptr = ct;
  crypto_aead_lock (ct_ptr, mac, s->key, full_nonce, ad, ad_len, pt, pt_len);
}

int
cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
         size_t ad_len, const uint8_t nonce[CRY_NONCE_WIRE_SZ],
         const uint8_t mac[16], uint8_t *pt)
{
  uint8_t full_nonce[CRY_NONCE_FULL_SZ];
  nonce_full_bld (nonce, full_nonce);
  int rc = crypto_aead_unlock (pt, mac, s->key, full_nonce, ad, ad_len, ct,
                               ct_len);
  return (rc == 0) ? 0 : -1;
}
