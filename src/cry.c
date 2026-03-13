#include "cry.h"
#include "monocypher.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
cry_init (Cry *s, const uint8_t psk[32])
{
  memcpy (s->key, psk, 32);
  s->cnt = 1;
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read (fd, s->n_pfx, 16);
  close (fd);
  if (n != 16)
    return -1;
  return 0;
}

void
cry_enc (Cry *s, const uint8_t *pt, size_t pt_len, const uint8_t *ad,
         size_t ad_len, uint8_t nonce[24], uint8_t mac[16], uint8_t *ct)
{
  uint64_t cnt = s->cnt++;
  memcpy (nonce, s->n_pfx, 16);
  nonce[16] = (uint8_t)(cnt >> 56);
  nonce[17] = (uint8_t)(cnt >> 48);
  nonce[18] = (uint8_t)(cnt >> 40);
  nonce[19] = (uint8_t)(cnt >> 32);
  nonce[20] = (uint8_t)(cnt >> 24);
  nonce[21] = (uint8_t)(cnt >> 16);
  nonce[22] = (uint8_t)(cnt >> 8);
  nonce[23] = (uint8_t)(cnt);
  uint8_t *ct_ptr = ct;
  crypto_aead_lock (ct_ptr, mac, s->key, nonce, ad, ad_len, pt, pt_len);
}

int
cry_dec (Cry *s, const uint8_t *ct, size_t ct_len, const uint8_t *ad,
         size_t ad_len, const uint8_t nonce[24], const uint8_t mac[16],
         uint8_t *pt)
{
  int rc = crypto_aead_unlock (pt, mac, s->key, nonce, ad, ad_len, ct, ct_len);
  return (rc == 0) ? 0 : -1;
}
