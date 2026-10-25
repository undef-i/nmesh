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
#define AG_KEY_SZ 32
#define AG_NONCE_SZ 32
#define AG_MAC_SZ 32

_Static_assert (sizeof (((CryPeer *)0)->tx_key) == AG_KEY_SZ,
                "session key size must equal the AEAD key size");
_Static_assert (CRY_NONCE_WIRE_SZ == AG_NONCE_SZ,
                "wire nonce size must equal the AEAD nonce size");
_Static_assert (CRY_MAC_SZ == AG_MAC_SZ,
                "wire mac size must equal the AEAD tag size");

typedef struct
{
  uint8_t b[16];
} AgBlk;

typedef struct
{
  AgBlk s[6];
} AgSt;

static uint8_t ag_sbox[256];
static bool ag_sbox_ok;
static bool ag_hw;

static uint8_t
ag_xtime (uint8_t x)
{
  return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t
ag_gmul (uint8_t a, uint8_t b)
{
  uint8_t p = 0;
  for (int i = 0; i < 8; i++)
    {
      if (b & 1)
        p ^= a;
      a = ag_xtime (a);
      b >>= 1;
    }
  return p;
}

static void
ag_sbox_init (void)
{
  if (ag_sbox_ok)
    return;
  for (int i = 0; i < 256; i++)
    {
      uint8_t inv = 0;
      if (i != 0)
        {
          uint8_t r = 1, base = (uint8_t)i;
          int e = 254;
          while (e)
            {
              if (e & 1)
                r = ag_gmul (r, base);
              base = ag_gmul (base, base);
              e >>= 1;
            }
          inv = r;
        }
      uint8_t v = inv;
      v ^= (uint8_t)((inv << 1) | (inv >> 7));
      v ^= (uint8_t)((inv << 2) | (inv >> 6));
      v ^= (uint8_t)((inv << 3) | (inv >> 5));
      v ^= (uint8_t)((inv << 4) | (inv >> 4));
      ag_sbox[i] = (uint8_t)(v ^ 0x63);
    }
  ag_sbox_ok = true;
}

static void
ag_rnd_soft (uint8_t out[16], const uint8_t in[16], const uint8_t k[16])
{
  uint8_t t[16], u[16];
  for (int i = 0; i < 16; i++)
    t[i] = ag_sbox[in[i]];
  for (int c = 0; c < 4; c++)
    for (int r = 0; r < 4; r++)
      u[4 * c + r] = t[4 * ((c + r) & 3) + r];
  for (int c = 0; c < 4; c++)
    {
      uint8_t a0 = u[4 * c], a1 = u[4 * c + 1], a2 = u[4 * c + 2],
              a3 = u[4 * c + 3];
      uint8_t x0 = ag_xtime (a0), x1 = ag_xtime (a1), x2 = ag_xtime (a2),
              x3 = ag_xtime (a3);
      out[4 * c] = (uint8_t)(x0 ^ x1 ^ a1 ^ a2 ^ a3);
      out[4 * c + 1] = (uint8_t)(a0 ^ x1 ^ x2 ^ a2 ^ a3);
      out[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ x2 ^ x3 ^ a3);
      out[4 * c + 3] = (uint8_t)(x0 ^ a0 ^ a1 ^ a2 ^ x3);
    }
  for (int i = 0; i < 16; i++)
    out[i] ^= k[i];
}

#if defined(__x86_64__)
#include <cpuid.h>
#include <immintrin.h>
static bool
ag_cpuid_aesni (void)
{
  unsigned int a, b, c, d;
  if (!__get_cpuid (1, &a, &b, &c, &d))
    return false;
  return (c & bit_AES) != 0;
}
#endif

static void
ag_rnd (uint8_t out[16], const uint8_t in[16], const uint8_t k[16])
{
  uint8_t kk[16];
  memcpy (kk, k, 16);
  ag_rnd_soft (out, in, kk);
}

static void
ag_xor (AgBlk *o, const AgBlk *a, const AgBlk *b)
{
  for (int i = 0; i < 16; i++)
    o->b[i] = (uint8_t)(a->b[i] ^ b->b[i]);
}

static void
ag_upd (AgSt *st, const AgBlk *d)
{
  AgBlk tmp = st->s[5];
  ag_rnd (st->s[5].b, st->s[4].b, st->s[5].b);
  ag_rnd (st->s[4].b, st->s[3].b, st->s[4].b);
  ag_rnd (st->s[3].b, st->s[2].b, st->s[3].b);
  ag_rnd (st->s[2].b, st->s[1].b, st->s[2].b);
  ag_rnd (st->s[1].b, st->s[0].b, st->s[1].b);
  ag_rnd (tmp.b, tmp.b, st->s[0].b);
  ag_xor (&st->s[0], &tmp, d);
}

static void
ag_init (AgSt *st, const uint8_t key[AG_KEY_SZ],
         const uint8_t nonce[AG_NONCE_SZ])
{
  static const uint8_t c0_[16] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05,
                                   0x08, 0x0d, 0x15, 0x22, 0x37, 0x59,
                                   0x90, 0xe9, 0x79, 0x62 };
  static const uint8_t c1_[16] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2,
                                   0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
                                   0x73, 0xb5, 0x28, 0xdd };
  AgBlk c0, c1, k0, k1, n0, n1, k0n0, k1n1;
  memcpy (c0.b, c0_, 16);
  memcpy (c1.b, c1_, 16);
  memcpy (k0.b, key, 16);
  memcpy (k1.b, key + 16, 16);
  memcpy (n0.b, nonce, 16);
  memcpy (n1.b, nonce + 16, 16);
  ag_xor (&k0n0, &k0, &n0);
  ag_xor (&k1n1, &k1, &n1);
  st->s[0] = k0n0;
  st->s[1] = k1n1;
  st->s[2] = c1;
  st->s[3] = c0;
  ag_xor (&st->s[4], &k0, &c0);
  ag_xor (&st->s[5], &k1, &c1);
  for (int i = 0; i < 4; i++)
    {
      ag_upd (st, &k0);
      ag_upd (st, &k1);
      ag_upd (st, &k0n0);
      ag_upd (st, &k1n1);
    }
}

static void
ag_absorb (AgSt *st, const uint8_t *src)
{
  AgBlk m;
  memcpy (m.b, src, 16);
  ag_upd (st, &m);
}

static void
ag_absorb_ad (AgSt *st, const uint8_t *ad, size_t ad_len)
{
  size_t i = 0;
  for (; i + 32 <= ad_len; i += 32)
    {
      ag_absorb (st, ad + i);
      ag_absorb (st, ad + i + 16);
    }
  for (; i + 16 <= ad_len; i += 16)
    ag_absorb (st, ad + i);
  if (ad_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, ad + i, ad_len % 16);
      ag_absorb (st, pad);
    }
}

static void
ag_ks (const AgSt *st, AgBlk *o)
{
  for (int i = 0; i < 16; i++)
    o->b[i] = (uint8_t)(st->s[5].b[i] ^ st->s[4].b[i] ^ st->s[1].b[i]
                        ^ (st->s[2].b[i] & st->s[3].b[i]));
}

static void
ag_mac (AgSt *st, uint8_t mac[AG_MAC_SZ], uint64_t ad_len, uint64_t m_len)
{
  AgBlk tmp;
  uint64_t ab = ad_len << 3, mb = m_len << 3;
  for (int i = 0; i < 8; i++)
    {
      tmp.b[i] = (uint8_t)(ab >> (8 * i));
      tmp.b[8 + i] = (uint8_t)(mb >> (8 * i));
    }
  ag_xor (&tmp, &tmp, &st->s[3]);
  for (int i = 0; i < 7; i++)
    ag_upd (st, &tmp);
  AgBlk t = st->s[0];
  ag_xor (&t, &t, &st->s[1]);
  ag_xor (&t, &t, &st->s[2]);
  memcpy (mac, t.b, 16);
  t = st->s[3];
  ag_xor (&t, &t, &st->s[4]);
  ag_xor (&t, &t, &st->s[5]);
  memcpy (mac + 16, t.b, 16);
}

static void
ag_enc_soft (uint8_t *ct, uint8_t mac[AG_MAC_SZ], const uint8_t *pt,
             size_t pt_len, const uint8_t *ad, size_t ad_len,
             const uint8_t nonce[AG_NONCE_SZ],
             const uint8_t key[AG_KEY_SZ])
{
  AgSt st;
  ag_init (&st, key, nonce);
  ag_absorb_ad (&st, ad, ad_len);
  size_t i = 0;
  for (; i + 16 <= pt_len; i += 16)
    {
      AgBlk m, o;
      memcpy (m.b, pt + i, 16);
      ag_ks (&st, &o);
      ag_xor (&o, &o, &m);
      memcpy (ct + i, o.b, 16);
      ag_upd (&st, &m);
    }
  if (pt_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, pt + i, pt_len % 16);
      AgBlk m, o;
      memcpy (m.b, pad, 16);
      ag_ks (&st, &o);
      ag_xor (&o, &o, &m);
      memcpy (ct + i, o.b, pt_len % 16);
      ag_upd (&st, &m);
    }
  ag_mac (&st, mac, ad_len, pt_len);
}

static int
ag_dec_soft (uint8_t *pt, const uint8_t *ct, size_t ct_len,
             const uint8_t mac[AG_MAC_SZ], const uint8_t *ad, size_t ad_len,
             const uint8_t nonce[AG_NONCE_SZ],
             const uint8_t key[AG_KEY_SZ])
{
  AgSt st;
  ag_init (&st, key, nonce);
  ag_absorb_ad (&st, ad, ad_len);
  size_t i = 0;
  for (; i + 16 <= ct_len; i += 16)
    {
      AgBlk cb, m, o;
      memcpy (cb.b, ct + i, 16);
      ag_ks (&st, &o);
      ag_xor (&m, &cb, &o);
      memcpy (pt + i, m.b, 16);
      ag_upd (&st, &m);
    }
  if (ct_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, ct + i, ct_len % 16);
      AgBlk cb, m, o;
      memcpy (cb.b, pad, 16);
      ag_ks (&st, &o);
      ag_xor (&m, &cb, &o);
      memcpy (pt + i, m.b, ct_len % 16);
      memset (m.b + (ct_len % 16), 0, 16 - (ct_len % 16));
      ag_upd (&st, &m);
    }
  uint8_t calc[AG_MAC_SZ];
  ag_mac (&st, calc, ad_len, ct_len);
  if (crypto_verify_32 (calc, mac) != 0)
    {
      memset (pt, 0, ct_len);
      return -1;
    }
  return 0;
}

#if defined(__x86_64__)
__attribute__ ((target ("aes"))) static inline void
agh_upd (__m128i st[6], __m128i d)
{
  __m128i tmp = st[5];
  st[5] = _mm_aesenc_si128 (st[4], st[5]);
  st[4] = _mm_aesenc_si128 (st[3], st[4]);
  st[3] = _mm_aesenc_si128 (st[2], st[3]);
  st[2] = _mm_aesenc_si128 (st[1], st[2]);
  st[1] = _mm_aesenc_si128 (st[0], st[1]);
  st[0] = _mm_xor_si128 (_mm_aesenc_si128 (tmp, st[0]), d);
}

__attribute__ ((target ("aes"))) static void
agh_init (__m128i st[6], const uint8_t key[AG_KEY_SZ],
          const uint8_t nonce[AG_NONCE_SZ])
{
  static const uint8_t c0_[16] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05,
                                   0x08, 0x0d, 0x15, 0x22, 0x37, 0x59,
                                   0x90, 0xe9, 0x79, 0x62 };
  static const uint8_t c1_[16] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2,
                                   0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
                                   0x73, 0xb5, 0x28, 0xdd };
  __m128i c0 = _mm_loadu_si128 ((const __m128i *)(const void *)c0_);
  __m128i c1 = _mm_loadu_si128 ((const __m128i *)(const void *)c1_);
  __m128i k0 = _mm_loadu_si128 ((const __m128i *)(const void *)key);
  __m128i k1 = _mm_loadu_si128 ((const __m128i *)(const void *)(key + 16));
  __m128i n0 = _mm_loadu_si128 ((const __m128i *)(const void *)nonce);
  __m128i n1 = _mm_loadu_si128 ((const __m128i *)(const void *)(nonce + 16));
  __m128i k0n0 = _mm_xor_si128 (k0, n0);
  __m128i k1n1 = _mm_xor_si128 (k1, n1);
  st[0] = k0n0;
  st[1] = k1n1;
  st[2] = c1;
  st[3] = c0;
  st[4] = _mm_xor_si128 (k0, c0);
  st[5] = _mm_xor_si128 (k1, c1);
  for (int i = 0; i < 4; i++)
    {
      agh_upd (st, k0);
      agh_upd (st, k1);
      agh_upd (st, k0n0);
      agh_upd (st, k1n1);
    }
}

__attribute__ ((target ("aes"))) static void
agh_absorb_ad (__m128i st[6], const uint8_t *ad, size_t ad_len)
{
  size_t i = 0;
  for (; i + 16 <= ad_len; i += 16)
    agh_upd (st, _mm_loadu_si128 ((const __m128i *)(const void *)(ad + i)));
  if (ad_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, ad + i, ad_len % 16);
      agh_upd (st, _mm_loadu_si128 ((const __m128i *)(const void *)pad));
    }
}

__attribute__ ((target ("aes"))) static inline __m128i
agh_ks (const __m128i st[6])
{
  return _mm_xor_si128 (
      _mm_xor_si128 (_mm_xor_si128 (st[5], st[4]), st[1]),
      _mm_and_si128 (st[2], st[3]));
}

__attribute__ ((target ("aes"))) static void
agh_mac (__m128i st[6], uint8_t mac[AG_MAC_SZ], uint64_t ad_len,
         uint64_t m_len)
{
  __m128i tmp = _mm_set_epi64x ((long long)(m_len << 3),
                                (long long)(ad_len << 3));
  tmp = _mm_xor_si128 (tmp, st[3]);
  for (int i = 0; i < 7; i++)
    agh_upd (st, tmp);
  _mm_storeu_si128 ((__m128i *)(void *)mac,
                    _mm_xor_si128 (_mm_xor_si128 (st[2], st[1]), st[0]));
  _mm_storeu_si128 ((__m128i *)(void *)(mac + 16),
                    _mm_xor_si128 (_mm_xor_si128 (st[5], st[4]), st[3]));
}

__attribute__ ((target ("aes"))) static void
agh_enc_det (uint8_t *ct, uint8_t mac[AG_MAC_SZ], const uint8_t *pt,
             size_t pt_len, const uint8_t *ad, size_t ad_len,
             const uint8_t nonce[AG_NONCE_SZ],
             const uint8_t key[AG_KEY_SZ])
{
  __m128i st[6];
  agh_init (st, key, nonce);
  agh_absorb_ad (st, ad, ad_len);
  size_t i = 0;
  for (; i + 16 <= pt_len; i += 16)
    {
      __m128i m = _mm_loadu_si128 ((const __m128i *)(const void *)(pt + i));
      _mm_storeu_si128 ((__m128i *)(void *)(ct + i),
                        _mm_xor_si128 (agh_ks (st), m));
      agh_upd (st, m);
    }
  if (pt_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, pt + i, pt_len % 16);
      __m128i m = _mm_loadu_si128 ((const __m128i *)(const void *)pad);
      __m128i o = _mm_xor_si128 (agh_ks (st), m);
      uint8_t out[16];
      _mm_storeu_si128 ((__m128i *)(void *)out, o);
      memcpy (ct + i, out, pt_len % 16);
      agh_upd (st, m);
    }
  agh_mac (st, mac, ad_len, pt_len);
}

__attribute__ ((target ("aes"))) static int
agh_dec_det (uint8_t *pt, const uint8_t *ct, size_t ct_len,
             const uint8_t mac[AG_MAC_SZ], const uint8_t *ad, size_t ad_len,
             const uint8_t nonce[AG_NONCE_SZ],
             const uint8_t key[AG_KEY_SZ])
{
  __m128i st[6];
  agh_init (st, key, nonce);
  agh_absorb_ad (st, ad, ad_len);
  size_t i = 0;
  for (; i + 16 <= ct_len; i += 16)
    {
      __m128i cb = _mm_loadu_si128 ((const __m128i *)(const void *)(ct + i));
      __m128i m = _mm_xor_si128 (cb, agh_ks (st));
      _mm_storeu_si128 ((__m128i *)(void *)(pt + i), m);
      agh_upd (st, m);
    }
  if (ct_len % 16)
    {
      uint8_t pad[16] = { 0 };
      memcpy (pad, ct + i, ct_len % 16);
      __m128i cb = _mm_loadu_si128 ((const __m128i *)(const void *)pad);
      __m128i m = _mm_xor_si128 (cb, agh_ks (st));
      uint8_t out[16];
      _mm_storeu_si128 ((__m128i *)(void *)out, m);
      memcpy (pt + i, out, ct_len % 16);
      for (size_t j = ct_len % 16; j < 16; j++)
        out[j] = 0;
      agh_upd (st, _mm_loadu_si128 ((const __m128i *)(const void *)out));
    }
  uint8_t calc[AG_MAC_SZ];
  agh_mac (st, calc, ad_len, ct_len);
  if (crypto_verify_32 (calc, mac) != 0)
    {
      memset (pt, 0, ct_len);
      return -1;
    }
  return 0;
}
#endif

static void
ag_enc_det (uint8_t *ct, uint8_t mac[AG_MAC_SZ], const uint8_t *pt,
            size_t pt_len, const uint8_t *ad, size_t ad_len,
            const uint8_t nonce[AG_NONCE_SZ],
            const uint8_t key[AG_KEY_SZ])
{
#if defined(__x86_64__)
  if (ag_hw)
    {
      agh_enc_det (ct, mac, pt, pt_len, ad, ad_len, nonce, key);
      return;
    }
#endif
  ag_enc_soft (ct, mac, pt, pt_len, ad, ad_len, nonce, key);
}

static int
ag_dec_det (uint8_t *pt, const uint8_t *ct, size_t ct_len,
            const uint8_t mac[AG_MAC_SZ], const uint8_t *ad, size_t ad_len,
            const uint8_t nonce[AG_NONCE_SZ],
            const uint8_t key[AG_KEY_SZ])
{
#if defined(__x86_64__)
  if (ag_hw)
    return agh_dec_det (pt, ct, ct_len, mac, ad, ad_len, nonce, key);
#endif
  return ag_dec_soft (pt, ct, ct_len, mac, ad, ad_len, nonce, key);
}

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
  ag_enc_det (ct, mac, pt, pt_len, ad, ad_len, nonce, key);
}

int
cry_init (Cry *s, const uint8_t psk[32], bool auth_ibs)
{
  if (sodium_init () < 0)
    return -1;
  ag_sbox_init ();
#if defined(__x86_64__)
  ag_hw = ag_cpuid_aesni ();
#endif
  int has_aesni = ag_hw ? 1 : 0;
  int has_pclmul = sodium_runtime_has_pclmul ();
  int has_avx = sodium_runtime_has_avx ();
  s->auth_ibs = auth_ibs;
  if (auth_ibs)
    randombytes_buf (s->key, sizeof (s->key));
  else
    {
      /* Fixed salt: both ends must derive the same master key from the PSK. */
      static const uint8_t psk_salt[crypto_pwhash_SALTBYTES]
          = "nmesh-psk-salt01";
      if (crypto_pwhash (s->key, sizeof (s->key), (const char *)psk,
                         32, psk_salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13)
          != 0)
        return -1;
    }
  atomic_store_explicit (&s->cnt, 1, memory_order_relaxed);
  randombytes_buf (s->n_sid, CRY_NONCE_SID_SZ);
  randombytes_buf (s->kx_sk, CRY_KX_SEC_SZ);
  crypto_scalarmult_base (s->kx_pk, s->kx_sk);
  s->peer_arr = NULL;
  s->peer_cnt = 0;
  s->peer_cap = 0;
  pthread_mutex_init (&s->mtx, NULL);
  fprintf (stderr, "crypto: aead=aegis256 aesni=%d pclmul=%d avx=%d\n",
           has_aesni, has_pclmul, has_avx);
  return 0;
}

void
cry_set_ibs (Cry *s, const uint8_t mpk[96], const uint8_t sk[48])
{
  if (!s || !mpk || !sk)
    return;
  s->auth_ibs = true;
  randombytes_buf (s->ibs_ckie_key, sizeof (s->ibs_ckie_key));
  memcpy (s->ibs_mpk, mpk, IBS_MPK_SZ);
  memcpy (s->ibs_sk, sk, IBS_SK_SZ);
  uint8_t seed[16 + IBS_MPK_SZ + IBS_SK_SZ];
  memcpy (seed, "nmesh-ibs-local", 16);
  memcpy (seed + 16U, mpk, IBS_MPK_SZ);
  memcpy (seed + 16U + IBS_MPK_SZ, sk, IBS_SK_SZ);
  crypto_generichash (s->key, sizeof (s->key), seed, sizeof (seed), NULL, 0);
  sodium_memzero (seed, sizeof (seed));
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
  sodium_memzero (s->key, sizeof (s->key));
  sodium_memzero (s->ibs_sk, sizeof (s->ibs_sk));
  sodium_memzero (s->n_sid, sizeof (s->n_sid));
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
  const uint8_t *kdf_key = s->auth_ibs ? NULL : s->key;
  size_t kdf_key_len = s->auth_ibs ? 0 : sizeof (s->key);
  seed[0] = 4;
  memcpy (seed + 1U, shared, sizeof (shared));
  memcpy (seed + 1U + sizeof (shared), low_lla, 16);
  memcpy (seed + 1U + sizeof (shared) + 16U, high_lla, 16);
  memcpy (seed + 1U + sizeof (shared) + 32U, low_pk, CRY_KX_PUB_SZ);
  memcpy (seed + 1U + sizeof (shared) + 32U + CRY_KX_PUB_SZ, high_pk,
          CRY_KX_PUB_SZ);
  crypto_generichash (low_to_high, sizeof (low_to_high), seed, sizeof (seed),
                      kdf_key, kdf_key_len);
  seed[0] = 5;
  crypto_generichash (high_to_low, sizeof (high_to_low), seed, sizeof (seed),
                      kdf_key, kdf_key_len);
  seed[0] = 6;
  crypto_generichash (low_to_high_sid, sizeof (low_to_high_sid), seed,
                      sizeof (seed), kdf_key, kdf_key_len);
  seed[0] = 7;
  crypto_generichash (high_to_low_sid, sizeof (high_to_low_sid), seed,
                      sizeof (seed), kdf_key, kdf_key_len);

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
  return ag_dec_det (pt, ct, ct_len, mac, ad, ad_len, nonce, s->key);
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
          int rc = ag_dec_det (pt, ct, ct_len, mac, ad, ad_len, nonce,
                               key);
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
