#include "ibs.h"
#include <alloca.h>
#include <sodium.h>
#include <string.h>
#include "blst.h"
#include "blst_aux.h"

#define IBS_DST "nmesh-ibs-v1"

static void
scalar_from_msg (blst_scalar *out, const uint8_t *msg, size_t msg_len,
                 const blst_p1_affine *U)
{
  unsigned char hash[crypto_generichash_BYTES];
  crypto_generichash_state st;
  crypto_generichash_init (&st, NULL, 0, sizeof (hash));
  crypto_generichash_update (&st, msg, msg_len);
  {
    byte buf[96];
    blst_p1_affine_serialize (buf, U);
    crypto_generichash_update (&st, buf, sizeof (buf));
  }
  crypto_generichash_final (&st, hash, sizeof (hash));
  blst_scalar_from_be_bytes (out, hash, sizeof (hash));
}

bool
ibs_setup (uint8_t msk[IBS_MSK_SZ], uint8_t mpk[IBS_MPK_SZ])
{
  if (!msk || !mpk)
    return false;
  blst_scalar s;
  randombytes_buf (msk, IBS_MSK_SZ);
  blst_scalar_from_be_bytes (&s, msk, IBS_MSK_SZ);
  if (!blst_sk_check (&s))
    return false;
  blst_p2 gen;
  blst_p2_from_affine (&gen, blst_p2_affine_generator ());
  blst_p2 pk;
  blst_p2_mult (&pk, &gen, msk, 8 * IBS_MSK_SZ);
  blst_p2_affine pk_aff;
  blst_p2_to_affine (&pk_aff, &pk);
  blst_p2_affine_compress (mpk, &pk_aff);
  return true;
}

bool
ibs_extract (const uint8_t msk[IBS_MSK_SZ], const uint8_t *id,
             size_t id_len, uint8_t sk[IBS_SK_SZ])
{
  if (!msk || !id || id_len == 0 || !sk)
    return false;
  blst_p1 Q_id;
  blst_hash_to_g1 (&Q_id, id, id_len,
                   (const byte *)IBS_DST, sizeof (IBS_DST) - 1, NULL, 0);
  blst_p1 SK;
  blst_p1_mult (&SK, &Q_id, msk, 8 * IBS_MSK_SZ);
  blst_p1_affine sk_aff;
  blst_p1_to_affine (&sk_aff, &SK);
  blst_p1_affine_compress (sk, &sk_aff);
  return true;
}

bool
ibs_sign (const uint8_t sk[IBS_SK_SZ], const uint8_t *id,
          size_t id_len, const uint8_t *msg, size_t msg_len,
          uint8_t sig[IBS_SIG_SZ])
{
  if (!sk || !id || id_len == 0 || !msg || msg_len == 0 || !sig)
    return false;
  blst_p1_affine sk_aff;
  if (blst_p1_uncompress (&sk_aff, sk) != 0)
    return false;

  /* r = BLAKE2b-512("nmesh-ibs-r-v1" || sk || msg || ctr) mod r,
     ctr counting up from 0 while the result is zero (RFC 6979). */
  blst_scalar r;
  for (uint32_t ctr = 0;; ctr++)
    {
      unsigned char hash[64];
      crypto_generichash_state st;
      crypto_generichash_init (&st, NULL, 0, sizeof (hash));
      crypto_generichash_update (&st, (const uint8_t *)"nmesh-ibs-r-v1",
                                 sizeof ("nmesh-ibs-r-v1") - 1);
      crypto_generichash_update (&st, sk, IBS_SK_SZ);
      crypto_generichash_update (&st, msg, msg_len);
      {
        uint8_t cb[4] = { (uint8_t)ctr, (uint8_t)(ctr >> 8),
                          (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 24) };
        crypto_generichash_update (&st, cb, sizeof (cb));
      }
      crypto_generichash_final (&st, hash, sizeof (hash));
      blst_scalar_from_be_bytes (&r, hash, sizeof (hash));
      if (blst_sk_check (&r))
        break;
    }

  /* U = r * Q_ID */
  blst_p1 Q;
  blst_hash_to_g1 (&Q, id, id_len,
                   (const byte *)IBS_DST, sizeof (IBS_DST) - 1, NULL, 0);
  blst_p1 U;
  blst_p1_mult (&U, &Q, (const byte *)&r, 8 * IBS_MSK_SZ);
  blst_p1_affine U_aff;
  blst_p1_to_affine (&U_aff, &U);
  blst_p1_affine_compress (sig, &U_aff);

  blst_scalar h;
  scalar_from_msg (&h, msg, msg_len, &U_aff);

  blst_scalar t;
  blst_sk_add_n_check (&t, &r, &h);

  blst_p1 sk_p1;
  blst_p1_from_affine (&sk_p1, &sk_aff);
  blst_p1 V;
  blst_p1_mult (&V, &sk_p1, (const byte *)&t, 8 * IBS_MSK_SZ);
  blst_p1_affine V_aff;
  blst_p1_to_affine (&V_aff, &V);
  blst_p1_affine_compress (sig + IBS_SK_SZ, &V_aff);

  return true;
}

bool
ibs_verify (const uint8_t mpk[IBS_MPK_SZ], const uint8_t *id,
            size_t id_len, const uint8_t *msg, size_t msg_len,
            const uint8_t sig[IBS_SIG_SZ])
{
  if (!mpk || !id || id_len == 0 || !msg || msg_len == 0 || !sig)
    return false;

  blst_p1_affine U_aff, V_aff;
  if (blst_p1_uncompress (&U_aff, sig) != 0)
    return false;
  if (blst_p1_uncompress (&V_aff, sig + IBS_SK_SZ) != 0)
    return false;

  blst_p2_affine mpk_aff;
  if (blst_p2_uncompress (&mpk_aff, mpk) != 0)
    return false;

  blst_p1 Q_id;
  blst_hash_to_g1 (&Q_id, id, id_len,
                   (const byte *)IBS_DST, sizeof (IBS_DST) - 1, NULL, 0);

  blst_scalar h;
  scalar_from_msg (&h, msg, msg_len, &U_aff);

  blst_p1 hQ;
  blst_p1_mult (&hQ, &Q_id, (const byte *)&h, 8 * IBS_MSK_SZ);
  blst_p1 U_hQ;
  blst_p1_add_affine (&U_hQ, &hQ, &U_aff);
  blst_p1_affine U_hQ_aff;
  blst_p1_to_affine (&U_hQ_aff, &U_hQ);

  size_t ctx_sz = blst_pairing_sizeof ();
  const blst_p2_affine *g2 = blst_p2_affine_generator ();

  blst_pairing *ctx = alloca (ctx_sz);
  memset (ctx, 0, ctx_sz);
  blst_pairing_init (ctx, false, NULL, 0);

  /* e(V, P2) */
  blst_pairing_raw_aggregate (ctx, g2, &V_aff);

  /* e(-(U+hQ), MPK) = e(U+hQ, MPK)^(-1) */
  {
    blst_p1 neg;
    blst_p1_from_affine (&neg, &U_hQ_aff);
    blst_p1_cneg (&neg, true);
    blst_p1_affine neg_aff;
    blst_p1_to_affine (&neg_aff, &neg);
    blst_pairing_raw_aggregate (ctx, &mpk_aff, &neg_aff);
  }

  blst_pairing_commit (ctx);
  bool ok = blst_pairing_finalverify (ctx, NULL);
  return ok;
}
