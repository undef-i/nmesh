#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IBS_MSK_SZ 32
#define IBS_MPK_SZ 96
#define IBS_SK_SZ  48
#define IBS_SIG_SZ 96

bool ibs_setup (uint8_t msk[IBS_MSK_SZ], uint8_t mpk[IBS_MPK_SZ]);

bool ibs_extract (const uint8_t msk[IBS_MSK_SZ], const uint8_t *id,
                  size_t id_len, uint8_t sk[IBS_SK_SZ]);

bool ibs_sign (const uint8_t sk[IBS_SK_SZ], const uint8_t *id,
               size_t id_len, const uint8_t *msg, size_t msg_len,
               uint8_t sig[IBS_SIG_SZ]);

bool ibs_verify (const uint8_t mpk[IBS_MPK_SZ], const uint8_t *id,
                 size_t id_len, const uint8_t *msg, size_t msg_len,
                 const uint8_t sig[IBS_SIG_SZ]);
