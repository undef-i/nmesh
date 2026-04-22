#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FRAG_BKT_MAX 512

typedef struct
{
  uint8_t src_lla[16];
  uint32_t msg_id;
  uint64_t cre_ts;
  uint16_t tot_len;
  uint16_t rx_bytes;
  bool end_seen;
  bool is_act;
} FBktMeta;

typedef struct
{
  uint8_t *buf;
  uint8_t *rx_bmp;
} FBktData;

uint8_t *frag_asm (const uint8_t src_lla[16], uint32_t msg_id, uint16_t off,
                   bool mf, const uint8_t *data, size_t data_len,
                   uint16_t *out_len);
void frag_reap_tk (uint64_t sys_ts);
