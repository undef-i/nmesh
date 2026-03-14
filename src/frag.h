#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define FRAG_BKT_MAX 512

typedef struct
{
  uint32_t msg_id;
  uint64_t cre_ts;
  bool end_seen;
  uint16_t tot_len;
  uint16_t rx_bytes;
  bool is_act;
  uint8_t buf[65535];
  uint8_t rx_bmp[65535 / 8 + 1];
} FBkt;

uint8_t *frag_asm (uint32_t msg_id, uint16_t off, bool mf, const uint8_t *data,
                   size_t data_len, uint16_t *out_len);
void frag_reap_tk (uint64_t sys_ts);
