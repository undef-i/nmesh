#pragma once
#include "pkt.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define BATCH_MAX 64
#define UDP_PND_MAX 256

typedef struct
{
  uint8_t dst_ip[16];
  uint16_t dst_port;
  size_t data_len;
  uint8_t data[UDP_PL_MAX];
} UdpPMsg;

typedef struct
{
  int fd;
  UdpPMsg pend[UDP_PND_MAX];
  uint32_t pend_head;
  uint32_t pend_cnt;
} Udp;

typedef struct
{
  uint8_t dst_ip[16];
  uint16_t dst_port;
  uint8_t *data;
  size_t data_len;
} UdpMsg;

typedef void (*UdpEmsgsizeCallback) (const uint8_t dst_ip[16],
                                     uint16_t dst_port, size_t atmpt_plen);
typedef void (*UdpUnreachCallback) (const uint8_t dst_ip[16],
                                    uint16_t dst_port);
int udp_init (Udp *s, uint16_t *port);
void udp_free (Udp *s);
int udp_tx_arr (Udp *s, UdpMsg *msgs, int cnt);
int udp_rx_arr (Udp *s, uint8_t buf_arr[][UDP_PL_MAX], uint8_t src_ips[][16],
                uint16_t src_ports[], size_t len_arr[], int m_cnt);
int udp_tx (Udp *s, const uint8_t dst_ip[16], uint16_t dst_port,
            const uint8_t *data, size_t data_len);
bool udp_gso_set (Udp *s, uint16_t seg_sz);
void udp_emsg_cb_set (UdpEmsgsizeCallback cb);
void udp_unr_cb_set (UdpUnreachCallback cb);
bool udp_w_want (const Udp *s);
int udp_w_hnd (Udp *s);
uint64_t udp_bp_ev (void);
