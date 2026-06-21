#include "tcp.h"
#include "gossip.h"
#include "packet.h"
#include "replay.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static TpRt *g_tp_rt = NULL;
static int g_tp_epfd = -1;
static Cry *g_tp_cry = NULL;
static const Cfg *g_tp_cfg = NULL;
static uint64_t g_tp_sid = 0;
static uint64_t g_tp_conn_last_warn_ts = 0;
static pthread_t g_tp_owner_tid;
static bool g_tp_owner_set = false;
static _Thread_local uint32_t g_tp_batch_depth = 0;

static void tp_conn_close (TpRt *tp, int epfd, TpConn *conn);
static bool tp_conn_tx_frame (TpRt *tp, int epfd, TpConn *conn,
                              const uint8_t *data, size_t len, bool hi);
static bool tp_conn_tx_frame_ex (TpRt *tp, int epfd, TpConn *conn,
                                 const uint8_t *data, size_t len, bool hi,
                                 bool preauth_ok);
static bool tp_conn_rsv (TpRt *tp, uint32_t need);
static bool tp_fd_idx_rsv (TpRt *tp, uint32_t need);
static bool tp_hot_idx_rsv (TpRt *tp, uint32_t need);
static bool tp_flow_idx_rsv (TpRt *tp, uint32_t need);
static void tp_flow_idx_forget_conn (TpRt *tp, uint32_t conn_idx);
static void tp_flow_idx_prune (TpRt *tp, uint64_t now);
static bool tp_conn_rx_in_rsv (TpConn *conn, uint32_t need);
static bool tp_conn_rx_rsv (TpConn *conn, uint32_t need);
static bool tp_conn_enqueue (TpConn *conn, const uint8_t *data, size_t len,
                             bool hi);
static uint32_t tp_conn_rx_frame_max (const TpConn *conn);
static void tp_send_cache_note (TpRt *tp, const TpConn *conn);
static void tp_tx_ring_free (TpTxRing *ring);
static bool tp_ip_is_zero (const uint8_t ip[16]);
static bool tp_lla_is_zero (const uint8_t lla[16]);
static uint32_t tp_hash_lla (const uint8_t lla[16]);
static uint32_t tp_hash_ep (const uint8_t ip[16], uint16_t port);
static uint32_t tp_flow_hash_norm (uint32_t flow_hash);
static ssize_t tp_sock_writev (int fd, const struct iovec *iov, int iovcnt,
                               bool more);
static void tp_fd_cfg (int fd);
static bool tp_sock_rtt_ms_get (int fd, uint32_t *out_rtt_ms);
static bool tp_conn_rtt_ms_get (const TpConn *conn, uint32_t *out_rtt_ms);
static void tp_conn_txq_sync (TpRt *tp, TpConn *conn);
static void tp_flush_deferred (void);
static bool tp_owner_thread (void);
static bool tp_send_hello (TpConn *conn);

#define TP_TXQ_BATCH_FRAMES 16U
#define TP_PING_KX_PL_SZ (PING_PL_SZ + TP_KX_PUB_SZ + CRY_KX_PUB_SZ)
#define TP_PONG_KX_PL_SZ (PONG_PL_SZ + TP_KX_PUB_SZ + CRY_KX_PUB_SZ)

_Static_assert (TP_WIRE_SALT_SZ == sizeof (((TpConn *)0)->wire_salt),
                "tcp wire salt size");
_Static_assert (TP_WIRE_KEY_SZ == sizeof (((TpConn *)0)->wire_rx_key),
                "tcp wire key size");
_Static_assert (TP_WIRE_MAC_SZ == CRY_MAC_SZ, "tcp wire mac size");
_Static_assert (TP_KX_PUB_SZ == sizeof (((TpConn *)0)->wire_kx_pk),
                "tcp kx pub size");
_Static_assert (TP_KX_SEC_SZ == sizeof (((TpConn *)0)->wire_kx_sk),
                "tcp kx sec size");

typedef enum
{
  TP_AUTH_FAIL = 0,
  TP_AUTH_PENDING,
  TP_AUTH_OK,
} TpAuthRes;

typedef struct
{
  uint8_t salt[TP_WIRE_SALT_SZ];
  uint64_t ts;
} TpSaltReplay;

static TpSaltReplay *g_tp_salt_rp = NULL;
static uint32_t g_tp_salt_rp_cnt = 0;
static uint32_t g_tp_salt_rp_cap = 0;
static _Thread_local uint8_t *g_tp_wire_tx_buf = NULL;
static _Thread_local uint32_t g_tp_wire_tx_cap = 0;

static bool
tp_inbound_static_ok (const Rt *rt, const uint8_t peer_lla[16],
                      const uint8_t ip[16], uint16_t port)
{
  if (!rt || !peer_lla || !ip || port == 0 || tp_lla_is_zero (peer_lla)
      || tp_ip_is_zero (ip))
    return false;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (re->state == RT_DED || re->r2d != 0 || !re->is_static)
        continue;
      if (memcmp (re->lla, peer_lla, 16) != 0)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0 || re->ep_port != port)
        continue;
      return true;
    }
  return false;
}

static uint32_t
tp_conn_idx (const TpRt *tp, const TpConn *conn)
{
  if (!tp || !conn || !tp->conn_arr)
    return TP_IDX_INV;
  uint32_t idx = conn->slot_idx;
  if (idx >= tp->conn_cap || tp->conn_arr[idx] != conn)
    return TP_IDX_INV;
  return idx;
}

static bool
tp_conn_slot_live (const TpRt *tp, uint32_t slot_idx, const TpConn *conn)
{
  return tp && conn && tp->conn_arr && slot_idx < tp->conn_cap
         && tp->conn_arr[slot_idx] == conn;
}

static void
tp_u64_wr (uint8_t dst[8], uint64_t v)
{
  for (int i = 0; i < 8; i++)
    dst[i] = (uint8_t)(v >> (56 - i * 8));
}

static uint32_t
tp_u32_rd (const uint8_t src[4])
{
  return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16)
         | ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

static void
tp_u32_wr (uint8_t dst[4], uint32_t v)
{
  dst[0] = (uint8_t)(v >> 24);
  dst[1] = (uint8_t)(v >> 16);
  dst[2] = (uint8_t)(v >> 8);
  dst[3] = (uint8_t)v;
}

static void
tp_u16_wr (uint8_t dst[2], uint16_t v)
{
  dst[0] = (uint8_t)(v >> 8);
  dst[1] = (uint8_t)v;
}

static bool
tp_salt_rp_rsv (uint32_t need)
{
  if (need <= g_tp_salt_rp_cap)
    return true;
  uint32_t new_cap = g_tp_salt_rp_cap ? g_tp_salt_rp_cap : 64U;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  TpSaltReplay *new_arr
      = realloc (g_tp_salt_rp, sizeof (*g_tp_salt_rp) * new_cap);
  if (!new_arr)
    return false;
  g_tp_salt_rp = new_arr;
  g_tp_salt_rp_cap = new_cap;
  return true;
}

static void
tp_salt_rp_reap (uint64_t now)
{
  uint32_t out = 0;
  for (uint32_t i = 0; i < g_tp_salt_rp_cnt; i++)
    {
      bool stale = g_tp_salt_rp[i].ts != 0 && now > g_tp_salt_rp[i].ts
                   && (now - g_tp_salt_rp[i].ts) > KA_TMO;
      if (stale)
        continue;
      if (out != i)
        g_tp_salt_rp[out] = g_tp_salt_rp[i];
      out++;
    }
  g_tp_salt_rp_cnt = out;
}

static bool
tp_salt_rp_seen (const uint8_t salt[TP_WIRE_SALT_SZ], uint64_t now)
{
  tp_salt_rp_reap (now);
  for (uint32_t i = 0; i < g_tp_salt_rp_cnt; i++)
    {
      if (memcmp (g_tp_salt_rp[i].salt, salt, TP_WIRE_SALT_SZ) == 0)
        return true;
    }
  return false;
}

static bool
tp_salt_rp_commit (const uint8_t salt[TP_WIRE_SALT_SZ], uint64_t now)
{
  if (tp_salt_rp_seen (salt, now))
    return false;
  if (!tp_salt_rp_rsv (g_tp_salt_rp_cnt + 1U))
    return false;
  memcpy (g_tp_salt_rp[g_tp_salt_rp_cnt].salt, salt, TP_WIRE_SALT_SZ);
  g_tp_salt_rp[g_tp_salt_rp_cnt].ts = now;
  g_tp_salt_rp_cnt++;
  return true;
}

static bool
tp_kx_ensure (TpConn *conn)
{
  if (!conn)
    return false;
  if (conn->wire_kx_ready)
    return true;
  randombytes_buf (conn->wire_kx_sk, TP_KX_SEC_SZ);
  crypto_scalarmult_base (conn->wire_kx_pk, conn->wire_kx_sk);
  conn->wire_kx_ready = true;
  return true;
}

static void
tp_wire_derive (TpConn *conn)
{
  if (!conn || !g_tp_cry || conn->wire_ready)
    return;
  uint8_t seed[1U + TP_WIRE_SALT_SZ];
  uint8_t c2s[TP_WIRE_KEY_SZ];
  uint8_t s2c[TP_WIRE_KEY_SZ];

  seed[0] = 0;
  memcpy (seed + 1U, conn->wire_salt, TP_WIRE_SALT_SZ);
  crypto_generichash (c2s, sizeof (c2s), seed, sizeof (seed), g_tp_cry->key,
                      sizeof (g_tp_cry->key));

  seed[0] = 1;
  crypto_generichash (s2c, sizeof (s2c), seed, sizeof (seed), g_tp_cry->key,
                      sizeof (g_tp_cry->key));

  if (conn->inbound)
    {
      memcpy (conn->wire_rx_key, c2s, TP_WIRE_KEY_SZ);
      memcpy (conn->wire_tx_key, s2c, TP_WIRE_KEY_SZ);
    }
  else
    {
      memcpy (conn->wire_tx_key, c2s, TP_WIRE_KEY_SZ);
      memcpy (conn->wire_rx_key, s2c, TP_WIRE_KEY_SZ);
    }
  conn->wire_rx_seq = 0;
  conn->wire_tx_seq = 0;
  conn->wire_ready = true;
  sodium_memzero (seed, sizeof (seed));
  sodium_memzero (c2s, sizeof (c2s));
  sodium_memzero (s2c, sizeof (s2c));
}

static bool
tp_wire_rekey_fs (TpConn *conn)
{
  if (!conn || !g_tp_cry || !conn->wire_ready || conn->wire_fs_ready
      || !conn->wire_kx_ready || !conn->wire_peer_kx_ready)
    return false;

  uint8_t shared[crypto_scalarmult_BYTES];
  if (crypto_scalarmult (shared, conn->wire_kx_sk, conn->wire_peer_pk) != 0)
    return false;

  uint8_t init_pk[TP_KX_PUB_SZ];
  uint8_t resp_pk[TP_KX_PUB_SZ];
  if (conn->inbound)
    {
      memcpy (init_pk, conn->wire_peer_pk, sizeof (init_pk));
      memcpy (resp_pk, conn->wire_kx_pk, sizeof (resp_pk));
    }
  else
    {
      memcpy (init_pk, conn->wire_kx_pk, sizeof (init_pk));
      memcpy (resp_pk, conn->wire_peer_pk, sizeof (resp_pk));
    }

  uint8_t seed[1U + TP_WIRE_SALT_SZ + crypto_scalarmult_BYTES
               + 2U * TP_KX_PUB_SZ];
  uint8_t c2s[TP_WIRE_KEY_SZ];
  uint8_t s2c[TP_WIRE_KEY_SZ];
  seed[0] = 2;
  memcpy (seed + 1U, conn->wire_salt, TP_WIRE_SALT_SZ);
  memcpy (seed + 1U + TP_WIRE_SALT_SZ, shared, sizeof (shared));
  memcpy (seed + 1U + TP_WIRE_SALT_SZ + sizeof (shared), init_pk,
          sizeof (init_pk));
  memcpy (seed + 1U + TP_WIRE_SALT_SZ + sizeof (shared) + sizeof (init_pk),
          resp_pk, sizeof (resp_pk));
  crypto_generichash (c2s, sizeof (c2s), seed, sizeof (seed), g_tp_cry->key,
                      sizeof (g_tp_cry->key));

  seed[0] = 3;
  crypto_generichash (s2c, sizeof (s2c), seed, sizeof (seed), g_tp_cry->key,
                      sizeof (g_tp_cry->key));

  if (conn->inbound)
    {
      memcpy (conn->wire_rx_key, c2s, TP_WIRE_KEY_SZ);
      memcpy (conn->wire_tx_key, s2c, TP_WIRE_KEY_SZ);
    }
  else
    {
      memcpy (conn->wire_tx_key, c2s, TP_WIRE_KEY_SZ);
      memcpy (conn->wire_rx_key, s2c, TP_WIRE_KEY_SZ);
    }
  conn->wire_rx_seq = 0;
  conn->wire_tx_seq = 0;
  conn->wire_fs_ready = true;
  sodium_memzero (conn->wire_kx_sk, sizeof (conn->wire_kx_sk));
  sodium_memzero (shared, sizeof (shared));
  sodium_memzero (seed, sizeof (seed));
  sodium_memzero (c2s, sizeof (c2s));
  sodium_memzero (s2c, sizeof (s2c));
  return true;
}

static uint32_t
tp_wire_len_mask (const uint8_t key[TP_WIRE_KEY_SZ], uint64_t seq)
{
  uint8_t seq_buf[8];
  uint8_t mask[crypto_shorthash_BYTES];
  tp_u64_wr (seq_buf, seq);
  crypto_shorthash (mask, seq_buf, sizeof (seq_buf), key);
  return tp_u32_rd (mask);
}

static void
tp_wire_mask (const uint8_t key[TP_WIRE_KEY_SZ], uint64_t seq, uint8_t *buf,
              size_t len)
{
  if (!key || !buf || len == 0)
    return;
  size_t mask_len = len < PKT_HDR_SZ ? len : PKT_HDR_SZ;
  uint8_t seed[16];
  uint8_t mask[crypto_shorthash_BYTES];
  tp_u64_wr (seed, seq);
  for (size_t off = 0; off < mask_len; off += sizeof (mask))
    {
      tp_u64_wr (seed + 8, (uint64_t)(off / sizeof (mask)));
      crypto_shorthash (mask, seed, sizeof (seed), key);
      size_t n = mask_len - off;
      if (n > sizeof (mask))
        n = sizeof (mask);
      for (size_t i = 0; i < n; i++)
        buf[off + i] ^= mask[i];
    }
  sodium_memzero (seed, sizeof (seed));
  sodium_memzero (mask, sizeof (mask));
}

static bool
tp_wire_encode (TpConn *conn, const uint8_t *data, size_t len,
                uint8_t *wire, size_t *wire_len)
{
  if (!conn || !data || !wire || !wire_len || !conn->wire_ready
      || len == 0 || len > TP_PL_MAX)
    return false;
  uint64_t seq = conn->wire_tx_seq;
  uint32_t masked_len
      = (uint32_t)len ^ tp_wire_len_mask (conn->wire_tx_key, seq);
  tp_u32_wr (wire, masked_len);
  memcpy (wire + sizeof (uint32_t), data, len);
  tp_wire_mask (conn->wire_tx_key, seq, wire + sizeof (uint32_t), len);
  conn->wire_tx_seq = seq + 1U;
  *wire_len = sizeof (uint32_t) + len;
  return true;
}

static bool
tp_wire_decode_len (TpConn *conn, const uint8_t hdr[sizeof (uint32_t)],
                    uint32_t *out_len)
{
  if (!conn || !hdr || !out_len || !conn->wire_ready)
    return false;
  uint32_t masked_len = tp_u32_rd (hdr);
  uint32_t len
      = masked_len ^ tp_wire_len_mask (conn->wire_rx_key, conn->wire_rx_seq);
  if (len == 0 || len > tp_conn_rx_frame_max (conn))
    return false;
  *out_len = len;
  return true;
}

static bool
tp_wire_decode_body (TpConn *conn, const uint8_t hdr[sizeof (uint32_t)],
                     uint8_t *buf, uint32_t body_len, uint32_t plain_len)
{
  if (!conn || !hdr || !buf || !conn->wire_ready
      || body_len != plain_len)
    return false;
  (void)hdr;
  tp_wire_mask (conn->wire_rx_key, conn->wire_rx_seq, buf, plain_len);
  conn->wire_rx_seq++;
  return true;
}

static size_t
tp_auth_pad_len (size_t base_pl_len)
{
  if (base_pl_len >= PKT_PT_MAX)
    return 0;
  return (size_t)randombytes_uniform ((uint32_t)(PKT_PT_MAX - base_pl_len + 1U));
}

static uint8_t *
tp_pkt_enc (Cry *s, uint8_t pkt_type, const uint8_t *payload, size_t pl_len,
            uint8_t *buf, size_t *out_len)
{
  uint8_t hdr[PKT_CH_SZ];
  uint8_t nonce[PKT_NONCE_SZ], mac[PKT_MAC_SZ];
  hdr[0] = (uint8_t)(pkt_type & PKT_TF_TYPE_MASK);
  hdr[1] = 32;
  uint8_t *ct = buf + PKT_NONCE_SZ + PKT_MAC_SZ;
  memcpy (ct, hdr, PKT_CH_SZ);
  memcpy (ct + PKT_CH_SZ, payload, pl_len);
  cry_enc (s, ct, pl_len + PKT_CH_SZ, NULL, 0, nonce, mac, ct);
  memcpy (buf, nonce, PKT_NONCE_SZ);
  memcpy (buf + PKT_NONCE_SZ, mac, PKT_MAC_SZ);
  *out_len = PKT_HDR_SZ + pl_len;
  return buf;
}

static uint8_t *
tp_ping_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
             uint64_t ts, uint64_t sid, uint64_t prb_tok,
             const uint8_t kx_pk[TP_KX_PUB_SZ], uint8_t *buf,
             size_t *out_len)
{
  uint8_t payload[PKT_PT_MAX];
  tp_u64_wr (payload, ts);
  tp_u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  tp_u16_wr (payload + 32, our_port);
  tp_u64_wr (payload + 34, prb_tok);
  memcpy (payload + PING_PL_SZ, kx_pk, TP_KX_PUB_SZ);
  memcpy (payload + PING_PL_SZ + TP_KX_PUB_SZ, cry_kx_pub (s),
          CRY_KX_PUB_SZ);
  size_t pad_len = tp_auth_pad_len (TP_PING_KX_PL_SZ);
  if (pad_len > 0)
    randombytes_buf (payload + TP_PING_KX_PL_SZ, pad_len);
  return tp_pkt_enc (s, PT_PING, payload, TP_PING_KX_PL_SZ + pad_len, buf,
                     out_len);
}

static uint8_t *
tp_pong_bld (Cry *s, const uint8_t our_lla[16], uint16_t our_port,
             uint64_t o_ts, uint64_t sid, uint64_t rx_ts, uint64_t prb_tok,
             const uint8_t kx_pk[TP_KX_PUB_SZ], uint8_t *buf,
             size_t *out_len)
{
  uint8_t payload[PKT_PT_MAX];
  tp_u64_wr (payload, o_ts);
  tp_u64_wr (payload + 8, sid);
  memcpy (payload + 16, our_lla, 16);
  tp_u16_wr (payload + 32, our_port);
  tp_u64_wr (payload + 34, rx_ts);
  tp_u64_wr (payload + 42, prb_tok);
  memcpy (payload + PONG_PL_SZ, kx_pk, TP_KX_PUB_SZ);
  memcpy (payload + PONG_PL_SZ + TP_KX_PUB_SZ, cry_kx_pub (s),
          CRY_KX_PUB_SZ);
  size_t pad_len = tp_auth_pad_len (TP_PONG_KX_PL_SZ);
  if (pad_len > 0)
    randombytes_buf (payload + TP_PONG_KX_PL_SZ, pad_len);
  return tp_pkt_enc (s, PT_PONG, payload, TP_PONG_KX_PL_SZ + pad_len, buf,
                     out_len);
}

static ssize_t
tp_sock_writev (int fd, const struct iovec *iov, int iovcnt, bool more)
{
  struct msghdr msg;
  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = (struct iovec *)iov;
  msg.msg_iovlen = (size_t)iovcnt;
  int flags = MSG_NOSIGNAL;
#ifdef MSG_MORE
  if (more)
    flags |= MSG_MORE;
#endif
  return sendmsg (fd, &msg, flags);
}

static void
tp_fd_cfg (int fd)
{
  if (fd < 0)
    return;
  int one = 1;
  (void)setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof (one));
  (void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
#ifdef TCP_KEEPIDLE
  int keepidle = (int)(KA_TMO / 1000ULL);
  if (keepidle < 1)
    keepidle = 1;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle,
                    sizeof (keepidle));
#endif
#ifdef TCP_KEEPINTVL
  int keepintvl = 5;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl,
                    sizeof (keepintvl));
#endif
#ifdef TCP_KEEPCNT
  int keepcnt = 3;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof (keepcnt));
#endif
#ifdef TCP_USER_TIMEOUT
  int user_tmo = (int)KA_TMO;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_tmo,
                    sizeof (user_tmo));
#endif
}

static bool
tp_sock_rtt_ms_get (int fd, uint32_t *out_rtt_ms)
{
#ifdef TCP_INFO
  if (fd < 0 || !out_rtt_ms)
    return false;
  struct tcp_info info;
  socklen_t info_len = sizeof (info);
  memset (&info, 0, sizeof (info));
  if (getsockopt (fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) != 0
      || info.tcpi_rtt == 0)
    return false;
  uint32_t rtt_ms = (uint32_t)((info.tcpi_rtt + 999U) / 1000U);
  *out_rtt_ms = rtt_ms > 0 ? rtt_ms : 1U;
  return true;
#else
  (void)fd;
  (void)out_rtt_ms;
  return false;
#endif
}

static bool
tp_conn_rtt_ms_get (const TpConn *conn, uint32_t *out_rtt_ms)
{
  if (!conn || conn->fd < 0 || conn->st != TP_ST_ESTABLISHED || !conn->auth)
    return false;
  return tp_sock_rtt_ms_get (conn->fd, out_rtt_ms);
}

static void
tp_send_cache_reset (TpRt *tp)
{
  if (!tp)
    return;
  if (tp->peer_hot_idx)
    for (uint32_t i = 0; i < tp->peer_hot_cap; i++)
      tp->peer_hot_idx[i] = TP_IDX_INV;
  if (tp->ep_hot_idx)
    for (uint32_t i = 0; i < tp->ep_hot_cap; i++)
      tp->ep_hot_idx[i] = TP_IDX_INV;
}

static void
tp_send_cache_note (TpRt *tp, const TpConn *conn)
{
  if (!tp || !conn || conn->fd < 0)
    return;
  uint32_t idx = tp_conn_idx (tp, conn);
  if (idx == TP_IDX_INV)
    return;
  if (tp->peer_hot_idx && tp->peer_hot_cap > 0 && conn->auth
      && !tp_lla_is_zero (conn->peer_lla))
    tp->peer_hot_idx[tp_hash_lla (conn->peer_lla) & (tp->peer_hot_cap - 1U)]
      = idx;
  if (tp->ep_hot_idx && tp->ep_hot_cap > 0 && conn->route_port != 0
      && !tp_ip_is_zero (conn->route_ip))
    tp->ep_hot_idx[tp_hash_ep (conn->route_ip, conn->route_port)
                   & (tp->ep_hot_cap - 1U)]
      = idx;
}

static void
tp_conn_limit_warn (TpRt *tp, const char *ctx)
{
  uint64_t now = sys_ts ();
  if (g_tp_conn_last_warn_ts != 0
      && (now <= g_tp_conn_last_warn_ts
          || (now - g_tp_conn_last_warn_ts) < TP_WARN_INTV))
    return;
  int live = 0;
  if (tp)
    {
      for (uint32_t i = 0; i < tp->conn_cap; i++)
        {
          TpConn *conn = tp->conn_arr[i];
          if (conn && conn->fd >= 0)
            live++;
        }
    }
  fprintf (stderr,
           "tcp: connection table saturated (%d/%u active), rejecting %s\n",
           live, tp ? (unsigned)tp->conn_cap : 0U,
           ctx ? ctx : "connection");
  g_tp_conn_last_warn_ts = now;
}

static inline void
tp_lock (TpRt *tp)
{
  if (tp)
    pthread_mutex_lock (&tp->mtx);
}

static inline void
tp_unlock (TpRt *tp)
{
  if (tp)
    pthread_mutex_unlock (&tp->mtx);
}

static bool
tp_owner_thread (void)
{
  return g_tp_owner_set && pthread_equal (pthread_self (), g_tp_owner_tid);
}

static uint64_t
tp_auth_tok_new (void)
{
  uint64_t tok = 0;
  do
    {
      randombytes_buf (&tok, sizeof (tok));
    }
  while (tok == 0);
  return tok;
}

static bool
tp_ip_is_zero (const uint8_t ip[16])
{
  if (!ip)
    return true;
  for (int i = 0; i < 16; i++)
    {
      if (ip[i] != 0)
        return false;
    }
  return true;
}

static bool
tp_lla_is_zero (const uint8_t lla[16])
{
  return tp_ip_is_zero (lla);
}

static uint32_t
tp_hash_mix64 (uint64_t x)
{
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  return (uint32_t)(x ^ (x >> 32));
}

static uint32_t
tp_hash_lla (const uint8_t lla[16])
{
  uint64_t lo = 0;
  uint64_t hi = 0;
  memcpy (&lo, lla, sizeof (lo));
  memcpy (&hi, lla + sizeof (lo), sizeof (hi));
  return tp_hash_mix64 (lo) ^ tp_hash_mix64 (hi);
}

static uint32_t
tp_hash_ep (const uint8_t ip[16], uint16_t port)
{
  return tp_hash_lla (ip) ^ ((uint32_t)port * 0x9e3779b1U);
}

static uint32_t
tp_flow_hash_norm (uint32_t flow_hash)
{
  return flow_hash != 0 ? flow_hash : 0x9e3779b9U;
}

static uint32_t
tp_conn_txq_stop_bytes (const TpConn *conn)
{
  uint32_t stop = (conn && conn->sndbuf_bytes > 0) ? conn->sndbuf_bytes : 0U;
  if (stop > 0 && stop <= (UINT32_MAX / TP_TXQ_STOP_MULT))
    stop *= TP_TXQ_STOP_MULT;
  else if (stop > 0)
    stop = UINT32_MAX;
  return (stop >= TP_TXQ_FRAME_BYTES) ? stop : TP_TXQ_FRAME_BYTES;
}

static uint32_t
tp_conn_txq_batch_bytes (const TpConn *conn)
{
  uint32_t batch = TP_TXQ_FRAME_BYTES * TP_TXQ_BATCH_FRAMES;
  uint32_t stop = tp_conn_txq_stop_bytes (conn);
  if (batch > stop)
    batch = stop;
  return batch >= TP_TXQ_FRAME_BYTES ? batch : TP_TXQ_FRAME_BYTES;
}

static void
tp_conn_sock_sync (TpConn *conn)
{
  if (!conn || conn->fd < 0)
    return;
  int sndbuf = 0;
  socklen_t sndbuf_len = sizeof (sndbuf);
  if (getsockopt (conn->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sndbuf_len) == 0
      && sndbuf > 0)
    conn->sndbuf_bytes = (uint32_t)sndbuf;
  else
    conn->sndbuf_bytes = TP_TXQ_FRAME_BYTES;
}

static void
tp_conn_txq_sync (TpRt *tp, TpConn *conn)
{
  if (!tp || !conn)
    return;
  bool is_qd = conn->tx_q_bytes != 0;
  if (conn->tx_qd != is_qd)
    {
      conn->tx_qd = is_qd;
      if (is_qd)
        (void)__atomic_add_fetch (&tp->tx_qd_cnt, 1U, __ATOMIC_RELAXED);
      else
        (void)__atomic_sub_fetch (&tp->tx_qd_cnt, 1U, __ATOMIC_RELAXED);
    }
  bool is_bp = conn->tx_q_bytes >= tp_conn_txq_stop_bytes (conn);
  if (conn->tx_bp == is_bp)
    return;
  conn->tx_bp = is_bp;
  if (is_bp)
    (void)__atomic_add_fetch (&tp->tx_bp_cnt, 1U, __ATOMIC_RELAXED);
  else
    (void)__atomic_sub_fetch (&tp->tx_bp_cnt, 1U, __ATOMIC_RELAXED);
}

static bool
tp_conn_peer_match (const TpConn *conn, const uint8_t peer_lla[16])
{
  if (!conn || conn->fd < 0 || !peer_lla || tp_lla_is_zero (peer_lla)
      || tp_lla_is_zero (conn->peer_lla))
    return false;
  return memcmp (conn->peer_lla, peer_lla, 16) == 0;
}

static int
tp_conn_cmp (const uint8_t our_lla[16], const TpConn *a, const TpConn *b)
{
  if (!a || !b)
    return a ? 1 : (b ? -1 : 0);
  if (a->auth != b->auth)
    return a->auth ? 1 : -1;
  if (a->st != b->st)
    return (a->st == TP_ST_ESTABLISHED) ? 1 : -1;

  bool a_pref_out = memcmp (our_lla, a->peer_lla, 16) > 0;
  bool a_pref = a_pref_out ? !a->inbound : a->inbound;
  bool b_pref_out = memcmp (our_lla, b->peer_lla, 16) > 0;
  bool b_pref = b_pref_out ? !b->inbound : b->inbound;
  if (a_pref != b_pref)
    return a_pref ? 1 : -1;

  if (a->ts != b->ts)
    return (a->ts < b->ts) ? 1 : -1;
  if (a->fd != b->fd)
    return (a->fd < b->fd) ? 1 : -1;
  return 0;
}

static void
tp_conn_dedup_peer (TpRt *tp, int epfd, const uint8_t our_lla[16],
                    const uint8_t peer_lla[16])
{
  if (!tp || !our_lla || !peer_lla || tp_lla_is_zero (peer_lla))
    return;

  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!tp_conn_peer_match (conn, peer_lla))
        continue;
      TpConn *best = conn;
      for (uint32_t j = i + 1U; j < tp->conn_cap; j++)
        {
          TpConn *cand = tp->conn_arr[j];
          if (!tp_conn_peer_match (cand, peer_lla))
            continue;
          if (cand->lane_hash != conn->lane_hash)
            continue;
          if (tp_conn_cmp (our_lla, cand, best) > 0)
            best = cand;
        }
      for (uint32_t j = i; j < tp->conn_cap; j++)
        {
          TpConn *cand = tp->conn_arr[j];
          if (cand == best || !tp_conn_peer_match (cand, peer_lla))
            continue;
          if (cand->lane_hash != best->lane_hash)
            continue;
          tp_conn_close (tp, epfd, cand);
        }
    }
}

static void
tp_ev_upd (int epfd, const TpConn *conn)
{
  if (!conn || conn->fd < 0)
    return;
  struct epoll_event ev;
  memset (&ev, 0, sizeof (ev));
  ev.events = EPOLLIN | EPOLLERR | EPOLLRDHUP;
  if (conn->st == TP_ST_CONNECTING || conn->tx_hi.len > 0
      || (conn->auth && conn->tx_lo.len > 0))
    ev.events |= EPOLLOUT;
  ev.data.u64 = TP_EV_CONN_BASE | (uint32_t)conn->fd;
  (void)epoll_ctl (epfd, EPOLL_CTL_MOD, conn->fd, &ev);
}

static void
tp_ev_add (int epfd, const TpConn *conn)
{
  if (!conn || conn->fd < 0)
    return;
  struct epoll_event ev;
  memset (&ev, 0, sizeof (ev));
  ev.events = EPOLLIN | EPOLLERR | EPOLLRDHUP;
  if (conn->st == TP_ST_CONNECTING || conn->tx_hi.len > 0
      || (conn->auth && conn->tx_lo.len > 0))
    ev.events |= EPOLLOUT;
  ev.data.u64 = TP_EV_CONN_BASE | (uint32_t)conn->fd;
  (void)epoll_ctl (epfd, EPOLL_CTL_ADD, conn->fd, &ev);
}

static bool
tp_tx_ring_cap_ok (uint32_t cap)
{
  return cap > 0 && (cap & (cap - 1U)) == 0;
}

static void
tp_tx_ring_free (TpTxRing *ring)
{
  if (!ring)
    return;
  free (ring->buf);
  ring->buf = NULL;
  ring->cap = 0;
  ring->head = 0;
  ring->len = 0;
}

static bool
tp_tx_ring_rsv (TpTxRing *ring, uint32_t need)
{
  if (!ring)
    return false;
  if (need <= ring->cap)
    return true;
  uint32_t old_cap = ring->cap;
  uint32_t base_need = need > TP_TXQ_FRAME_BYTES ? need : TP_TXQ_FRAME_BYTES;
  uint32_t new_cap = old_cap ? old_cap : 1U;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = base_need;
          break;
        }
      new_cap *= 2U;
    }
  while (new_cap < base_need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = base_need;
          break;
        }
      new_cap *= 2U;
    }
  if (!tp_tx_ring_cap_ok (new_cap))
    return false;
  uint8_t *new_buf = malloc (new_cap);
  if (!new_buf)
    return false;
  if (ring->buf && ring->len > 0)
    {
      uint32_t tail = (ring->head + ring->len) & (ring->cap - 1U);
      uint32_t first = ring->len;
      if (tail <= ring->head)
        {
          first = ring->cap - ring->head;
          if (first > ring->len)
            first = ring->len;
        }
      memcpy (new_buf, ring->buf + ring->head, first);
      if (ring->len > first)
        memcpy (new_buf + first, ring->buf, ring->len - first);
    }
  free (ring->buf);
  ring->buf = new_buf;
  ring->cap = new_cap;
  ring->head = 0;
  return true;
}

static bool
tp_tx_ring_write (TpTxRing *ring, const uint8_t *buf, uint32_t len)
{
  if (!ring || !buf || len == 0 || !ring->buf || ring->cap == 0
      || len > (ring->cap - ring->len))
    return false;
  uint32_t tail = (ring->head + ring->len) & (ring->cap - 1U);
  uint32_t first = ring->cap - tail;
  if (first > len)
    first = len;
  memcpy (ring->buf + tail, buf, first);
  if (len > first)
    memcpy (ring->buf, buf + first, len - first);
  ring->len += len;
  return true;
}

static void
tp_pend_free (TpPendQ *q)
{
  if (!q)
    return;
  free (q->buf);
  memset (q, 0, sizeof (*q));
}

static bool
tp_pend_rsv (TpPendQ *q, uint32_t need)
{
  if (!q)
    return false;
  if (need <= q->cap)
    return true;
  uint32_t new_cap = q->cap ? q->cap : TP_TXQ_FRAME_BYTES;
  while (new_cap < need)
    {
      if (new_cap > UINT32_MAX / 2U)
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  uint8_t *new_buf = realloc (q->buf, new_cap);
  if (!new_buf)
    return false;
  q->buf = new_buf;
  q->cap = new_cap;
  return true;
}

static bool
tp_pend_write (TpPendQ *q, const uint8_t *data, size_t len, bool hi)
{
  if (!q || !data || len == 0 || len > TP_PL_MAX)
    return false;
  uint32_t rec_len = 1U + sizeof (uint32_t) + (uint32_t)len;
  if (rec_len > UINT32_MAX - q->len)
    return false;
  uint32_t need = q->len + rec_len;
  if (need > TP_TXQ_FRAME_BYTES * TP_TXQ_STOP_MULT)
    return false;
  if (!tp_pend_rsv (q, need))
    return false;
  uint8_t *dst = q->buf + q->len;
  dst[0] = hi ? 1U : 0U;
  tp_u32_wr (dst + 1U, (uint32_t)len);
  memcpy (dst + 1U + sizeof (uint32_t), data, len);
  q->len = need;
  return true;
}

static bool
tp_pend_flush (TpConn *conn)
{
  if (!conn)
    return false;
  uint32_t off = 0;
  while (off < conn->tx_pend.len)
    {
      if (conn->tx_pend.len - off < 1U + sizeof (uint32_t))
        return false;
      bool hi = conn->tx_pend.buf[off] != 0;
      uint32_t len = tp_u32_rd (conn->tx_pend.buf + off + 1U);
      off += 1U + sizeof (uint32_t);
      if (len == 0 || len > TP_PL_MAX || len > conn->tx_pend.len - off)
        return false;
      if (!tp_conn_enqueue (conn, conn->tx_pend.buf + off, len, hi))
        return false;
      off += len;
    }
  tp_pend_free (&conn->tx_pend);
  return true;
}

static void
tp_tx_ring_drop (TpTxRing *ring, uint32_t len)
{
  if (!ring || len == 0 || len > ring->len || ring->cap == 0)
    return;
  ring->head = (ring->head + len) & (ring->cap - 1U);
  ring->len -= len;
  if (ring->len == 0)
    ring->head = 0;
}

static int
tp_tx_ring_iov (const TpTxRing *ring, struct iovec iov[2])
{
  if (!ring || !iov || ring->len == 0 || !ring->buf || ring->cap == 0)
    return 0;
  uint32_t first = ring->cap - ring->head;
  if (first > ring->len)
    first = ring->len;
  iov[0].iov_base = ring->buf + ring->head;
  iov[0].iov_len = first;
  if (ring->len == first)
    return 1;
  iov[1].iov_base = ring->buf;
  iov[1].iov_len = ring->len - first;
  return 2;
}

static bool
tp_conn_rx_in_rsv (TpConn *conn, uint32_t need)
{
  if (!conn || need == 0)
    return false;
  if (need <= conn->rx_in_cap && conn->rx_in)
    return true;
  uint32_t new_cap = conn->rx_in_cap ? conn->rx_in_cap : TP_TXQ_FRAME_BYTES;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  uint8_t *new_buf = realloc (conn->rx_in, new_cap);
  if (!new_buf)
    return false;
  conn->rx_in = new_buf;
  conn->rx_in_cap = new_cap;
  return true;
}

static void
tp_conn_rx_in_compact (TpConn *conn)
{
  if (!conn || conn->rx_in_off == 0)
    return;
  if (conn->rx_in_off >= conn->rx_in_len)
    {
      conn->rx_in_off = 0;
      conn->rx_in_len = 0;
      return;
    }
  memmove (conn->rx_in, conn->rx_in + conn->rx_in_off,
           conn->rx_in_len - conn->rx_in_off);
  conn->rx_in_len -= conn->rx_in_off;
  conn->rx_in_off = 0;
}

static bool
tp_conn_rx_rsv (TpConn *conn, uint32_t need)
{
  if (!conn || need == 0 || need > (uint32_t)(TP_PL_MAX + TP_WIRE_MAC_SZ))
    return false;
  if (need <= conn->rx_cap && conn->rx_buf)
    return true;
  uint8_t *new_buf = realloc (conn->rx_buf, need);
  if (!new_buf)
    return false;
  conn->rx_buf = new_buf;
  conn->rx_cap = need;
  return true;
}

static bool
tp_wire_tx_rsv (uint32_t need)
{
  if (need == 0 || need > (uint32_t)TP_TXQ_FRAME_BYTES)
    return false;
  if (need <= g_tp_wire_tx_cap && g_tp_wire_tx_buf)
    return true;
  uint8_t *new_buf = realloc (g_tp_wire_tx_buf, need);
  if (!new_buf)
    return false;
  g_tp_wire_tx_buf = new_buf;
  g_tp_wire_tx_cap = need;
  return true;
}

static uint32_t
tp_conn_rx_frame_max (const TpConn *conn)
{
  return (conn && conn->auth) ? (uint32_t)TP_PL_MAX : (uint32_t)UDP_PL_MAX;
}

static TpConn *
tp_conn_new (uint32_t slot_idx)
{
  TpConn *conn = calloc (1, sizeof (*conn));
  if (!conn)
    return NULL;
  conn->slot_idx = slot_idx;
  conn->fd = -1;
  conn->auth_tok = tp_auth_tok_new ();
  return conn;
}

static bool
tp_fd_idx_rsv (TpRt *tp, uint32_t need)
{
  if (!tp)
    return false;
  if (need <= tp->fd_idx_cap)
    return true;
  uint32_t new_cap = tp->fd_idx_cap ? tp->fd_idx_cap : TP_CONN_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  uint32_t *new_arr = realloc (tp->fd_idx_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    return false;
  for (uint32_t i = tp->fd_idx_cap; i < new_cap; i++)
    new_arr[i] = TP_IDX_INV;
  tp->fd_idx_arr = new_arr;
  tp->fd_idx_cap = new_cap;
  return true;
}

static bool
tp_hot_idx_rsv (TpRt *tp, uint32_t need)
{
  if (!tp)
    return false;
  if (need <= tp->peer_hot_cap && need <= tp->ep_hot_cap)
    return true;
  uint32_t new_cap = tp->peer_hot_cap ? tp->peer_hot_cap : TP_CONN_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  uint32_t *peer_hot = malloc (sizeof (*peer_hot) * new_cap);
  if (!peer_hot)
    return false;
  uint32_t *ep_hot = malloc (sizeof (*ep_hot) * new_cap);
  if (!ep_hot)
    {
      free (peer_hot);
      return false;
    }
  free (tp->peer_hot_idx);
  free (tp->ep_hot_idx);
  tp->peer_hot_idx = peer_hot;
  tp->ep_hot_idx = ep_hot;
  tp->peer_hot_cap = new_cap;
  tp->ep_hot_cap = new_cap;
  tp_send_cache_reset (tp);
  return true;
}

static bool
tp_flow_idx_rsv (TpRt *tp, uint32_t need)
{
  if (!tp)
    return false;
  if (need <= tp->flow_cap)
    return true;
  uint32_t new_cap = tp->flow_cap ? tp->flow_cap : TP_CONN_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  TpFlowEnt *new_arr = realloc (tp->flow_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    return false;
  tp->flow_arr = new_arr;
  tp->flow_cap = new_cap;
  return true;
}

static void
tp_flow_idx_prune (TpRt *tp, uint64_t now)
{
  if (!tp || !tp->flow_arr)
    return;
  for (uint32_t i = 0; i < tp->flow_cnt; i++)
    {
      TpFlowEnt *ent = &tp->flow_arr[i];
      bool stale = ent->ts != 0 && now > ent->ts
                   && (now - ent->ts) > TP_FLOW_IDLE_TMO;
      bool dead = ent->conn_idx >= tp->conn_cap
                  || !tp->conn_arr[ent->conn_idx];
      if (!stale && !dead)
        continue;
      tp->flow_arr[i] = tp->flow_arr[tp->flow_cnt - 1U];
      tp->flow_cnt--;
      i--;
    }
}

static void
tp_flow_idx_forget_conn (TpRt *tp, uint32_t conn_idx)
{
  if (!tp || !tp->flow_arr)
    return;
  uint32_t out = 0;
  for (uint32_t i = 0; i < tp->flow_cnt; i++)
    {
      if (tp->flow_arr[i].conn_idx == conn_idx)
        continue;
      if (out != i)
        tp->flow_arr[out] = tp->flow_arr[i];
      out++;
    }
  tp->flow_cnt = out;
}

static bool
tp_conn_fd_bind (TpRt *tp, TpConn *conn, int fd)
{
  if (!tp || !conn || fd < 0)
    return false;
  uint32_t idx = tp_conn_idx (tp, conn);
  if (idx == TP_IDX_INV)
    return false;
  if (!tp_fd_idx_rsv (tp, (uint32_t)fd + 1U))
    return false;
  tp->fd_idx_arr[fd] = idx;
  conn->fd = fd;
  tp_conn_sock_sync (conn);
  return true;
}

static void
tp_conn_fd_unbind (TpRt *tp, const TpConn *conn)
{
  if (!tp || !conn || conn->fd < 0 || !tp->fd_idx_arr
      || (uint32_t)conn->fd >= tp->fd_idx_cap)
    return;
  uint32_t idx = tp_conn_idx (tp, conn);
  if (idx != TP_IDX_INV && tp->fd_idx_arr[conn->fd] == idx)
    tp->fd_idx_arr[conn->fd] = TP_IDX_INV;
}

static void
tp_conn_close (TpRt *tp, int epfd, TpConn *conn)
{
  if (!tp || !conn)
    return;
  uint32_t idx = tp_conn_idx (tp, conn);
  int fd = conn->fd;
  tp_conn_txq_sync (tp, conn);
  if (conn->tx_qd)
    {
      conn->tx_qd = false;
      (void)__atomic_sub_fetch (&tp->tx_qd_cnt, 1U, __ATOMIC_RELAXED);
    }
  if (conn->tx_bp)
    {
      conn->tx_bp = false;
      (void)__atomic_sub_fetch (&tp->tx_bp_cnt, 1U, __ATOMIC_RELAXED);
    }
  tp_conn_fd_unbind (tp, conn);
  conn->fd = -1;
  if (idx != TP_IDX_INV)
    tp_flow_idx_forget_conn (tp, idx);
  if (idx != TP_IDX_INV)
    tp->conn_arr[idx] = NULL;
  tp_send_cache_reset (tp);
  if (fd >= 0)
    {
      (void)epoll_ctl (epfd, EPOLL_CTL_DEL, fd, NULL);
      close (fd);
    }
  tp_tx_ring_free (&conn->tx_hi);
  tp_tx_ring_free (&conn->tx_lo);
  tp_pend_free (&conn->tx_pend);
  free (conn->rx_in);
  free (conn->rx_buf);
  free (conn);
}

static void
tp_conn_drain_start (TpRt *tp, int epfd, TpConn *conn)
{
  if (!tp || !conn || conn->auth || conn->fd < 0)
    return;
  conn->drain = true;
  if (conn->tx_q_bytes != 0)
    {
      conn->tx_q_bytes = 0;
      tp_tx_ring_free (&conn->tx_hi);
      tp_tx_ring_free (&conn->tx_lo);
      tp_pend_free (&conn->tx_pend);
      tp_conn_txq_sync (tp, conn);
    }
  conn->rx_in_off = conn->rx_in_len;
  tp_ev_upd (epfd, conn);
}

static bool
tp_conn_rsv (TpRt *tp, uint32_t need)
{
  if (!tp)
    return false;
  if (need <= tp->conn_cap)
    return true;
  uint32_t new_cap = tp->conn_cap ? tp->conn_cap : TP_CONN_CAP_INIT;
  while (new_cap < need)
    {
      if (new_cap > (UINT32_MAX / 2U))
        {
          new_cap = need;
          break;
        }
      new_cap *= 2U;
    }
  TpConn **new_arr = realloc (tp->conn_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    {
      fprintf (stderr,
               "tcp: failed to expand connection table to %u entries\n",
               (unsigned)new_cap);
      return false;
    }
  tp->conn_arr = new_arr;
  for (uint32_t i = tp->conn_cap; i < new_cap; i++)
    tp->conn_arr[i] = NULL;
  if (!tp_hot_idx_rsv (tp, new_cap))
    return false;
  tp->conn_cap = new_cap;
  return true;
}

static TpConn *
tp_conn_alloc (TpRt *tp)
{
  if (!tp)
    return NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      if (!tp->conn_arr[i])
        {
          TpConn *conn = tp_conn_new (i);
          if (!conn)
            return NULL;
          tp->conn_arr[i] = conn;
          return conn;
        }
    }
  tp_conn_limit_warn (tp, "connection");
  uint32_t old_cap = tp->conn_cap;
  if (!tp_conn_rsv (tp, old_cap + 1U))
    return NULL;
  TpConn *conn = tp_conn_new (old_cap);
  if (!conn)
    return NULL;
  tp->conn_arr[old_cap] = conn;
  return conn;
}

static TpConn *
tp_conn_by_fd (TpRt *tp, int fd)
{
  if (!tp || fd < 0 || !tp->fd_idx_arr || (uint32_t)fd >= tp->fd_idx_cap)
    return NULL;
  uint32_t idx = tp->fd_idx_arr[fd];
  if (idx == TP_IDX_INV || idx >= tp->conn_cap)
    return NULL;
  TpConn *conn = tp->conn_arr[idx];
  return (conn && conn->fd == fd) ? conn : NULL;
}

static TpConn *
tp_conn_by_peer (TpRt *tp, const uint8_t peer_lla[16])
{
  if (!tp || !peer_lla)
    return NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!conn || conn->fd < 0 || !conn->auth)
        continue;
      if (tp_conn_peer_match (conn, peer_lla))
        return conn;
    }
  return NULL;
}

static TpConn *
tp_conn_by_ep (TpRt *tp, const uint8_t ip[16], uint16_t port)
{
  if (!tp || !ip || port == 0)
    return NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!conn || conn->fd < 0)
        continue;
      if (memcmp (conn->route_ip, ip, 16) != 0 || conn->route_port != port)
        continue;
      return conn;
    }
  return NULL;
}

static TpConn *
tp_conn_hot_lookup (TpRt *tp, const uint8_t ip[16], uint16_t port,
                    const uint8_t peer_lla[16], bool has_peer)
{
  if (!tp || !ip || port == 0)
    return NULL;
  if (has_peer && tp->peer_hot_idx && tp->peer_hot_cap > 0)
    {
      uint32_t idx = tp->peer_hot_idx[tp_hash_lla (peer_lla)
                                      & (tp->peer_hot_cap - 1U)];
      if (idx != TP_IDX_INV && idx < tp->conn_cap)
        {
          TpConn *conn = tp->conn_arr[idx];
          if (conn && conn->st == TP_ST_ESTABLISHED && conn->auth
              && tp_conn_peer_match (conn, peer_lla))
            return conn;
        }
    }
  if (tp->ep_hot_idx && tp->ep_hot_cap > 0)
    {
      uint32_t idx
        = tp->ep_hot_idx[tp_hash_ep (ip, port) & (tp->ep_hot_cap - 1U)];
      if (idx != TP_IDX_INV && idx < tp->conn_cap)
        {
          TpConn *conn = tp->conn_arr[idx];
          if (conn && conn->st == TP_ST_ESTABLISHED
              && memcmp (conn->route_ip, ip, 16) == 0
              && conn->route_port == port)
            return conn;
        }
    }
  return NULL;
}

static bool
tp_conn_route_match (const TpConn *conn, const uint8_t ip[16], uint16_t port,
                     const uint8_t peer_lla[16], bool has_peer)
{
  if (!conn || conn->fd < 0 || !ip || port == 0)
    return false;
  if (memcmp (conn->route_ip, ip, 16) != 0 || conn->route_port != port)
    return false;
  if (has_peer && !tp_conn_peer_match (conn, peer_lla))
    return false;
  return true;
}

static bool
tp_flow_ent_match (const TpFlowEnt *ent, const uint8_t ip[16], uint16_t port,
                   const uint8_t peer_lla[16], bool has_peer,
                   uint32_t flow_hash)
{
  if (!ent || !ip || port == 0 || flow_hash == 0)
    return false;
  if (ent->flow_hash != flow_hash || ent->has_peer != has_peer)
    return false;
  if (has_peer)
    {
      if (memcmp (ent->peer_lla, peer_lla, 16) != 0)
        return false;
    }
  else if (ent->route_port != port || memcmp (ent->route_ip, ip, 16) != 0)
    return false;
  return true;
}

static bool
tp_conn_flow_peer_match (const TpConn *conn, const uint8_t ip[16],
                         uint16_t port, const uint8_t peer_lla[16],
                         bool has_peer)
{
  return has_peer ? tp_conn_peer_match (conn, peer_lla)
                  : tp_conn_route_match (conn, ip, port, peer_lla, has_peer);
}

static TpConn *
tp_flow_idx_lookup (TpRt *tp, const uint8_t ip[16], uint16_t port,
                    const uint8_t peer_lla[16], bool has_peer,
                    uint32_t flow_hash, uint64_t now)
{
  if (!tp || !tp->flow_arr)
    return NULL;
  tp_flow_idx_prune (tp, now);
  for (uint32_t i = 0; i < tp->flow_cnt; i++)
    {
      TpFlowEnt *ent = &tp->flow_arr[i];
      if (!tp_flow_ent_match (ent, ip, port, peer_lla, has_peer, flow_hash))
        continue;
      if (ent->conn_idx < tp->conn_cap)
        {
          TpConn *conn = tp->conn_arr[ent->conn_idx];
          if (tp_conn_flow_peer_match (conn, ip, port, peer_lla, has_peer))
            {
              ent->ts = now;
              return conn;
            }
        }
      tp->flow_arr[i] = tp->flow_arr[tp->flow_cnt - 1U];
      tp->flow_cnt--;
      i--;
    }
  return NULL;
}

static bool
tp_flow_idx_note (TpRt *tp, const uint8_t ip[16], uint16_t port,
                  const uint8_t peer_lla[16], bool has_peer,
                  uint32_t flow_hash, const TpConn *conn, uint64_t now)
{
  if (!tp || !ip || port == 0 || flow_hash == 0 || !conn)
    return false;
  uint32_t conn_idx = tp_conn_idx (tp, conn);
  if (conn_idx == TP_IDX_INV)
    return false;
  for (uint32_t i = 0; i < tp->flow_cnt; i++)
    {
      TpFlowEnt *ent = &tp->flow_arr[i];
      if (!tp_flow_ent_match (ent, ip, port, peer_lla, has_peer, flow_hash))
        continue;
      ent->conn_idx = conn_idx;
      ent->ts = now;
      return true;
    }
  if (!tp_flow_idx_rsv (tp, tp->flow_cnt + 1U))
    return false;
  TpFlowEnt *ent = &tp->flow_arr[tp->flow_cnt++];
  memset (ent, 0, sizeof (*ent));
  memcpy (ent->route_ip, ip, 16);
  if (has_peer)
    memcpy (ent->peer_lla, peer_lla, 16);
  ent->route_port = port;
  ent->flow_hash = flow_hash;
  ent->conn_idx = conn_idx;
  ent->ts = now;
  ent->has_peer = has_peer;
  return true;
}

static TpConn *
tp_conn_lane_pick (TpRt *tp, const uint8_t ip[16], uint16_t port,
                   const uint8_t peer_lla[16], bool has_peer)
{
  if (!tp || !ip || port == 0)
    return NULL;
  TpConn *best = NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!tp_conn_flow_peer_match (conn, ip, port, peer_lla, has_peer))
        continue;
      if (conn->tx_bp)
        continue;
      if (!best || conn->tx_q_bytes < best->tx_q_bytes)
        best = conn;
    }
  return best;
}

static TpConn *
tp_conn_flow_lookup (TpRt *tp, const uint8_t ip[16], uint16_t port,
                     const uint8_t peer_lla[16], bool has_peer,
                     uint32_t flow_hash)
{
  if (!tp || !ip || port == 0 || flow_hash == 0)
    return NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!tp_conn_flow_peer_match (conn, ip, port, peer_lla, has_peer))
        continue;
      if (conn->lane_hash == flow_hash)
        return conn;
    }
  return NULL;
}

static bool
tp_conn_enqueue (TpConn *conn, const uint8_t *data, size_t len, bool hi)
{
  if (!conn)
    return false;
  if (!data || len == 0 || len > TP_PL_MAX)
    return false;
  if (!conn->wire_ready)
    {
      if (conn->inbound)
        return false;
      randombytes_buf (conn->wire_salt, TP_WIRE_SALT_SZ);
      tp_wire_derive (conn);
    }
  size_t frame_len = sizeof (uint32_t) + len;
  uint32_t rem = (uint32_t)frame_len;
  uint32_t salt_len
      = (!conn->inbound && !conn->wire_salt_tx) ? TP_WIRE_SALT_SZ : 0U;
  TpTxRing *ring = hi ? &conn->tx_hi : &conn->tx_lo;
  if (salt_len > UINT32_MAX - rem
      || rem + salt_len > UINT32_MAX - conn->tx_q_bytes)
    return false;
  uint32_t hi_add = salt_len + (hi ? rem : 0U);
  uint32_t lo_add = hi ? 0U : rem;
  if (hi_add > UINT32_MAX - conn->tx_hi.len
      || lo_add > UINT32_MAX - conn->tx_lo.len)
    return false;
  if (hi_add > 0 && !tp_tx_ring_rsv (&conn->tx_hi, conn->tx_hi.len + hi_add))
    return false;
  if (lo_add > 0 && !tp_tx_ring_rsv (&conn->tx_lo, conn->tx_lo.len + lo_add))
    return false;
  if (!tp_wire_tx_rsv ((uint32_t)frame_len))
    return false;
  size_t wire_len = 0;
  bool ok = tp_wire_encode (conn, data, len, g_tp_wire_tx_buf, &wire_len);
  if (!ok || wire_len != frame_len)
    return false;
  if (salt_len > 0
      && !tp_tx_ring_write (&conn->tx_hi, conn->wire_salt, salt_len))
    return false;
  if (!tp_tx_ring_write (ring, g_tp_wire_tx_buf, (uint32_t)wire_len))
    return false;
  if (salt_len > 0)
    {
      conn->wire_salt_tx = true;
      conn->tx_q_bytes += salt_len;
    }
  conn->tx_q_bytes += rem;
  return true;
}

static bool
tp_conn_flush (TpRt *tp, int epfd, TpConn *conn)
{
  if (!tp || !conn || conn->fd < 0 || conn->st != TP_ST_ESTABLISHED)
    return false;
  conn->tx_defer = false;
  for (;;)
    {
      TpTxRing *ring = conn->tx_hi.len > 0 ? &conn->tx_hi : &conn->tx_lo;
      if (ring->len == 0)
        {
          tp_conn_txq_sync (tp, conn);
          tp_ev_upd (epfd, conn);
          return true;
        }
      if (!conn->auth && ring == &conn->tx_lo)
        {
          tp_conn_txq_sync (tp, conn);
          tp_ev_upd (epfd, conn);
          return true;
        }
      struct iovec iov[2];
      int iovcnt = tp_tx_ring_iov (ring, iov);
      bool more = ring == &conn->tx_hi && conn->auth && conn->tx_lo.len > 0;
      ssize_t n = tp_sock_writev (conn->fd, iov, iovcnt, more);
      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              tp_conn_txq_sync (tp, conn);
              tp_ev_upd (epfd, conn);
              return true;
            }
          return false;
        }
      if (n == 0)
        {
          tp_conn_txq_sync (tp, conn);
          tp_ev_upd (epfd, conn);
          return true;
        }
      tp_tx_ring_drop (ring, (uint32_t)n);
      if (conn->tx_q_bytes >= (uint32_t)n)
        conn->tx_q_bytes -= (uint32_t)n;
      else
        conn->tx_q_bytes = 0;
      tp_conn_txq_sync (tp, conn);
    }
}

static bool
tp_conn_tx_frame (TpRt *tp, int epfd, TpConn *conn, const uint8_t *data,
                  size_t len, bool hi)
{
  return tp_conn_tx_frame_ex (tp, epfd, conn, data, len, hi, false);
}

static bool
tp_conn_tx_frame_ex (TpRt *tp, int epfd, TpConn *conn, const uint8_t *data,
                     size_t len, bool hi, bool preauth_ok)
{
  if (!tp || !conn || conn->fd < 0 || !data || len == 0 || len > TP_PL_MAX)
    return false;
  if (!conn->auth && !preauth_ok)
    {
      if (!conn->hello_tx && !conn->inbound && !tp_send_hello (conn))
        return false;
      if (!tp_pend_write (&conn->tx_pend, data, len, hi))
        return false;
      tp_ev_upd (epfd, conn);
      return true;
    }
  if (conn->st != TP_ST_ESTABLISHED)
    {
      if (!tp_conn_enqueue (conn, data, len, hi))
        return false;
      tp_conn_txq_sync (tp, conn);
      tp_ev_upd (epfd, conn);
      return true;
    }
  if (!tp_conn_enqueue (conn, data, len, hi))
    return false;
  tp_conn_txq_sync (tp, conn);
  tp_ev_upd (epfd, conn);
  if (!hi && !conn->auth)
    return true;
  if (!hi)
    {
      if (g_tp_batch_depth != 0)
        {
          conn->tx_defer = true;
          if (conn->tx_q_bytes < tp_conn_txq_batch_bytes (conn))
            return true;
          conn->tx_defer = false;
          return tp_conn_flush (tp, epfd, conn);
        }
      return tp_conn_flush (tp, epfd, conn);
    }
  return tp_conn_flush (tp, epfd, conn);
}

static bool
tp_send_hello (TpConn *conn)
{
  if (!conn || !g_tp_cry || !g_tp_cfg)
    return false;
  if (conn->hello_tx)
    return true;
  uint8_t ping_buf[UDP_PL_MAX];
  size_t ping_len = 0;
  if (conn->auth_tok == 0)
    conn->auth_tok = tp_auth_tok_new ();
  if (conn->auth)
    ping_bld (g_tp_cry, g_tp_cfg->addr, g_tp_cfg->port, sys_ts (), g_tp_sid,
              conn->auth_tok, ping_buf, &ping_len);
  else if (tp_kx_ensure (conn))
    tp_ping_bld (g_tp_cry, g_tp_cfg->addr, g_tp_cfg->port, sys_ts (), g_tp_sid,
                 conn->auth_tok, conn->wire_kx_pk, ping_buf, &ping_len);
  else
    return false;
  bool ok
    = tp_conn_tx_frame_ex (g_tp_rt, g_tp_epfd, conn, ping_buf, ping_len, true,
                           true);
  if (!ok)
    return false;
  conn->hello_tx = true;
  return true;
}

static void
tp_conn_route_sync (TpConn *conn, const Rt *rt)
{
  if (!conn || !rt || !conn->auth)
    return;
  uint8_t route_ip[16] = { 0 };
  uint16_t route_port = 0;
  if (rt_peer_ep_fnd (rt, conn->peer_lla, route_ip, &route_port))
    {
      memcpy (conn->route_ip, route_ip, 16);
      conn->route_port = route_port;
    }
}

static bool
tp_conn_auth_finish (TpRt *tp, int epfd, TpConn *conn, Rt *rt,
                     const Cfg *cfg, const uint8_t peer_lla[16],
                     uint64_t peer_sid, uint16_t peer_port)
{
  if (!tp || !conn || !cfg || !peer_lla)
    return false;
  if (conn->inbound && cfg->p2p != P2P_EN
      && !tp_inbound_static_ok (rt, peer_lla, conn->sock_ip, peer_port))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  if (conn->inbound && !tp_ip_is_zero (conn->sock_ip) && peer_port != 0)
    {
      memcpy (conn->route_ip, conn->sock_ip, 16);
      conn->route_port = peer_port;
    }
  uint64_t now = sys_ts ();
  if (rt && rt_peer_sess (rt, peer_lla, peer_sid, now))
    rx_rp_rst_lla (rt, peer_lla);
  if (rt && conn->route_port != 0 && !tp_ip_is_zero (conn->route_ip))
    rt_ep_upd (rt, peer_lla, conn->route_ip, conn->route_port, TP_MASK_TCP,
               now);
  uint32_t slot_idx = conn->slot_idx;
  memcpy (conn->peer_lla, peer_lla, 16);
  if (!tp_conn_rx_rsv (conn, TP_PL_MAX))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  if (conn->inbound && !tp_salt_rp_commit (conn->wire_salt, now))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  if (!tp_wire_rekey_fs (conn))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  conn->auth = true;
  if (!tp_pend_flush (conn))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  tp_conn_route_sync (conn, rt);
  tp_conn_dedup_peer (tp, epfd, cfg->addr, peer_lla);
  if (!tp_conn_slot_live (tp, slot_idx, conn))
    return false;
  if ((conn->tx_hi.len > 0 || conn->tx_lo.len > 0)
      && !tp_conn_flush (tp, epfd, conn))
    {
      tp_conn_close (tp, epfd, conn);
      return false;
    }
  return tp_conn_slot_live (tp, slot_idx, conn);
}

static TpAuthRes
tp_conn_auth (TpRt *tp, int epfd, TpConn *conn, Rt *rt, const Cfg *cfg,
              const uint8_t *frame, size_t len)
{
  if (!tp || !conn || !cfg || !g_tp_cry || !frame || len == 0)
    return TP_AUTH_FAIL;
  uint8_t pt_buf[UDP_PL_MAX];
  PktHdr hdr;
  uint8_t *pt = NULL;
  size_t pt_len = 0;
  if (pkt_dec (g_tp_cry, (uint8_t *)frame, len, pt_buf, sizeof (pt_buf), &hdr,
               &pt, &pt_len)
      != 0)
    return TP_AUTH_FAIL;
  uint8_t peer_lla[16] = { 0 };
  uint64_t peer_sid = 0;
  uint16_t peer_port = 0;
  uint64_t prb_tok = 0;
  if (hdr.pkt_type == PT_PING)
    {
      uint64_t req_ts = 0;
      if (on_ping (pt, pt_len, &req_ts, &peer_sid, peer_lla, &peer_port,
                   &prb_tok)
          != 0
          || prb_tok == 0 || pt_len < TP_PING_KX_PL_SZ
          || !tp_kx_ensure (conn))
        return TP_AUTH_FAIL;
      memcpy (conn->wire_peer_pk, pt + PING_PL_SZ, TP_KX_PUB_SZ);
      conn->wire_peer_kx_ready = true;
      if (!cry_peer_rekey (g_tp_cry, cfg->addr, peer_lla,
                           pt + PING_PL_SZ + TP_KX_PUB_SZ))
        fprintf (stderr, "crypto: tcp peer rekey failed on ping\n");
      uint8_t pong_buf[UDP_PL_MAX];
      size_t pong_len = 0;
      tp_pong_bld (g_tp_cry, cfg->addr, cfg->port, req_ts, g_tp_sid,
                   sys_ts (), prb_tok, conn->wire_kx_pk, pong_buf, &pong_len);
      if (!tp_conn_tx_frame_ex (tp, epfd, conn, pong_buf, pong_len, true,
                                true))
        return TP_AUTH_FAIL;
    }
  else if (hdr.pkt_type == PT_PONG)
    {
      uint64_t req_ts = 0;
      uint64_t peer_rx_ts = 0;
      if (on_pong (pt, pt_len, &req_ts, &peer_sid, peer_lla, &peer_port,
                   &peer_rx_ts, &prb_tok)
          != 0
          || prb_tok == 0 || prb_tok != conn->auth_tok
          || pt_len < TP_PONG_KX_PL_SZ)
        return TP_AUTH_FAIL;
      memcpy (conn->wire_peer_pk, pt + PONG_PL_SZ, TP_KX_PUB_SZ);
      conn->wire_peer_kx_ready = true;
      if (!cry_peer_rekey (g_tp_cry, cfg->addr, peer_lla,
                           pt + PONG_PL_SZ + TP_KX_PUB_SZ))
        fprintf (stderr, "crypto: tcp peer rekey failed on pong\n");
    }
  else
    {
      return TP_AUTH_FAIL;
    }

  return tp_conn_auth_finish (tp, epfd, conn, rt, cfg, peer_lla, peer_sid,
                              peer_port)
             ? TP_AUTH_OK
             : TP_AUTH_FAIL;
}

static TpProto
tp_pick_proto (const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
               uint16_t port)
{
  if (!cfg || !ip || port == 0)
    return TP_PROTO_NONE;
  return cfg_tp_pick (cfg, rt_ep_tp_mask (rt, ip, port));
}

static bool
tp_probe_allow (const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
                uint16_t port)
{
  if (!cfg || !ip || port == 0)
    return false;
  if (!tp_mask_has (cfg->tp_mask, TP_PROTO_TCP))
    return false;
  if (tp_pick_proto (rt, cfg, ip, port) == TP_PROTO_TCP)
    return true;
  if (!rt)
    return false;
  for (uint32_t i = 0; i < rt->cnt; i++)
    {
      const Re *re = &rt->re_arr[i];
      if (re->r2d != 0 || re->state == RT_DED || !re->is_static)
        continue;
      if (memcmp (re->ep_ip, ip, 16) != 0 || re->ep_port != port)
        continue;
      if (!IS_LLA_VAL (re->lla))
        return true;
    }
  return false;
}

int
tp_rt_init (TpRt *tp, uint16_t port)
{
  if (!tp || port == 0)
    return -1;
  memset (tp, 0, sizeof (*tp));
  tp->listen_fd = -1;
  pthread_mutex_init (&tp->mtx, NULL);
  tp_send_cache_reset (tp);
  if (!tp_conn_rsv (tp, TP_CONN_CAP_INIT)
      || !tp_fd_idx_rsv (tp, TP_CONN_CAP_INIT)
      || !tp_hot_idx_rsv (tp, TP_CONN_CAP_INIT))
    {
      free (tp->fd_idx_arr);
      tp->fd_idx_arr = NULL;
      tp->fd_idx_cap = 0;
      free (tp->peer_hot_idx);
      tp->peer_hot_idx = NULL;
      tp->peer_hot_cap = 0;
      free (tp->ep_hot_idx);
      tp->ep_hot_idx = NULL;
      tp->ep_hot_cap = 0;
      pthread_mutex_destroy (&tp->mtx);
      return -1;
    }
  int fd = socket (AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      free (tp->conn_arr);
      tp->conn_arr = NULL;
      tp->conn_cap = 0;
      free (tp->fd_idx_arr);
      tp->fd_idx_arr = NULL;
      tp->fd_idx_cap = 0;
      free (tp->peer_hot_idx);
      tp->peer_hot_idx = NULL;
      tp->peer_hot_cap = 0;
      free (tp->ep_hot_idx);
      tp->ep_hot_idx = NULL;
      tp->ep_hot_cap = 0;
      pthread_mutex_destroy (&tp->mtx);
      return -1;
    }
  int one = 1;
  (void)setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
  (void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
  int v6only = 0;
  (void)setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof (v6only));
  struct sockaddr_in6 addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (port);
  if (bind (fd, (struct sockaddr *)&addr, sizeof (addr)) != 0)
    {
      close (fd);
      free (tp->conn_arr);
      tp->conn_arr = NULL;
      tp->conn_cap = 0;
      free (tp->fd_idx_arr);
      tp->fd_idx_arr = NULL;
      tp->fd_idx_cap = 0;
      free (tp->peer_hot_idx);
      tp->peer_hot_idx = NULL;
      tp->peer_hot_cap = 0;
      free (tp->ep_hot_idx);
      tp->ep_hot_idx = NULL;
      tp->ep_hot_cap = 0;
      pthread_mutex_destroy (&tp->mtx);
      return -1;
    }
  if (listen (fd, SOMAXCONN) != 0)
    {
      close (fd);
      free (tp->conn_arr);
      tp->conn_arr = NULL;
      tp->conn_cap = 0;
      free (tp->fd_idx_arr);
      tp->fd_idx_arr = NULL;
      tp->fd_idx_cap = 0;
      free (tp->peer_hot_idx);
      tp->peer_hot_idx = NULL;
      tp->peer_hot_cap = 0;
      free (tp->ep_hot_idx);
      tp->ep_hot_idx = NULL;
      tp->ep_hot_cap = 0;
      pthread_mutex_destroy (&tp->mtx);
      return -1;
    }
  tp->listen_fd = fd;
  return 0;
}

void
tp_rt_free (TpRt *tp)
{
  if (!tp)
    return;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr ? tp->conn_arr[i] : NULL;
      if (!conn)
        continue;
      if (conn->fd >= 0)
        close (conn->fd);
      tp->conn_arr[i] = NULL;
      tp_tx_ring_free (&conn->tx_hi);
      tp_tx_ring_free (&conn->tx_lo);
      tp_pend_free (&conn->tx_pend);
      free (conn->rx_in);
      free (conn->rx_buf);
      free (conn);
    }
  free (tp->conn_arr);
  tp->conn_arr = NULL;
  tp->conn_cap = 0;
  free (tp->fd_idx_arr);
  tp->fd_idx_arr = NULL;
  tp->fd_idx_cap = 0;
  free (tp->peer_hot_idx);
  tp->peer_hot_idx = NULL;
  tp->peer_hot_cap = 0;
  free (tp->ep_hot_idx);
  tp->ep_hot_idx = NULL;
  tp->ep_hot_cap = 0;
  free (tp->flow_arr);
  tp->flow_arr = NULL;
  tp->flow_cnt = 0;
  tp->flow_cap = 0;
  tp_send_cache_reset (tp);
  if (tp->listen_fd >= 0)
    close (tp->listen_fd);
  tp->listen_fd = -1;
  free (g_tp_wire_tx_buf);
  g_tp_wire_tx_buf = NULL;
  g_tp_wire_tx_cap = 0;
  free (g_tp_salt_rp);
  g_tp_salt_rp = NULL;
  g_tp_salt_rp_cnt = 0;
  g_tp_salt_rp_cap = 0;
  pthread_mutex_destroy (&tp->mtx);
}

int
tp_rt_listen_fd_get (const TpRt *tp)
{
  return tp ? tp->listen_fd : -1;
}

void
tp_glb_bind (TpRt *tp, int epfd, Cry *cry_ctx, const Cfg *cfg, uint64_t sid)
{
  g_tp_rt = tp;
  g_tp_epfd = epfd;
  g_tp_cry = cry_ctx;
  g_tp_cfg = cfg;
  g_tp_sid = sid;
  g_tp_owner_tid = pthread_self ();
  g_tp_owner_set = true;
}

void
tp_glb_unbind (void)
{
  g_tp_rt = NULL;
  g_tp_epfd = -1;
  g_tp_cry = NULL;
  g_tp_cfg = NULL;
  g_tp_sid = 0;
  g_tp_owner_set = false;
}

bool
tp_rtt_get (const uint8_t ip[16], uint16_t port, uint32_t *out_rtt_ms)
{
  if (!g_tp_rt || !ip || port == 0 || !out_rtt_ms)
    return false;
  tp_lock (g_tp_rt);
  TpConn *conn = tp_conn_by_ep (g_tp_rt, ip, port);
  bool ok = tp_conn_rtt_ms_get (conn, out_rtt_ms);
  tp_unlock (g_tp_rt);
  return ok;
}

bool
tp_alive_get (const uint8_t peer_lla[16], const uint8_t ip[16], uint16_t port)
{
  if (!g_tp_rt || !peer_lla || !ip || port == 0 || tp_lla_is_zero (peer_lla))
    return false;
  tp_lock (g_tp_rt);
  TpConn *conn = tp_conn_by_peer (g_tp_rt, peer_lla);
  bool ok = conn && conn->fd >= 0 && conn->st == TP_ST_ESTABLISHED
            && conn->auth && memcmp (conn->route_ip, ip, 16) == 0
            && conn->route_port == port;
  tp_unlock (g_tp_rt);
  return ok;
}

bool
tp_send_fd (int fd, const uint8_t *data, size_t len)
{
  if (!g_tp_rt)
    return false;
  tp_lock (g_tp_rt);
  TpConn *conn = tp_conn_by_fd (g_tp_rt, fd);
  if (!conn || conn->st != TP_ST_ESTABLISHED)
    {
      tp_unlock (g_tp_rt);
      return false;
    }
  bool ok = tp_conn_tx_frame (g_tp_rt, g_tp_epfd, conn, data, len, true);
  if (!ok)
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_send_cache_note (g_tp_rt, conn);
  tp_unlock (g_tp_rt);
  return true;
}

static void
tp_flush_deferred (void)
{
  if (!g_tp_rt || g_tp_epfd < 0)
    return;
  tp_lock (g_tp_rt);
  for (uint32_t i = 0; i < g_tp_rt->conn_cap; i++)
    {
      TpConn *conn = g_tp_rt->conn_arr[i];
      if (!conn || conn->fd < 0 || conn->st != TP_ST_ESTABLISHED)
        continue;
      if (!conn->tx_defer)
        continue;
      if (!tp_conn_flush (g_tp_rt, g_tp_epfd, conn))
        tp_conn_close (g_tp_rt, g_tp_epfd, conn);
    }
  tp_unlock (g_tp_rt);
}

void
tp_batch_begin (void)
{
  if (!g_tp_rt || g_tp_epfd < 0)
    return;
  if (g_tp_batch_depth == UINT32_MAX)
    return;
  g_tp_batch_depth++;
}

void
tp_batch_end (void)
{
  if (!g_tp_rt || g_tp_epfd < 0 || g_tp_batch_depth == 0)
    return;
  g_tp_batch_depth--;
  if (g_tp_batch_depth != 0)
    return;
  if (tp_owner_thread ())
    tp_flush_deferred ();
}

static bool
tp_send_kind (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len, bool hi,
              uint32_t flow_hash)
{
  if (!udp || !rt || !cfg || !ip || port == 0 || !data || len == 0)
    return false;
  TpProto proto = tp_pick_proto (rt, cfg, ip, port);
  if (proto == TP_PROTO_NONE)
    return false;
  if (proto != TP_PROTO_TCP)
    {
      udp_tx (udp, ip, port, data, len);
      return true;
    }
  if (!g_tp_rt || g_tp_epfd < 0 || !g_tp_cry || !g_tp_cfg)
    return false;

  tp_lock (g_tp_rt);
  uint8_t peer_lla[16] = { 0 };
  bool has_peer = rt_ep_peer_lla (rt, ip, port, peer_lla);
  uint64_t now = sys_ts ();
  flow_hash = hi ? 0 : tp_flow_hash_norm (flow_hash);
  TpConn *conn = flow_hash != 0
                   ? tp_flow_idx_lookup (g_tp_rt, ip, port, peer_lla,
                                         has_peer, flow_hash, now)
                   : tp_conn_hot_lookup (g_tp_rt, ip, port, peer_lla,
                                         has_peer);
  if (!conn && flow_hash != 0)
    {
      conn = tp_conn_flow_lookup (g_tp_rt, ip, port, peer_lla, has_peer,
                                  flow_hash);
      if (conn)
        (void)tp_flow_idx_note (g_tp_rt, ip, port, peer_lla, has_peer,
                                flow_hash, conn, now);
    }
  if (!conn && flow_hash != 0)
    {
      conn = tp_conn_lane_pick (g_tp_rt, ip, port, peer_lla, has_peer);
      if (conn)
        (void)tp_flow_idx_note (g_tp_rt, ip, port, peer_lla, has_peer,
                                flow_hash, conn, now);
    }
  if (flow_hash == 0)
    {
      if (!conn && has_peer)
        conn = tp_conn_by_peer (g_tp_rt, peer_lla);
      if (!conn)
        conn = tp_conn_by_ep (g_tp_rt, ip, port);
    }
  if (conn)
    {
      bool ok = tp_conn_tx_frame (g_tp_rt, g_tp_epfd, conn, data, len, hi);
      if (!ok)
        {
          tp_conn_close (g_tp_rt, g_tp_epfd, conn);
          tp_unlock (g_tp_rt);
          return false;
        }
      tp_send_cache_note (g_tp_rt, conn);
      tp_unlock (g_tp_rt);
      return true;
    }

  int fd = socket (AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_fd_cfg (fd);
  int syncnt = TP_CONN_SYN_RETRIES;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof (syncnt));
  struct sockaddr_in6 sa;
  memset (&sa, 0, sizeof (sa));
  sa.sin6_family = AF_INET6;
  sa.sin6_port = htons (port);
  memcpy (sa.sin6_addr.s6_addr, ip, 16);
  TpConn *n_conn = tp_conn_alloc (g_tp_rt);
  if (!n_conn)
    {
      close (fd);
      tp_unlock (g_tp_rt);
      return false;
    }
  if (!tp_conn_fd_bind (g_tp_rt, n_conn, fd))
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  n_conn->st = TP_ST_CONNECTING;
  n_conn->ts = now;
  n_conn->inbound = false;
  memcpy (n_conn->route_ip, ip, 16);
  n_conn->route_port = port;
  n_conn->lane_hash = flow_hash;
  if (has_peer)
    memcpy (n_conn->peer_lla, peer_lla, 16);
  if (flow_hash != 0)
    (void)tp_flow_idx_note (g_tp_rt, ip, port, peer_lla, has_peer, flow_hash,
                            n_conn, now);
  int rc = connect (fd, (struct sockaddr *)&sa, sizeof (sa));
  if (rc == 0)
    {
      n_conn->st = TP_ST_ESTABLISHED;
      if (!tp_send_hello (n_conn))
        {
          tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
          tp_unlock (g_tp_rt);
          return false;
        }
      if (!tp_conn_tx_frame (g_tp_rt, g_tp_epfd, n_conn, data, len, hi))
        {
          tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
          tp_unlock (g_tp_rt);
          return false;
        }
      tp_send_cache_note (g_tp_rt, n_conn);
    }
  else if (errno != EINPROGRESS)
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  else if (!tp_conn_tx_frame (g_tp_rt, g_tp_epfd, n_conn, data, len, false))
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_ev_add (g_tp_epfd, n_conn);
  tp_unlock (g_tp_rt);
  return true;
}

bool
tp_send (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
         uint16_t port, const uint8_t *data, size_t len)
{
  return tp_send_kind (udp, rt, cfg, ip, port, data, len, false, 0);
}

bool
tp_send_flow (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len,
              uint32_t flow_hash)
{
  return tp_send_kind (udp, rt, cfg, ip, port, data, len, false, flow_hash);
}

bool
tp_send_ctrl (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len)
{
  return tp_send_kind (udp, rt, cfg, ip, port, data, len, true, 0);
}

bool
tp_probe (const Rt *rt, const Cfg *cfg, const uint8_t ip[16], uint16_t port)
{
  if (!rt || !cfg || !ip || port == 0)
    return false;
  if (!tp_probe_allow (rt, cfg, ip, port))
    return false;
  if (!g_tp_rt || g_tp_epfd < 0 || !g_tp_cry || !g_tp_cfg)
    return false;

  tp_lock (g_tp_rt);
  uint8_t peer_lla[16] = { 0 };
  bool has_peer = rt_ep_peer_lla (rt, ip, port, peer_lla);
  TpConn *conn = tp_conn_hot_lookup (g_tp_rt, ip, port, peer_lla, has_peer);
  if (!conn && has_peer)
    conn = tp_conn_by_peer (g_tp_rt, peer_lla);
  if (!conn)
    conn = tp_conn_by_ep (g_tp_rt, ip, port);
  if (conn)
    {
      bool ok = true;
      if (conn->st == TP_ST_CONNECTING)
        {
          int err = 0;
          socklen_t err_len = sizeof (err);
          if (getsockopt (conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) == 0
              && err == 0)
            conn->st = TP_ST_ESTABLISHED;
        }
      if (conn->st == TP_ST_ESTABLISHED && !conn->hello_tx)
        ok = tp_send_hello (conn);
      tp_send_cache_note (g_tp_rt, conn);
      tp_unlock (g_tp_rt);
      return ok;
    }

  int fd = socket (AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_fd_cfg (fd);
  int syncnt = TP_CONN_SYN_RETRIES;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof (syncnt));
  struct sockaddr_in6 sa;
  memset (&sa, 0, sizeof (sa));
  sa.sin6_family = AF_INET6;
  sa.sin6_port = htons (port);
  memcpy (sa.sin6_addr.s6_addr, ip, 16);
  TpConn *n_conn = tp_conn_alloc (g_tp_rt);
  if (!n_conn)
    {
      close (fd);
      tp_unlock (g_tp_rt);
      return false;
    }
  if (!tp_conn_fd_bind (g_tp_rt, n_conn, fd))
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  n_conn->st = TP_ST_CONNECTING;
  n_conn->ts = sys_ts ();
  n_conn->inbound = false;
  memcpy (n_conn->route_ip, ip, 16);
  n_conn->route_port = port;
  if (has_peer)
    memcpy (n_conn->peer_lla, peer_lla, 16);
  int rc = connect (fd, (struct sockaddr *)&sa, sizeof (sa));
  if (rc == 0)
    {
      n_conn->st = TP_ST_ESTABLISHED;
      if (!tp_send_hello (n_conn))
        {
          tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
          tp_unlock (g_tp_rt);
          return false;
        }
      tp_send_cache_note (g_tp_rt, n_conn);
    }
  else if (errno != EINPROGRESS)
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, n_conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_ev_add (g_tp_epfd, n_conn);
  tp_unlock (g_tp_rt);
  return true;
}

bool
tp_tx_pending (void)
{
  if (!g_tp_rt)
    return false;
  if (g_tp_batch_depth != 0)
    return __atomic_load_n (&g_tp_rt->tx_bp_cnt, __ATOMIC_RELAXED) != 0;
  return __atomic_load_n (&g_tp_rt->tx_qd_cnt, __ATOMIC_RELAXED) != 0;
}

bool
tp_w_want (void)
{
  if (!g_tp_rt)
    return false;
  return __atomic_load_n (&g_tp_rt->tx_bp_cnt, __ATOMIC_RELAXED) != 0;
}

void
tp_rt_tick (TpRt *tp, Rt *rt, const Cfg *cfg)
{
  if (!tp)
    return;
  tp_lock (tp);
  uint64_t now = sys_ts ();
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = tp->conn_arr[i];
      if (!conn || conn->fd < 0)
        continue;
      if (conn->auth)
        tp_conn_route_sync (conn, rt);
      if (conn->auth && rt && cfg && conn->route_port != 0
          && conn->st == TP_ST_ESTABLISHED
          && tp_mask_has (cfg->tp_mask, TP_PROTO_TCP)
          && tp_mask_has (rt_ep_tp_mask (rt, conn->route_ip, conn->route_port),
                          TP_PROTO_TCP))
        {
          uint32_t rtt_ms = 0;
          if (tp_conn_rtt_ms_get (conn, &rtt_ms))
            rt_rtt_upd (rt, conn->peer_lla, conn->route_ip, conn->route_port,
                        rtt_ms, now);
        }
      if (conn->st == TP_ST_CONNECTING && now > conn->ts
          && (now - conn->ts) > TP_CONN_TMO)
        {
          tp_conn_close (tp, g_tp_epfd, conn);
          continue;
        }
      if (conn->auth && rt && cfg && conn->route_port != 0
          && (!tp_mask_has (cfg->tp_mask, TP_PROTO_TCP)
              || !tp_mask_has (rt_ep_tp_mask (rt, conn->route_ip,
                                              conn->route_port),
                               TP_PROTO_TCP)))
        {
          tp_conn_close (tp, g_tp_epfd, conn);
          continue;
        }
    }
  tp_unlock (tp);
}

void
tp_rt_accept_ready (TpRt *tp, int epfd)
{
  if (!tp || tp->listen_fd < 0)
    return;
  tp_lock (tp);
  for (;;)
    {
      struct sockaddr_in6 sa;
      socklen_t sl = sizeof (sa);
      int fd = accept4 (tp->listen_fd, (struct sockaddr *)&sa, &sl,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
          tp_unlock (tp);
          return;
        }
      tp_fd_cfg (fd);
      TpConn *conn = tp_conn_alloc (tp);
      if (!conn)
        {
          close (fd);
          continue;
        }
      if (!tp_conn_fd_bind (tp, conn, fd))
        {
          tp_conn_close (tp, epfd, conn);
          continue;
        }
      conn->st = TP_ST_ESTABLISHED;
      conn->inbound = true;
      conn->ts = sys_ts ();
      memcpy (conn->sock_ip, sa.sin6_addr.s6_addr, 16);
      conn->sock_port = ntohs (sa.sin6_port);
      tp_ev_add (epfd, conn);
    }
  tp_unlock (tp);
}

void
tp_rt_conn_ready (TpRt *tp, int epfd, int fd, uint32_t events, Rt *rt,
                  const Cfg *cfg, TpFrameFn cb, void *cb_arg)
{
  if (!tp || !cb)
    return;
  for (;;)
    {
      TpSrc src;
      memset (&src, 0, sizeof (src));
      const uint8_t *frame_ptr = NULL;
      size_t frame_len = 0;
      bool have_frame = false;

      tp_lock (tp);
      TpConn *conn = tp_conn_by_fd (tp, fd);
      if (!conn)
        {
          tp_unlock (tp);
          return;
        }
      if ((events & (EPOLLERR | EPOLLRDHUP | EPOLLHUP)) != 0)
        {
          tp_conn_close (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      if (conn->st == TP_ST_CONNECTING && (events & EPOLLOUT) != 0)
        {
          int err = 0;
          socklen_t err_len = sizeof (err);
          if (getsockopt (conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0
              || err != 0)
            {
              tp_conn_close (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          conn->st = TP_ST_ESTABLISHED;
          if (!tp_send_hello (conn))
            {
              tp_conn_close (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          tp_ev_upd (epfd, conn);
        }
      if ((events & EPOLLOUT) != 0 && conn->fd >= 0
          && conn->st == TP_ST_ESTABLISHED
          && (conn->tx_hi.len > 0 || conn->tx_lo.len > 0))
        {
          bool ok = tp_conn_flush (tp, epfd, conn);
          if (!ok)
            {
              tp_conn_close (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
        }
      if ((events & EPOLLIN) == 0 || conn->fd < 0)
        {
          tp_unlock (tp);
          return;
        }

      tp_conn_rx_in_compact (conn);
      if (!tp_conn_rx_in_rsv (conn, TP_TXQ_FRAME_BYTES))
        {
          tp_conn_close (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      while (conn->rx_in_len < conn->rx_in_cap)
        {
          ssize_t n = read (conn->fd, conn->rx_in + conn->rx_in_len,
                            conn->rx_in_cap - conn->rx_in_len);
          if (n > 0)
            {
              conn->rx_in_len += (uint32_t)n;
              continue;
            }
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
          tp_conn_close (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }

      if (conn->drain)
        {
          conn->rx_in_off = conn->rx_in_len;
          tp_unlock (tp);
          return;
        }

      if (!conn->wire_ready)
        {
          uint32_t avail = conn->rx_in_len - conn->rx_in_off;
          if (avail < TP_WIRE_SALT_SZ)
            {
              tp_unlock (tp);
              return;
            }
          memcpy (conn->wire_salt, conn->rx_in + conn->rx_in_off,
                  TP_WIRE_SALT_SZ);
          conn->rx_in_off += TP_WIRE_SALT_SZ;
          uint64_t now = sys_ts ();
          if (tp_salt_rp_seen (conn->wire_salt, now))
            {
              tp_conn_drain_start (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          tp_wire_derive (conn);
        }

      uint32_t avail = conn->rx_in_len - conn->rx_in_off;
      if (avail < sizeof (conn->hdr_buf))
        {
          tp_unlock (tp);
          return;
        }
      memcpy (conn->hdr_buf, conn->rx_in + conn->rx_in_off,
              sizeof (conn->hdr_buf));
      uint32_t plain_len = 0;
      if (!tp_wire_decode_len (conn, conn->hdr_buf, &plain_len))
        {
          if (conn->auth)
            tp_conn_close (tp, epfd, conn);
          else
            tp_conn_drain_start (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      if (avail < sizeof (conn->hdr_buf) + plain_len)
        {
          tp_unlock (tp);
          return;
        }
      conn->rx_in_off += sizeof (conn->hdr_buf);
      uint8_t *plain = conn->rx_in + conn->rx_in_off;
      if (!tp_wire_decode_body (conn, conn->hdr_buf, plain, plain_len,
                                plain_len))
        {
          if (conn->auth)
            tp_conn_close (tp, epfd, conn);
          else
            tp_conn_drain_start (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      if (!conn->auth)
        {
          uint32_t slot_idx = conn->slot_idx;
          TpAuthRes ar
              = tp_conn_auth (tp, epfd, conn, rt, cfg, plain, plain_len);
          if (ar == TP_AUTH_FAIL)
            {
              if (tp_conn_slot_live (tp, slot_idx, conn))
                tp_conn_drain_start (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          if (ar == TP_AUTH_PENDING)
            {
              if (!tp_conn_slot_live (tp, slot_idx, conn))
                {
                  tp_unlock (tp);
                  return;
                }
              conn->ts = sys_ts ();
              conn->rx_in_off += plain_len;
              tp_unlock (tp);
              events = EPOLLIN;
              continue;
            }
          conn->ts = sys_ts ();
          conn->rx_in_off += plain_len;
          tp_unlock (tp);
          events = EPOLLIN;
          continue;
        }
      conn->ts = sys_ts ();
      if (conn->fd >= 0 && conn->auth)
        {
          src.is_tcp = true;
          src.tcp_fd = conn->fd;
          memcpy (src.peer_lla, conn->peer_lla, 16);
          memcpy (src.route_ip, conn->route_ip, 16);
          src.route_port = conn->route_port;
          frame_ptr = plain;
          frame_len = plain_len;
          have_frame = true;
        }
      if (conn->fd < 0)
        {
          tp_unlock (tp);
          return;
        }
      conn->rx_in_off += plain_len;
      tp_unlock (tp);

      if (have_frame && !cb (frame_ptr, frame_len, &src, cb_arg))
        {
          tp_lock (tp);
          conn = tp_conn_by_fd (tp, fd);
          if (conn)
            tp_conn_close (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      events = EPOLLIN;
    }
}
