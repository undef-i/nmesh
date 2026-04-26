#include "tcp.h"
#include "gossip.h"
#include "packet.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

static void tp_conn_close (TpRt *tp, int epfd, TpConn *conn);
static bool tp_conn_tx_frame (TpRt *tp, int epfd, TpConn *conn,
                              const uint8_t *data, size_t len, bool hi);
static bool tp_conn_rsv (TpRt *tp, uint32_t need);
static bool tp_fd_idx_rsv (TpRt *tp, uint32_t need);
static bool tp_hot_idx_rsv (TpRt *tp, uint32_t need);
static void tp_send_cache_note (TpRt *tp, const TpConn *conn);
static bool tp_ip_is_zero (const uint8_t ip[16]);
static bool tp_lla_is_zero (const uint8_t lla[16]);
static uint32_t tp_hash_lla (const uint8_t lla[16]);
static uint32_t tp_hash_ep (const uint8_t ip[16], uint16_t port);
static ssize_t tp_sock_write (int fd, const void *buf, size_t len);
static ssize_t tp_sock_writev (int fd, const struct iovec *iov, int iovcnt);

static uint32_t
tp_conn_idx (const TpRt *tp, const TpConn *conn)
{
  if (!tp || !conn || !tp->conn_arr || conn < tp->conn_arr)
    return TP_IDX_INV;
  ptrdiff_t idx = conn - tp->conn_arr;
  if (idx < 0 || (uint32_t)idx >= tp->conn_cap)
    return TP_IDX_INV;
  return (uint32_t)idx;
}

static ssize_t
tp_sock_write (int fd, const void *buf, size_t len)
{
  return send (fd, buf, len, MSG_NOSIGNAL);
}

static ssize_t
tp_sock_writev (int fd, const struct iovec *iov, int iovcnt)
{
  struct msghdr msg;
  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = (struct iovec *)iov;
  msg.msg_iovlen = (size_t)iovcnt;
  return sendmsg (fd, &msg, MSG_NOSIGNAL);
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
  if (now <= g_tp_conn_last_warn_ts
      || (now - g_tp_conn_last_warn_ts) < TP_WARN_INTV)
    return;
  int live = 0;
  if (tp)
    {
      for (uint32_t i = 0; i < tp->conn_cap; i++)
        {
          if (tp->conn_arr[i].fd >= 0)
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
tp_conn_txq_stop_bytes (const TpConn *conn)
{
  uint32_t stop = (conn && conn->sndbuf_bytes > 0) ? conn->sndbuf_bytes : 0U;
  return (stop >= TP_TXQ_FRAME_BYTES) ? stop : TP_TXQ_FRAME_BYTES;
}

static uint32_t
tp_conn_txq_cap (const TpConn *conn, bool hi)
{
  uint32_t stop = tp_conn_txq_stop_bytes (conn);
  if (!hi)
    return stop;
  return (stop <= UINT32_MAX - TP_TXQ_FRAME_BYTES)
           ? (stop + TP_TXQ_FRAME_BYTES)
           : UINT32_MAX;
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

  TpConn *best = NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = &tp->conn_arr[i];
      if (!tp_conn_peer_match (conn, peer_lla))
        continue;
      if (!best || tp_conn_cmp (our_lla, conn, best) > 0)
        best = conn;
    }
  if (!best)
    return;

  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = &tp->conn_arr[i];
      if (conn == best || !tp_conn_peer_match (conn, peer_lla))
        continue;
      tp_conn_close (tp, epfd, conn);
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
  if (conn->st == TP_ST_CONNECTING || conn->tx_hi_head || conn->tx_lo_head)
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
  if (conn->st == TP_ST_CONNECTING || conn->tx_hi_head || conn->tx_lo_head)
    ev.events |= EPOLLOUT;
  ev.data.u64 = TP_EV_CONN_BASE | (uint32_t)conn->fd;
  (void)epoll_ctl (epfd, EPOLL_CTL_ADD, conn->fd, &ev);
}

static void
tp_txq_free (TpTxNode *head)
{
  while (head)
    {
      TpTxNode *next = head->next;
      free (head);
      head = next;
    }
}

static void
tp_conn_reset (TpConn *conn)
{
  if (!conn)
    return;
  tp_txq_free (conn->tx_hi_head);
  tp_txq_free (conn->tx_lo_head);
  memset (conn, 0, sizeof (*conn));
  conn->fd = -1;
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
  (void)tp;
  if (!conn || conn->fd < 0)
    return;
  int fd = conn->fd;
  tp_conn_fd_unbind (tp, conn);
  (void)epoll_ctl (epfd, EPOLL_CTL_DEL, fd, NULL);
  close (fd);
  tp_conn_reset (conn);
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
  TpConn *new_arr = realloc (tp->conn_arr, sizeof (*new_arr) * new_cap);
  if (!new_arr)
    {
      fprintf (stderr,
               "tcp: failed to expand connection table to %u entries\n",
               (unsigned)new_cap);
      return false;
    }
  tp->conn_arr = new_arr;
  for (uint32_t i = tp->conn_cap; i < new_cap; i++)
    memset (&tp->conn_arr[i], 0, sizeof (tp->conn_arr[i]));
  for (uint32_t i = tp->conn_cap; i < new_cap; i++)
    tp->conn_arr[i].fd = -1;
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
      if (tp->conn_arr[i].fd < 0)
        {
          tp_conn_reset (&tp->conn_arr[i]);
          return &tp->conn_arr[i];
        }
    }
  tp_conn_limit_warn (tp, "connection");
  uint32_t old_cap = tp->conn_cap;
  if (!tp_conn_rsv (tp, old_cap + 1U))
    return NULL;
  tp_conn_reset (&tp->conn_arr[old_cap]);
  return &tp->conn_arr[old_cap];
}

static TpConn *
tp_conn_by_fd (TpRt *tp, int fd)
{
  if (!tp || fd < 0 || !tp->fd_idx_arr || (uint32_t)fd >= tp->fd_idx_cap)
    return NULL;
  uint32_t idx = tp->fd_idx_arr[fd];
  if (idx == TP_IDX_INV || idx >= tp->conn_cap)
    return NULL;
  TpConn *conn = &tp->conn_arr[idx];
  return conn->fd == fd ? conn : NULL;
}

static TpConn *
tp_conn_by_peer (TpRt *tp, const uint8_t peer_lla[16])
{
  if (!tp || !peer_lla)
    return NULL;
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = &tp->conn_arr[i];
      if (conn->fd < 0 || !conn->auth)
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
      TpConn *conn = &tp->conn_arr[i];
      if (conn->fd < 0)
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
          TpConn *conn = &tp->conn_arr[idx];
          if (conn->st == TP_ST_ESTABLISHED && conn->auth
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
          TpConn *conn = &tp->conn_arr[idx];
          if (conn->st == TP_ST_ESTABLISHED
              && memcmp (conn->route_ip, ip, 16) == 0
              && conn->route_port == port)
            return conn;
        }
    }
  return NULL;
}

static TpTxNode *
tp_tx_node_new (const uint8_t *data, size_t len, size_t skip)
{
  if (!data || len == 0 || len > UDP_PL_MAX)
    return NULL;
  uint32_t net_len = htonl ((uint32_t)len);
  size_t frame_len = sizeof (net_len) + len;
  if (skip >= frame_len)
    return NULL;
  size_t rem = frame_len - skip;
  TpTxNode *node = malloc (sizeof (*node) + rem);
  if (!node)
    return NULL;
  memset (node, 0, sizeof (*node));
  node->len = (uint32_t)rem;
  if (skip < sizeof (net_len))
    {
      size_t hdr_off = skip;
      size_t hdr_rem = sizeof (net_len) - hdr_off;
      memcpy (node->data, ((const uint8_t *)&net_len) + hdr_off, hdr_rem);
      memcpy (node->data + hdr_rem, data, len);
      return node;
    }
  memcpy (node->data, data + (skip - sizeof (net_len)), rem);
  return node;
}

static bool
tp_conn_enqueue (TpConn *conn, const uint8_t *data, size_t len, size_t skip,
                 bool hi)
{
  if (!conn)
    return false;
  TpTxNode *node = tp_tx_node_new (data, len, skip);
  if (!node)
    return false;
  uint32_t q_cap = tp_conn_txq_cap (conn, hi);
  if (conn->tx_q_bytes > q_cap || node->len > q_cap - conn->tx_q_bytes)
    {
      free (node);
      return false;
    }
  TpTxNode **head = hi ? &conn->tx_hi_head : &conn->tx_lo_head;
  TpTxNode **tail = hi ? &conn->tx_hi_tail : &conn->tx_lo_tail;
  if (*tail)
    (*tail)->next = node;
  else
    *head = node;
  *tail = node;
  conn->tx_q_bytes += node->len;
  return true;
}

static TpTxNode *
tp_conn_tx_head (TpConn *conn, TpTxNode ***head_out, TpTxNode ***tail_out)
{
  if (!conn)
    return NULL;
  if (conn->tx_hi_head)
    {
      if (head_out)
        *head_out = &conn->tx_hi_head;
      if (tail_out)
        *tail_out = &conn->tx_hi_tail;
      return conn->tx_hi_head;
    }
  if (conn->tx_lo_head)
    {
      if (head_out)
        *head_out = &conn->tx_lo_head;
      if (tail_out)
        *tail_out = &conn->tx_lo_tail;
      return conn->tx_lo_head;
    }
  return NULL;
}

static bool
tp_conn_flush (TpRt *tp, int epfd, TpConn *conn)
{
  if (!tp || !conn || conn->fd < 0 || conn->st != TP_ST_ESTABLISHED)
    return false;
  for (;;)
    {
      TpTxNode **head = NULL;
      TpTxNode **tail = NULL;
      TpTxNode *node = tp_conn_tx_head (conn, &head, &tail);
      if (!node)
        {
          tp_ev_upd (epfd, conn);
          return true;
        }
      ssize_t n
        = tp_sock_write (conn->fd, node->data + node->off, node->len - node->off);
      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              tp_ev_upd (epfd, conn);
              return true;
            }
          tp_conn_close (tp, epfd, conn);
          return false;
        }
      if (n == 0)
        {
          tp_ev_upd (epfd, conn);
          return true;
        }
      if (conn->tx_q_bytes >= (uint32_t)n)
        conn->tx_q_bytes -= (uint32_t)n;
      else
        conn->tx_q_bytes = 0;
      node->off += (uint32_t)n;
      if (node->off < node->len)
        {
          tp_ev_upd (epfd, conn);
          return true;
        }
      *head = node->next;
      if (!*head)
        *tail = NULL;
      free (node);
    }
}

static bool
tp_conn_tx_frame (TpRt *tp, int epfd, TpConn *conn, const uint8_t *data,
                  size_t len, bool hi)
{
  if (!tp || !conn || conn->fd < 0 || !data || len == 0 || len > UDP_PL_MAX)
    return false;
  if (conn->st != TP_ST_ESTABLISHED)
    {
      if (!tp_conn_enqueue (conn, data, len, 0, false))
        return false;
      tp_ev_upd (epfd, conn);
      return true;
    }
  if (conn->tx_hi_head || conn->tx_lo_head)
    {
      if (!tp_conn_enqueue (conn, data, len, 0, hi))
        return false;
      tp_ev_upd (epfd, conn);
      return tp_conn_flush (tp, epfd, conn);
    }
  uint32_t net_len = htonl ((uint32_t)len);
  struct iovec iov[2];
  iov[0].iov_base = &net_len;
  iov[0].iov_len = sizeof (net_len);
  iov[1].iov_base = (void *)data;
  iov[1].iov_len = len;
  size_t want = sizeof (net_len) + len;
  ssize_t n = tp_sock_writev (conn->fd, iov, 2);
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          if (!tp_conn_enqueue (conn, data, len, 0, hi))
            return false;
          tp_ev_upd (epfd, conn);
          return true;
        }
      return false;
    }
  if ((size_t)n == want)
    return true;
  if (!tp_conn_enqueue (conn, data, len, (size_t)n, hi))
    return false;
  tp_ev_upd (epfd, conn);
  return true;
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
  ping_bld (g_tp_cry, g_tp_cfg->addr, sys_ts (), g_tp_sid, 0, ping_buf,
            &ping_len);
  if (!tp_conn_tx_frame (g_tp_rt, g_tp_epfd, conn, ping_buf, ping_len, true))
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
      return;
    }
  if (conn->route_port != 0)
    return;
  if (conn->inbound && g_tp_cfg && !tp_ip_is_zero (conn->sock_ip)
      && g_tp_cfg->port != 0)
    {
      memcpy (conn->route_ip, conn->sock_ip, 16);
      conn->route_port = g_tp_cfg->port;
    }
}

static bool
tp_conn_auth (TpRt *tp, int epfd, TpConn *conn, const Rt *rt, const Cfg *cfg,
              const uint8_t *frame, size_t len)
{
  if (!tp || !conn || !cfg || !g_tp_cry || !frame || len == 0)
    return false;
  uint8_t pt_buf[UDP_PL_MAX];
  PktHdr hdr;
  uint8_t *pt = NULL;
  size_t pt_len = 0;
  if (pkt_dec (g_tp_cry, (uint8_t *)frame, len, pt_buf, sizeof (pt_buf), &hdr,
               &pt, &pt_len)
      != 0)
    return false;
  uint8_t peer_lla[16] = { 0 };
  if (hdr.pkt_type == PT_PING)
    {
      uint64_t req_ts = 0;
      uint64_t peer_sid = 0;
      uint64_t prb_tok = 0;
      if (on_ping (pt, pt_len, &req_ts, &peer_sid, peer_lla, &prb_tok) != 0)
        return false;
    }
  else if (hdr.pkt_type == PT_PONG)
    {
      uint64_t req_ts = 0;
      uint64_t peer_sid = 0;
      uint64_t peer_rx_ts = 0;
      uint64_t prb_tok = 0;
      if (on_pong (pt, pt_len, &req_ts, &peer_sid, peer_lla, &peer_rx_ts,
                   &prb_tok)
          != 0)
        return false;
    }
  else
    {
      return false;
    }

  memcpy (conn->peer_lla, peer_lla, 16);
  conn->auth = true;
  tp_conn_route_sync (conn, rt);
  tp_conn_dedup_peer (tp, epfd, cfg->addr, peer_lla);
  if (conn->fd < 0)
    return false;
  return true;
}

static TpProto
tp_pick_proto (const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
               uint16_t port)
{
  if (!cfg || !ip || port == 0)
    return TP_PROTO_NONE;
  return cfg_tp_pick (cfg, rt_ep_tp_mask (rt, ip, port));
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
      if (tp->conn_arr && tp->conn_arr[i].fd >= 0)
        close (tp->conn_arr[i].fd);
      if (tp->conn_arr)
        tp_conn_reset (&tp->conn_arr[i]);
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
  tp_send_cache_reset (tp);
  if (tp->listen_fd >= 0)
    close (tp->listen_fd);
  tp->listen_fd = -1;
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
}

void
tp_glb_unbind (void)
{
  g_tp_rt = NULL;
  g_tp_epfd = -1;
  g_tp_cry = NULL;
  g_tp_cfg = NULL;
  g_tp_sid = 0;
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
  if (!tp_conn_tx_frame (g_tp_rt, g_tp_epfd, conn, data, len, true))
    {
      tp_conn_close (g_tp_rt, g_tp_epfd, conn);
      tp_unlock (g_tp_rt);
      return false;
    }
  tp_send_cache_note (g_tp_rt, conn);
  tp_unlock (g_tp_rt);
  return true;
}

static bool
tp_send_kind (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len, bool hi)
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
  TpConn *conn = tp_conn_hot_lookup (g_tp_rt, ip, port, peer_lla, has_peer);
  if (!conn && has_peer)
    conn = tp_conn_by_peer (g_tp_rt, peer_lla);
  if (!conn)
    conn = tp_conn_by_ep (g_tp_rt, ip, port);
  if (conn)
    {
      if (!tp_conn_tx_frame (g_tp_rt, g_tp_epfd, conn, data, len, hi))
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
  int one = 1;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
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
      tp_conn_reset (n_conn);
      close (fd);
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
  return tp_send_kind (udp, rt, cfg, ip, port, data, len, false);
}

bool
tp_send_ctrl (Udp *udp, const Rt *rt, const Cfg *cfg, const uint8_t ip[16],
              uint16_t port, const uint8_t *data, size_t len)
{
  return tp_send_kind (udp, rt, cfg, ip, port, data, len, true);
}

bool
tp_w_want (void)
{
  if (!g_tp_rt)
    return false;
  tp_lock (g_tp_rt);
  for (uint32_t i = 0; i < g_tp_rt->conn_cap; i++)
    {
      if (g_tp_rt->conn_arr[i].tx_q_bytes
          >= tp_conn_txq_stop_bytes (&g_tp_rt->conn_arr[i]))
        {
          tp_unlock (g_tp_rt);
          return true;
        }
    }
  tp_unlock (g_tp_rt);
  return false;
}

void
tp_rt_tick (TpRt *tp, const Rt *rt, const Cfg *cfg)
{
  if (!tp)
    return;
  tp_lock (tp);
  uint64_t now = sys_ts ();
  for (uint32_t i = 0; i < tp->conn_cap; i++)
    {
      TpConn *conn = &tp->conn_arr[i];
      if (conn->fd < 0)
        continue;
      if (conn->auth)
        tp_conn_route_sync (conn, rt);
      if (conn->st == TP_ST_CONNECTING && now > conn->ts
          && (now - conn->ts) > TP_CONN_TMO)
        tp_conn_close (tp, g_tp_epfd, conn);
      if (conn->auth && cfg && conn->route_port != 0
          && (!tp_mask_has (cfg->tp_mask, TP_PROTO_TCP)
              || !tp_mask_has (rt_ep_tp_mask (rt, conn->route_ip,
                                              conn->route_port),
                               TP_PROTO_TCP)))
        tp_conn_close (tp, g_tp_epfd, conn);
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
      int one = 1;
      (void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
      TpConn *conn = tp_conn_alloc (tp);
      if (!conn)
        {
          close (fd);
          continue;
        }
      if (!tp_conn_fd_bind (tp, conn, fd))
        {
          tp_conn_reset (conn);
          close (fd);
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
tp_rt_conn_ready (TpRt *tp, int epfd, int fd, uint32_t events, const Rt *rt,
                  const Cfg *cfg, TpFrameFn cb, void *cb_arg)
{
  if (!tp || !cb)
    return;
  uint8_t frame_buf[UDP_PL_MAX];
  for (;;)
    {
      TpSrc src;
      memset (&src, 0, sizeof (src));
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
          && (conn->tx_hi_head || conn->tx_lo_head))
        {
          if (!tp_conn_flush (tp, epfd, conn))
            {
              tp_unlock (tp);
              return;
            }
        }
      if ((events & EPOLLIN) == 0 || conn->fd < 0)
        {
          tp_unlock (tp);
          return;
        }

      if (conn->rx_len == 0)
        {
          ssize_t n = read (conn->fd, conn->hdr_buf + conn->hdr_have,
                            sizeof (conn->hdr_buf) - conn->hdr_have);
          if (n <= 0)
            {
              if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                {
                  tp_unlock (tp);
                  return;
                }
              tp_conn_close (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          conn->hdr_have += (uint32_t)n;
          if (conn->hdr_have < sizeof (conn->hdr_buf))
            {
              tp_unlock (tp);
              return;
            }
          uint32_t net_len = 0;
          memcpy (&net_len, conn->hdr_buf, sizeof (net_len));
          conn->rx_len = ntohl (net_len);
          conn->hdr_have = 0;
          if (conn->rx_len == 0 || conn->rx_len > UDP_PL_MAX)
            {
              tp_conn_close (tp, epfd, conn);
              tp_unlock (tp);
              return;
            }
          conn->rx_have = 0;
        }
      ssize_t n = read (conn->fd, conn->rx_buf + conn->rx_have,
                        conn->rx_len - conn->rx_have);
      if (n <= 0)
        {
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
              tp_unlock (tp);
              return;
            }
          tp_conn_close (tp, epfd, conn);
          tp_unlock (tp);
          return;
        }
      conn->rx_have += (uint32_t)n;
      if (conn->rx_have < conn->rx_len)
        {
          tp_unlock (tp);
          return;
        }
      conn->ts = sys_ts ();
      if (!conn->auth
          && !tp_conn_auth (tp, epfd, conn, rt, cfg, conn->rx_buf,
                            conn->rx_len))
        {
          if (conn->fd < 0)
            {
              tp_unlock (tp);
              return;
            }
          conn->rx_len = 0;
          conn->rx_have = 0;
          tp_unlock (tp);
          events = EPOLLIN;
          continue;
        }
      if (conn->fd >= 0 && conn->auth)
        {
          src.is_tcp = true;
          src.tcp_fd = conn->fd;
          memcpy (src.peer_lla, conn->peer_lla, 16);
          memcpy (src.route_ip, conn->route_ip, 16);
          src.route_port = conn->route_port;
          frame_len = conn->rx_len;
          memcpy (frame_buf, conn->rx_buf, frame_len);
          have_frame = true;
        }
      if (conn->fd < 0)
        {
          tp_unlock (tp);
          return;
        }
      conn->rx_len = 0;
      conn->rx_have = 0;
      tp_unlock (tp);

      if (have_frame)
        cb (frame_buf, frame_len, &src, cb_arg);
      events = EPOLLIN;
    }
}
