#ifndef NM_DCO_H
#define NM_DCO_H

#include <linux/types.h>
#include <linux/in6.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/crypto.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/workqueue.h>
#include <net/dst_cache.h>

struct nm_dco_ctx;

struct nm_route {
	struct in6_addr dst_lla;
	u32 peer_id;
	struct rcu_head rcu;
	struct list_head list;
};

struct nm_peer {
	u32 id;
	struct in6_addr v6_ip;
	u8 key[32];
	char aead_name[32];


	u8 nonce_sid[4];
	u64 nonce_ctr;

	u8 rx_sid[4];
	u64 rx_max_cnt;
	u64 rx_bmp[16];
	bool rx_seen;

	struct crypto_aead *tfm;
	void __percpu *aead_req_pool;
	u32 aead_req_pool_sz;
	__be32 ep_ip;
	__be16 ep_p;
	struct nm_dco_ctx *ctx;
	struct dst_cache dst_cache;
	struct rcu_head rcu;
	struct sk_buff_head tx_q;
	struct work_struct tx_work;

	struct list_head list;
};

struct nm_dco_ctx {
	struct net *net;
	struct socket *sock;
	bool sock_borrowed;
	__be16 local_port;
	struct net_device __rcu *dev;
	struct list_head peers;
	struct list_head routes;
	rwlock_t lock;
	struct list_head list;
};

extern struct list_head nm_ctxs;
extern rwlock_t nm_ctxs_lock;

extern struct list_head nm_peers;
extern rwlock_t nm_lock;

struct nm_dco_ctx *nm_ctx_get_or_create(struct net *net, __be16 local_port);
struct nm_dco_ctx *nm_ctx_find_by_net(const struct net *net);
void nm_ctx_put(struct nm_dco_ctx *ctx);
void nm_ctx_destroy_all(void);

int nm_tx_init(struct nm_dco_ctx *ctx);
int nm_tx_init_from_fd(struct nm_dco_ctx *ctx, int ufd);
void nm_tx_fini(struct nm_dco_ctx *ctx);
int nm_tx_encap(struct sk_buff *skb, struct nm_peer *p);
int nm_rx_encap(struct sock *sk, struct sk_buff *skb);

netdev_tx_t nm_xmit(struct sk_buff *skb, struct net_device *dev);

#endif
