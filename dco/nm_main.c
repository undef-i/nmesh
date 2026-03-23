#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/random.h>
#include <linux/kmod.h>
#include <linux/net_namespace.h>
#include <linux/rcupdate.h>
#include <linux/percpu.h>
#include <crypto/aead.h>
#include <net/ipv6.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>
#include <net/gso.h>

#include "../include/nm_nl.h"
#include "nm_dco.h"

LIST_HEAD(nm_peers);
rwlock_t nm_lock = __RW_LOCK_UNLOCKED(nm_lock);

LIST_HEAD(nm_ctxs);
rwlock_t nm_ctxs_lock = __RW_LOCK_UNLOCKED(nm_ctxs_lock);

static struct rtnl_link_ops nm_link_ops;
static struct genl_family nm_nl_fam;
static struct notifier_block nm_netdev_notifier;
static void nm_tx_worker(struct work_struct *work);

static const struct nla_policy nm_nl_policy[NM_A_MAX + 1] = {
	[NM_A_IF_IDX]  = { .type = NLA_U32 },
	[NM_A_P_ID]    = { .type = NLA_U32 },
	[NM_A_V6_IP]   = { .type = NLA_BINARY, .len = 16 },
	[NM_A_EP_IP]   = { .type = NLA_BINARY, .len = 4 },
	[NM_A_EP_PORT] = { .type = NLA_U16 },
	[NM_A_K_DAT]   = { .type = NLA_BINARY, .len = 32 },
	[NM_A_UDP_FD]  = { .type = NLA_U32 },
};

static void nm_peer_free_now(struct nm_peer *p)
{
	if (!p)
		return;

	cancel_work_sync(&p->tx_work);
	skb_queue_purge(&p->tx_q);
	if (p->tfm)
		crypto_free_aead(p->tfm);
	if (p->aead_req_pool)
		free_percpu(p->aead_req_pool);
	dst_cache_destroy(&p->dst_cache);
	kfree(p);
}

static void nm_route_rcu_free(struct rcu_head *head)
{
	struct nm_route *r = container_of(head, struct nm_route, rcu);

	kfree(r);
}

static void nm_ctx_flush_state(struct nm_dco_ctx *ctx, int *flushed_peers)
{
	struct nm_peer *peer, *pn;
	struct nm_route *route, *rn;
	struct nm_peer **peer_arr = NULL;
	struct nm_route **route_arr = NULL;
	size_t peer_cap = 0, route_cap = 0;
	size_t peer_cnt = 0, route_cnt = 0;
	size_t i;
	int local_flushed = 0;

	read_lock_bh(&ctx->lock);
	list_for_each_entry(peer, &ctx->peers, list)
		peer_cap++;
	list_for_each_entry(route, &ctx->routes, list)
		route_cap++;
	read_unlock_bh(&ctx->lock);

	if (peer_cap) {
		peer_arr = kcalloc(peer_cap, sizeof(*peer_arr), GFP_KERNEL);
		if (!peer_arr) {
			if (flushed_peers)
				*flushed_peers = 0;
			return;
		}
	}
	if (route_cap) {
		route_arr = kcalloc(route_cap, sizeof(*route_arr), GFP_KERNEL);
		if (!route_arr) {
			kfree(peer_arr);
			if (flushed_peers)
				*flushed_peers = 0;
			return;
		}
	}

	write_lock_bh(&ctx->lock);
	list_for_each_entry_safe(peer, pn, &ctx->peers, list) {
		list_del_rcu(&peer->list);
		if (peer_cnt < peer_cap)
			peer_arr[peer_cnt++] = peer;
		local_flushed++;
	}
	list_for_each_entry_safe(route, rn, &ctx->routes, list) {
		list_del_rcu(&route->list);
		if (route_cnt < route_cap)
			route_arr[route_cnt++] = route;
	}
	write_unlock_bh(&ctx->lock);
	synchronize_rcu();

	for (i = 0; i < route_cnt; i++)
		kfree(route_arr[i]);
	for (i = 0; i < peer_cnt; i++)
		nm_peer_free_now(peer_arr[i]);

	kfree(route_arr);
	kfree(peer_arr);

	if (flushed_peers)
		*flushed_peers = local_flushed;
}


static struct nm_dco_ctx *nm_ctx_alloc(struct net *net, __be16 local_port)
{
	struct nm_dco_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->net = net;
	ctx->local_port = local_port;
	INIT_LIST_HEAD(&ctx->peers);
	INIT_LIST_HEAD(&ctx->routes);
	rwlock_init(&ctx->lock);

	return ctx;
}

struct nm_dco_ctx *nm_ctx_find_by_net(const struct net *net)
{
	struct nm_dco_ctx *ctx, *hit = NULL;

	read_lock_bh(&nm_ctxs_lock);
	list_for_each_entry(ctx, &nm_ctxs, list) {
		if (ctx->net == net) {
			hit = ctx;
			break;
		}
	}
	read_unlock_bh(&nm_ctxs_lock);

	return hit;
}

struct nm_dco_ctx *nm_ctx_get_or_create(struct net *net, __be16 local_port)
{
	struct nm_dco_ctx *ctx;

	ctx = nm_ctx_find_by_net(net);
	if (ctx) {
		if (local_port != 0)
			ctx->local_port = local_port;
		return ctx;
	}

	ctx = nm_ctx_alloc(net, local_port);
	if (IS_ERR(ctx))
		return ctx;

	write_lock_bh(&nm_ctxs_lock);
	list_add_tail(&ctx->list, &nm_ctxs);
	write_unlock_bh(&nm_ctxs_lock);

	return ctx;
}

void nm_ctx_put(struct nm_dco_ctx *ctx)
{
	if (!ctx)
		return;
}

void nm_ctx_destroy_all(void)
{
	struct nm_dco_ctx *ctx, *tmp;
	LIST_HEAD(to_free);

	write_lock_bh(&nm_ctxs_lock);
	list_for_each_entry_safe(ctx, tmp, &nm_ctxs, list) {
		list_del(&ctx->list);
		list_add_tail(&ctx->list, &to_free);
	}
	write_unlock_bh(&nm_ctxs_lock);

	synchronize_rcu();

	list_for_each_entry_safe(ctx, tmp, &to_free, list) {
		nm_ctx_flush_state(ctx, NULL);
		RCU_INIT_POINTER(ctx->dev, NULL);
		nm_tx_fini(ctx);
		kfree(ctx);
	}
}

static int nm_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct nm_dco_ctx *ctx, *hit = NULL;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	read_lock_bh(&nm_ctxs_lock);
	list_for_each_entry(ctx, &nm_ctxs, list) {
		if (rcu_access_pointer(ctx->dev) == dev) {
			hit = ctx;
			break;
		}
	}
	read_unlock_bh(&nm_ctxs_lock);

	if (!hit)
		return NOTIFY_DONE;

	pr_info("nmesh: device %s unregistered, purging DCO sockets\n", dev->name);
	RCU_INIT_POINTER(hit->dev, NULL);
	nm_tx_fini(hit);

	return NOTIFY_DONE;
}

static struct notifier_block nm_netdev_notifier = {
	.notifier_call = nm_netdev_event,
};


static void nm_tx_worker(struct work_struct *work)
{
	struct nm_peer *p = container_of(work, struct nm_peer, tx_work);
	struct sk_buff *skb;
	int batch = 0;

	while ((skb = skb_dequeue(&p->tx_q)) != NULL) {
		nm_tx_encap(skb, p);
		batch++;
		if (batch >= 128) {
			cond_resched();
			batch = 0;
		}
	}
}

netdev_tx_t nm_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipv6hdr *ip6h;
	struct nm_peer *peer, *hit;
	struct nm_route *route;
	struct nm_dco_ctx *ctx;
	struct sk_buff *curr, *next;
	struct sk_buff *head;
	bool is_gso = false;

	if (unlikely(!skb))
		return NETDEV_TX_OK;

	if (skb->protocol != htons(ETH_P_IPV6) ||
	    unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr)))) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	ctx = nm_ctx_find_by_net(dev_net(dev));
	if (!ctx) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (skb_is_gso(skb)) {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (IS_ERR(segs)) {
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		if (segs) {
			consume_skb(skb);
			head = segs;
			is_gso = true;
		} else {
			head = skb;
		}
	} else {
		head = skb;
	}

	rcu_read_lock();
	for (curr = head; curr; curr = next) {
		u32 peer_id = 0;

		if (is_gso) {
			next = curr->next;
			skb_mark_not_on_list(curr);
		} else {
			next = NULL;
		}

		ip6h = ipv6_hdr(curr);
		hit = NULL;

		list_for_each_entry_rcu(route, &ctx->routes, list) {
			if (!memcmp(&route->dst_lla, &ip6h->daddr, sizeof(route->dst_lla))) {
				peer_id = route->peer_id;
				break;
			}
		}

		if (peer_id == 0) {
			dev_kfree_skb(curr);
			continue;
		}

		list_for_each_entry_rcu(peer, &ctx->peers, list) {
			if (peer->id == peer_id) {
				hit = peer;
				break;
			}
		}

		if (!hit) {
			dev_kfree_skb(curr);
			continue;
		}

		if (curr->len <= 1600) {
			skb_queue_tail(&hit->tx_q, curr);
			schedule_work(&hit->tx_work);
		} else {
			nm_tx_encap(curr, hit);
		}
	}
	rcu_read_unlock();

	return NETDEV_TX_OK;
}

static const struct net_device_ops nm_netdev_ops = {
	.ndo_start_xmit      = nm_xmit,
	.ndo_set_mac_address = eth_mac_addr,
};

static void nm_setup(struct net_device *dev)
{
	struct nm_dco_ctx *ctx;

	ether_setup(dev);
	dev->netdev_ops = &nm_netdev_ops;

	dev->needs_free_netdev = true;
	dev->tx_queue_len = 1000;
	dev->flags |= IFF_NOARP | IFF_MULTICAST;
	dev->mtu = 1420;
	dev->features |= NETIF_F_SG | NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA;
	dev->hw_features |= NETIF_F_SG | NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA;

	eth_hw_addr_random(dev);

	netif_carrier_on(dev);

	ctx = nm_ctx_get_or_create(dev_net(dev), htons(11451));
	if (!IS_ERR(ctx))
		rcu_assign_pointer(ctx->dev, dev);
}

static struct rtnl_link_ops nm_link_ops = {
	.kind  = "nmesh",
	.setup = nm_setup,
};

static int nm_nl_if_new_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	u16 local_port = htons(11451);
	struct nm_dco_ctx *ctx;
	struct net_device *dev = NULL;
	u32 ifindex = 0;
	int udp_fd = -1;
	int ret;
	int flushed = 0;

	if (info->attrs[NM_A_EP_PORT]) {
		u16 p = nla_get_u16(info->attrs[NM_A_EP_PORT]);
		if (p != 0)
			local_port = htons(p);
	}

	if (info->attrs[NM_A_IF_IDX])
		ifindex = nla_get_u32(info->attrs[NM_A_IF_IDX]);
	if (info->attrs[NM_A_UDP_FD])
		udp_fd = (int)nla_get_u32(info->attrs[NM_A_UDP_FD]);

	ctx = nm_ctx_get_or_create(net, local_port);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	if (udp_fd >= 0) {
		nm_tx_fini(ctx);
		ret = nm_tx_init_from_fd(ctx, udp_fd);
		if (ret)
			return ret;
	} else if (!ctx->sock || ctx->sock_borrowed) {
		nm_tx_fini(ctx);
		ret = nm_tx_init(ctx);
		if (ret)
			return ret;
	}

	nm_ctx_flush_state(ctx, &flushed);

	if (ifindex) {
		rcu_read_lock();
		dev = dev_get_by_index_rcu(net, ifindex);
			if (dev) {
				rcu_assign_pointer(ctx->dev, dev);
				dev->needed_headroom = 128;
				dev->needed_tailroom = 32;
			}
		rcu_read_unlock();
	}

	pr_info("nmesh: [Ctrl] IF_NEW netns=%u udp/%u ifindex=%u dev=%s (flushed %d stale peers)\n",
		net->ns.inum, ntohs(ctx->local_port), ifindex,
		dev ? dev->name : "NULL", flushed);
	return 0;
}

static int nm_nl_if_del_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nm_dco_ctx *ctx;
	int flushed = 0;

	ctx = nm_ctx_find_by_net(net);
	if (!ctx)
		return 0;

	nm_ctx_flush_state(ctx, &flushed);
	RCU_INIT_POINTER(ctx->dev, NULL);
	nm_tx_fini(ctx);

	pr_info("nmesh: [Ctrl] IF_DEL netns=%u (flushed %d peers)\n",
		net->ns.inum, flushed);
	return 0;
}

static int nm_nl_p_add_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nm_dco_ctx *ctx;
	struct nm_peer *peer, *cur;
	u32 p_id;
	u16 ep_port;
	u8 *ep_ip;
	int ret;

	request_module("aes_x86_64");
	request_module("ghash_clmulni_intel");
	request_module("gcm");

	if (!info->attrs[NM_A_P_ID] || !info->attrs[NM_A_EP_PORT] ||
	    !info->attrs[NM_A_V6_IP] || !info->attrs[NM_A_EP_IP] ||
	    !info->attrs[NM_A_K_DAT])
		return -EINVAL;

	ctx = nm_ctx_find_by_net(net);
	if (!ctx || !ctx->sock || ctx->local_port == 0) {
		pr_err("nmesh: NM_C_P_ADD requires IF_NEW context with valid local port (netns=%u)\n",
		       net->ns.inum);
		return -ENOENT;
	}

	p_id = nla_get_u32(info->attrs[NM_A_P_ID]);
	ep_port = nla_get_u16(info->attrs[NM_A_EP_PORT]);
	ep_ip = nla_data(info->attrs[NM_A_EP_IP]);

	write_lock_bh(&ctx->lock);
	list_for_each_entry(cur, &ctx->peers, list) {
		if (cur->id != p_id)
			continue;

		memcpy(&cur->v6_ip, nla_data(info->attrs[NM_A_V6_IP]), sizeof(cur->v6_ip));
		memcpy(cur->key, nla_data(info->attrs[NM_A_K_DAT]), sizeof(cur->key));
		memcpy(&cur->ep_ip, ep_ip, sizeof(cur->ep_ip));
		cur->ep_p = htons(ep_port);

		memset(cur->nonce_sid, 0, sizeof(cur->nonce_sid));
		cur->nonce_ctr = 1;
		cur->rx_seen = false;
		memset(cur->rx_sid, 0, sizeof(cur->rx_sid));
		cur->rx_max_cnt = 0;
		memset(cur->rx_bmp, 0, sizeof(cur->rx_bmp));

		ret = crypto_aead_setkey(cur->tfm, cur->key, sizeof(cur->key));
		write_unlock_bh(&ctx->lock);

		if (ret)
			return ret;

		pr_info("nmesh: [Ctrl] Peer update netns=%u id=%u ep=%pI4:%u\n",
			net->ns.inum, p_id, &cur->ep_ip, ep_port);
		return 0;
	}
	write_unlock_bh(&ctx->lock);

	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return -ENOMEM;

	peer->id = p_id;
	memcpy(&peer->v6_ip, nla_data(info->attrs[NM_A_V6_IP]), sizeof(peer->v6_ip));
	memcpy(peer->key, nla_data(info->attrs[NM_A_K_DAT]), sizeof(peer->key));
	memcpy(&peer->ep_ip, ep_ip, sizeof(peer->ep_ip));
	peer->ep_p = htons(ep_port);
	peer->ctx = ctx;

	memset(peer->nonce_sid, 0, sizeof(peer->nonce_sid));
	peer->nonce_ctr = 1;
	peer->rx_seen = false;
	memset(peer->rx_sid, 0, sizeof(peer->rx_sid));
	peer->rx_max_cnt = 0;
	memset(peer->rx_bmp, 0, sizeof(peer->rx_bmp));

	peer->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(peer->tfm))
		peer->tfm = crypto_alloc_aead("rfc4106(gcm(aes))", 0, 0);

	if (IS_ERR(peer->tfm)) {
		ret = PTR_ERR(peer->tfm);
		peer->tfm = NULL;
		kfree(peer);
		pr_err("nmesh: crypto_alloc_aead failed (aes-gcm) netns=%u id=%u: %d\n",
		       net->ns.inum, p_id, ret);
		return ret;
	}

	ret = crypto_aead_setkey(peer->tfm, peer->key, sizeof(peer->key));
	if (ret) {
		crypto_free_aead(peer->tfm);
		kfree(peer);
		pr_err("nmesh: crypto_aead_setkey(aes-gcm) failed netns=%u id=%u: %d\n",
		       net->ns.inum, p_id, ret);
		return ret;
	}

	ret = crypto_aead_setauthsize(peer->tfm, 16);
	if (ret) {
		crypto_free_aead(peer->tfm);
		kfree(peer);
		pr_err("nmesh: crypto_aead_setauthsize(aes-gcm) failed netns=%u id=%u: %d\n",
		       net->ns.inum, p_id, ret);
		return ret;
	}

	peer->aead_req_pool_sz = sizeof(struct aead_request) +
				 crypto_aead_reqsize(peer->tfm);
	peer->aead_req_pool = __alloc_percpu(peer->aead_req_pool_sz,
					      __alignof__(struct aead_request));
	if (!peer->aead_req_pool) {
		crypto_free_aead(peer->tfm);
		kfree(peer);
		return -ENOMEM;
	}

	skb_queue_head_init(&peer->tx_q);
	INIT_WORK(&peer->tx_work, nm_tx_worker);

	/* insert into per-netns list (single ownership list only) */
	dst_cache_init(&peer->dst_cache, GFP_KERNEL);

	write_lock_bh(&ctx->lock);
	list_add_tail_rcu(&peer->list, &ctx->peers);
	write_unlock_bh(&ctx->lock);

	pr_info("nmesh: [Ctrl] Peer add netns=%u id=%u ep=%pI4:%u\n",
		net->ns.inum, p_id, &peer->ep_ip, ep_port);
	return 0;
}

static int nm_nl_r_flush_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nm_dco_ctx *ctx;
	struct nm_route *route, *rn;

	ctx = nm_ctx_find_by_net(net);
	if (!ctx)
		return -ENOENT;

	write_lock_bh(&ctx->lock);
	list_for_each_entry_safe(route, rn, &ctx->routes, list) {
		list_del_rcu(&route->list);
		call_rcu(&route->rcu, nm_route_rcu_free);
	}
	write_unlock_bh(&ctx->lock);

	return 0;
}

static int nm_nl_r_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nm_dco_ctx *ctx;
	struct nm_route *route;
	struct nm_peer *peer;
	struct in6_addr dst_lla;
	u32 peer_id;
	bool peer_ok = false;

	if (!info->attrs[NM_A_V6_IP] || !info->attrs[NM_A_P_ID])
		return -EINVAL;

	ctx = nm_ctx_find_by_net(net);
	if (!ctx)
		return -ENOENT;

	memcpy(&dst_lla, nla_data(info->attrs[NM_A_V6_IP]), sizeof(dst_lla));
	peer_id = nla_get_u32(info->attrs[NM_A_P_ID]);
	if (peer_id == 0)
		return -EINVAL;

	write_lock_bh(&ctx->lock);
	list_for_each_entry(peer, &ctx->peers, list) {
		if (peer->id == peer_id) {
			peer_ok = true;
			break;
		}
	}
	if (!peer_ok) {
		write_unlock_bh(&ctx->lock);
		return -ENOENT;
	}

	list_for_each_entry(route, &ctx->routes, list) {
		if (!memcmp(&route->dst_lla, &dst_lla, sizeof(dst_lla))) {
			route->peer_id = peer_id;
			write_unlock_bh(&ctx->lock);
			return 0;
		}
	}

	route = kzalloc(sizeof(*route), GFP_ATOMIC);
	if (!route) {
		write_unlock_bh(&ctx->lock);
		return -ENOMEM;
	}
	route->dst_lla = dst_lla;
	route->peer_id = peer_id;
	list_add_tail_rcu(&route->list, &ctx->routes);
	write_unlock_bh(&ctx->lock);

	return 0;
}

static const struct genl_ops nm_nl_ops[] = {
	{
		.cmd    = NM_C_IF_NEW,
		.doit   = nm_nl_if_new_doit,
		.policy = nm_nl_policy,
	},
	{
		.cmd    = NM_C_IF_DEL,
		.doit   = nm_nl_if_del_doit,
		.policy = nm_nl_policy,
	},
	{
		.cmd    = NM_C_P_ADD,
		.doit   = nm_nl_p_add_doit,
		.policy = nm_nl_policy,
	},
	{
		.cmd    = NM_C_R_FLUSH,
		.doit   = nm_nl_r_flush_doit,
		.policy = nm_nl_policy,
	},
	{
		.cmd    = NM_C_R_SET,
		.doit   = nm_nl_r_set_doit,
		.policy = nm_nl_policy,
	},
};

static struct genl_family nm_nl_fam = {
	.name          = NM_NL_FAM,
	.version       = NM_NL_VER,
	.maxattr       = NM_A_MAX,
	.ops           = nm_nl_ops,
	.n_ops         = ARRAY_SIZE(nm_nl_ops),
	.module        = THIS_MODULE,
	.netnsok       = true,
	.resv_start_op = 0,
};

static int __init nm_init(void)
{
	int ret;

	ret = rtnl_link_register(&nm_link_ops);
	if (ret)
		return ret;

	ret = genl_register_family(&nm_nl_fam);
	if (ret) {
		rtnl_link_unregister(&nm_link_ops);
		return ret;
	}

	ret = register_netdevice_notifier(&nm_netdev_notifier);
	if (ret) {
		genl_unregister_family(&nm_nl_fam);
		rtnl_link_unregister(&nm_link_ops);
		return ret;
	}

	pr_info("nmesh: module initialized (per-netns mode)\n");
	return 0;
}

static void __exit nm_exit(void)
{
	unregister_netdevice_notifier(&nm_netdev_notifier);
	genl_unregister_family(&nm_nl_fam);
	rtnl_link_unregister(&nm_link_ops);

	nm_ctx_destroy_all();

	pr_info("nmesh: module exited\n");
}

module_init(nm_init);
module_exit(nm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("nmesh DCO driver (per-netns)");
MODULE_AUTHOR("nmesh team");
MODULE_VERSION("0.2");
