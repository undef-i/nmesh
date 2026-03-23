#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/udp_tunnel.h>

#include "nm_dco.h"

#define NM_TX_HEADROOM      64
#define NM_TAG_LEN          16
#define NM_DEF_TTL          64
#define NM_HDR_LEN          2
#define NM_NONCE_LEN        12
#define NM_PFX_LEN          (NM_HDR_LEN + NM_NONCE_LEN)
#define NM_PKT_HDR_LEN      (NM_PFX_LEN + NM_TAG_LEN)
#define NM_AAD_LEN          NM_HDR_LEN

#define NM_PT_DATA          0
#define NM_PKT_TF_REL       0x80
#define NM_PKT_TF_TYPE_MASK 0x7f
#define NM_HOP_DEF          32


#define NM_RX_RP_W          16
#define NM_RX_RP_B          (NM_RX_RP_W * 64)

static DEFINE_SPINLOCK(nm_rx_lock);

static inline u64
nm_nonce_cnt_rd(const u8 nonce[NM_NONCE_LEN])
{
	return ((u64)nonce[4] << 56) | ((u64)nonce[5] << 48) |
	       ((u64)nonce[6] << 40) | ((u64)nonce[7] << 32) |
	       ((u64)nonce[8] << 24) | ((u64)nonce[9] << 16) |
	       ((u64)nonce[10] << 8) | (u64)nonce[11];
}

static inline void
nm_nonce_sid_rd(const u8 nonce[NM_NONCE_LEN], u8 sid[4])
{
	sid[0] = nonce[0];
	sid[1] = nonce[1];
	sid[2] = nonce[2];
	sid[3] = nonce[3];
}

static inline void
nm_rp_map_rst(u64 map[NM_RX_RP_W])
{
	memset(map, 0, sizeof(u64) * NM_RX_RP_W);
}

static void
nm_rp_map_shl(u64 map[NM_RX_RP_W], u64 sh)
{
	u64 tmp[NM_RX_RP_W];
	size_t w_sh, b_sh;
	int i;

	if (sh == 0)
		return;
	if (sh >= NM_RX_RP_B) {
		nm_rp_map_rst(map);
		return;
	}

	memset(tmp, 0, sizeof(tmp));
	w_sh = (size_t)(sh / 64);
	b_sh = (size_t)(sh % 64);

	for (i = NM_RX_RP_W - 1; i >= 0; i--) {
		size_t src;
		u64 v;

		if ((size_t)i < w_sh)
			continue;

		src = (size_t)i - w_sh;
		v = map[src] << b_sh;
		if (b_sh && src > 0)
			v |= map[src - 1] >> (64 - b_sh);

		tmp[i] = v;
	}

	memcpy(map, tmp, sizeof(tmp));
}

static inline bool
nm_rp_map_tst(const u64 map[NM_RX_RP_W], u64 df)
{
	size_t wi, bi;

	if (df >= NM_RX_RP_B)
		return false;
	wi = (size_t)(df / 64);
	bi = (size_t)(df % 64);
	return (map[wi] & (1ULL << bi)) != 0;
}

static inline void
nm_rp_map_set(u64 map[NM_RX_RP_W], u64 df)
{
	size_t wi, bi;

	if (df >= NM_RX_RP_B)
		return;
	wi = (size_t)(df / 64);
	bi = (size_t)(df % 64);
	map[wi] |= (1ULL << bi);
}

static bool
nm_rx_replay_check_and_update(struct nm_peer *p,
			      const u8 nonce[NM_NONCE_LEN])
{
	u8 sid[4];
	u64 cnt, df;
	unsigned long flags;
	bool ok = false;

	if (!p)
		return false;

	nm_nonce_sid_rd(nonce, sid);
	cnt = nm_nonce_cnt_rd(nonce);

	spin_lock_irqsave(&nm_rx_lock, flags);

	if (!p->rx_seen || memcmp(p->rx_sid, sid, sizeof(p->rx_sid)) != 0) {
		memcpy(p->rx_sid, sid, sizeof(p->rx_sid));
		p->rx_max_cnt = cnt;
		nm_rp_map_rst(p->rx_bmp);
		nm_rp_map_set(p->rx_bmp, 0);
		p->rx_seen = true;
		ok = true;
		goto out;
	}

	if (cnt > p->rx_max_cnt) {
		u64 sh = cnt - p->rx_max_cnt;
		nm_rp_map_shl(p->rx_bmp, sh);
		nm_rp_map_set(p->rx_bmp, 0);
		p->rx_max_cnt = cnt;
		ok = true;
		goto out;
	}

	df = p->rx_max_cnt - cnt;
	if (df >= NM_RX_RP_B)
		goto out;

	if (nm_rp_map_tst(p->rx_bmp, df))
		goto out;

	nm_rp_map_set(p->rx_bmp, df);
	ok = true;

out:
	spin_unlock_irqrestore(&nm_rx_lock, flags);
	return ok;
}

int
nm_tx_init(struct nm_dco_ctx *ctx)
{
	struct udp_port_cfg cfg = { 0 };
	struct udp_tunnel_sock_cfg tcfg = { 0 };
	int ret;

	if (!ctx)
		return -EINVAL;
	if (ctx->sock)
		return 0;

	cfg.family = AF_INET;
	cfg.local_ip.s_addr = htonl(INADDR_ANY);
	cfg.local_udp_port = ctx->local_port;

	ret = udp_sock_create(ctx->net, &cfg, &ctx->sock);
	if (ret) {
		pr_err("nmesh: nm_tx_init udp_sock_create failed netns=%u udp/%u ret=%d\n",
		       ctx->net ? ctx->net->ns.inum : 0,
		       ntohs(ctx->local_port), ret);
		ctx->sock = NULL;
		return ret;
	}

	tcfg.encap_type = 1;
	tcfg.encap_rcv = nm_rx_encap;
	setup_udp_tunnel_sock(ctx->net, ctx->sock, &tcfg);
	ctx->sock_borrowed = false;

	pr_info("nmesh: ctx socket ready netns=%u udp/%u\n",
		ctx->net ? ctx->net->ns.inum : 0, ntohs(ctx->local_port));
	return 0;
}

int
nm_tx_init_from_fd(struct nm_dco_ctx *ctx, int ufd)
{
	struct udp_tunnel_sock_cfg tcfg = { 0 };
	struct socket *sock;
	int err = 0;

	if (!ctx || ufd < 0)
		return -EINVAL;
	if (ctx->sock)
		return 0;

	sock = sockfd_lookup(ufd, &err);
	if (!sock)
		return err ? err : -EBADF;

	if (!sock->sk || sock->sk->sk_protocol != IPPROTO_UDP) {
		sockfd_put(sock);
		return -EINVAL;
	}
	if (sock_net(sock->sk) != ctx->net) {
		sockfd_put(sock);
		return -EXDEV;
	}

	ctx->sock = sock;
	ctx->sock_borrowed = true;
	ctx->local_port = inet_sk(sock->sk)->inet_sport;

	tcfg.encap_type = 1;
	tcfg.encap_rcv = nm_rx_encap;
	setup_udp_tunnel_sock(ctx->net, ctx->sock, &tcfg);

	pr_info("nmesh: ctx socket hijacked netns=%u udp/%u fd=%d\n",
		ctx->net ? ctx->net->ns.inum : 0, ntohs(ctx->local_port), ufd);
	return 0;
}

void
nm_tx_fini(struct nm_dco_ctx *ctx)
{
	struct socket *sock;
	bool borrowed;
	struct udp_tunnel_sock_cfg tcfg = { 0 };

	if (!ctx)
		return;

	write_lock_bh(&ctx->lock);
	sock = ctx->sock;
	borrowed = ctx->sock_borrowed;
	ctx->sock = NULL;
	ctx->sock_borrowed = false;
	write_unlock_bh(&ctx->lock);

	if (!sock)
		return;

	setup_udp_tunnel_sock(ctx->net, sock, &tcfg);
	if (borrowed)
		sockfd_put(sock);
	else
		udp_tunnel_sock_release(sock);
}

static int
nm_encrypt_skb_inplace(struct sk_buff *skb, struct nm_peer *p, int nfrags)
{
	struct aead_request *req;
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	void *req_mem;
	u8 *iv;
	u64 ctr;
	int payload_len, ret;

	if (!p || !p->tfm)
		return -EINVAL;
	if (unlikely(skb->len < NM_PKT_HDR_LEN))
		return -EINVAL;

	payload_len = skb->len - NM_PKT_HDR_LEN;

	ctr = __sync_fetch_and_add(&p->nonce_ctr, 1);
	iv = skb->data + NM_HDR_LEN;
	iv[0] = p->nonce_sid[0];
	iv[1] = p->nonce_sid[1];
	iv[2] = p->nonce_sid[2];
	iv[3] = p->nonce_sid[3];
	iv[4] = (u8)(ctr >> 56);
	iv[5] = (u8)(ctr >> 48);
	iv[6] = (u8)(ctr >> 40);
	iv[7] = (u8)(ctr >> 32);
	iv[8] = (u8)(ctr >> 24);
	iv[9] = (u8)(ctr >> 16);
	iv[10] = (u8)(ctr >> 8);
	iv[11] = (u8)ctr;

	if (!p->aead_req_pool || p->aead_req_pool_sz < sizeof(struct aead_request))
		return -EINVAL;

	req_mem = get_cpu_ptr(p->aead_req_pool);
	req = (struct aead_request *)req_mem;
	memset(req, 0, p->aead_req_pool_sz);
	if (!req) {
		put_cpu_ptr(req_mem);
		return -ENOMEM;
	}

	if (likely(!skb_is_nonlinear(skb))) {
		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], skb->data, NM_AAD_LEN);
		sg_set_buf(&sg[1], skb->data + NM_PFX_LEN, payload_len + NM_TAG_LEN);
	} else {
		if (unlikely(nfrags > MAX_SKB_FRAGS + 1)) {
			ret = -ENOSPC;
			goto out_put;
		}

		sg_init_table(sg, nfrags + 1);
		sg_set_buf(&sg[0], skb->data, NM_AAD_LEN);
		ret = skb_to_sgvec(skb, &sg[1], NM_PFX_LEN, payload_len + NM_TAG_LEN);
		if (unlikely(ret < 0))
			goto out_put;
	}

	aead_request_set_tfm(req, p->tfm);
	aead_request_set_crypt(req, sg, sg, payload_len, iv);
	aead_request_set_ad(req, NM_AAD_LEN);

	ret = crypto_aead_encrypt(req);
	memzero_explicit(req, p->aead_req_pool_sz);
	put_cpu_ptr(req_mem);
	return ret;

out_put:
	memzero_explicit(req, p->aead_req_pool_sz);
	put_cpu_ptr(req_mem);
	return ret;
}

static int
nm_decrypt_skb_inplace(struct sk_buff *skb, struct nm_peer *p)
{
	struct aead_request *req;
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	struct sk_buff *trailer;
	void *req_mem;
	const u8 *iv;
	int payload_len, nfrags, ret;

	if (!p || !p->tfm || !skb)
		return -EINVAL;
	if (unlikely(skb->len < NM_PKT_HDR_LEN))
		return -EINVAL;

	payload_len = skb->len - NM_PKT_HDR_LEN;
	nfrags = 0;

	if (!p->aead_req_pool || p->aead_req_pool_sz < sizeof(struct aead_request))
		return -EINVAL;

	req_mem = get_cpu_ptr(p->aead_req_pool);
	req = (struct aead_request *)req_mem;
	memset(req, 0, p->aead_req_pool_sz);
	if (!req) {
		put_cpu_ptr(req_mem);
		return -ENOMEM;
	}

	if (likely(!skb_is_nonlinear(skb))) {
		iv = skb->data + NM_HDR_LEN;
		sg_init_table(sg, 2);
		sg_set_buf(&sg[0], skb->data, NM_AAD_LEN);
		sg_set_buf(&sg[1], skb->data + NM_PFX_LEN, payload_len + NM_TAG_LEN);
	} else {
		nfrags = skb_cow_data(skb, 0, &trailer);
		if (unlikely(nfrags < 0 || nfrags > MAX_SKB_FRAGS + 1)) {
			ret = -ENOSPC;
			goto out_put;
		}

		iv = skb->data + NM_HDR_LEN;
		sg_init_table(sg, nfrags + 1);
		sg_set_buf(&sg[0], skb->data, NM_AAD_LEN);
		ret = skb_to_sgvec(skb, &sg[1], NM_PFX_LEN, payload_len + NM_TAG_LEN);
		if (unlikely(ret < 0))
			goto out_put;
	}

	aead_request_set_tfm(req, p->tfm);
	aead_request_set_crypt(req, sg, sg, payload_len + NM_TAG_LEN, (u8 *)iv);
	aead_request_set_ad(req, NM_AAD_LEN);

	ret = crypto_aead_decrypt(req);
	memzero_explicit(req, p->aead_req_pool_sz);
	put_cpu_ptr(req_mem);
	return ret;

out_put:
	memzero_explicit(req, p->aead_req_pool_sz);
	put_cpu_ptr(req_mem);
	return ret;
}

static int
nm_route_and_xmit(struct sk_buff *skb, struct nm_peer *p)
{
	struct rtable *rt;
	struct flowi4 fl4;
	struct sock *sk;
	__be32 saddr;
	__be16 sport;

	if (!p || !p->ctx || !p->ctx->sock)
		return -ENOTCONN;

	sk = p->ctx->sock->sk;

	memset(&fl4, 0, sizeof(fl4));
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.daddr = p->ep_ip;
	fl4.fl4_sport = inet_sk(sk)->inet_sport;
	fl4.fl4_dport = p->ep_p;

	rt = dst_cache_get_ip4(&p->dst_cache, &fl4.saddr);
	if (!rt) {
		rt = ip_route_output_key(sock_net(sk), &fl4);
		if (IS_ERR(rt))
			return PTR_ERR(rt);
		dst_cache_set_ip4(&p->dst_cache, &rt->dst, fl4.saddr);
	}

	saddr = fl4.saddr;
	sport = inet_sk(sk)->inet_sport;

	skb_scrub_packet(skb, false);

	udp_tunnel_xmit_skb(rt, sk, skb, saddr, p->ep_ip, 0, NM_DEF_TTL, 0,
			    sport, p->ep_p, false, sk->sk_no_check_tx);
	return 0;
}

int
nm_tx_encap(struct sk_buff *skb, struct nm_peer *p)
{
	u8 *hdr;
	int ret, nfrags = 0;
	int req_head = NM_TX_HEADROOM + NM_PKT_HDR_LEN;
	struct sk_buff *trailer;

	if (!skb || !p || !p->ctx || !p->ctx->sock)
		goto err_drop;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		ret = skb_checksum_help(skb);
		if (ret)
			goto err_drop;
	}
	skb->ip_summed = CHECKSUM_NONE;

	if (skb_headroom(skb) < req_head || skb_tailroom(skb) < NM_TAG_LEN ||
	    skb_cloned(skb)) {
		ret = pskb_expand_head(skb, req_head, NM_TAG_LEN, GFP_ATOMIC);
		if (ret)
			goto err_drop;
	}

	if (likely(!skb_is_nonlinear(skb))) {
		__skb_put(skb, NM_TAG_LEN);
	} else {
		nfrags = skb_cow_data(skb, NM_TAG_LEN, &trailer);
		if (unlikely(nfrags < 0))
			goto err_drop;
		pskb_put(skb, trailer, NM_TAG_LEN);
	}

	hdr = skb_push(skb, NM_PFX_LEN);
	hdr[0] = NM_PT_DATA;
	hdr[1] = NM_HOP_DEF;

	ret = nm_encrypt_skb_inplace(skb, p, nfrags);
	if (ret) {
		pr_warn("nmesh: aead encrypt failed peer=%u ret=%d\n", p->id, ret);
		goto err_drop;
	}

	ret = nm_route_and_xmit(skb, p);
	if (ret) {
		pr_warn("nmesh: udp xmit failed peer=%u ret=%d\n", p->id, ret);
		goto err_drop;
	}



	return 0;

err_drop:
	if (skb)
		dev_kfree_skb(skb);
	return -EINVAL;
}

static int
nm_rx_inject_plain(struct sk_buff *skb, struct nm_peer *peer)
{
	struct net_device *dev;
	int ret;

	if (!peer || !peer->ctx)
		return -EINVAL;

	rcu_read_lock();
	dev = rcu_dereference(peer->ctx->dev);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}
	dev_hold(dev);
	rcu_read_unlock();

	if (unlikely(skb->len < NM_PKT_HDR_LEN)) {
		dev_put(dev);
		return -EINVAL;
	}

	__skb_pull(skb, NM_PFX_LEN);
	ret = pskb_trim(skb, skb->len - NM_TAG_LEN);
	if (unlikely(ret)) {
		dev_put(dev);
		return ret;
	}

	skb_scrub_packet(skb, true);
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	netif_rx(skb);
	dev_put(dev);
	return 0;
}

int
nm_rx_encap(struct sock *sk, struct sk_buff *skb)
{
	struct nm_dco_ctx *ctx = NULL;
	struct nm_peer *peer;
	struct udphdr *uh;
	u8 *udp_pl;
	unsigned int pull_need;
	__be32 src_ip;
	__be16 src_port;
	u8 tf, ptype;
	bool rel_f;
	int ret;

	if (!skb)
		return 1;

	pull_need = skb_transport_offset(skb) + sizeof(struct udphdr) + NM_PFX_LEN;
	if (!pskb_may_pull(skb, pull_need))
		return 1;

	uh = udp_hdr(skb);
	udp_pl = (u8 *)(uh + 1);

	src_ip = ip_hdr(skb)->saddr;
	src_port = uh->source;

	ctx = nm_ctx_find_by_net(sock_net(sk));
	if (!ctx) {
		pr_warn("nmesh: rx no ctx for sk=%p src=%pI4:%u\n",
			sk, &src_ip, ntohs(src_port));
		return 1;
	}

	tf = udp_pl[0];
	ptype = tf & NM_PKT_TF_TYPE_MASK;
	rel_f = (tf & NM_PKT_TF_REL) != 0;

	if (ptype != NM_PT_DATA || rel_f || skb->len == pull_need + NM_TAG_LEN)
		return 1;

	if (iptunnel_pull_offloads(skb))
		goto drop;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct udphdr)))
		goto drop;
	__skb_pull(skb, skb_transport_offset(skb) + sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	if (unlikely(skb->len < NM_PKT_HDR_LEN))
		goto drop;

	peer = NULL;
	read_lock_bh(&ctx->lock);
	list_for_each_entry(peer, &ctx->peers, list) {
		if (peer->ep_ip == src_ip && peer->ep_p == src_port)
			break;
	}
	if (!peer || peer->ep_ip != src_ip || peer->ep_p != src_port) {
		pr_warn("nmesh: rx peer mismatch netns=%u src=%pI4:%u\n",
			ctx->net ? ctx->net->ns.inum : 0, &src_ip, ntohs(src_port));
		read_unlock_bh(&ctx->lock);
		goto drop;
	}

	if (!nm_rx_replay_check_and_update(peer, skb->data + NM_HDR_LEN)) {
		pr_warn("nmesh: replay drop peer=%u src=%pI4:%u\n",
			peer->id, &src_ip, ntohs(src_port));
		read_unlock_bh(&ctx->lock);
		goto drop;
	}

	ret = nm_decrypt_skb_inplace(skb, peer);
	if (ret) {
		pr_warn("nmesh: decrypt failed peer=%u src=%pI4:%u ret=%d\n",
			peer->id, &src_ip, ntohs(src_port), ret);
		read_unlock_bh(&ctx->lock);
		goto drop;
	}

	ret = nm_rx_inject_plain(skb, peer);
	read_unlock_bh(&ctx->lock);
	if (ret) {
		pr_warn("nmesh: inject failed peer=%u src=%pI4:%u ret=%d\n",
			peer->id, &src_ip, ntohs(src_port), ret);
		goto drop;
	}
	return 0;

drop:
	kfree_skb(skb);
	return 0;
}
