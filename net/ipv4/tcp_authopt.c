// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/tcp_authopt.h>
#include <crypto/hash.h>
#include <trace/events/tcp.h>

/* All current algorithms have a mac length of 12 but crypto API digestsize can be larger */
#define TCP_AUTHOPT_MAXMACBUF	20
#define TCP_AUTHOPT_MAX_TRAFFIC_KEY_LEN	20

struct tcp_authopt_key_info* __tcp_authopt_key_info_lookup(struct sock *sk, struct tcp_authopt_info* info, int key_id)
{
	struct tcp_authopt_key_info* key;

	hlist_for_each_entry_rcu(key, &info->head, node, lockdep_sock_is_held(sk))
		if (key->local_id == key_id)
			return key;

	return NULL;
}

struct tcp_authopt_key_info* tcp_authopt_key_info_lookup(struct sock *sk, int key_id)
{
	struct tcp_authopt_info* info;
	struct tcp_authopt_key_info* key;

	info = rcu_dereference_check(tcp_sk(sk)->authopt_info, lockdep_sock_is_held(sk));
	if (!info)
		return NULL;

	hlist_for_each_entry_rcu(key, &info->head, node, lockdep_sock_is_held(sk))
		if (key->local_id == key_id)
			return key;

	return NULL;
}

int tcp_set_authopt(struct sock *sk, sockptr_t optval, unsigned int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_authopt opt;
	struct tcp_authopt_info *info;

	if (optlen < sizeof(opt))
		return -EINVAL;

	BUG_ON(!lockdep_sock_is_held(sk));
	if (copy_from_sockptr(&opt, optval, sizeof(opt)))
		return -EFAULT;

	info = rcu_dereference_check(tp->authopt_info, lockdep_sock_is_held(sk));
	if (!info) {
		info = kmalloc(sizeof(*info), GFP_KERNEL | __GFP_ZERO);
		if (!info)
			return -ENOMEM;

		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		INIT_HLIST_HEAD(&info->head);
		rcu_assign_pointer(tp->authopt_info, info);
	}
	info->local_send_id = opt.local_send_id;

	return 0;
}

static void tcp_authopt_key_del(struct sock *sk, struct tcp_authopt_key_info *key)
{
	hlist_del_rcu(&key->node);
	atomic_sub(sizeof(*key), &sk->sk_omem_alloc);
	kfree_rcu(key, rcu);
}

/* free info and keys but don't touch tp->authopt_info */
void __tcp_authopt_info_free(struct sock *sk, struct tcp_authopt_info *info)
{
	struct hlist_node *n;
	struct tcp_authopt_key_info *key;

	hlist_for_each_entry_safe(key, n, &info->head, node)
		tcp_authopt_key_del(sk, key);
	kfree_rcu(info, rcu);
}

/* free everything and clear tcp_sock.authopt_info to NULL */
void tcp_authopt_clear(struct sock *sk)
{
	struct tcp_authopt_info *info;

	info = rcu_dereference_protected(tcp_sk(sk)->authopt_info, lockdep_sock_is_held(sk));
	if (info) {
		__tcp_authopt_info_free(sk, info);
		tcp_sk(sk)->authopt_info = NULL;
	}
}

int tcp_set_authopt_key(struct sock *sk, sockptr_t optval, unsigned int optlen)
{
	struct tcp_authopt_key opt;
	struct tcp_authopt_info *info;
	struct tcp_authopt_key_info *key_info;
	u8 traffic_key_len, maclen;

	if (optlen < sizeof(opt))
		return -EINVAL;

	if (copy_from_sockptr(&opt, optval, sizeof(opt)))
		return -EFAULT;

	if (opt.keylen > TCP_AUTHOPT_MAXKEYLEN)
		return -EINVAL;

	if (opt.local_id == 0)
		return -EINVAL;

	/* must set authopt before setting keys */
	info = rcu_dereference_protected(tcp_sk(sk)->authopt_info, lockdep_sock_is_held(sk));
	if (!info)
		return -EINVAL;

	if (opt.flags & TCP_AUTHOPT_KEY_DEL) {
		key_info = __tcp_authopt_key_info_lookup(sk, info, opt.local_id);
		if (!key_info)
			return -ENOENT;
		tcp_authopt_key_del(sk, key_info);
		return 0;
	}

	/* check the algorithm */
	if (opt.alg == TCP_AUTHOPT_ALG_HMAC_SHA_1_96) {
		traffic_key_len = 20;
		maclen = 12;
	} else if (opt.alg == TCP_AUTHOPT_ALG_AES_128_CMAC_96) {
		traffic_key_len = 16;
		maclen = 12;
	} else
		return -ENOSYS;

	/* If an old value exists for same local_id it is deleted */
	key_info = __tcp_authopt_key_info_lookup(sk, info, opt.local_id);
	if (key_info)
		tcp_authopt_key_del(sk, key_info);
	key_info = sock_kmalloc(sk, sizeof(*key_info), GFP_KERNEL | __GFP_ZERO);
	if (!key_info)
		return -ENOMEM;
	key_info->local_id = opt.local_id;
	key_info->flags = opt.flags & TCP_AUTHOPT_KEY_EXCLUDE_OPTS;
	key_info->send_id = opt.send_id;
	key_info->recv_id = opt.recv_id;
	key_info->alg = opt.alg;
	key_info->keylen = opt.keylen;
	memcpy(key_info->key, opt.key, opt.keylen);
	key_info->maclen = maclen;
	key_info->traffic_key_len = traffic_key_len;
	hlist_add_head_rcu(&key_info->node, &info->head);

	return 0;
}

static int tcp_authopt_clone_keys(
		struct sock *newsk,
		const struct sock *oldsk,
		struct tcp_authopt_info *new_info,
		struct tcp_authopt_info *old_info)
{
	struct tcp_authopt_key_info* old_key;
	struct tcp_authopt_key_info* new_key;

	hlist_for_each_entry_rcu(old_key, &old_info->head, node, lockdep_sock_is_held(sk)) {
		new_key = sock_kmalloc(newsk, sizeof(*new_key), GFP_KERNEL);
		if (!new_key)
			return -ENOMEM;
		memcpy(new_key, old_key, sizeof(*new_key));
		hlist_add_head_rcu(&new_key->node, &new_info->head);
	}

	return 0;
}

/** Called to create accepted sockets.
 * 
 *  Need to copy authopt info from listen socket.
 */
int __tcp_authopt_openreq(struct sock *newsk, const struct sock *oldsk, struct request_sock *req)
{
	struct tcp_authopt_info *old_info;
	struct tcp_authopt_info *new_info;
	int err;

	old_info = rcu_dereference(tcp_sk(oldsk)->authopt_info);
	if (!old_info)
		return 0;

	new_info = kmalloc(sizeof(*new_info), GFP_KERNEL | __GFP_ZERO);
	if (!new_info)
		return -ENOMEM;

	sk_nocaps_add(newsk, NETIF_F_GSO_MASK);
	new_info->src_isn = tcp_rsk(req)->snt_isn;
	new_info->dst_isn = tcp_rsk(req)->rcv_isn;
	new_info->local_send_id = old_info->local_send_id;
	INIT_HLIST_HEAD(&new_info->head);
	err = tcp_authopt_clone_keys(newsk, oldsk, new_info, old_info);
	if (err) {
		__tcp_authopt_info_free(newsk, new_info);
		return err;
	}
	rcu_assign_pointer(tcp_sk(newsk)->authopt_info, new_info);

	return 0;
}

struct tcp_authopt_context_v4 {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be32 sisn;
	__be32 disn;
};

static int tcp_authopt_traffic_key_v4(
		struct crypto_shash *tfm,
		u8* key,
		unsigned int keylen,
		struct tcp_authopt_context_v4 *context,
		u8 *traffic_key)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	err = crypto_shash_setkey(tfm, key, keylen);
	if (err)
		return err;

	err = crypto_shash_init(desc);
	if (err)
		return err;
	// RFC5926 section 3.1.1.1
	err = crypto_shash_update(desc, "\x01TCP-AO", 7);
	if (err)
		return err;
	err = crypto_shash_update(desc, (u8*)context, sizeof(*context));
	if (err)
		return err;
	err = crypto_shash_update(desc, "\x00\xa0", 2);
	if (err)
		return err;

	return crypto_shash_final(desc, traffic_key);
}

static int tcp_authopt_get_traffic_key(
		struct sock *sk,
		struct sk_buff *skb,
		struct tcp_authopt_key_info *key,
		bool input,
		u8* traffic_key)
{
	struct crypto_shash *kdf_tfm;
	struct tcphdr *th = tcp_hdr(skb);
	struct tcp_authopt_context_v4 context;
	int err;

	if (key->alg == TCP_AUTHOPT_ALG_HMAC_SHA_1_96)
		kdf_tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	else
		return -EINVAL;
	if (IS_ERR(kdf_tfm))
		return PTR_ERR(kdf_tfm);
	BUG_ON(crypto_shash_digestsize(kdf_tfm) != key->traffic_key_len);

	/* Addresses from packet on input and from socket on output
	 * This is because output has is computed before prepending IP
	 */
	if (input) {
		context.saddr = ip_hdr(skb)->saddr;
		context.daddr = ip_hdr(skb)->daddr;
	} else {
		context.saddr = sk->sk_rcv_saddr;
		context.daddr = sk->sk_daddr;
	}
	/* TCP ports from header */
	context.sport = th->source;
	context.dport = th->dest;

	/* special cases for SYN and SYN/ACK */
	if (th->syn && !th->ack) {
		context.sisn = th->seq;
		context.disn = 0;
	} else if (th->syn && th->ack) {
		context.sisn = th->seq;
		context.disn = htonl(ntohl(th->ack_seq) - 1);
	} else {
		struct tcp_authopt_info *authopt_info = rcu_dereference(tcp_sk(sk)->authopt_info);
		/* authopt was removed from under us, maybe socket deleted? */
		if (!authopt_info) {
			err = -EINVAL;
			goto out;
		}
		/* Initial sequence numbers for ESTABLISHED connections from info */
		if (input) {
			context.sisn = htonl(authopt_info->dst_isn);
			context.disn = htonl(authopt_info->src_isn);
		} else {
			context.sisn = htonl(authopt_info->src_isn);
			context.disn = htonl(authopt_info->dst_isn);
		}
	}

	printk("context: %*ph input=%d%s%s\n", (int)sizeof(context), (u8*)&context, input, th->syn ? " SYN" : "", th->ack ? " ACK" : "");
	err = tcp_authopt_traffic_key_v4(kdf_tfm, key->key, key->keylen, &context, traffic_key);
	printk("traffic_key: %*phN\n", 20, traffic_key);

out:
	crypto_free_shash(kdf_tfm);
	return err;
}

static int crypto_shash_update_zero(struct shash_desc *desc, int len)
{
	u8 zero = 0;
	int i, err;

	for (i = 0; i < len; ++i) {
		err = crypto_shash_update(desc, &zero, 1);
		if (err)
			return err;
	}

	return 0;
}

static int tcp_authopt_hash_hdr_v4(
		struct shash_desc *desc,
		__be32 sne,
		__be32 saddr,
		__be32 daddr,
		struct tcphdr *th,
		int nbytes)
{
	int err;

	err = crypto_shash_update(desc, (u8*)&sne, 4);
	if (err)
		return err;

	{
		struct tcp4_pseudohdr phdr = {
			.saddr = saddr,
			.daddr = daddr,
			.pad = 0,
			.protocol = IPPROTO_TCP,
			.len = htons(nbytes)
		};
		err = crypto_shash_update(desc, (u8*)&phdr, sizeof(phdr));
		if (err)
			return err;
	}
	{
		struct tcphdr hashed_th = *th;
		hashed_th.check = 0;
		err = crypto_shash_update(desc, (u8*)&hashed_th, sizeof(hashed_th));
		if (err)
			return err;
	}
	return 0;
}

/* TCP authopt as found in header */
struct tcphdr_authopt
{
	u8 num;
	u8 len;
	u8 keyid;
	u8 rnextkeyid;
	u8 mac[0];
};

/* Find TCP_AUTHOPT in header.
 *
 * Returns pointer to TCP_AUTHOPT or NULL if not found.
 */
static u8 *tcp_authopt_find_option(struct tcphdr *th)
{
	int length = (th->doff << 2) - sizeof(*th);
	u8 *ptr = (u8 *)(th + 1);

	while (length >= 2) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			if (length < 2)
				return NULL;
			opsize = *ptr++;
			if (opsize < 2)
				return NULL;
			if (opsize > length)
				return NULL;
			if (opcode == TCPOPT_AUTHOPT)
				return ptr - 2;
		}
		ptr += opsize - 2;
		length -= opsize;
	}
	return NULL;
}

/** Hash tcphdr options.
 *  If include_options is false then only the TCPOPT_AUTHOPT option itself is hashed
 *  Maybe we could skip option parsing by asuming the AUTHOPT header is at hash_location-4?
 */
static int tcp_authopt_hash_opts(
		struct shash_desc *desc,
		struct tcphdr *th,
		bool include_options)
{
	int err;
	/* start of options */
	u8 *tcp_opts = (u8*)(th + 1);
	/* end of options */
	u8 *tcp_data = ((u8*)th) + th->doff * 4;
	/* pointer to TCPOPT_AUTHOPT */
	u8 *authopt_ptr = tcp_authopt_find_option(th);
	u8 authopt_len;
	
	if (!authopt_ptr)
		return -EINVAL;
	authopt_len = *(authopt_ptr + 1);

	if (include_options) {
		err = crypto_shash_update(desc, tcp_opts, authopt_ptr - tcp_opts + 4);
		if (err)
			return err;
		err = crypto_shash_update_zero(desc, authopt_len - 4);
		if (err)
			return err;
		err = crypto_shash_update(desc, authopt_ptr + authopt_len, tcp_data - (authopt_ptr + authopt_len));
		if (err)
			return err;
	} else {
		err = crypto_shash_update(desc, authopt_ptr, 4);
		if (err)
			return err;
		err = crypto_shash_update_zero(desc, authopt_len - 4);
		if (err)
			return err;
	}

	return 0;
}

static int skb_shash_frags(
		struct shash_desc *desc,
		struct sk_buff* skb)
{
	struct sk_buff *frag_iter;
	int err, i;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		skb_frag_foreach_page(f, skb_frag_off(f), skb_frag_size(f),
						p, p_off, p_len, copied) {
			vaddr = kmap_atomic(p);
			err = crypto_shash_update(desc, vaddr + p_off, p_len);
			kunmap_atomic(vaddr);
			if (err)
				return err;
		}
	}

	skb_walk_frags(skb, frag_iter) {
		err = skb_shash_frags(desc, frag_iter);
		if (err)
			return err;
	}

	return 0;
}

static int tcp_authopt_hash_v4(
		struct crypto_shash *tfm,
		struct sk_buff *skb,
		__be32 saddr,
		__be32 daddr,
		struct tcphdr *th,
		bool include_options,
		u8 *output_mac)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	err = crypto_shash_init(desc);
	if (err)
		return err;

	err = tcp_authopt_hash_hdr_v4(desc, 0, saddr, daddr, th, skb->len);
	if (err)
		return err;
	err = tcp_authopt_hash_opts(desc, th, include_options);
	if (err)
		return err;

	{
		int tholen = th->doff * 4;
		err = crypto_shash_update(desc, (u8*)th + tholen, skb_headlen(skb) - tholen);
		if (err)
			return err;
	}
	err = skb_shash_frags(desc, skb);
	if (err)
		return err;

	return crypto_shash_final(desc, output_mac);
}

int __tcp_authopt_calc_mac(
		struct sock *sk,
		struct sk_buff *skb,
		struct tcp_authopt_key_info *key,
		bool input,
		char *macbuf)
{
	struct crypto_shash *tfm;
	u8 traffic_key[TCP_AUTHOPT_MAX_TRAFFIC_KEY_LEN];
	int err;

	if (sk->sk_family != AF_INET)
		return -EINVAL;
	BUG_ON(key->traffic_key_len > sizeof(traffic_key));
	err = tcp_authopt_get_traffic_key(sk, skb, key, input, traffic_key);
	if (err)
		return err;

	if (key->alg == TCP_AUTHOPT_ALG_HMAC_SHA_1_96)
		tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	else
		return -EINVAL;
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	if (crypto_shash_digestsize(tfm) > TCP_AUTHOPT_MAXMACBUF) {
		err = -EINVAL;
		goto out_free_tfm;
	}
	err = crypto_shash_setkey(tfm, traffic_key, key->traffic_key_len);
	if (err)
		goto out_free_tfm;

	err = tcp_authopt_hash_v4(tfm,
			skb,
			input ? ip_hdr(skb)->saddr : sk->sk_rcv_saddr,
			input ? ip_hdr(skb)->daddr : sk->sk_rcv_saddr,
			tcp_hdr(skb),
			!(key->flags & TCP_AUTHOPT_KEY_EXCLUDE_OPTS),
			macbuf);
	pr_warn("mac: %*phN\n", key->maclen, macbuf);

out_free_tfm:
	crypto_free_shash(tfm);
	return err;
}

int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk,
		struct sk_buff *skb)
{
	/* MAC inside option is truncated to 12 bytes but crypto API needs output
	 * buffer to be large enough so we use a buffer on the stack.
	 */
	u8 macbuf[TCP_AUTHOPT_MAXMACBUF];
	int err;

	BUG_ON(key->maclen > sizeof(macbuf));
	err = __tcp_authopt_calc_mac(sk, skb, key, false, macbuf);
	if (err) {
		memset(hash_location, 0, key->maclen);
		return err;
	}
	memcpy(hash_location, macbuf, key->maclen);

	return 0;
}

static struct tcp_authopt_key_info* tcp_authopt_inbound_key_lookup(
		struct sock *sk,
		struct tcp_authopt_info *info,
		u8 recv_id)
{
	struct tcp_authopt_key_info *key;

	/* multiple matches will cause occasional failures */
	hlist_for_each_entry_rcu(key, &info->head, node, 0)
		if (key->recv_id == recv_id)
			return key;

	return NULL;
}

int __tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb, struct tcp_authopt_info *info)
{
	struct tcphdr *th = (struct tcphdr*)skb_transport_header(skb);
	struct tcphdr_authopt *opt = (struct tcphdr_authopt*)tcp_authopt_find_option(th);
	struct tcp_authopt_key_info *key;
	u8 macbuf[16];
	int err;

	/* wrong, should reject if missing key: */
	if (!opt)
		return 0;

	key = tcp_authopt_inbound_key_lookup(sk, info, opt->keyid);
	/* bad inbound key len */
	if (key->maclen + 4 != opt->len)
		return -EINVAL;

	err = __tcp_authopt_calc_mac(sk, skb, key, true, macbuf);
	if (err)
		return err;

	if (memcmp(macbuf, opt->mac, key->maclen)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTHOPTFAILURE);
		net_info_ratelimited("TCP Authentication Failed\n");
		return -EINVAL;
	}

	return 0;
}
