// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/tcp_authopt.h>
#include <crypto/hash.h>
#include <trace/events/tcp.h>

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

	info = tcp_authopt_info_deref(sk);
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

	if (copy_from_sockptr(&opt, optval, sizeof(opt)))
		return -EFAULT;

	info = rcu_dereference_protected(tp->authopt_info, lockdep_sock_is_held(sk));
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

void tcp_authopt_clear(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_authopt_info *info;
	struct tcp_authopt_key_info *key;
	struct hlist_node *n;

	if (!tp->authopt_info)
		return;

	info = rcu_dereference_protected(tp->authopt_info, 1);
	hlist_for_each_entry_safe(key, n, &info->head, node)
		tcp_authopt_key_del(sk, key);
	kfree_rcu(rcu_dereference_protected(tp->authopt_info, 1), rcu);
	tp->authopt_info = NULL;
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

	if (opt.flags & TCP_AUTHOPT_KEY_DEL) {
		info = tcp_authopt_info_deref(sk);
		key_info = __tcp_authopt_key_info_lookup(sk, info, opt.local_id);
		if (!key_info)
			return -ENOENT;
		tcp_authopt_key_del(sk, key_info);
		return 0;
	}

	if (opt.kdf == TCP_AUTHOPT_KDF_HMAC_SHA1)
		traffic_key_len = 20;
	else if (opt.kdf == TCP_AUTHOPT_KDF_HMAC_SHA1)
		traffic_key_len = 16;
	else
		return -ENOSYS;

	if (opt.kdf == TCP_AUTHOPT_MAC_HMAC_SHA_1_96)
		maclen = 12;
	else if (opt.kdf == TCP_AUTHOPT_MAC_AES_128_CMAC_96)
		maclen = 12;
	else
		return -ENOSYS;

	/* If an old value exists for same local_id it is deleted */
	info = tcp_authopt_info_deref(sk);
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
	key_info->kdf = opt.kdf;
	key_info->mac = opt.mac;
	key_info->keylen = opt.keylen;
	memcpy(key_info->key, opt.key, opt.keylen);
	key_info->maclen = maclen;
	key_info->traffic_key_len = traffic_key_len;
	hlist_add_head_rcu(&key_info->node, &info->head);

	return 0;
}

static int tcp_authopt_traffic_key_v4(
		struct crypto_shash *tfm,
		u8* key,
		unsigned int keylen,
		__be32 saddr,
		__be32 daddr,
		__be16 sport,
		__be16 dport,
		__be32 sisn,
		__be32 disn,
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
	crypto_shash_update(desc, "\x01TCP-AO", 7);
	// RFC5925 section 5.2
	crypto_shash_update(desc, (u8*)&saddr, 4);
	crypto_shash_update(desc, (u8*)&daddr, 4);
	crypto_shash_update(desc, (u8*)&sport, 2);
	crypto_shash_update(desc, (u8*)&dport, 2);
	crypto_shash_update(desc, (u8*)&sisn, 4);
	crypto_shash_update(desc, (u8*)&disn, 4);
	crypto_shash_update(desc, "\x00\xa0", 2);
	err = crypto_shash_final(desc, traffic_key);
	return err;
}

static int tcp_authopt_get_traffic_key(
		struct sock *sk,
		struct tcp_authopt_key_info *key,
		__be32 sisn,
		__be32 disn,
		u8* traffic_key)
{
	struct crypto_shash *kdf_tfm;
	struct inet_sock *inet = inet_sk(sk);
	int err;

	if (key->kdf == TCP_AUTHOPT_KDF_HMAC_SHA1)
		kdf_tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	else
		return -EINVAL;
	if (IS_ERR(kdf_tfm))
		return PTR_ERR(kdf_tfm);
	BUG_ON(crypto_shash_digestsize(kdf_tfm) != key->traffic_key_len);

	/* This assumes a SYN packet */
	err = tcp_authopt_traffic_key_v4(kdf_tfm,
			key->key, key->keylen,
			inet->inet_saddr,
			inet->inet_daddr,
			inet->inet_sport,
			inet->inet_dport,
			sisn,
			disn,
			traffic_key);
	printk("traffic_key: %*ph\n", 20, traffic_key);

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
	/* start of final hash block */
	u8 *tcp_option_hash_ptr = tcp_opts;
	u8 *p = tcp_opts;
	u8 len;

	while (true) {
		if (p >= tcp_data)
			break;
		if (*p == TCPOPT_NOP) {
			++p;
			continue;
		}
		if (*p == TCPOPT_EOL)
			break;
		len = *(p + 1);
		if (p + len > tcp_data)
			return -EINVAL;
		if (*p == TCPOPT_AUTHOPT) {
			if (include_options)
				err = crypto_shash_update(desc, tcp_opts, p + 4 - tcp_opts);
			else
				err = crypto_shash_update(desc, p, 4);
			if (err)
				return err;
			/* Replace hash itself with zeros */
			err = crypto_shash_update_zero(desc, len - 4);
			if (err)
				return err;
			tcp_option_hash_ptr = p + len;
		}
		p += len;
	}
	if (include_options) {
		err = crypto_shash_update(desc, tcp_option_hash_ptr, tcp_data - tcp_option_hash_ptr);
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
	err = tcp_authopt_hash_opts(desc, th, true);
	if (err)
		return err;

	{
		int tholen = th->doff * 4;
		err = crypto_shash_update(desc, (u8*)th + tholen, skb_headlen(skb) - tholen);
		if (err)
			return err;
	}
	if (skb_shinfo(skb)->nr_frags) {
		pr_warn("tcp authopt does not handle fragmented skbs\n");
		return -EINVAL;
	}

	return crypto_shash_final(desc, output_mac);
}

int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk,
		struct sk_buff *skb)
{
	struct tcp_authopt_info *authopt_info;
	struct crypto_shash *tfm;
	struct inet_sock *inet = inet_sk(sk);
	struct tcphdr *th = tcp_hdr(skb);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	u8 traffic_key[TCP_AUTHOPT_MAX_TRAFFIC_KEY_LEN];
	/* MAC inside option is truncated to 12 bytes but crypto API needs output
	 * buffer to be large enough so we use a buffer on the stack.
	 */
	u8 macbuf[16];
	int err;

	authopt_info = tcp_authopt_info_deref(sk);
	BUG_ON(key->traffic_key_len > sizeof(traffic_key));
	if (tcb->tcp_flags & TCPHDR_SYN)
		err = tcp_authopt_get_traffic_key(
				sk,
				key,
				htonl(tcb->seq),
				0, /* SYN */
				traffic_key);
	else
		err = tcp_authopt_get_traffic_key(
				sk, key,
				authopt_info->src_isn,
				authopt_info->dst_isn,
				traffic_key);
	if (err)
		return err;

	if (key->mac == TCP_AUTHOPT_MAC_HMAC_SHA_1_96)
		tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	else
		return -EINVAL;
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	if (crypto_shash_digestsize(tfm) < sizeof(macbuf)) {
		err = -ENOBUFS;
		goto out_free_tfm;
	}
	err = crypto_shash_setkey(tfm, traffic_key, key->traffic_key_len);
	if (err)
		goto out_free_tfm;

	err = tcp_authopt_hash_v4(tfm,
			skb,
			inet->inet_saddr,
			inet->inet_daddr,
			th,
			!(key->flags & TCP_AUTHOPT_KEY_EXCLUDE_OPTS),
			macbuf);
	if (err)
		goto out_free_tfm;
	memcpy(hash_location, macbuf, key->maclen);
	printk("mac: %*ph\n", key->maclen, hash_location);

	return 0;

out_free_tfm:
	crypto_free_shash(tfm);
	return err;
}
