// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <net/tcp.h>
#include <net/tcp_authopt.h>
#include <crypto/hash.h>
#include <trace/events/tcp.h>

struct tcp_authopt_key_info *__tcp_authopt_key_info_lookup(const struct sock *sk,
							   struct tcp_authopt_info *info,
							   int key_id)
{
	struct tcp_authopt_key_info *key;

	hlist_for_each_entry_rcu(key, &info->head, node, lockdep_sock_is_held(sk))
		if (key->local_id == key_id)
			return key;

	return NULL;
}

static struct tcp_authopt_info *__tcp_authopt_info_get_or_create(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_authopt_info *info;

	info = rcu_dereference_check(tp->authopt_info, lockdep_sock_is_held(sk));
	if (info)
		return info;

	info = kmalloc(sizeof(*info), GFP_KERNEL | __GFP_ZERO);
	if (!info)
		return ERR_PTR(-ENOMEM);

	sk_nocaps_add(sk, NETIF_F_GSO_MASK);
	INIT_HLIST_HEAD(&info->head);
	rcu_assign_pointer(tp->authopt_info, info);

	return info;
}

int tcp_set_authopt(struct sock *sk, sockptr_t optval, unsigned int optlen)
{
	struct tcp_authopt opt;
	struct tcp_authopt_info *info;

	WARN_ON(!lockdep_sock_is_held(sk));

	/* If userspace optlen is too short fill the rest with zeros */
	if (optlen > sizeof(opt))
		return -EINVAL;
	memset(&opt, 0, sizeof(opt));
	if (copy_from_sockptr(&opt, optval, optlen))
		return -EFAULT;

	info = __tcp_authopt_info_get_or_create(sk);
	if (IS_ERR(info))
		return PTR_ERR(info);

	info->flags = opt.flags & (
			TCP_AUTHOPT_FLAG_LOCK_KEYID |
			TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID |
			TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED);
	//if (opt.flag & TCP_AUTHOPT_FLAG_LOCK_KEYID)
	info->local_send_id = opt.local_send_id;
	if (opt.flags & TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID)
		info->send_rnextkeyid = opt.send_rnextkeyid;

	return 0;
}

int tcp_get_authopt_val(struct sock *sk, struct tcp_authopt *opt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_authopt_info *info;

	WARN_ON(!lockdep_sock_is_held(sk));
	memset(opt, 0, sizeof(*opt));
	info = rcu_dereference_check(tp->authopt_info, lockdep_sock_is_held(sk));
	if (!info)
		return -EINVAL;
	opt->flags = info->flags;

	return 0;
}

static void tcp_authopt_key_del(struct sock *sk, struct tcp_authopt_info *info, struct tcp_authopt_key_info *key)
{
	hlist_del_rcu(&key->node);
	if (info->send_key == key)
		info->send_key = NULL;
	atomic_sub(sizeof(*key), &sk->sk_omem_alloc);
	// This might need to go into a real RCU callback
	tcp_authopt_alg_release(key->alg);
	kfree_rcu(key, rcu);
}

/* free info and keys but don't touch tp->authopt_info */
void __tcp_authopt_info_free(struct sock *sk, struct tcp_authopt_info *info)
{
	struct hlist_node *n;
	struct tcp_authopt_key_info *key;

	hlist_for_each_entry_safe(key, n, &info->head, node)
		tcp_authopt_key_del(sk, info, key);
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
	struct tcp_authopt_alg *alg;
	int err;

	/* If userspace optlen is too short fill the rest with zeros */
	if (optlen > sizeof(opt))
		return -EINVAL;
	memset(&opt, 0, sizeof(opt));
	if (copy_from_sockptr(&opt, optval, optlen))
		return -EFAULT;

	if (opt.keylen > TCP_AUTHOPT_MAXKEYLEN)
		return -EINVAL;

	if (opt.local_id == 0)
		return -EINVAL;

	/* Delete is a special case: we ignore all fields other than local_id */
	if (opt.flags & TCP_AUTHOPT_KEY_DEL) {
		info = rcu_dereference_check(tcp_sk(sk)->authopt_info, lockdep_sock_is_held(sk));
		if (!info)
			return -ENOENT;
		key_info = __tcp_authopt_key_info_lookup(sk, info, opt.local_id);
		if (!key_info)
			return -ENOENT;
		tcp_authopt_key_del(sk, info, key_info);
		return 0;
	}

	/* Initialize tcp_authopt_info if not already set */
	info = __tcp_authopt_info_get_or_create(sk);
	if (IS_ERR(info))
		return PTR_ERR(info);

	/* check key family */
	if (opt.flags & TCP_AUTHOPT_KEY_ADDR_BIND) {
		if (sk->sk_family != opt.addr.ss_family)
			return -EINVAL;
	}

	/* check the algorithm */
	alg = tcp_authopt_alg_get(opt.alg);
	if (!alg)
		return -EINVAL;
	WARN_ON(alg->alg_id != opt.alg);
	err = tcp_authopt_alg_require(alg);
	if (err)
		return err;

	/* If an old value exists for same local_id it is deleted */
	key_info = __tcp_authopt_key_info_lookup(sk, info, opt.local_id);
	if (key_info)
		tcp_authopt_key_del(sk, info, key_info);
	key_info = sock_kmalloc(sk, sizeof(*key_info), GFP_KERNEL | __GFP_ZERO);
	if (!key_info) {
		tcp_authopt_alg_release(alg);
		return -ENOMEM;
	}
	key_info->local_id = opt.local_id;
	key_info->flags = opt.flags & (TCP_AUTHOPT_KEY_EXCLUDE_OPTS | TCP_AUTHOPT_KEY_ADDR_BIND);
	key_info->send_id = opt.send_id;
	key_info->recv_id = opt.recv_id;
	key_info->alg_id = opt.alg;
	key_info->alg = alg;
	key_info->keylen = opt.keylen;
	memcpy(key_info->key, opt.key, opt.keylen);
	key_info->maclen = alg->maclen;
	key_info->traffic_key_len = alg->traffic_key_len;
	memcpy(&key_info->addr, &opt.addr, sizeof(key_info->addr));
	hlist_add_head_rcu(&key_info->node, &info->head);

	return 0;
}

static int tcp_authopt_clone_keys(struct sock *newsk,
				  const struct sock *oldsk,
				  struct tcp_authopt_info *new_info,
				  struct tcp_authopt_info *old_info)
{
	struct tcp_authopt_key_info *old_key;
	struct tcp_authopt_key_info *new_key;

	hlist_for_each_entry_rcu(old_key, &old_info->head, node, lockdep_sock_is_held(sk)) {
		new_key = sock_kmalloc(newsk, sizeof(*new_key), GFP_ATOMIC);
		if (!new_key)
			return -ENOMEM;
		memcpy(new_key, old_key, sizeof(*new_key));
		tcp_authopt_alg_incref(old_key->alg);
		hlist_add_head_rcu(&new_key->node, &new_info->head);
	}

	return 0;
}
