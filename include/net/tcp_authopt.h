/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_TCP_AUTHOPT_H
#define _LINUX_TCP_AUTHOPT_H

#include <uapi/linux/tcp.h>

/* Representation of a Master Key Tuple as per RFC5925 */
struct tcp_authopt_key_info {
	struct hlist_node node;
	/* Local identifier */
	u32 local_id;
	u32 flags;
	/* Wire identifiers */
	u8 send_id, recv_id;
	u8 kdf, mac;
	u8 keylen;
	u8 key[TCP_AUTHOPT_MAXKEYLEN];
	u8 maclen;
	u8 traffic_key_len;
	struct rcu_head rcu;
};

/* All current algorithms have a mac length of 12 */
#define TCP_AUTHOPT_MAXMACLEN	12
#define TCP_AUTHOPT_MAX_TRAFFIC_KEY_LEN	20

/* Per-socket information regarding tcp_authopt */
struct tcp_authopt_info {
	struct hlist_head head;
	u32 local_send_id;
	u32 src_isn;
	u32 dst_isn;
	u8 rnextkeyid;
	struct rcu_head rcu;
};

#ifdef CONFIG_TCP_AUTHOPT
static inline struct tcp_authopt_info* tcp_authopt_info_deref(const struct sock *sk)
{
	return rcu_dereference(tcp_sk(sk)->authopt_info);
}
struct tcp_authopt_key_info* tcp_authopt_key_info_lookup(struct sock *sk, int key_id);
void tcp_authopt_clear(struct sock *sk);
int tcp_set_authopt(struct sock *sk, sockptr_t optval, unsigned int optlen);
int tcp_set_authopt_key(struct sock *sk, sockptr_t optval, unsigned int optlen);
int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb);
#else
static inline struct tcp_authopt_info* tcp_authopt_info_deref(struct sock *sk) {
	return NULL;
}
static inline struct tcp_authopt_key_info* tcp_authopt_key_info_lookup(struct sock *sk, int key_id) {
	return NULL;
}
static inline int tcp_set_authopt(struct sock *sk, sockptr_t optval, unsigned int optlen) {
	return -ENOPROTOOPT;
}
static inline void tcp_authopt_clear(struct sock *sk) {
}
static inline int tcp_set_authopt_key(struct sock *sk, sockptr_t optval, unsigned int optlen) {
	return -ENOPROTOOPT;
}
static inline int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb) {
	return -ENOSYS;
}
#endif

#endif /* _LINUX_TCP_AUTHOPT_H */
