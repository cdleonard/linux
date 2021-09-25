/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_TCP_AUTHOPT_H
#define _LINUX_TCP_AUTHOPT_H

#ifndef __GENKSYMS__

#include <uapi/linux/tcp.h>
#include <linux/livepatch.h>

/* Do not modify kconfig for livepatch */
#define CONFIG_TCP_AUTHOPT 1

/* BEGIN: inline ABI to avoid other header changes */

#define TCP_AUTHOPT            38      /* TCP Authentication Option (RFC5925) */
#define TCP_AUTHOPT_KEY                39      /* TCP Authentication Option Key (RFC5925) */

/**
 * enum tcp_authopt_flag - flags for `tcp_authopt.flags`
 */
enum tcp_authopt_flag {
	/**
	 * @TCP_AUTHOPT_FLAG_LOCK_KEYID: keyid controlled by sockopt
	 *
	 * If this is set `tcp_authopt.send_keyid` is used to determined sending
	 * key. Otherwise a key with send_id == recv_rnextkeyid is preferred.
	 */
	TCP_AUTHOPT_FLAG_LOCK_KEYID = (1 << 0),
	/**
	 * @TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID: Override rnextkeyid from userspace
	 *
	 * If this is set then `tcp_authopt.send_rnextkeyid` is sent on outbound
	 * packets. Other the recv_id of the current sending key is sent.
	 */
	TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID = (1 << 1),
	/**
	 * @TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED:
	 *	Configure behavior of segments with TCP-AO coming from hosts for which no
	 *	key is configured. The default recommended by RFC is to silently accept
	 *	such connections.
	 */
	TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED = (1 << 2),
};

/**
 * struct tcp_authopt - Per-socket options related to TCP Authentication Option
 */
struct tcp_authopt {
	/** @flags: Combination of &enum tcp_authopt_flag */
	__u32	flags;
	/**
	 * @send_keyid: `tcp_authopt_key.send_id` of preferred send key
	 *
	 * This is only used if `TCP_AUTHOPT_FLAG_LOCK_KEYID` is set.
	 */
	__u8	send_keyid;
	/**
	 * @send_rnextkeyid: The rnextkeyid to send in packets
	 *
	 * This is controlled by the user iff TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID is
	 * set. Otherwise rnextkeyid is the recv_id of the current key.
	 */
	__u8	send_rnextkeyid;
	/** @recv_keyid: A recently-received keyid value. Only for getsockopt. */
	__u8	recv_keyid;
	/** @recv_rnextkeyid: A recently-received rnextkeyid value. Only for getsockopt. */
	__u8	recv_rnextkeyid;
};

/**
 * enum tcp_authopt_key_flag - flags for `tcp_authopt.flags`
 *
 * @TCP_AUTHOPT_KEY_DEL: Delete the key and ignore non-id fields
 * @TCP_AUTHOPT_KEY_EXCLUDE_OPTS: Exclude TCP options from signature
 * @TCP_AUTHOPT_KEY_ADDR_BIND: Key only valid for `tcp_authopt.addr`
 */
enum tcp_authopt_key_flag {
	TCP_AUTHOPT_KEY_DEL = (1 << 0),
	TCP_AUTHOPT_KEY_EXCLUDE_OPTS = (1 << 1),
	TCP_AUTHOPT_KEY_ADDR_BIND = (1 << 2),
};

/**
 * enum tcp_authopt_alg - Algorithms for TCP Authentication Option
 */
enum tcp_authopt_alg {
	TCP_AUTHOPT_ALG_HMAC_SHA_1_96 = 1,
	TCP_AUTHOPT_ALG_AES_128_CMAC_96 = 2,
};

/* for TCP_AUTHOPT_KEY socket option */
#define TCP_AUTHOPT_MAXKEYLEN	80

/**
 * struct tcp_authopt_key - TCP Authentication KEY
 *
 * Key are identified by the combination of:
 * - send_id
 * - recv_id
 * - addr (iff TCP_AUTHOPT_KEY_ADDR_BIND)
 *
 * RFC5925 requires that key ids must not overlap for the same TCP connection.
 * This is not enforced by linux.
 */
struct tcp_authopt_key {
	/** @flags: Combination of &enum tcp_authopt_key_flag */
	__u32	flags;
	/** @send_id: keyid value for send */
	__u8	send_id;
	/** @recv_id: keyid value for receive */
	__u8	recv_id;
	/** @alg: One of &enum tcp_authopt_alg */
	__u8	alg;
	/** @keylen: Length of the key buffer */
	__u8	keylen;
	/** @key: Secret key */
	__u8	key[TCP_AUTHOPT_MAXKEYLEN];
	/**
	 * @addr: Key is only valid for this address
	 *
	 * Ignored unless TCP_AUTHOPT_KEY_ADDR_BIND flag is set
	 */
	struct __kernel_sockaddr_storage addr;
};

/* END: inline ABI to avoid other header changes */

#define TCPOPT_AUTHOPT		29	/* Auth Option (RFC5925) */

/* According to RFC5925 the length of the authentication option varies based on
 * the signature algorithm. Linux only implements the algorithms defined in
 * RFC5926 which have a constant length of 16.
 *
 * This is used in stack allocation of tcp option buffers for output. It is
 * shorter than the length of the MD5 option.
 *
 * Input packets can have authentication options of different lengths but they
 * will always be flagged as invalid (since no such algorithms are supported).
 */
#define TCPOLEN_AUTHOPT_OUTPUT	16

struct tcp_authopt_alg_imp;

/**
 * struct tcp_authopt_key_info - Representation of a Master Key Tuple as per RFC5925
 *
 * Key structure lifetime is only protected by RCU so readers needs to hold a
 * single rcu_read_lock until they're done with the key.
 */
struct tcp_authopt_key_info {
	struct hlist_node node;
	struct rcu_head rcu;
	u32 flags;
	/* Wire identifiers */
	u8 send_id, recv_id;
	u8 alg_id;
	u8 keylen;
	u8 key[TCP_AUTHOPT_MAXKEYLEN];
	struct sockaddr_storage addr;
	struct tcp_authopt_alg_imp *alg;
};

/**
 * struct tcp_authopt_info - Per-socket information regarding tcp_authopt
 *
 * This is lazy-initialized in order to avoid increasing memory usage for
 * regular TCP sockets. Once created it is only destroyed on socket close.
 */
struct tcp_authopt_info {
	/** @head: List of tcp_authopt_key_info */
	struct hlist_head head;
	struct rcu_head rcu;
	/**
	 * @send_keyid - Current key used for sending, cached.
	 *
	 * Once a key is found it only changes by user or remote request.
	 */
	struct tcp_authopt_key_info *send_key;
	u32 flags;
	u8 send_keyid;
	u8 send_rnextkeyid;
	u8 recv_keyid;
	u8 recv_rnextkeyid;
	u32 src_isn;
	u32 dst_isn;
};

/* Do not use tcp_authopt_info itself as shadow to allow transfer from live to timewait socket. */
struct tcp_authopt_sock_shadow {
	struct tcp_authopt_info *info;
};

#define TCP_AUTHOPT_SOCK_SHADOW 19861023

static inline struct tcp_authopt_sock_shadow* get_tcp_authopt_shadow(struct sock *sk) {
	return klp_shadow_get(sk, TCP_AUTHOPT_SOCK_SHADOW);
}

static inline struct tcp_authopt_info* get_tcp_authopt_info(struct tcp_sock *tp) {
	struct tcp_authopt_sock_shadow* shadow = get_tcp_authopt_shadow((struct sock *)tp);
	return shadow ? shadow->info : NULL;
}

static inline struct tcp_authopt_info* get_tcp_tw_authopt_info(struct tcp_timewait_sock *tw) {
	struct tcp_authopt_sock_shadow* shadow = get_tcp_authopt_shadow((struct sock *)tw);
	return shadow ? shadow->info : NULL;
}

#ifdef CONFIG_TCP_AUTHOPT
extern int sysctl_tcp_authopt;
extern int tcp_authopt_needed;

void tcp_authopt_free(struct sock *sk, struct tcp_authopt_info *info);
void tcp_authopt_clear(struct sock *sk);
int tcp_set_authopt(struct sock *sk, char __user *optval, unsigned int optlen);
int tcp_get_authopt_val(struct sock *sk, struct tcp_authopt *key);
int tcp_set_authopt_key(struct sock *sk, char __user *optval, unsigned int optlen);
struct tcp_authopt_key_info *__tcp_authopt_select_key(
		const struct sock *sk,
		struct tcp_authopt_info *info,
		const struct sock *addr_sk,
		u8 *rnextkeyid,
		bool locked);
static inline struct tcp_authopt_key_info *tcp_authopt_select_key(
		const struct sock *sk,
		const struct sock *addr_sk,
		u8 *rnextkeyid)
{
	if (tcp_authopt_needed) {
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			return __tcp_authopt_select_key(sk, info, addr_sk, rnextkeyid, true);
	}
	return NULL;
}
int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb);
int tcp_v4_authopt_hash_reply(
		char *hash_location,
		struct tcp_authopt_info *info,
		struct tcp_authopt_key_info *key,
		__be32 saddr,
		__be32 daddr,
		struct tcphdr *th);
int __tcp_authopt_openreq(struct sock *newsk, const struct sock *oldsk, struct request_sock *req);
static inline int tcp_authopt_openreq(
		struct sock *newsk,
		const struct sock *oldsk,
		struct request_sock *req)
{
	if (!get_tcp_authopt_info(tcp_sk(oldsk)))
		return 0;
	else
		return __tcp_authopt_openreq(newsk, oldsk, req);
}
void __tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp);
static inline void tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp)
{
	if (tcp_authopt_needed)
		return __tcp_authopt_time_wait(tcptw, tp);
}
int __tcp_authopt_inbound_check(
		struct sock *sk,
		struct sk_buff *skb,
		struct tcp_authopt_info *info);
/** tcp_authopt_inbound_check - check for valid TCP-AO signature.
 *
 * Return negative ERRNO on error, 0 if not present and 1 if present and valid
 * If both TCP-AO and MD5 signatures are found this is reported as an error.
 */
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb)
{
	if (tcp_authopt_needed) {
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			return __tcp_authopt_inbound_check(sk, skb, info);
	}

	return 0;
}
#else
static inline int tcp_set_authopt(struct sock *sk, char __user *optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}
static inline int tcp_get_authopt_val(struct sock *sk, struct tcp_authopt *key)
{
	return -ENOPROTOOPT;
}
static inline void tcp_authopt_free(struct sock *sk, struct tcp_authopt_info *info)
{
}
static inline void tcp_authopt_clear(struct sock *sk)
{
}
static inline int tcp_set_authopt_key(struct sock *sk, char __user *optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}
static inline struct tcp_authopt_key_info *tcp_authopt_select_key(
		const struct sock *sk,
		const struct sock *addr_sk,
		u8 *rnextkeyid)
{
	return NULL;
}
static inline int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb)
{
	return -EINVAL;
}
static inline int tcp_authopt_openreq(struct sock *newsk,
				      const struct sock *oldsk,
				      struct request_sock *req)
{
	return 0;
}
static inline void tcp_authopt_time_wait(
		struct tcp_timewait_sock *tcptw,
		struct tcp_sock *tp);
{
}
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}
#endif

#endif /* __GENKSYMS__ */

#endif /* _LINUX_TCP_AUTHOPT_H */
