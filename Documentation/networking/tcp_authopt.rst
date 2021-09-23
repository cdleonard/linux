.. SPDX-License-Identifier: GPL-2.0

=========================
TCP Authentication Option
=========================

The TCP Authentication option specified by RFC5925 replaces the TCP MD5
Signature option. It similar in goals but not compatible in either wire formats
or ABI.

Interface
=========

Individual keys can be added to or removed through an TCP socket by using
TCP_AUTHOPT_KEY setsockopt and a struct tcp_authopt_key. There is no
support for reading back keys and updates always replace the old key. These
structures represent "Master Key Tuples (MKTs)" as described by the RFC.

Per-socket options can set or read using the TCP_AUTHOPT sockopt and a struct
tcp_authopt. This is optional: doing setsockopt TCP_AUTHOPT_KEY is sufficient to
enable the feature.

Configuration associated with TCP Authentication is global for each network
namespace, this means that all sockets for which TCP_AUTHOPT is enabled will
be affected by the same set of keys.

Manipulating keys requires ``CAP_NET_ADMIN``.

Key binding
-----------

Keys can be bound to remote addresses in a way that is somewhat similar to
``TCP_MD5SIG``. By default a key matches all connections but matching criteria can
be specified as fields inside struct tcp_authopt_key together with matching
flags in tcp_authopt_key.flags. The sort of these "matching criteria" can
expand over time by increasing the size of `struct tcp_authopt_key` and adding
new flags.

 * Address binding is optional, by default keys match all addresses
 * Local address is ignored, matching is done by remote address
 * Ports are ignored
 * It is possible to match a specific VRF by l3index (default is to ignore)
 * It is possible to match with a fixed prefixlen (default is full address)

RFC5925 requires that key ids do not overlap when tcp identifiers (addr/port)
overlap. This is not enforced by linux, configuring ambiguous keys will result
in packet drops and lost connections.

Key selection
-------------

On getsockopt(TCP_AUTHOPT) information is provided about keyid/rnextkeyid in
the last send packet and about the keyid/rnextkeyd in the last valid received
packet.

By default the sending keyid is selected to match the rnextkeyid value sent by
the remote side, visible as recv_rnextkeyid in getsockopt. If that keyid is not
available then the valid key with the longest send validity time is used, and
otherwise ties are broken by preferring lowest numeric send_id.

If the ``TCP_AUTHOPT_LOCK_KEYID`` flag is set then the sending key is selected
by the `tcp_authopt.send_local_id` field and recv_rnextkeyid is ignored. If no
key with local_id == send_local_id is valid then the same default is used
as for missing recv_rnextkeyid.

The rnextkeyid value sent on the wire is the recv_id of the valid key with the
longest recv validity time, and otherwise ties are broken by preferring lowest
numeric recv_id.

If the TCP_AUTHOPT_LOCK_RNEXTKEY flag is set in `tcp_authopt.flags` the value of
`tcp_authopt.send_rnextkeyid` is sent instead.

The default key selection behavior is designed to implement key rollover in a
way that is compatible with existing vendors without needing userspace key
management. It also tries to behave predictably in all scenarios therefore it
breaks ties by numeric IDs.

A userspace daemon can use the "lock" flags to implement different key
management and key rotation policies.

ABI Reference
=============

.. kernel-doc:: include/uapi/linux/tcp.h
   :identifiers: tcp_authopt tcp_authopt_flag tcp_authopt_key tcp_authopt_key_flag tcp_authopt_alg
