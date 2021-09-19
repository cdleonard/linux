# SPDX-License-Identifier: GPL-2.0
"""Basic test for interaction between TCP_AUTHOPT and TCP_MD5SIG

Configuring both on same socket is allowed but RFC5925 doesn't allow both on the
same packet or same connection.

The naive handling of inserting or validation both options is incorrect.
"""

import logging
import socket

import pytest
from scapy.layers.inet import TCP

from . import linux_tcp_authopt
from .tcp_connection_fixture import TCPConnectionFixture
from .scapy_utils import (
    scapy_sniffer_stop,
    scapy_tcp_get_authopt_val,
    scapy_tcp_get_md5_sig,
)
from .utils import check_socket_echo

logger = logging.getLogger(__name__)

DEFAULT_TCP_AUTHOPT_KEY = linux_tcp_authopt.tcp_authopt_key(
    alg=linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
    key=b"hello",
)

DEFAULT_TCP_MD5_KEY_SECRET = b"hello"


@pytest.mark.parametrize(
    "address_family,use_tcp_authopt,use_tcp_md5sig",
    [
        (socket.AF_INET, 0, 0),
        (socket.AF_INET, 1, 0),
        (socket.AF_INET, 0, 1),
        (socket.AF_INET6, 0, 0),
        (socket.AF_INET6, 1, 0),
        (socket.AF_INET6, 0, 1),
        (socket.AF_INET, 1, 1),
        (socket.AF_INET6, 1, 1),
    ],
)
def test_basic_authopt_md5(exit_stack, address_family, use_tcp_authopt, use_tcp_md5sig):
    con = TCPConnectionFixture(address_family=address_family)
    if use_tcp_authopt:
        con.tcp_authopt_key = DEFAULT_TCP_AUTHOPT_KEY
    if use_tcp_md5sig:
        con.tcp_md5_key = DEFAULT_TCP_MD5_KEY_SECRET
    exit_stack.enter_context(con)

    con.client_socket.connect((str(con.server_addr), con.server_port))
    check_socket_echo(con.client_socket)
    check_socket_echo(con.client_socket)
    check_socket_echo(con.client_socket)
    con.client_socket.close()

    scapy_sniffer_stop(con.sniffer)
    fail = False
    for p in con.sniffer.results:
        has_tcp_authopt = scapy_tcp_get_authopt_val(p[TCP]) is not None
        has_tcp_md5sig = scapy_tcp_get_md5_sig(p[TCP]) is not None

        if has_tcp_authopt and has_tcp_md5sig:
            logger.error("Packet has both AO and MD5: %r", p)
            fail = False

        if use_tcp_authopt:
            if not has_tcp_authopt:
                logger.error("missing AO: %r", p)
                fail = True
        elif use_tcp_md5sig:
            if not has_tcp_md5sig:
                logger.error("missing MD5: %r", p)
                fail = True
        else:
            if has_tcp_md5sig or has_tcp_authopt:
                logger.error("unexpected MD5 or AO: %r", p)
                fail = True

    assert not fail
