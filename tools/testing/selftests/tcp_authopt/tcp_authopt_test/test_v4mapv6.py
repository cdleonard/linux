# SPDX-License-Identifier: GPL-2.0
"""By default any IPv6 server will also receive packets from IPv4 clients

This is not currently supported by TCP_AUTHOPT but it should fail in an orderly
manner rather than crash ebcause of incorrect casts.
"""

from contextlib import nullcontext
import logging
import socket
import pytest

from . import linux_tcp_authopt
from .server import SimpleServerThread
from .netns_fixture import NamespaceFixture
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_listen_socket,
    create_client_socket,
)

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("mode", ["none", "ao", "ao-addrbind", "md5"])
def test_v4mapv6(exit_stack, mode: str):
    """Test ipv4 client and ipv6 server with and without TCP-AO"""
    nsfixture = NamespaceFixture()
    exit_stack.enter_context(nsfixture)
    server_ipv4_addr = nsfixture.get_addr(socket.AF_INET, 1)

    listen_socket = create_listen_socket(ns=nsfixture.server_netns_name, family=socket.AF_INET6)
    listen_socket = exit_stack.enter_context(listen_socket)

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    client_socket = create_client_socket(
        ns=nsfixture.client_netns_name,
        family=socket.AF_INET,
    )
    client_socket = exit_stack.push(client_socket)

    if mode == "ao":
        alg = linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
        key = linux_tcp_authopt.tcp_authopt_key(alg=alg, key="hello")
        linux_tcp_authopt.set_tcp_authopt_key(listen_socket, key)
        linux_tcp_authopt.set_tcp_authopt_key(client_socket, key)

    if mode == "ao-addrbind":
        alg = linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
        client_ipv6_addr = nsfixture.get_addr(socket.AF_INET6, 2)
        server_key = linux_tcp_authopt.tcp_authopt_key(
            alg=alg, key="hello", addr=client_ipv6_addr
        )
        server_key.flags = linux_tcp_authopt.TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
        linux_tcp_authopt.set_tcp_authopt_key(listen_socket, server_key)

        client_key = linux_tcp_authopt.tcp_authopt_key(alg=alg, key="hello")
        linux_tcp_authopt.set_tcp_authopt_key(client_socket, client_key)

    if mode == "md5":
        from . import linux_tcp_md5sig

        server_key = linux_tcp_md5sig.tcp_md5sig(key=b"hello")
        server_key.set_ipv6_addr_all()
        linux_tcp_md5sig.setsockopt_md5sig(listen_socket, server_key)
        client_key = linux_tcp_md5sig.tcp_md5sig(key=b"hellx")
        client_key.set_ipv4_addr_all()
        linux_tcp_md5sig.setsockopt_md5sig(client_socket, client_key)

    with pytest.raises(socket.timeout) if mode != "none" else nullcontext():
        client_socket.connect((str(server_ipv4_addr), DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket)
    client_socket.close()
