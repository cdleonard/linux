# SPDX-License-Identifier: GPL-2.0
import socket
import pytest
from ipaddress import IPv4Address
from .sockaddr import sockaddr_in
from contextlib import nullcontext
from .server import SimpleServerThread
from .utils import create_listen_socket, check_socket_echo, DEFAULT_TCP_SERVER_PORT
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig


def test_md5sig_packunpack():
    s1 = tcp_md5sig(flags=0, prefixlen=0, ifindex=0, keylen=0, key=b"a\x00b")
    s2 = tcp_md5sig.unpack(s1.pack())
    assert s1.key[0:2] == s2.key[0:2]
    assert len(s2.key) == 80


def test_md5_basic(exit_stack):
    tcp_md5_key = b"12345"

    listen_socket = exit_stack.enter_context(create_listen_socket())
    setsockopt_md5sig(
        listen_socket,
        tcp_md5sig(
            key=tcp_md5_key,
            addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
        )
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(
        client_socket,
        tcp_md5sig(
            key=tcp_md5_key,
            addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
        )
    )

    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    check_socket_echo(client_socket)


@pytest.mark.parametrize("goodkey", [True, False])
def test_md5_noaddr(exit_stack, goodkey: bool):

    listen_socket = exit_stack.enter_context(create_listen_socket())
    server_key = tcp_md5sig(key=b"12345")
    server_key.set_ipv4_addr_all()
    setsockopt_md5sig(listen_socket, server_key)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(1)
    client_key = tcp_md5sig(key=b"12345" if goodkey else b"54321")
    client_key.set_ipv4_addr_all()
    setsockopt_md5sig(client_socket, client_key)
    exit_stack.push(client_socket)

    with pytest.raises(socket.timeout) if goodkey == False else nullcontext():
        client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_md5_validation(exit_stack, address_family):
    from .full_tcp_sniff_session import FullTCPSniffSession
    from .tcp_connection_fixture import TCPConnectionFixture
    from .scapy_utils import calc_tcp_md5_hash
    from .scapy_utils import scapy_tcp_get_md5_sig
    from .scapy_utils import scapy_sniffer_stop
    from scapy.layers.inet import TCP

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    con = TCPConnectionFixture(
        address_family=address_family, sniffer_session=sniffer_session
    )
    con.tcp_md5_key = b"12345"
    exit_stack.enter_context(con)

    con.client_socket.connect((str(con.server_addr), con.server_port))
    check_socket_echo(con.client_socket)
    con.client_socket.close()

    sniffer_session.wait_close()
    scapy_sniffer_stop(con.sniffer)

    for p in con.sniffer.results:
        captured = scapy_tcp_get_md5_sig(p[TCP])
        computed = calc_tcp_md5_hash(p, con.tcp_md5_key)
        assert captured.hex() == computed.hex()
