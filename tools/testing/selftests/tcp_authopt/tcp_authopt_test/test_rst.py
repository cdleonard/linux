# SPDX-License-Identifier: GPL-2.0
import logging
import socket
from contextlib import ExitStack

import pytest
import waiting
from scapy.layers.inet import TCP

from . import linux_tcp_authopt
from .full_tcp_sniff_session import FullTCPSniffSession
from .linux_tcp_authopt import tcp_authopt_key
from .scapy_tcp_authopt import TcpAuthOptAlg_HMAC_SHA1, add_tcp_authopt_signature
from .tcp_connection_fixture import TCPConnectionFixture
from .scapy_utils import (
    scapy_sniffer_stop,
    tcp_seq_wrap
)
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    socket_set_linger,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey

logger = logging.getLogger(__name__)


DEFAULT_TCP_AUTHOPT_KEY = tcp_authopt_key(
    alg=linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
    key=b"hello",
)


@pytest.mark.parametrize(
    "address_family,signed",
    [(socket.AF_INET, True), (socket.AF_INET, False)],
)
def test_rst(exit_stack: ExitStack, address_family, signed: bool):
    """Check that an unsigned RST breaks a normal connection but not one protected by TCP-AO"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(sniffer_session=sniffer_session)
    if signed:
        context.tcp_authopt_key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)

    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_client2server_packet()
    p[TCP].flags = "R"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1001)
    context.client_l2socket.send(p)

    if signed:
        # When protected by TCP-AO unsigned RSTs are ignored.
        check_socket_echo(context.client_socket)
    else:
        # By default an RST that guesses seq can kill the connection.
        with pytest.raises(ConnectionResetError):
            check_socket_echo(context.client_socket)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_rst_signed_manually(exit_stack: ExitStack, address_family):
    """Check that an manually signed RST breaks a connection protected by TCP-AO"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(address_family=address_family, sniffer_session=sniffer_session)
    context.tcp_authopt_key = key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)

    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_client2server_packet()
    p[TCP].flags = "R"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1001)

    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, client_isn, server_isn
    )
    context.client_l2socket.send(p)

    # The server socket will close in response to RST without a TIME-WAIT
    # Attempting to send additional packets will result in a timeout because
    # the signature can't be validated.
    with pytest.raises(socket.timeout):
        check_socket_echo(context.client_socket)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_tw_ack(exit_stack: ExitStack, address_family):
    """Manually sent a duplicate ACK after FIN and check TWSK signs replies correctly

    Kernel has a custom code path for this
    """

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(address_family=address_family, sniffer_session=sniffer_session)
    context.tcp_authopt_key = key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect and close nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    assert context.get_client_tcp_state() == "ESTAB"
    assert context.get_server_tcp_state() == "ESTAB"
    context.client_socket.close()
    sniffer_session.wait_close()

    assert context.get_client_tcp_state() == "TIME-WAIT"
    assert context.get_server_tcp_state() is None

    # Sent a duplicate FIN/ACK
    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_server2client_packet()
    p[TCP].flags = "FA"
    p[TCP].seq = tcp_seq_wrap(server_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(client_isn + 1002)
    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, server_isn, client_isn
    )
    pr = context.server_l2socket.sr1(p)
    assert pr[TCP].ack == tcp_seq_wrap(server_isn + 1001)
    assert pr[TCP].seq == tcp_seq_wrap(client_isn + 1001)
    assert pr[TCP].flags == "A"

    scapy_sniffer_stop(context.sniffer)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    # The server does not have enough state to validate the ACK from TIME-WAIT
    # so it reports a failure.
    assert context.server_nstat_json()["TcpExtTCPAuthOptFailure"] == 1
    assert context.client_nstat_json()["TcpExtTCPAuthOptFailure"] == 0


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_tw_rst(exit_stack: ExitStack, address_family):
    """Manually sent a signed invalid packet after FIN and check TWSK signs RST correctly

    Kernel has a custom code path for this
    """
    key = DEFAULT_TCP_AUTHOPT_KEY
    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(
        address_family=address_family,
        sniffer_session=sniffer_session,
        tcp_authopt_key=key,
    )
    context.server_thread.keep_half_open = True
    exit_stack.enter_context(context)

    # connect, transfer data and close client nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    context.client_socket.close()

    # since server keeps connection open client goes to FIN-WAIT-2
    def check_socket_states():
        client_tcp_state_name = context.get_client_tcp_state()
        server_tcp_state_name = context.get_server_tcp_state()
        logger.info("%s %s", client_tcp_state_name, server_tcp_state_name)
        return (
            client_tcp_state_name == "FIN-WAIT-2"
            and server_tcp_state_name == "CLOSE-WAIT"
        )

    waiting.wait(check_socket_states)

    # sending a FIN-ACK with incorrect seq makes
    # tcp_timewait_state_process return a TCP_TW_RST
    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_server2client_packet()
    p[TCP].flags = "FA"
    p[TCP].seq = tcp_seq_wrap(server_isn + 1001 + 1)
    p[TCP].ack = tcp_seq_wrap(client_isn + 1002)
    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, server_isn, client_isn
    )
    context.server_l2socket.send(p)

    # remove delay by scapy trick?
    import time

    time.sleep(1)
    scapy_sniffer_stop(context.sniffer)

    # Check client socket moved from FIN-WAIT-2 to CLOSED
    assert context.get_client_tcp_state() is None

    # Check some RST was seen
    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)

    # Check everything was valid
    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    # Check no snmp failures
    context.assert_no_snmp_output_failures()


def test_rst_linger(exit_stack: ExitStack):
    """Test RST sent deliberately via SO_LINGER is valid"""
    context = TCPConnectionFixture(
        sniffer_kwargs=dict(count=8), tcp_authopt_key=DEFAULT_TCP_AUTHOPT_KEY
    )
    exit_stack.enter_context(context)

    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    socket_set_linger(context.client_socket, 1, 0)
    context.client_socket.close()

    context.sniffer.join(timeout=3)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)


@pytest.mark.parametrize("address_family", (socket.AF_INET, socket.AF_INET6))
@pytest.mark.parametrize("index", range(10))
def test_short_conn(exit_stack: ExitStack, address_family, index):
    """Test TWSK sends signed RST"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(
        address_family=address_family,
        sniffer_session=sniffer_session,
        tcp_authopt_key=DEFAULT_TCP_AUTHOPT_KEY,
    )
    exit_stack.enter_context(context)

    # Connect and close nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    context.client_socket.close()

    sniffer_session.wait_close()
    scapy_sniffer_stop(context.sniffer)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    context.assert_no_snmp_output_failures()
