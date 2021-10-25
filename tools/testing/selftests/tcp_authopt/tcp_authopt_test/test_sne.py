# SPDX-License-Identifier: GPL-2.0
"""Validate SNE implementation for TCP-AO"""

import logging
import socket
from contextlib import ExitStack

import pytest

from .linux_tcp_authopt import set_tcp_authopt_key_kwargs
from .linux_tcp_repair import get_tcp_repair_recv_send_queue_seq, tcp_repair_toggle
from .linux_tcp_repair_authopt import get_tcp_repair_authopt
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
    socket_set_linger,
)

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("signed", [False, True])
def test_high_seq_rollover(exit_stack: ExitStack, signed: bool):
    """Test SNE by rolling over from a high seq/ack value

    Create many connections until a very high seq/ack is found and then transfer
    enough for those values to roll over.

    A side effect of this approach is that this stresses connection
    establishment.
    """
    overflow = 0x200000
    bufsize = 0x10000
    secret_key = b"12345"
    mode = "recv"
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = nsfixture.get_addr(socket.AF_INET, 1)
    client_addr = nsfixture.get_addr(socket.AF_INET, 2)
    server_addr_port = (str(server_addr), DEFAULT_TCP_SERVER_PORT)
    listen_socket = create_listen_socket(
        ns=nsfixture.server_netns_name,
        bind_addr=server_addr,
        listen_depth=1024,
    )
    exit_stack.enter_context(listen_socket)
    if signed:
        set_tcp_authopt_key_kwargs(listen_socket, key=secret_key)
    server_thread = SimpleServerThread(listen_socket, mode=mode, bufsize=bufsize)
    exit_stack.enter_context(server_thread)

    found = False
    client_socket = None
    for iternum in range(10000):
        try:
            # Manually assign increasing client ports
            #
            # Sometimes linux kills timewait sockets (TCPTimeWaitOverflow) and
            # then attempts to reuse the port. The stricter validation
            # requirements of TCP-AO mean the other side of the socket survives
            # and rejects packets coming from the reused port.
            #
            # This issue is not related to SNE so a workaround is acceptable.
            client_socket = create_client_socket(
                ns=nsfixture.client_netns_name,
                bind_addr=client_addr,
                bind_port=10000 + iternum,
            )
            if signed:
                set_tcp_authopt_key_kwargs(client_socket, key=secret_key)
            try:
                client_socket.connect(server_addr_port)
            except:
                logger.error("failed connect on iteration %d", iternum, exc_info=True)
                raise

            recv_seq, send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
            if (recv_seq + overflow > 0x100000000 and mode == "echo") or (
                send_seq + overflow > 0x100000000
            ):
                found = True
                break
            # Wait for graceful close to avoid swamping server listen queue.
            # This makes the test work even with a server listen_depth=1 but set
            # a very high value anyway.
            socket_set_linger(client_socket, 1, 1)
            client_socket.close()
            client_socket = None
        finally:
            if not found and client_socket:
                client_socket.close()
    assert found
    assert client_socket is not None

    logger.debug("setup recv_seq %08x send_seq %08x", recv_seq, send_seq)

    if signed:
        with tcp_repair_toggle(client_socket):
            init_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        assert init_tcp_repair_authopt.src_isn + 1 == send_seq
        assert init_tcp_repair_authopt.dst_isn + 1 == recv_seq
        assert init_tcp_repair_authopt.snd_sne == 0
        assert init_tcp_repair_authopt.rcv_sne == 0
        logger.debug("tcp repair authopt: %r", init_tcp_repair_authopt)

    logger.info("transfer %d bytes", 2 * overflow)
    fail_transfer = False
    for iternum in range(2 * overflow // bufsize):
        try:
            if mode == "recv":
                from .utils import randbytes

                send_buf = randbytes(bufsize)
                client_socket.sendall(send_buf)
            else:
                check_socket_echo(client_socket, bufsize)
        except:
            logger.error("failed traffic on iteration %d", iternum, exc_info=True)
            fail_transfer = True
            break

    new_recv_seq, new_send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
    logger.debug("final recv_seq %08x send_seq %08x", new_recv_seq, new_send_seq)

    if signed:
        with tcp_repair_toggle(client_socket):
            exit_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        logger.debug("exit tcp repair authopt: %r", exit_tcp_repair_authopt)
        assert exit_tcp_repair_authopt.src_isn == init_tcp_repair_authopt.src_isn
        assert exit_tcp_repair_authopt.dst_isn == init_tcp_repair_authopt.dst_isn
        assert (
            exit_tcp_repair_authopt.snd_sne != 0 or exit_tcp_repair_authopt.rcv_sne != 0
        )

    assert new_recv_seq < recv_seq or new_send_seq < send_seq
    assert not fail_transfer
