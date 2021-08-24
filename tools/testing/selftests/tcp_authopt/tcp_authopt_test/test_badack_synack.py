import subprocess

import pytest
import socket
import waiting
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.packet import Packet
from scapy.sendrecv import sndrcv

from . import linux_tcp_authopt
from .scapy_tcp_authopt import TcpAuthOptAlg_HMAC_SHA1, add_tcp_authopt_signature
from .tcp_connection_fixture import TCPConnectionFixture
from .scapy_utils import TCPOPT_AUTHOPT


def break_tcp_authopt_signature(packet: Packet):
    """Invalidate TCP-AO signature inside a packet

    The packet must already be signed and it gets modified in-place.
    """
    opt = packet[TCP].options[-1]
    assert opt[0] == TCPOPT_AUTHOPT
    old_packet_bytes = bytes(packet)
    opt_mac = bytearray(opt[1])
    opt_mac[-1] ^= 0xFF
    packet[TCP].options[-1] = (opt[0], bytes(opt_mac))
    new_packet_bytes = bytes(packet)
    assert new_packet_bytes != old_packet_bytes

    # Check packet checksum was recomputed so we don't get dropped for other reasons.
    new_packet = Ether(new_packet_bytes)
    assert new_packet[TCP].chksum != packet[TCP].chksum


@pytest.mark.parametrize(
    "address_family,mode",
    [
        (socket.AF_INET, "goodsign"),
        (socket.AF_INET, "fakesign"),
        (socket.AF_INET, "unsigned"),
        (socket.AF_INET6, "goodsign"),
        (socket.AF_INET6, "fakesign"),
        (socket.AF_INET6, "unsigned"),
    ],
)
def test_badack_to_synack(exit_stack, address_family, mode: str):
    """Test bad ack in reponse to server to syn/ack.

    This is handled by a minisocket in the TCP_SYN_RECV state on a separate code path
    """
    con = TCPConnectionFixture()
    if mode != "unsigned":
        con.tcp_authopt_key = linux_tcp_authopt.tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
            key=b"hello",
        )
    exit_stack.enter_context(con)

    client_l2socket = con.client_l2socket
    client_isn = 1000
    server_isn = 0

    def sign(packet):
        if mode == "unsigned":
            return
        add_tcp_authopt_signature(
            packet,
            TcpAuthOptAlg_HMAC_SHA1(),
            con.tcp_authopt_key.key,
            client_isn,
            server_isn,
        )

    # Prevent TCP in client namespace from sending RST
    # Do this by removing the client address and insert a static ARP on server side
    subprocess.run(
        f"""\
ip netns exec {con.nsfixture.client_netns_name} ip addr del {con.client_addr}/16 dev veth0
ip netns exec {con.nsfixture.server_netns_name} ip neigh add {con.client_addr} lladdr {con.nsfixture.client_mac_addr} dev veth0
""",
        shell=True,
        check=True,
    )

    p1 = con.create_client2server_packet()
    p1[TCP].flags = "S"
    p1[TCP].seq = client_isn
    p1[TCP].ack = 0
    sign(p1)

    ans, unans = sndrcv(client_l2socket, [p1], timeout=1)
    assert len(unans) == 0
    assert len(ans) == 1
    p2 = ans[0].answer
    server_isn = p2[TCP].seq
    assert p2[TCP].ack == client_isn + 1
    assert p2[TCP].flags == "SA"

    p3 = con.create_client2server_packet()
    p3[TCP].flags = "A"
    p3[TCP].seq = client_isn + 1
    p3[TCP].ack = server_isn + 1
    sign(p3)
    if mode == "fakesign":
        break_tcp_authopt_signature(p3)

    assert con.server_nstat_json()["TcpExtTCPAuthOptFailure"] == 0
    client_l2socket.send(p3)

    def confirm_good():
        return len(con.server_thread.server_socket) > 0

    def confirm_fail():
        return con.server_nstat_json()["TcpExtTCPAuthOptFailure"] == 1

    def wait_good():
        assert not confirm_fail()
        return confirm_good()

    def wait_fail():
        assert not confirm_good()
        return confirm_fail()

    if mode == "fakesign":
        waiting.wait(wait_fail, timeout_seconds=5, sleep_seconds=0.1)
    else:
        waiting.wait(wait_good, timeout_seconds=5, sleep_seconds=0.1)
