import logging
import os
import socket
import time
import errno
import subprocess
import typing
from contextlib import ExitStack, contextmanager
from ipaddress import IPv4Address, IPv6Address
from nsenter import Namespace
import struct

import pytest
from scapy.layers.inet import TCP
from scapy.packet import Packet
import scapy.sessions

from . import tcp_authopt_alg
from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT_FLAG_LOCK_KEYID,
    TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID,
    set_tcp_authopt,
    get_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig
from .server import SimpleServerThread
from .sockaddr import sockaddr_in, sockaddr_unpack
from .utils import (
    AsyncSnifferContext,
    SimpleWaitEvent,
    netns_context,
    nstat_json,
    randbytes,
    recvall,
    scapy_sniffer_stop,
)

logger = logging.getLogger(__name__)


def can_capture():
    # This is too restrictive:
    return os.geteuid() == 0


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)

TCP_SERVER_PORT = 17971


@pytest.fixture
def exit_stack():
    with ExitStack() as exit_stack:
        yield exit_stack


class NamespaceFixture:
    """Create a pair of namespaces connect by one veth pair

    Each end of the pair has multiple addresses but everything is in the same subnet
    """

    ns1_name = "tcp_authopt_test_1"
    ns2_name = "tcp_authopt_test_2"

    @classmethod
    def get_ipv4_addr(cls, ns=1, index=1) -> IPv4Address:
        return IPv4Address("10.10.0.0") + (ns << 8) + index

    @classmethod
    def get_ipv6_addr(cls, ns=1, index=1) -> IPv6Address:
        return IPv6Address("fd00::") + (ns << 16) + index

    @classmethod
    def get_addr(cls, address_family=socket.AF_INET, ns=1, index=1):
        if address_family == socket.AF_INET:
            return cls.get_ipv4_addr(ns, index)
        elif address_family == socket.AF_INET6:
            return cls.get_ipv6_addr(ns, index)
        else:
            raise ValueError(f"Bad address_family={address_family}")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def __enter__(self):
        script = f"""
set -e -x
ip netns del {self.ns1_name} || true
ip netns del {self.ns2_name} || true
ip netns add {self.ns1_name}
ip netns add {self.ns2_name}
ip link add veth0 netns {self.ns1_name} type veth peer name veth0 netns {self.ns2_name}
ip netns exec {self.ns1_name} ip link set veth0 up
ip netns exec {self.ns2_name} ip link set veth0 up
"""
        for index in [1, 2, 3]:
            script += f"ip -n {self.ns1_name} addr add {self.get_ipv4_addr(1, index)}/16 dev veth0\n"
            script += f"ip -n {self.ns2_name} addr add {self.get_ipv4_addr(2, index)}/16 dev veth0\n"
            script += f"ip -n {self.ns1_name} addr add {self.get_ipv6_addr(1, index)}/64 dev veth0 nodad\n"
            script += f"ip -n {self.ns2_name} addr add {self.get_ipv6_addr(2, index)}/64 dev veth0 nodad\n"
        subprocess.run(script, shell=True, check=True)
        return self

    def __exit__(self, *a):
        script = f"""
set -e -x
ip netns del {self.ns1_name} || true
ip netns del {self.ns2_name} || true
"""
        subprocess.run(script, shell=True, check=True)


def check_socket_echo(sock, size=1024):
    """Send random bytes and check they are received"""
    send_buf = randbytes(size)
    sock.sendall(send_buf)
    recv_buf = recvall(sock, size)
    assert send_buf == recv_buf


def test_nonauth_connect(exit_stack):
    listen_socket = exit_stack.enter_context(create_listen_socket())
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)


def test_multi_nonauth_connect():
    """Test that the client/server infrastructure does not leak or hang"""
    for i in range(10):
        with ExitStack() as exit_stack:
            logger.info("ITER %d", i)
            test_nonauth_connect(exit_stack)


def test_md5sig_packunpack():
    s1 = tcp_md5sig(flags=0, prefixlen=0, ifindex=0, keylen=0, key=b"a\x00b")
    s2 = tcp_md5sig.unpack(s1.pack())
    assert s1.key[0:2] == s2.key[0:2]
    assert len(s2.key) == 80


def test_authopt_key_pack_noaddr():
    b = bytes(tcp_authopt_key(key=b"a\x00b"))
    assert b[7] == 3
    assert b[8:13] == b"a\x00b\x00\x00"


def test_authopt_key_pack_addr():
    b = bytes(tcp_authopt_key(key=b"a\x00b", addr="10.0.0.1"))
    assert struct.unpack("H", b[88:90])[0] == socket.AF_INET
    assert sockaddr_unpack(b[88:]).addr == IPv4Address("10.0.0.1")


def test_authopt_key_pack_addr6():
    b = bytes(tcp_authopt_key(key=b"abc", addr="fd00::1"))
    assert struct.unpack("H", b[88:90])[0] == socket.AF_INET6
    assert sockaddr_unpack(b[88:]).addr == IPv6Address("fd00::1")


def test_md5_basic(exit_stack):
    tcp_md5_key = b"12345"

    listen_socket = exit_stack.enter_context(create_listen_socket())
    setsockopt_md5sig(
        listen_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(
        client_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )

    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)


class CompleteTCPCaptureSniffSession(scapy.sessions.DefaultSession):
    """Smart scapy sniff session

    Allow waiting to capture FIN
    """

    found_syn = False
    found_synack = False
    found_fin = False
    found_client_fin = False
    found_server_fin = False

    def __init__(self, server_port=None, **kw):
        super().__init__(**kw)
        self.server_port = server_port
        self._close_event = SimpleWaitEvent()

    def on_packet_received(self, p):
        super().on_packet_received(p)
        if not p or not TCP in p:
            return
        th = p[TCP]
        # logger.debug("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if th.flags.S and not th.flags.A:
            if th.dport == self.server_port or self.server_port is None:
                self.found_syn = True
        if th.flags.S and th.flags.A:
            if th.sport == self.server_port or self.server_port is None:
                self.found_synack = True
        if th.flags.F:
            if self.server_port is None:
                self.found_fin = True
                self._close_event.set()
            elif self.server_port == th.dport:
                self.found_client_fin = True
                self.found_fin = True
                if self.found_server_fin and self.found_client_fin:
                    self._close_event.set()
            elif self.server_port == th.sport:
                self.found_server_fin = True
                self.found_fin = True
                if self.found_server_fin and self.found_client_fin:
                    self._close_event.set()

    def wait_close(self, timeout=10):
        self._close_event.wait(timeout=timeout)


@skipif_cant_capture
def test_complete_sniff(exit_stack: ExitStack):
    """Test that the whole TCP conversation is sniffed by scapy"""
    session = CompleteTCPCaptureSniffSession(server_port=TCP_SERVER_PORT)
    sniffer = exit_stack.enter_context(
        AsyncSnifferContext(
            filter=f"tcp port {TCP_SERVER_PORT}", iface="lo", session=session
        )
    )

    listen_socket = create_listen_socket()
    listen_socket = exit_stack.enter_context(listen_socket)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)
    client_socket.close()
    session.wait_close()
    sniffer.stop()

    found_syn = False
    found_synack = False
    found_client_fin = False
    found_server_fin = False
    for p in sniffer.results:
        th = p[TCP]
        logger.info("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if p[TCP].flags.S and not p[TCP].flags.A:
            assert p[TCP].dport == TCP_SERVER_PORT
            found_syn = True
        if p[TCP].flags.S and p[TCP].flags.A:
            assert p[TCP].sport == TCP_SERVER_PORT
            found_synack = True
        if p[TCP].flags.F:
            if p[TCP].dport == TCP_SERVER_PORT:
                found_client_fin = True
            else:
                found_server_fin = True
    assert found_syn and found_synack and found_client_fin and found_server_fin


class MainTestBase:
    """Can be parametrized by inheritance"""

    master_key = b"testvector"
    address_family = None
    alg_name = "HMAC-SHA-1-96"

    def get_alg(self):
        return tcp_authopt_alg.get_alg(self.alg_name)

    def get_alg_id(self) -> int:
        if self.alg_name == "HMAC-SHA-1-96":
            return linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96
        elif self.alg_name == "AES-128-CMAC-96":
            return linux_tcp_authopt.TCP_AUTHOPT_ALG_AES_128_CMAC_96
        else:
            raise ValueError()

    @skipif_cant_capture
    def test_authopt_connect_sniff(self, exit_stack: ExitStack):
        session = CompleteTCPCaptureSniffSession(server_port=TCP_SERVER_PORT)
        sniffer = exit_stack.enter_context(
            AsyncSnifferContext(
                filter=f"tcp port {TCP_SERVER_PORT}", iface="lo", session=session
            )
        )

        listen_socket = create_listen_socket(family=self.address_family)
        listen_socket = exit_stack.enter_context(listen_socket)
        exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

        client_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        client_socket = exit_stack.push(client_socket)

        set_tcp_authopt_key(
            listen_socket,
            tcp_authopt_key(alg=self.get_alg_id(), key=self.master_key),
        )
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(alg=self.get_alg_id(), key=self.master_key),
        )

        # even if one signature is incorrect keep processing the capture
        old_nstat = nstat_json()
        valkey = TcpAuthValidatorKey(key=self.master_key, alg_name=self.alg_name)
        validator = TcpAuthValidator(keys=[valkey])

        try:
            client_socket.settimeout(1.0)
            client_socket.connect(("localhost", TCP_SERVER_PORT))
            for _ in range(5):
                check_socket_echo(client_socket)
        except socket.timeout:
            logger.warning("socket timeout", exc_info=True)
            pass
        client_socket.close()
        session.wait_close()
        sniffer.stop()

        logger.info("capture: %r", sniffer.results)
        for p in sniffer.results:
            validator.handle_packet(p)

        assert not validator.any_fail
        assert not validator.any_unsigned
        # Fails because of duplicate packets:
        # assert not validator.any_incomplete
        new_nstat = nstat_json()
        assert (
            0
            == new_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
            - old_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
        )


def test_has_tcp_authopt():
    from .linux_tcp_authopt import has_tcp_authopt

    assert has_tcp_authopt()


def test_tcp_authopt_key_del_without_active(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)

    # nothing happens:
    key = tcp_authopt_key()
    key.delete_flag = True
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno in [errno.EINVAL, errno.ENOENT]


def test_tcp_authopt_key_setdel(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)
    set_tcp_authopt(sock, tcp_authopt())

    # delete returns ENOENT
    key = tcp_authopt_key()
    key.delete_flag = True
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno == errno.ENOENT

    key = tcp_authopt_key(send_id=1, recv_id=2)
    set_tcp_authopt_key(sock, key)
    # First delete works fine:
    key.delete_flag = True
    set_tcp_authopt_key(sock, key)
    # Duplicate delete returns ENOENT
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno == errno.ENOENT


class TestMainV4(MainTestBase):
    address_family = socket.AF_INET


class TestMainV4AES(MainTestBase):
    address_family = socket.AF_INET
    alg_name = "AES-128-CMAC-96"


class TestMainV6(MainTestBase):
    address_family = socket.AF_INET6


def create_capture_socket(ns: str = "", **kw):
    from scapy.config import conf
    from scapy.data import ETH_P_ALL

    with netns_context(ns):
        capture_socket = conf.L2listen(type=ETH_P_ALL, **kw)
    return capture_socket


def test_namespace_fixture(exit_stack: ExitStack):
    nsfixture = exit_stack.enter_context(NamespaceFixture())

    # create sniffer socket
    capture_socket = exit_stack.enter_context(
        create_capture_socket(ns=nsfixture.ns1_name, iface="veth0")
    )

    # create sniffer thread
    session = CompleteTCPCaptureSniffSession(server_port=TCP_SERVER_PORT)
    sniffer = exit_stack.enter_context(
        AsyncSnifferContext(opened_socket=capture_socket, session=session)
    )

    # create listen socket:
    listen_socket = exit_stack.enter_context(
        create_listen_socket(ns=nsfixture.ns1_name)
    )

    # create client socket:
    with Namespace("/var/run/netns/" + nsfixture.ns2_name, "net"):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    # create server thread:
    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    # set keys:
    server_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    client_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    set_tcp_authopt_key(listen_socket, server_key)
    set_tcp_authopt_key(client_socket, client_key)

    # Run test test
    client_socket.settimeout(1.0)
    client_socket.connect(("10.10.1.1", TCP_SERVER_PORT))
    for _ in range(3):
        check_socket_echo(client_socket)
    client_socket.close()

    session.wait_close()
    scapy_sniffer_stop(sniffer)
    plist = sniffer.results
    logger.info("plist: %r", plist)
    assert any((TCP in p and p[TCP].dport == TCP_SERVER_PORT) for p in plist)


def create_listen_socket(
    ns: str = "",
    family=socket.AF_INET,
    reuseaddr=True,
    listen_depth=10,
    bind_addr="",
    bind_port=TCP_SERVER_PORT,
):
    with netns_context(ns):
        listen_socket = socket.socket(family, socket.SOCK_STREAM)
    if reuseaddr:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((str(bind_addr), bind_port))
    listen_socket.listen(listen_depth)
    return listen_socket


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_server_bind(exit_stack: ExitStack, address_family):
    """ "Server only accept client2, check client1 fails"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = str(nsfixture.get_addr(address_family, 1, 1))
    client_addr = str(nsfixture.get_addr(address_family, 2, 1))
    client_addr2 = str(nsfixture.get_addr(address_family, 2, 2))

    # create server:
    listen_socket = exit_stack.push(
        create_listen_socket(family=address_family, ns=nsfixture.ns1_name)
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # set keys:
    server_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
        addr=client_addr2,
    )
    set_tcp_authopt(
        listen_socket,
        tcp_authopt(flags=linux_tcp_authopt.TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED),
    )
    set_tcp_authopt_key(listen_socket, server_key)

    # create client socket:
    def create_client_socket():
        with Namespace("/var/run/netns/" + nsfixture.ns2_name, "net"):
            client_socket = socket.socket(address_family, socket.SOCK_STREAM)
        client_key = tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="hello",
        )
        set_tcp_authopt_key(client_socket, client_key)
        return client_socket

    # addr match:
    # with create_client_socket() as client_socket2:
    #    client_socket2.bind((client_addr2, 0))
    #    client_socket2.settimeout(1.0)
    #    client_socket2.connect((server_addr, TCP_SERVER_PORT))

    # addr mismatch:
    with create_client_socket() as client_socket1:
        client_socket1.bind((client_addr, 0))
        with pytest.raises(socket.timeout):
            client_socket1.settimeout(1.0)
            client_socket1.connect((server_addr, TCP_SERVER_PORT))


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_client_bind(exit_stack: ExitStack, address_family):
    """ "Client configures different keys with same id but different addresses"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr1 = str(nsfixture.get_addr(address_family, 1, 1))
    server_addr2 = str(nsfixture.get_addr(address_family, 1, 2))
    client_addr = str(nsfixture.get_addr(address_family, 2, 1))

    # create servers:
    listen_socket1 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family, ns=nsfixture.ns1_name, bind_addr=server_addr1
        )
    )
    listen_socket2 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family, ns=nsfixture.ns1_name, bind_addr=server_addr2
        )
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket1, mode="echo"))
    exit_stack.enter_context(SimpleServerThread(listen_socket2, mode="echo"))

    # set keys:
    set_tcp_authopt_key(
        listen_socket1,
        tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="11111",
        ),
    )
    set_tcp_authopt_key(
        listen_socket2,
        tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="22222",
        ),
    )

    # create client socket:
    def create_client_socket():
        with netns_context(nsfixture.ns2_name):
            client_socket = socket.socket(address_family, socket.SOCK_STREAM)
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(
                alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
                key="11111",
                flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
                addr=server_addr1,
            ),
        )
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(
                alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
                key="22222",
                flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
                addr=server_addr2,
            ),
        )
        client_socket.settimeout(1.0)
        client_socket.bind((client_addr, 0))
        return client_socket

    with create_client_socket() as client_socket1:
        client_socket1.connect((server_addr1, TCP_SERVER_PORT))
        check_socket_echo(client_socket1)
    with create_client_socket() as client_socket2:
        client_socket2.connect((server_addr2, TCP_SERVER_PORT))
        check_socket_echo(client_socket2)


@contextmanager
def make_tcp_authopt_socket_pair(
    server_addr="127.0.0.1",
    server_authopt: tcp_authopt = None,
    server_key_list: typing.Iterable[tcp_authopt_key] = [],
    client_authopt: tcp_authopt = None,
    client_key_list: typing.Iterable[tcp_authopt_key] = [],
) -> typing.Tuple[socket.socket, socket.socket]:
    """Make a pair for connected sockets for key switching tests."""
    with ExitStack() as exit_stack:
        listen_socket = exit_stack.enter_context(
            create_listen_socket(bind_addr=server_addr)
        )
        server_thread = exit_stack.enter_context(
            SimpleServerThread(listen_socket, mode="echo")
        )
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(1.0)

        if server_authopt:
            set_tcp_authopt(listen_socket, server_authopt)
        for k in server_key_list:
            set_tcp_authopt_key(listen_socket, k)
        if client_authopt:
            set_tcp_authopt(client_socket, client_authopt)
        for k in client_key_list:
            set_tcp_authopt_key(client_socket, k)

        client_socket.connect((server_addr, TCP_SERVER_PORT))
        check_socket_echo(client_socket)
        server_socket = server_thread.server_socket[0]

        yield client_socket, server_socket


def test_get_keyids(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2],
            client_key_list=[ck1],
        )
    )

    check_socket_echo(client_socket)
    client_tcp_authopt = get_tcp_authopt(client_socket)
    server_tcp_authopt = get_tcp_authopt(server_socket)
    assert server_tcp_authopt.send_keyid == 11
    assert server_tcp_authopt.send_rnextkeyid == 12
    assert server_tcp_authopt.recv_keyid == 12
    assert server_tcp_authopt.recv_rnextkeyid == 11
    assert client_tcp_authopt.send_keyid == 12
    assert client_tcp_authopt.send_rnextkeyid == 11
    assert client_tcp_authopt.recv_keyid == 11
    assert client_tcp_authopt.recv_rnextkeyid == 12


def test_rollover_send_keyid(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG_LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).recv_keyid == 11
    assert get_tcp_authopt(server_socket).recv_keyid == 12

    # Explicit request for key2
    set_tcp_authopt(
        client_socket, tcp_authopt(send_keyid=22, flags=TCP_AUTHOPT_FLAG_LOCK_KEYID)
    )
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).recv_keyid == 21
    assert get_tcp_authopt(server_socket).recv_keyid == 22


def test_rollover_rnextkeyid(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG_LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_rnextkeyid == 11

    # request rnextkeyd=22 but server does not have it
    set_tcp_authopt(
        client_socket,
        tcp_authopt(send_rnextkeyid=21, flags=TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID),
    )
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_rnextkeyid == 21
    assert get_tcp_authopt(server_socket).send_keyid == 11

    # after adding k2 on server the key is switched
    set_tcp_authopt_key(server_socket, sk2)
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).send_keyid == 21


def test_rollover_delkey(exit_stack: ExitStack):
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG_LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_keyid == 12

    # invalid send_keyid is just ignored
    set_tcp_authopt(client_socket, tcp_authopt(send_keyid=7))
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).send_keyid == 12
    assert get_tcp_authopt(server_socket).recv_keyid == 12
    assert get_tcp_authopt(client_socket).recv_keyid == 11

    # If a key is removed it is replaced by anything that matches
    ck1.delete_flag = True
    set_tcp_authopt_key(client_socket, ck1)
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).send_keyid == 22
    assert get_tcp_authopt(server_socket).send_keyid == 21
    assert get_tcp_authopt(server_socket).recv_keyid == 22
    assert get_tcp_authopt(client_socket).recv_keyid == 21
