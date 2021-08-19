"""Python wrapper around linux TCP_MD5SIG ABI"""

import socket
import struct
from dataclasses import dataclass
from .sockaddr import sockaddr_unpack


IPPROTO_TCP = 6
TCP_MD5SIG = 14
TCP_MD5SIG_EXT = 32
TCP_MD5SIG_MAXKEYLEN = 80


@dataclass
class tcp_md5sig:
    """Like linux struct tcp_md5sig"""

    addr = None
    flags: int
    prefixlen: int
    keylen: int
    ifindex: int
    key: bytes

    TCP_MD5SIG_FLAG_PREFIX = 0x1
    TCP_MD5SIG_FLAG_PREFIX = 0x2
    sizeof = 128 + 88

    def __init__(
        self, addr=None, flags=0, prefixlen=0, keylen=None, ifindex=0, key=bytes()
    ):
        self.addr = addr
        self.flags = flags
        self.prefixlen = prefixlen
        self.ifindex = ifindex
        self.key = key
        if keylen is None:
            self.keylen = len(key)
        else:
            self.keylen = keylen

    def get_addr_bytes(self) -> bytes:
        if self.addr is None:
            return b"\0" * 128
        if self.addr is bytes:
            assert len(self.addr) == 128
            return self.addr
        return self.addr.pack()

    def pack(self) -> bytes:
        return struct.pack(
            "128sBBHi80s",
            self.get_addr_bytes(),
            self.flags,
            self.prefixlen,
            self.keylen,
            self.ifindex,
            self.key,
        )

    @classmethod
    def unpack(cls, buffer: bytes) -> "tcp_md5sig":
        tup = struct.unpack("128sBBHi80s", buffer)
        addr = sockaddr_unpack(tup[0])
        return cls(addr, *tup[1:])


def setsockopt_md5sig(sock, **kw):
    sig = tcp_md5sig(**kw)
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, sig.pack())


def getsockopt_md5sig(sock, **kw) -> tcp_md5sig:
    buffer = sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, tcp_md5sig.sizeof)
    return tcp_md5sig.unpack(buffer)
