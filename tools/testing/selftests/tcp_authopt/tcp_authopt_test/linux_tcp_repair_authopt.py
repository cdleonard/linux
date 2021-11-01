# SPDX-License-Identifier: GPL-2.0
import socket
import struct
from dataclasses import dataclass

TCP_REPAIR_AUTHOPT = 40


@dataclass
class tcp_repair_authopt:
    """Like linux struct tcp_authopt"""

    src_isn: int = 0
    dst_isn: int = 0
    snd_sne: int = 0
    rcv_sne: int = 0

    struct_format = "IIII"
    sizeof = struct.calcsize(struct_format)

    def pack(self) -> bytes:
        return struct.pack(
            self.struct_format,
            self.src_isn,
            self.dst_isn,
            self.snd_sne,
            self.rcv_sne,
        )

    def __bytes__(self):
        return self.pack()

    @classmethod
    def unpack(cls, b: bytes):
        tup = struct.unpack(cls.struct_format, b)
        return cls(*tup)


def get_tcp_repair_authopt(sock: socket.socket) -> tcp_repair_authopt:
    b = sock.getsockopt(socket.SOL_TCP, TCP_REPAIR_AUTHOPT, tcp_repair_authopt.sizeof)
    return tcp_repair_authopt.unpack(b)
