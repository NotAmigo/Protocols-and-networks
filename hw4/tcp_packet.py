from packet import Packet
from scapy.all import IP, TCP, RandShort


class TCPPacket(Packet):
    def __init__(self, dst, session_id: int, seq: int, port: int):
        super(TCPPacket, self).__init__(dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> TCP:
        return (
                IP(dst=self.dst, ttl=ttl, id=self.id)
                / TCP(flags=0x2, dport=self.port, sport=RandShort(),
                      seq=self.seq)
        )
