from packet import Packet
from scapy.all import IP, TCP, IPv6, RandShort


class TCPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(TCPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> TCP:
        if self.packet == IP:
            inner_packet = IP(dst=self.dst, ttl=ttl, id=self.id)
        elif self.packet == IPv6:
            inner_packet = IPv6(dst=self.dst, hlim=ttl)
        else:
            raise ValueError("Unknown packet type")
        return (
                inner_packet
                / TCP(flags=0x2, dport=self.port, sport=RandShort(),
                      seq=self.seq)
        )
