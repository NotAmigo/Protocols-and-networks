from packet import Packet
from scapy.all import IP, TCP, IPv6, RandShort
from IPPacket import get_packet_by_version


class TCPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(TCPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> TCP:
        return (
                get_packet_by_version(self.packet, self.dst, ttl, self.id)
                / TCP(flags=0x2, dport=self.port, sport=RandShort(),
                      seq=self.seq)
        )
