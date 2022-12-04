from packet import Packet
from scapy.all import IP, TCP, RandShort
from type_dict import TypeDict


class TCPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(TCPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> TCP:
        type_dict = TypeDict(self.dst, ttl, self.id)
        return (
                type_dict(self.packet)
                / TCP(flags=0x2, dport=self.port, sport=RandShort(),
                      seq=self.seq)
        )
