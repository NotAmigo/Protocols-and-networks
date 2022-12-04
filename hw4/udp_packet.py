from packet import Packet
from scapy.all import IP, UDP, RandShort
from type_dict import TypeDict


class UDPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(UDPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> UDP:
        type_dict = TypeDict(self.dst, ttl, self.id)
        return (
                type_dict(self.packet)
                / UDP(dport=self.port, sport=RandShort())
        )
