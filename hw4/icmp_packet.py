from scapy.all import RandString, IP, ICMP, IPv6
from type_dict import TypeDict

from packet import Packet


class ICMPPacket(Packet):
    def __init__(self, packet,
                 dst: str,
                 session_id: int,
                 seq: int,
                 length: int,
                 payload=None):
        super(ICMPPacket, self).__init__(packet, dst, session_id, seq)

        self.payload = payload if payload is not None \
            else str(RandString(length - 8))
        self.length = length

    def get_packet(self, ttl: int) -> ICMP:
        type_dict = TypeDict(self.dst, ttl, self.id)
        return (
                type_dict(self.packet)
                / ICMP(id=self.id, seq=self.seq)
                / self.payload
                )