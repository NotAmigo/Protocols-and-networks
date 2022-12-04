from scapy.all import RandString, IP, ICMP, IPv6

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
        if self.packet == IP:
            inner_packet = IP(dst=self.dst, ttl=ttl, id=self.id)
        elif self.packet == IPv6:
            inner_packet = IPv6(dst=self.dst, hlim=ttl)
        else:
            raise ValueError("Unknown packet type")
        return (
                inner_packet
                / ICMP(id=self.id, seq=self.seq)
                / self.payload
                )