from packet import Packet
from scapy.all import IP, IPv6, UDP, RandShort


class UDPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(UDPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> UDP:
        if self.packet == IP:
            inner_packet = IP(dst=self.dst, ttl=ttl, id=self.id)
        elif self.packet == IPv6:
            inner_packet = IPv6(dst=self.dst, hlim=ttl)
        else:
            raise ValueError("Unknown packet type")
        return (
                inner_packet
                / UDP(dport=self.port, sport=RandShort())
        )
