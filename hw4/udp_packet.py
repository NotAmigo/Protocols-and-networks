from packet import Packet
from scapy.all import IP, UDP, RandShort


class UDPPacket(Packet):
    def __init__(self, dst, session_id: int, seq: int, src: str, port: int):
        super(UDPPacket, self).__init__(dst, session_id, seq, src)
        self.port = port

    def get_packet(self, ttl) -> UDP:
        return (
                IP(dst=self.dst, ttl=ttl)
                / UDP(dport=self.port, sport=RandShort())
        )
