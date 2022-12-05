from packet import Packet
from IPPacket import get_packet_by_version
from scapy.all import IP, IPv6, UDP, RandShort


class UDPPacket(Packet):
    def __init__(self, packet, dst, session_id: int, seq: int, port: int):
        super(UDPPacket, self).__init__(packet, dst, session_id, seq)
        self.port = port

    def get_packet(self, ttl) -> UDP:
        return (get_packet_by_version(self.packet, self.dst, ttl, self.id)
                / UDP(dport=self.port, sport=RandShort()))
