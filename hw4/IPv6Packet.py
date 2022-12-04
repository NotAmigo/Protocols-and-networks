from scapy.all import IPv6


class IPv6Packet:
    def __init__(self, dest, ttl):
        self.dest = dest
        self.ttl = ttl

    def __call__(self):
        return IPv6(dest=self.dest, hlim=self.ttl)