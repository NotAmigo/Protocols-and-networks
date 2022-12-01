from scapy.all import IP


class IPv4Packet:
    def __init__(self, dest, ttl, id):
        self.dest = dest
        self.ttl = ttl
        self.id = id

    def __call__(self):
        return IP(dest=self.dest, ttl=self.ttl, id=self.id)