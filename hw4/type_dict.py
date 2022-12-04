from scapy.all import IP, IPv6


class TypeDict():
    def __init__(self, dest, ttl, id):
        self.dest = dest
        self.ttl = ttl
        self.id = id
        self.inner_dict = {IP: IP(dest=dest, ttl=ttl, id=id),
                           IPv6: IPv6(dest=dest, hlim=ttl)}

    def __call__(self, key):
        if key in self.inner_dict:
            return self.inner_dict[key]
        else:
            raise KeyError("No such key in dictionary")