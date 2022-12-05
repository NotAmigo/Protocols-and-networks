from scapy.all import IP, IPv6


def get_packet_by_version(version: int, dst, ports, id):
    if version == 4:
        return IP(dst=dst, ttl=ports, id=id)
    elif version == 6:
        return IPv6(dst=dst, hlim=ports)
    else:
        raise ValueError("Unknown IP version")
