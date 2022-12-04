from scapy.all import IP, IPv6, UDP

a = IP(dest='8.8.8.8', ttl=1, id=1)

print(a)