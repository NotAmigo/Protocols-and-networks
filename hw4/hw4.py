import scapy.all

# packet = IPv6(dst="2001:4860:4860::8888") / ICMPv6EchoRequest()
waypoint = "2001:301:0:8002:203:47ff:fea5:3085"
target = "2001:5f9:4:7:2e0:81ff:fe52:9a6b"
t = traceroute6(waypoint, minttl=15 ,maxttl=34,l4=IPv6ExtHdrRouting(addresses=[target])/ICMPv6EchoRequest(data=RandString(7)))
print(t)