from scapy.all import *
import socket

dst = "8.8.8.8"


def to_milliseconds(timestamp):
    return int(timestamp * 1000)


def try_getservbyport(port):
    try:
        return socket.getservbyport(port)
    except:
        return "-"


def try_get_type_packet(request, packet):
    if packet is TCP:
        return request[packet]
    elif packet is UDP:
        try:
            return request[UDP]
        except:
            return None
    else:
        raise Exception("Unknown packet type")


def get_flags(packet):
    try:
        return packet.flags
    except:
        return None


def TCP_port_scanner(dst, ports, packet):
    ans, unans = sr(IP(dst=dst) / packet(sport=1488, dport=ports),
                    verbose=0)
    for answer in ans:
        request, response = answer
        proto_request = request[packet]
        proto_response = try_get_type_packet(request, packet)
        flags = get_flags(proto_response)
        if proto_response and flags and flags == 18: # TODO: rewrite on getlayer[TCP] and haslayer[TCP] f.e
            port = proto_request.dport
            protocol = proto_request.name
            application_protocol = try_getservbyport(port)
            timestamp = to_milliseconds(response.time - request.sent_time)
            print(f"{protocol} {port} {timestamp}ms {application_protocol}")



TCP_port_scanner(dst, (53, 60), TCP)
