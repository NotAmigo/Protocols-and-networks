from scapy.all import *
import socket
import click

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


def port_scanner(dst, ports, packet):
    ans, unans = sr(IP(dst=dst) / packet(sport=1488, dport=ports), timeout=2, verbose=0)
    for answer in ans:
        request, response = answer
        proto_request = request[packet]
        proto_response = try_get_type_packet(response, packet)
        flags = get_flags(proto_response)
        if proto_response and flags and flags == 18: # TODO: rewrite on getlayer[TCP] and haslayer[TCP] f.e
            port = proto_request.dport
            protocol = proto_request.name
            application_protocol = try_getservbyport(port)
            timestamp = to_milliseconds(response.time - request.sent_time)
            print(f"{protocol} {port} {timestamp}ms {application_protocol}")


def get_args(ports):
    for port in ports:
        print(port)


@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('--timeout', default=2, help='Timeout')
@click.option('-g', '--guess', is_flag=True, help='Guess mode')
@click.option('-j', '--num-threads', default=1, help='Number of threads')
@click.argument('dst', nargs=1)
@click.argument('ports', nargs=-1)
def portscan(verbose, timeout, guess, num_threads, ports, dst):
    click.echo(dst)