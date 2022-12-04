import click
from scapy.all import IPv6, IP
from socket import inet_aton, error, inet_pton, AF_INET6
from icmp_packet import ICMPPacket
from tcp_packet import TCPPacket
from udp_packet import UDPPacket
from tracert import Traceroute
from IPv4Packet import IPv4Packet
from IPv6Packet import IPv6Packet


def check_IPv6_validation(ip):
    try:
        inet_pton(AF_INET6, ip)
        return True
    except error:
        raise click.BadParameter('Invalid IPv6 address')


def check_IPv4_validation(ip):
    try:
        inet_aton(ip)
        return True
    except error:
        return False


@click.command()
@click.argument('destination', nargs=1, default='8.8.8.8')
@click.argument('type', nargs=1)
@click.option('--id', default=0, help='Custom id')
@click.option('--seq', default=0,
              help='Custom SEQ only for ICMP and UDP and TCP')
@click.option('--len', default=40, help='Length of the ICMP packet. '
                                        'If you type custom, payload, length '
                                        'will be ignored, length ignored for '
                                        'TCP')
@click.option('--payload', default=None, help='Custom ICMP packet payload')
@click.option('--port', '-p', default=80, help='Custom TCP destination port')
@click.option('--max_ttl', default=30, help='Max TTL')
@click.option('--repeat', '-n', default=3, help='Requests per TTL')
@click.option('--timeout', '-t', default=3, help='Timeout for each request')
@click.option('--verbose', '-v', is_flag=True, help='Autonomous system number')
@click.option('--interval', default=0, help='Interval between requests')
@click.option('--debug', is_flag=True, help='Debug mode')
def main(destination, type, id, seq, len, payload, port, max_ttl, repeat, timeout, verbose, interval, debug):
    packet = None
    if check_IPv4_validation(destination):
        packet = IP
    elif check_IPv6_validation(destination):
        packet = IPv6
    if type == 'icmp':
        packet = ICMPPacket(packet, destination, id, seq, len, payload)
    elif type == 'tcp':
        packet = TCPPacket(packet, destination, id, seq, port)
    elif type == 'udp':
        packet = UDPPacket(packet, destination, id, seq, port)
    else:
        print('Wrong type')
        return
    traceroute = Traceroute(destination, packet, max_ttl,
                            repeat, timeout, interval, debug, verbose)
    traceroute.run()


if __name__ == '__main__':
    main()
