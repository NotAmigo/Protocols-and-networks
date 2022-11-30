import click
from icmp_packet import ICMPPacket
from tcp_packet import TCPPacket
from udp_packet import UDPPacket
from traceroute import Traceroute

hostname = "8.8.8.8"
NETWORK_ROUTER_ADMIN_LOGIN = '192.168.1.120'


@click.command()
@click.argument('destination', nargs=1, default='8.8.8.8')
@click.argument('type', nargs=1, default='icmp')
@click.option('--source', default=NETWORK_ROUTER_ADMIN_LOGIN,
              help='Source IP address')
@click.option('--id', default=0, help='Custom id')
@click.option('--seq', default=0, help='Custom SEQ')
@click.option('--len', default=40, help='Length of the ICMP packet. '
                                        'If you type custom, payload, length '
                                        'will be ignored, length ignored for '
                                        'TCP')
@click.option('--payload', default=None, help='Custom ICMP packet payload')
@click.option('--port', '-p', default=80, help='Custom TCP destination port')
@click.option('--max_ttl', default=30, help='Max TTL')
@click.option('--repeat', '-n', default=3, help='Requests per TTL')
@click.option('--timeout', '-t', default=3, help='Timeout for each request')
@click.option('--verbose', '-v', is_flag=True, help='Номер автономной системы')
@click.option('--interval', default=0, help='Interval between requests')
@click.option('--debug', is_flag=True, help='Debug mode')
def main(destination, type, source, id, seq, len, payload, port, max_ttl, repeat, timeout, verbose, interval, debug):
    if type == 'icmp':
        packet = ICMPPacket(destination, id, seq, source, len, payload)
    elif type == 'tcp':
        packet = TCPPacket(destination, id, seq, source, port)
    elif type == 'udp':
        packet = UDPPacket(destination, id, seq, source, port)
    else:
        print('Wrong type')
        return
    traceroute = Traceroute(destination, packet, max_ttl,
                            repeat, timeout, interval, debug, verbose)
    traceroute.run()


if __name__ == '__main__':
    main()
