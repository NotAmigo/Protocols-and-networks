from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr
import socket
import click
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class PortScan:
    def __init__(self, verbose, timeout, guess, dest, ports):
        self.verbose = verbose
        self.timeout = timeout
        self.guess = guess
        self.dest = dest
        self.ports = ports
        self.enum = {"tcp": self.tcp_scan, "udp": self.udp_scan}

    @staticmethod
    def get_args(ports):
        answer = []
        if not ports:
            answer.append(("tcp", (1, 1000)))
            return answer
        for port in ports:
            if "/" not in port:
                answer.append((port, (1, 1000)))
            else:
                protocol, inner_ports = port.split("/")
                ports_range = []
                inner_ports = inner_ports.split(",")
                for inner_port in inner_ports:
                    if "-" in inner_port:
                        start, end = inner_port.split("-")
                        ports_range += list(range(int(start), int(end) + 1))
                    else:
                        ports_range.append(int(inner_port))
                answer.append((protocol, ports_range))
        return answer

    @staticmethod
    def to_milliseconds(timestamp):
        return int(timestamp * 1000)

    @staticmethod
    def try_getservbyport(port):
        try:
            return socket.getservbyport(port)
        except:
            return "-"

    def scan(self, packet, packet_type):
        ans, unans = sr(IP(dst=self.dest) / packet, timeout=self.timeout, verbose=0)
        for answer in ans:
            request, response = answer
            if response.haslayer(packet_type):
                port = request[packet_type].dport
                protocol = request[packet_type].name
                application_protocol = self.try_getservbyport(port)
                timestamp = f"{self.to_milliseconds(response.time - request.sent_time)} ms"
                print(f"{protocol} {port} {timestamp if self.verbose else ''} {application_protocol if self.guess else ''}")

    def tcp_scan(self, ports):
        packet = TCP(sport=1337, dport=ports, flags="S")
        self.scan(packet, TCP)

    def udp_scan(self, ports):
        packet = UDP(sport=1488, dport=ports) / DNS(rd=1, qd=DNSQR(qname=self.dest))
        self.scan(packet, UDP)

    def run(self):
        self.ports = self.get_args(self.ports)
        for protocol, ports in self.ports:
            if protocol in self.enum:
                self.enum[protocol](ports)
            else:
                raise KeyError("Wrong protocol")


@click.command()
@click.argument('dst', nargs=1, required=True)
@click.argument('ports', nargs=-1, required=False)
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('--timeout', default=2, help='Timeout')
@click.option('-g', '--guess', is_flag=True, help='Guess mode')
def main(verbose, timeout, guess, dst, ports):
    portscaner = PortScan(verbose, timeout, guess, dst, ports)
    portscaner.run()


if __name__ == '__main__':
    main()
