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


def tcp_scan(dst, ports):
    ans, unans = sr(IP(dst=dst) / TCP(sport=1337, dport=ports, flags="S"), timeout=2, verbose=0)
    for answer in ans:
        request, response = answer
        if response.haslayer(TCP):
            port = request[TCP].dport
            protocol = request[TCP].name
            application_protocol = try_getservbyport(port)
            timestamp = to_milliseconds(response.time - request.sent_time)
            print(f"{protocol} {port} {timestamp}ms {application_protocol}")


def udp_scan(dst, ports):
    ans, unans = sr(IP(dst=dst) / UDP(sport=1488, dport=ports) / DNS(rd=1, qd=DNSQR(qname=dst)), timeout=5, verbose=0)
    for answer in ans:
        request, response = answer
        if response.haslayer(UDP):
            port = request[UDP].dport
            protocol = request[UDP].name
            application_protocol = try_getservbyport(port)
            timestamp = to_milliseconds(response.time - request.sent_time)
            print(f"{protocol} {port} {timestamp}ms {application_protocol}")


enum = {"tcp": tcp_scan, "udp": udp_scan}


def get_args(ports):
    answer = []
    if not ports:
        answer.append(("tcp", (1, 1000)))
        return answer
    for port in ports.split():
        if "/" not in port:
            answer.append((port, (1, 1000)))
        else:
            protocol, ports = port.split("/")
            ports_range = []
            ports = ports.split(",")
            for inner_port in ports:
                if "-" in inner_port:
                    start, end = inner_port.split("-")
                    ports_range += list(range(int(start), int(end) + 1))
                else:
                    ports_range.append(int(inner_port))
            answer.append((protocol, ports_range))
    return answer


@click.command()
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('--timeout', default=2, help='Timeout')
@click.option('-g', '--guess', is_flag=True, help='Guess mode')
@click.option('-j', '--num-threads', default=1, help='Number of threads')
@click.argument('dst', nargs=1, required=True)
@click.argument('ports', nargs=-1, required=False)
def main(dst, ports):
    args = get_args(ports)
    for protocol, ports in args:
        if protocol in enum:
            enum[protocol](dst, ports)
        else:
            print(f"Unknown protocol {protocol}")


if __name__ == '__main__':
    main()
