from scapy.all import *
import socket

dst = "192.168.1.1"


def to_millisecondss(timestamp):
    return int(timestamp * 1000)


def TCP_port_scanner(dst, ports):
    ans, unans = sr(IP(dst=dst) / TCP(sport=1488, dport=ports), verbose=0)
    for response in ans:
        port = response[1][TCP].dport
        a = 5
    # for i in ports:
    #     ans, unans = sr(IP(dst=dst) / TCP(sport=65, dport=i), timeout=1, verbose=0)
    #     try:
    #         serv = socket.getservbyport(i)
    #     except:
    #         serv = "-"
    #     timestamp = to_millisecondss(ans[0][1].time - ans[0][0].sent_time)
    #     print(f"TCP {i} {timestamp} {serv}")


def UDP_port_scanner(dst, ports):
    ans, unans = sr(IP(dst=dst) / UDP(sport=65, dport=ports), timeout=1, verbose=0)
    print(ans.summary())


TCP_port_scanner(dst, (440, 445))
