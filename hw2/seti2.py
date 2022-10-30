import socket
import sys

import dnslib


ADDRESS = ('www.yandex.ru')
IP = '0.0.0.0'
PORT = 65432
ROOT = '192.203.230.10'
DNSPORT = 53


def recursive_dns_sniffer(info, address, addrdig):
    s.sendto(info, address)
    try:
        data, addr = s.recvfrom(1024)
    except ConnectionResetError:
        print('ConnectionResetError')
        sys.exit(1)
    dns = dnslib.DNSRecord.parse(data)
    if dns.header.a != 0:
        s.sendto(data, addrdig)
        return
    if dns.header.rcode != 0:
        s.sendto(data, addrdig)
        return
    for answer in dns.ar:
        if answer.rtype == 1:
            a = '.'.join(map(str, answer.rdata.data))
            recursive_dns_sniffer(info, (a, DNSPORT), addrdig)
        if answer.rtype == 41:
            return


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((IP, PORT))
    datadig, addrdig = s.recvfrom(1024)
    address = (ROOT, DNSPORT)
    ans = recursive_dns_sniffer(datadig, address, addrdig)
    if ans is None:
        s.sendto(b'No answer', addrdig)
        print('No answer')