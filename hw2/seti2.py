import socket
import sys
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A


ADDRESS = ('www.yandex.ru')
IP = '0.0.0.0'
PORT = 65432
ROOT = '192.203.230.10'
DNSPORT = 53


class Sniffer:
    def __init__(self):
        self.answer = []

    def recursive_dns_sniffer(self, info, address, addrdig):
        s.sendto(info, address)
        try:
            data, addr = s.recvfrom(1024)
            while data <= info:
                data, addr = s.recvfrom(1024)
        except ConnectionResetError:
            print('ConnectionResetError')
            sys.exit(1)
        dns = DNSRecord.parse(data)
        if dns.header.a != 0:
            self.answer.append(data)
            return
        if dns.header.rcode != 0:
            self.answer.append(data)
            return
        for answer in dns.ar:
            if answer.rtype == 1:
                b = str(answer.rdata)
                self.recursive_dns_sniffer(info, (b, DNSPORT), addrdig)
            if answer.rtype == 41:
                continue
        if not self.answer:
            for test in dns.auth:
                ip = str(test.rdata.label)
                req = DNSRecord.question(ip).pack()
                sniffer = Sniffer()
                sniffer.recursive_dns_sniffer(req, (ROOT, DNSPORT), addrdig)
                test2 = list(set(sniffer()))
                if not test2:
                    continue
                for t in test2:
                    curr_dns = DNSRecord.parse(t)
                    jopa = str(curr_dns.a.rdata)
                    self.recursive_dns_sniffer(info, (jopa, DNSPORT), addrdig)

    def __call__(self):
        return list(set(self.answer))


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((IP, PORT))
    while True:
        datadig, addrdig = s.recvfrom(1024)
        dnsdatatest = DNSRecord.parse(datadig)
        if 'multiply' in str(dnsdatatest.q.qname):
            mult = 1
            name = str(dnsdatatest.q.qname).split('.')
            for part in name:
                if part.isdigit():
                    mult *= int(part)
                    mult %= 256
                if part == 'multiply':
                    break
            answermult = f'127.0.0.{mult}'
            a2 = DNSRecord(DNSHeader(qr=1, aa=1, ra=1),
                          q=DNSQuestion(str(dnsdatatest.q.qname)),
                          a=RR((str(dnsdatatest.q.qname)), rdata=A(f'127.0.0.{mult}')))
            a2.header.id = dnsdatatest.header.id
            response = a2.pack()
            s.sendto(response, addrdig)
            continue
        address = (ROOT, DNSPORT)
        sniffer = Sniffer()
        sniffer.recursive_dns_sniffer(datadig, address, addrdig)
        answer = sniffer()
        for ans in answer:
            a = DNSRecord.parse(ans)
            s.sendto(ans, addrdig)