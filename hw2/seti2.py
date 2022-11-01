import json
import socket
import sys
import threading
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A
from functools import wraps
from datetime import datetime
from playsound import playsound


IP = '0.0.0.0'
PORT = 53
ROOT = '192.203.230.10'
DNSPORT = 53


class Sniffer:
    def __init__(self, sock: socket.socket):
        self.answer = []
        self.socket = sock
        self.ttl = 0

    def recursive_dns_sniffer(self, info: bytes, address: tuple[str, int]) -> None:
        self.socket.sendto(info, address)
        try:
            data, addr = self.socket.recvfrom(1024)
            while data <= info:
                data, addr = self.socket.recvfrom(1024)
        except ConnectionResetError:
            sys.exit(1)
        dns = DNSRecord.parse(data)
        if dns.header.a != 0 or dns.header.rcode != 0:
            self.ttl = dns.a.ttl
            self.answer.append(data)
            return
        for answer in dns.ar:
            if answer.rtype == 1:
                b = str(answer.rdata)
                self.recursive_dns_sniffer(info, (b, DNSPORT))
            else:
                continue
        if not self.answer:
            for test in dns.auth:
                ip = str(test.rdata.label)
                req = DNSRecord.question(ip).pack()
                sniffer = Sniffer(self.socket)
                sniffer.recursive_dns_sniffer(req, (ROOT, DNSPORT))
                test2 = list(set(sniffer()[0]))
                if not test2:
                    continue
                for t in test2:
                    curr_dns = DNSRecord.parse(t)
                    curr_ip = str(curr_dns.a.rdata)
                    self.recursive_dns_sniffer(info, (curr_ip, DNSPORT))

    def __call__(self):
        return sorted(list(set(self.answer))), self.ttl


def dns_ttl_cache(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cache_key = args[1]
        if cache_key not in wrapper.cache:
            wrapper.cache[cache_key] = func(*args, **kwargs)
        if wrapper.cache[cache_key][1] < int(datetime.now().timestamp()) - wrapper.cache[cache_key][2]:
            wrapper.cache[cache_key] = func(*args, **kwargs)
        with open('cache.json', 'w', encoding='utf-8') as f1:
            json.dump(wrapper.cache, f1, ensure_ascii=False, indent=4, default=str)
        return wrapper.cache[cache_key]
    with open('cache.json', 'r', encoding='utf-8') as f:
        wrapper.cache = json.load(f)
    return wrapper


@dns_ttl_cache
def get_result(s: socket.socket, req: str) -> tuple[list[bytes], int, int]:
    dnsdatatest = DNSRecord.question(req)
    if 'multiply' in req:
        return multiply_ip_handler(dnsdatatest)
    address = (ROOT, DNSPORT)
    sniffer = Sniffer(s)
    sniffer.recursive_dns_sniffer(dnsdatatest.pack(), address)
    ans = sniffer()
    return [a.decode('cp437') for a in ans[0]], ans[1], int(datetime.now().timestamp())


def play():
    threading.Thread(target=playsound, args=('hello.mp3', True,), daemon=True).start()


def multiply_ip_handler(dns: DNSRecord) -> tuple[list[bytes], int, int]:
    mul = 1
    querry_name = str(dns.q.qname)
    for part in querry_name.split('.'):
        if part.isdigit():
            mul *= int(part)
            mul %= 256
        if part == 'multiply':
            break
    answer = f'127.0.0.{mul}'
    response = DNSRecord(DNSHeader(qr=1, aa=1, ra=1),
                         q=DNSQuestion(querry_name),
                         a=RR(querry_name, rdata=A(answer)))
    response.header.id = dns.header.id
    ttl = response.a.ttl = 1488
    return [response.pack().decode('cp437')], ttl, int(datetime.now().timestamp())


def main():
    play()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((IP, PORT))
        while True:
            datadig, addrdig = s.recvfrom(1024)
            parse = DNSRecord.parse(datadig)
            dnsreq, id = str(parse.q.qname), parse.header.id
            response = [c.encode('cp437') for c in get_result(s, dnsreq)[0]]
            for ans in response:
                dnsans = DNSRecord.parse(ans)
                dnsans.header.id = id
                s.sendto(dnsans.pack(), addrdig)


main()
