import json
import socket
import threading
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A
from functools import wraps
from datetime import datetime
from playsound import playsound

IP = '0.0.0.0'
ROOT = '192.203.230.10'
DESTPORT = 53
PORT = 5533


def recursive_sniffer(s: socket.socket, info: bytes, address: tuple[str, int]) -> tuple[bytes, int]:
    stack = [address]
    is_timed_out = False
    while stack:
        s.sendto(info, stack.pop())
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            is_timed_out = True
            break
        dns = DNSRecord.parse(data)
        if dns.header.a or dns.header.rcode:
            return data, dns.a.ttl
        filtered_ar = list(filter(lambda x: x.rtype == 1, dns.ar))
        if filtered_ar:
            for add in filtered_ar:
                stack.append((str(add.rdata), DESTPORT))
        elif dns.auth:
            res = recursive_sniffer(s, DNSRecord.question(dns.auth[0].rdata.label).pack(), (ROOT, DESTPORT))
            respack = dns.parse(res[0])
            stack.append((str(respack.a.rdata), DESTPORT))
    no_dns = DNSRecord.parse(info)
    no_dns.header.rcode = 2 if is_timed_out else 1
    return no_dns.pack(), 0


def dns_ttl_cache(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cache_key = args[1]
        if cache_key not in wrapper.cache \
                or wrapper.cache[cache_key][1] < int(datetime.now().timestamp()) - wrapper.cache[cache_key][2]:
            wrapper.cache[cache_key] = func(*args, **kwargs)
        with open('cache.json', 'w', encoding='utf-8') as f1:
            json.dump(wrapper.cache, f1, ensure_ascii=False, indent=4, default=str)
        return wrapper.cache[cache_key]
    with open('cache.json', 'r', encoding='utf-8') as f:
        wrapper.cache = json.load(f)
    return wrapper


@dns_ttl_cache
def get_result(s: socket.socket, req: str) -> tuple[str, int, int]:
    dnsdatatest = DNSRecord.question(req)
    if 'multiply' in req:
        return multiply_ip_handler(dnsdatatest)
    address = (ROOT, DESTPORT)
    ans = recursive_sniffer(s, dnsdatatest.pack(), address)
    return ans[0].decode('cp437'), ans[1], int(datetime.now().timestamp())


def play():
    threading.Thread(target=playsound, args=('hello.mp3', True,), daemon=True).start()


def multiply_ip_handler(dns: DNSRecord) -> tuple[str, int, int]:
    mul = 1
    querry_name = str(dns.q.qname)
    for part in querry_name.split('.'):
        if part.isdigit():
            mul *= int(part)
        if part == 'multiply':
            break
    answer = f'127.0.0.{mul % 256}'
    response = DNSRecord(DNSHeader(qr=1, aa=1, ra=1),
                         q=DNSQuestion(querry_name),
                         a=RR(querry_name, rdata=A(answer)))
    response.header.id = dns.header.id
    ttl = response.a.ttl = 100000
    return response.pack().decode('cp437'), ttl, int(datetime.now().timestamp())


def main():
    play()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((IP, PORT))
        s.settimeout(1)
        while True:
            try:
                datadig, addrdig = s.recvfrom(1024)
            except socket.timeout:
                continue
            parse = DNSRecord.parse(datadig)
            dnsreq, id = str(parse.q.qname), parse.header.id
            response = get_result(s, dnsreq)[0].encode('cp437')
            dnsans = DNSRecord.parse(response)
            dnsans.header.id = id
            s.sendto(dnsans.pack(), addrdig)


main()
