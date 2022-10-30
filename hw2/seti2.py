import socket
import binascii

ADDRESS = ('www.yandex.ru')
IP = '127.0.0.1'
PORT = 65432
ROOT = '192.203.230.10'
DNSPORT = 53

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((IP, PORT))
    datadig, addrdig = s.recvfrom(1024)
    s.sendto(datadig, ('199.7.91.13', 53))
    data, addr = s.recvfrom(1024)
    s.sendto(data, addrdig)
    print(data)
    print(addr)