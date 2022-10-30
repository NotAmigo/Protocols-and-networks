import socket

ADDRESS = ('www.yandex.ru')
IP = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((IP, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print(conn)
    print(addr)
    with conn:
        while True:
            data = conn.recv(1024)
            print(f'{data!r}')
            if not data:
                break
            conn.sendall(data)