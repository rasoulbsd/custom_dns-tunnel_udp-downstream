import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 1234))
print('UDP Echo server on port 1234')

while True:
    data, addr = s.recvfrom(65535)
    print(f'Received {len(data)} bytes from {addr}: {data}')
    s.sendto(data, addr)
    print(f'Echoed back to {addr}')
