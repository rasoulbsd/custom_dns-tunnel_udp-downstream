import socket, time

addr = ("127.0.0.1", 5358)
msgs = [
    b"A\n",
    b"C\n",
    b"DSOVMIOEVnewewcew\n",
    b"CDSCECWECWEC\n",
]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)

for i, m in enumerate(msgs):
    print(f"send[{i}]:", m)
    s.sendto(m, addr)
    try:
        data, _ = s.recvfrom(65535)
        print(f"echo[{i}]:", data)
    except socket.timeout:
        print(f"timeout[{i}] waiting for echo")
        break
