import sys
import socket
import struct

if len(sys.argv) != 3:
    print("Usage: python Gen-IP-Port.py <IP> <PORT>")
    sys.exit(1)

ip = sys.argv[1]
port = int(sys.argv[2])

af_bytes = struct.pack('<H', 2)
port_bytes = struct.pack('>H', port)
ip_bytes = socket.inet_aton(ip)

total_bytes = af_bytes + port_bytes + ip_bytes
hex_value = '{:016x}'.format(int.from_bytes(total_bytes, 'little'))

print(f"mov r9, 0x{hex_value}")