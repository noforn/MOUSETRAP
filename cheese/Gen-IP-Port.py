import sys
import socket
import struct

if len(sys.argv) < 3:
    print("Usage: python Gen-IP-Port.py [-32] <IP> <PORT>")
    sys.exit(1)

mode_32 = False
args = sys.argv[1:]

if "-32" in args:
    mode_32 = True
    args.remove("-32")

if len(args) != 2:
    print("Usage: python Gen-IP-Port.py [-32] <IP> <PORT>")
    sys.exit(1)

ip = args[0]
port = int(args[1])

af_bytes = struct.pack('<H', 2)
port_bytes = struct.pack('>H', port)
try:
    # Resolve domain to IP (handles IPs too)
    ip_resolved = socket.gethostbyname(ip)
except socket.gaierror:
    print(f"[-] Could not resolve domain: {ip}")
    sys.exit(1)

ip_bytes = socket.inet_aton(ip_resolved)

if mode_32:
    # 32-bit: Split into two 4-byte pushes
    # Stack layout (low to high): [Fam][Port][IP]
    # Push order (grows down): Push IP, then Push Fam/Port
    
    val_ip = int.from_bytes(ip_bytes, 'little')
    val_port_af = int.from_bytes(af_bytes + port_bytes, 'little')
    
    print(f"[+] IP:\n push 0x{val_ip:08x}")
    print(f"[+] Port:\n push 0x{val_port_af:08x}")
else:
    # 64-bit: Single 8-byte value
    total_bytes = af_bytes + port_bytes + ip_bytes
    hex_value = '{:016x}'.format(int.from_bytes(total_bytes, 'little'))
    print(f"mov r9, 0x{hex_value}")