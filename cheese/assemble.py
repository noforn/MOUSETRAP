#!/usr/bin/env python3
"""
Assemble x64 shellcode from .asm files using Keystone.
Usage: python assemble.py <input.asm> [output.bin]
"""

import sys
import struct
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def assemble_file(input_file, output_file=None):
    if output_file is None:
        output_file = input_file.rsplit('.', 1)[0] + '.bin'

    with open(input_file, 'r') as f:
        code = f.read()

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    try:
        encoding, count = ks.asm(code)
    except Exception as e:
        print(f"[-] Assembly error: {e}")
        return False

    shellcode = bytes(encoding)

    with open(output_file, 'wb') as f:
        f.write(shellcode)

    print(f"[+] Assembled {count} instructions")
    print(f"[+] Output: {output_file} ({len(shellcode)} bytes)")

    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python assemble.py <input.asm> [output.bin]")
        print("Example: python assemble.py asm-executor.asm executor.bin")
        return

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    assemble_file(input_file, output_file)

if __name__ == "__main__":
    main()
