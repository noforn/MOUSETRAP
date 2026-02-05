import sys

def ror13_hash(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

def string_to_hex_chunks(s: str, chunk_size: int = 8) -> list[tuple[str, int]]:
    s_bytes = s.encode('ascii') + b'\x00'

    chunks = []
    for i in range(0, len(s_bytes), chunk_size):
        chunk = s_bytes[i:i+chunk_size]
        chunk = chunk.ljust(chunk_size, b'\x00')

        hex_val = 0
        for j, byte in enumerate(chunk):
            hex_val |= byte << (j * 8)

        chunks.append((f"0x{hex_val:0{chunk_size*2}x}", len(s_bytes[i:i+chunk_size])))

    return chunks

def generate_asm(label: str, s: str, base_offset: int = 128):
    chunks = string_to_hex_chunks(s)

    print(f"; String: \"{s}\" ({len(s)+1} bytes with null)")
    print(f"{label}:")

    offset = base_offset
    for i, (hex_val, byte_count) in enumerate(chunks):
        if i == 0:
            print(f"    mov rax, {hex_val}")
            print(f"    mov [rbp - {offset}], rax")
        else:
            # Determine optimal instruction size
            val = int(hex_val, 16)
            if val <= 0xFFFFFFFF:
                if val <= 0xFFFF:
                    print(f"    mov ax, {hex_val}")
                    print(f"    mov word ptr [rbp - {offset}], ax")
                else:
                    print(f"    mov eax, {hex_val}")
                    print(f"    mov dword ptr [rbp - {offset}], eax")
            else:
                print(f"    mov rax, {hex_val}")
                print(f"    mov [rbp - {offset}], rax")

        offset -= 8

    print(f"    lea rdx, [rbp - {base_offset}]")
    print()

def print_raw_hex(s: str):
    chunks = string_to_hex_chunks(s)

    print(f"\n; \"{s}\" -> {len(s)+1} bytes (including null)")
    print(f"; Memory layout (starting at lowest address):")

    s_bytes = s.encode('ascii') + b'\x00'
    for i, b in enumerate(s_bytes):
        char_repr = chr(b) if 32 <= b < 127 else '\\0' if b == 0 else f'\\x{b:02x}'
        print(f";   offset +{i}: 0x{b:02x} = '{char_repr}'")

    print(f"\n; Hex values for mov instructions:")
    for i, (hex_val, _) in enumerate(chunks):
        chunk_start = i * 8
        chunk_end = min(chunk_start + 8, len(s_bytes))
        chunk_str = s[chunk_start:chunk_end] if chunk_start < len(s) else ""
        print(f";   Chunk {i}: {hex_val}  ; \"{chunk_str}\"")

    return chunks

def print_api_hashes(names: list[str]):
    print("; ROR13 API hashes for shellcode")
    for name in names:
        h = ror13_hash(name)
        print(f"    mov r8d, 0x{h:08x}    ; {name}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python hexdomain.py <domain_or_string>     # Generate hex for string")
        print("  python hexdomain.py --hash <func_name>     # Generate ROR13 API hash")
        print()
        print("Examples:")
        print("  python hexdomain.py docs-share.org")
        print("  python hexdomain.py --hash LoadLibraryA")
        print("  python hexdomain.py --hash InternetOpenA InternetConnectA")
        print()
        return

    if sys.argv[1] == "--hash":
        if len(sys.argv) < 3:
            print("Error: --hash requires at least one function name")
            return
        print_api_hashes(sys.argv[2:])
    else:
        target = sys.argv[1]
        print_raw_hex(target)
        print()
        generate_asm("set_string", target)

if __name__ == "__main__":
    main()
