import sys
import argparse

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    parser = argparse.ArgumentParser(description="Obfuscate Server URL")
    parser.add_argument("url", help="The URL to obfuscate")
    parser.add_argument("--key", default="Gdb1p_dnbp1DD@#", help="The XOR key")
    args = parser.parse_args()

    url_bytes = args.url.encode('utf-8')
    key_bytes = args.key.encode('utf-8')
    
    encrypted = xor_encrypt(url_bytes, key_bytes)
    
    print(f"[*] URL: {args.url}")
    print(f"[*] Key: {args.key}")
    
    # format rust byte array
    rust_array = ", ".join([f"0x{b:02x}" for b in encrypted])
    print(f"\n// Rust Code:")
    print(f"let url_bytes: [u8; {len(encrypted)}] = [{rust_array}];")
    print(f"let url_key = b\"{args.key}\";")

if __name__ == "__main__":
    main()