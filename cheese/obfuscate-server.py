import sys
import argparse

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    parser = argparse.ArgumentParser(description="Obfuscate Server URL")
    parser.add_argument("url", help="The URL to obfuscate")
    parser.add_argument("--key", default="Gdb1p_dnbp1DD@#", help="The XOR key")
    parser.add_argument("--out", default="../mouse-trap/src/url_bytes.bin", help="Output binary file path")
    args = parser.parse_args()

    url_bytes = args.url.encode('utf-8')
    key_bytes = args.key.encode('utf-8')

    encrypted = xor_encrypt(url_bytes, key_bytes)

    with open(args.out, 'wb') as f:
        f.write(encrypted)

    print(f"[*] URL: {args.url}")
    print(f"[*] Key: {args.key}")
    print(f"[*] Written to: {args.out}")

if __name__ == "__main__":
    main()