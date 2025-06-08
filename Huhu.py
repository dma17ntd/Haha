import os
import base64
import random
import string
import hashlib
import hmac
import binascii
import bz2
import zlib
import lzma
import marshal
import hex
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# Copyright by MinhAnhs.

def manhs_generate_key():
    """Generate random key"""
    return get_random_bytes(32)  # 256-bit AES key

def manhs_encrypt(input_file, output_file):
    """Main function to encrypt a file"""
    
    # Check if public/private keys exist
    if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
        print("Generating RSA keys...")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open('private.pem', 'wb') as f:
            f.write(private_key)

        with open('public.pem', 'wb') as f:
            f.write(public_key)

    # Load public key
    with open('public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    # Generate random AES key and PBKDF2 salt
    aes_key = manhs_generate_key()
    pbkdf2_salt = get_random_bytes(16)
    key = PBKDF2(aes_key, pbkdf2_salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    
    # Open input file and read content
    with open(input_file, 'rb') as f:
        file_data = f.read()

    # AES GCM encryption
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    
    # PBKDF2 + HMAC + SHA256
    hmac_obj = hmac.new(key, ciphertext, hashlib.sha256)
    hmac_hash = hmac_obj.digest()
    
    # Encrypt HMAC hash with RSA public key
    cipher_rsa = pkcs1_15.new(public_key)
    encrypted_hmac = cipher_rsa.encrypt(hmac_hash)

    # Encode data in base64
    encoded_ciphertext = base64.b64encode(ciphertext)
    encoded_tag = base64.b64encode(tag)
    encoded_hmac = base64.b64encode(encrypted_hmac)
    encoded_salt = base64.b64encode(pbkdf2_salt)

    # Write to temporary file
    with open('manhs_output', 'wb') as f:
        f.write(encoded_ciphertext)
        f.write(encoded_tag)
        f.write(encoded_hmac)
        f.write(encoded_salt)
    
    # Nén dữ liệu lần 2
    compressed_data = encoded_ciphertext + encoded_tag + encoded_hmac + encoded_salt
    compressed_data = xor_encode(compressed_data)
    compressed_data = base64_encode(compressed_data)
    compressed_data = base85_encode(compressed_data)
    compressed_data = bz2_compress(compressed_data)
    compressed_data = zlib_compress(compressed_data)
    compressed_data = lzma_compress(compressed_data)
    compressed_data = marshal_encode(compressed_data)
    compressed_data = hex_encode(compressed_data)

    # Write compressed encrypted data to output file
    with open(output_file, 'wb') as f:
        f.write(compressed_data)

def xor_encode(data):
    """XOR Encoding"""
    key = get_random_bytes(16)
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def base64_encode(data):
    """Base64 Encoding"""
    return base64.b64encode(data)

def base85_encode(data):
    """Base85 Encoding"""
    return base64.a85encode(data)

def bz2_compress(data):
    """BZ2 Compression"""
    return bz2.compress(data)

def zlib_compress(data):
    """Zlib Compression"""
    return zlib.compress(data)

def lzma_compress(data):
    """LZMA Compression"""
    return lzma.compress(data)

def marshal_encode(data):
    """Marshal Encoding"""
    return marshal.dumps(data)

def hex_encode(data):
    """Hex Encoding"""
    return binascii.hexlify(data)

def main():
    """Main entry point for script execution"""
    input_file = input("Nhập tên file đầu vào (ví dụ: file.py): ")
    output_file = input("Nhập tên file đầu ra (ví dụ: file_out.py): ")

    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"File '{input_file}' không tồn tại!")
        return

    # Call the encryption function
    manhs_encrypt(input_file, output_file)
    print(f"File đã được mã hóa và lưu vào '{output_file}'")

if __name__ == "__main__":
    main()
