import os, base64, rsa, sys, time, subprocess, re, textwrap
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

# === RSA Key Generation ===
def create_rsa_keys():
    if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
        print("[*] Đang tạo khóa RSA...")
        pubkey, privkey = rsa.newkeys(2048)
        with open("private.pem", "wb") as f:
            f.write(privkey.save_pkcs1('PEM'))
        with open("public.pem", "wb") as f:
            f.write(pubkey.save_pkcs1('PEM'))
        print("[✓] Tạo khóa RSA thành công.")
    else:
        print("[!] Khóa RSA đã tồn tại.")

# === PBKDF2 Key Derivation ===
def derive_key(password: bytes, salt: bytes, key_len=32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len, count=100_000, hmac_hash_module=SHA256)

# === Comment thêm bản quyền sau khi obfuscate ===
def add_custom_comment(filename, custom_header):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        pattern = r"#\s*Created by pyminifier\s*\(https://github\.com/liftoff/pyminifier\)\n?"
        content = re.sub(pattern, "", content)
        content = custom_header.strip() + '\n' + content
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[✓] Đã thêm comment bản quyền vào {filename}")
    except Exception as e:
        print(f"[!] Lỗi thêm comment: {e}")

# === Encryption Process ===
def encrypt_file(input_file, output_file):
    import hashlib

    with open(input_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()

    raw_key = get_random_bytes(32)
    salt = get_random_bytes(16)
    derived_key = derive_key(raw_key, salt)

    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    nonce = cipher.nonce

    salt_masked = ''.join(chr(c ^ salt[i % len(salt)]) for i, c in enumerate(raw_key)).encode('latin1')
    encrypted_key_b64 = base64.b64encode(salt_masked).decode()
    salt_b64 = base64.b64encode(salt).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    hmac_data = salt + nonce + tag + ciphertext
    hmac_calculated = HMAC.new(derived_key, hmac_data, digestmod=SHA256).digest()
    hmac_b64 = base64.b64encode(hmac_calculated).decode()

    with open("private.pem", "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(plaintext.encode(), privkey, 'SHA-256')
    signature_b64 = base64.b64encode(signature).decode()

    temp_out = f"__temp_{output_file}"

    code_template = f'''\
import base64, rsa, sys, os, hashlib, time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

def manhs_debug():
    try:
        import sys
        sys.settrace(lambda *a, **k: None)
        if sys.gettrace():
            return True
    except:
        pass
    try:
        import ctypes
        if hasattr(ctypes, "windll") and ctypes.windll.kernel32.IsDebuggerPresent() != 0:
            return True
    except:
        pass
    try:
        import psutil
        sus = ['gdb', 'frida', 'ollydbg', 'x64dbg', 'ida', 'wireshark']
        for proc in psutil.process_iter(['name']):
            pname = (proc.info['name'] or '').lower()
            if any(s in pname for s in sus):
                return True
    except:
        pass
    return False

def manhs_anti():
    t1 = time.perf_counter()
    time.sleep(0.05)
    t2 = time.perf_counter()
    return (t2 - t1) > 0.2

def manhs_glitch():
    try:
        with open(__file__, 'w') as f:
            f.write("#Code bị phá hủy do debug hoặc sửa mã!")
    except:
        pass
    sys.exit(1)

def check_integrity():
    try:
        with open(__file__, 'rb') as f:
            content = f.read()
        expected_hash = "SHA256_HASH_PLACEHOLDER"
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            manhs_glitch()
    except:
        manhs_glitch()

def xor_decrypt(b64_key, salt):
    enc = base64.b64decode(b64_key).decode('latin1')
    salt = base64.b64decode(salt)
    return bytes(ord(c) ^ salt[i % len(salt)] for i, c in enumerate(enc))

def verify_sig(data, sig_b64):
    with open("public.pem", "rb") as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())
    try:
        rsa.verify(data.encode(), base64.b64decode(sig_b64), pubkey)
        return True
    except:
        return False

if manhs_debug() or manhs_anti():
    manhs_glitch()

check_integrity()

key = xor_decrypt("{encrypted_key_b64}", "{salt_b64}")
salt = base64.b64decode("{salt_b64}")
derived_key = PBKDF2(key, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

nonce = base64.b64decode("{nonce_b64}")
tag = base64.b64decode("{tag_b64}")
ciphertext = base64.b64decode("{ciphertext_b64}")
hmac_received = base64.b64decode("{hmac_b64}")

hmac_data = salt + nonce + tag + ciphertext
try:
    HMAC.new(derived_key, hmac_data, digestmod=SHA256).verify(hmac_received)
except:
    manhs_glitch()

cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
except:
    manhs_glitch()

if not verify_sig(plaintext, "{signature_b64}"):
    manhs_glitch()

exec(plaintext)
'''

    with open(temp_out, 'w', encoding='utf-8') as f:
        f.write(textwrap.dedent(code_template))

    # 🛡️ Tính checksum SHA256 sau khi ghi file
    with open(temp_out, 'rb') as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    with open(temp_out, 'r+', encoding='utf-8') as f:
        code = f.read()
        code = code.replace("SHA256_HASH_PLACEHOLDER", sha256)
        f.seek(0)
        f.write(code)
        f.truncate()

    # Obfuscate
    subprocess.run([
        "pyminifier",
        "--obfuscate",
        "--replacement-length=6",
        "--bzip2",
        "--lzma",
        "--gzip",
        temp_out
    ], stdout=open(output_file, 'w', encoding='utf-8'))

    os.remove(temp_out)

    # Ghi bản quyền
    custom_header = """
# Copyright By MinhAnhs
# Đã mã hóa và bảo vệ quyền tác giả
# Chống decode và chỉnh sửa
"""
    add_custom_comment(output_file, custom_header)

    print(f"[✓] File đã được mã hóa, obfuscate và lưu tại: {output_file}")

# === Main ===
def main():
    print("=== AES-GCM Encryptor + Anti-Debug + RSA + Pyminifier ===")
    create_rsa_keys()

    input_file = input("Nhập tên file đầu vào (vd: file.py): ").strip()
    output_file = input("Nhập tên file đầu ra (vd: file_out.py): ").strip()

    if not os.path.exists(input_file):
        print("[!] File không tồn tại.")
        return

    encrypt_file(input_file, output_file)

if __name__ == "__main__":
    main()
