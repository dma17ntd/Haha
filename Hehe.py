import os, base64, rsa, sys, time, hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

# Color
xla = "\033[1;38;5;10m"
vang = "\033[1;38;5;11m"
xduong = "\033[1;38;5;14m"
trang = "\033[1;38;5;15m"
xlight = "\033[1;38;5;50m"
do = "\033[1;38;5;196m"
htim = "\033[1;38;5;198m"
ma = "\033[1;38;5;199m"
cam = "\033[1;38;5;202m"
hong = "\033[1;38;5;205m"

# Ky Tu
ma_td = xla + "[" + trang + "</>" + xla + "]"
success = xla + "[" + vang + "✓" + xla + "]"
error = do + "(" + vang + "!" + do + ")"
waring = cam + "[" + vang + "*" + cam + "]" + xla

os.system('clear')

# === RSA Key Generation ===
def manhs_rsa_keys():
    if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
        print(f"{waring} Đang tạo khóa")
        pubkey, privkey = rsa.newkeys(2048)
        with open("private.pem", "wb") as f:
            f.write(privkey.save_pkcs1('PEM'))
        with open("public.pem", "wb") as f:
            f.write(pubkey.save_pkcs1('PEM'))
        print(f"{success} Tạo khóa thành công.")
    else:
        print(f"{waring} Khóa đã tồn tại.")

# === PBKDF2 Key Derivation ===
def manhs_key(password: bytes, salt: bytes, key_len=32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len, count=100_000, hmac_hash_module=SHA256)

# === Encryption Process ===
def manhs_encrypt(manhs_in, manhs_out):
    with open(manhs_in, 'r', encoding='utf-8') as f:
        plaintext = f.read()

    manhscuti = get_random_bytes(32)
    salt = get_random_bytes(16)
    derived_key = manhs_key(manhscuti, salt)

    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    nonce = cipher.nonce

    salt_masked = ''.join(chr(c ^ salt[i % len(salt)]) for i, c in enumerate(manhscuti)).encode('latin1')
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

    # Mã hóa public.pem bằng XOR + base64
    xor_key = b'manhsxor'
    with open("public.pem", "rb") as f:
        pub_bytes = f.read()
    encrypted_pub = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(pub_bytes)])
    pub_b64 = base64.b64encode(encrypted_pub).decode()
    key_b64 = base64.b64encode(xor_key).decode()

    temp_out = f"__temp_{manhs_out}"
    with open(temp_out, 'w', encoding='utf-8') as f:
        f.write(f'''\
import base64, rsa
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

def manhs_cuti(b64_key, salt):
    enc = base64.b64decode(b64_key).decode('latin1')
    salt = base64.b64decode(salt)
    return bytes(ord(c) ^ salt[i % len(salt)] for i, c in enumerate(enc))

def decrypt_public_key(pub_b64, key_b64):
    encrypted = base64.b64decode(pub_b64)
    key = base64.b64decode(key_b64)
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])

def manhs_verify(data, sig_b64):
    pub_pem = decrypt_public_key("{pub_b64}", "{key_b64}")
    pubkey = rsa.PublicKey.load_pkcs1(pub_pem)
    try:
        rsa.verify(data.encode(), base64.b64decode(sig_b64), pubkey)
        return True
    except:
        return False

key = manhs_cuti("{encrypted_key_b64}", "{salt_b64}")
salt = base64.b64decode("{salt_b64}")
derived_key = PBKDF2(key, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

nonce = base64.b64decode("{nonce_b64}")
tag = base64.b64decode("{tag_b64}")
ciphertext = base64.b64decode("{ciphertext_b64}")
hmac_received = base64.b64decode("{hmac_b64}")

hmac_data = salt + nonce + tag + ciphertext
HMAC.new(derived_key, hmac_data, digestmod=SHA256).verify(hmac_received)

cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()

if not manhs_verify(plaintext, "{signature_b64}"):
    exit(1)

exec(plaintext)
''')

    with open(temp_out, 'rb') as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    with open(temp_out, 'r+', encoding='utf-8') as f:
        code = f.read()
        code = code.replace("SHA256_HASH_PLACEHOLDER", sha256)
        f.seek(0)
        f.write(code)
        f.truncate()

    os.rename(temp_out, manhs_out)
    os.remove('private.pem')
    os.remove('public.pem')

    print(f"{success} File đã được mã hóa và lưu tại: {manhs_out}")

# === Main ===
def main():
    print(f"=== AES-GCM Encryptor + RSA + Public Key Obfuscation ===")
    manhs_rsa_keys()

    manhs_in = input(f"{xla}┌──>{ma_td}<-->Nhập tên file đầu vào ({xduong}vd{trang}: {hong}file.py{xla}){xla}\n└>{xlight}$ {ma}").strip()
    manhs_out = input(f"{xla}┌──>{ma_td}<-->Nhập tên file đầu ra ({xduong}vd{trang}: {hong}file_out.py{xla}){xla}\n└>{xlight}$ {ma}").strip()

    if not os.path.exists(manhs_in):
        print(f"{error} File không tồn tại.")
        return

    manhs_encrypt(manhs_in, manhs_out)

if __name__ == "__main__":
    main()
