import os, sys, base64, re, subprocess, time
import rsa
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import platform
import uuid

# Màu sắc
do = "\033[1;38;5;9m"
vang = "\033[1;38;5;226m"
trang = "\033[1;38;5;255m"
xla = "\033[1;32m"

success = xla + "[" + vang + "✓" + xla + "]"
error = do + "[" + vang + "!" + do + "]"
waring = do + "(" + vang + "!" + do + ")"

ma_ = os.getcwd()
os.system('clear')

def manhs_rsa_key():
    if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
        print(f"{waring} Đang tạo khóa...")
        (pubkey, privkey) = rsa.newkeys(2048)
        with open("private.pem", "wb") as f:
            f.write(privkey.save_pkcs1('PEM'))
        with open("public.pem", "wb") as f:
            f.write(pubkey.save_pkcs1('PEM'))
        print(f"{success} Đã tạo khóa xong")
    else:
        print(f"{waring} Đang dùng khóa hiện có")

def manhs_comment(filename, tdung_manhs):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        pattern = r"#\s*Created by pyminifier\s*\(https://github\.com/liftoff/pyminifier\)\n?"
        content = re.sub(pattern, "", content)
        content = tdung_manhs.strip() + '\n' + content
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"\n{success} Đã obfuscate {filename}")
    except Exception as e:
        print(f"\n{error} Lỗi obfuscate: {e}")

def is_sandbox_or_vm():
    try:
        system = platform.system().lower()
        if system == "windows":
            import subprocess
            try:
                output = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxGuest"', shell=True, stderr=subprocess.DEVNULL)
                if b"VBoxGuest" in output:
                    return True
            except:
                pass
            try:
                output = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmtools"', shell=True, stderr=subprocess.DEVNULL)
                if b"vmtools" in output:
                    return True
            except:
                pass
            suspicious_drivers = ['vbox', 'vmware', 'qemu']
            drivers = subprocess.check_output("driverquery", shell=True).decode().lower()
            if any(d in drivers for d in suspicious_drivers):
                return True
        else:
            vm_files = [
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/sys_vendor',
                '/proc/scsi/scsi'
            ]
            for f in vm_files:
                if os.path.exists(f):
                    with open(f, 'r') as file:
                        content = file.read().lower()
                        if any(x in content for x in ['vmware', 'virtualbox', 'qemu', 'kvm']):
                            return True
            import re
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '08:00:27']
            if any(mac.lower().startswith(prefix) for prefix in vm_mac_prefixes):
                return True
        return False
    except:
        return False

def manhs_encrypted(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        code = f.read()

    # Sinh key AES random 32 bytes, salt, iv
    aes_key = get_random_bytes(32)
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Derive key từ aes_key với PBKDF2
    key = PBKDF2(aes_key, salt, dkLen=32, count=100_000)

    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(code.encode())

    # Mã hóa AES key bằng RSA public key
    with open("public.pem", "rb") as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())
    encrypted_aes_key = rsa.encrypt(aes_key, pubkey)

    # Tạo chữ ký bằng private key
    with open("private.pem", "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(code.encode(), privkey, 'SHA-256')

    b64 = lambda x: base64.b64encode(x).decode()
    salt_b64 = b64(salt)
    iv_b64 = b64(iv)
    data_b64 = b64(ciphertext)
    signature_b64 = b64(signature)
    encrypted_key_b64 = b64(encrypted_aes_key)

    junido_kai = f"__temp_{output_file}"

    with open(junido_kai, 'w', encoding='utf-8') as f:
        f.write(f'''
import os, sys, time, base64, rsa, platform, uuid, re
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

def is_sandbox_or_vm():
    try:
        system = platform.system().lower()
        if system == "windows":
            import subprocess
            try:
                output = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\Services\\\\VBoxGuest"', shell=True, stderr=subprocess.DEVNULL)
                if b"VBoxGuest" in output:
                    return True
            except:
                pass
            try:
                output = subprocess.check_output('reg query "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\Services\\\\vmtools"', shell=True, stderr=subprocess.DEVNULL)
                if b"vmtools" in output:
                    return True
            except:
                pass
            suspicious_drivers = ['vbox', 'vmware', 'qemu']
            drivers = subprocess.check_output("driverquery", shell=True).decode().lower()
            if any(d in drivers for d in suspicious_drivers):
                return True
        else:
            vm_files = [
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/sys_vendor',
                '/proc/scsi/scsi'
            ]
            for f in vm_files:
                if os.path.exists(f):
                    with open(f, 'r') as file:
                        content = file.read().lower()
                        if any(x in content for x in ['vmware', 'virtualbox', 'qemu', 'kvm']):
                            return True
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '08:00:27']
            if any(mac.lower().startswith(prefix) for prefix in vm_mac_prefixes):
                return True
        return False
    except:
        return False

def detect_debug():
    try:
        import ctypes, psutil, subprocess
        if hasattr(ctypes, "windll") and ctypes.windll.kernel32.IsDebuggerPresent():
            return True
        if sys.gettrace():
            return True
        suspects = ['frida', 'gdb', 'x64dbg', 'ollydbg', 'ida', 'wireshark']
        for p in psutil.process_iter(['name']):
            name = p.info['name'] or ''
            if any(s in name.lower() for s in suspects):
                return True
    except:
        pass
    if is_sandbox_or_vm():
        return True
    t1 = time.perf_counter()
    time.sleep(0.05)
    t2 = time.perf_counter()
    if (t2 - t1) > 0.2:
        return True
    return False

def manhs_glitch():
    try:
        with open(__file__, 'w', encoding='utf-8') as f:
            f.write("#Copyright : Manhs\\n")
            f.write("#Code bị phá hủy do phát hiện sửa đổi hoặc debug!\\n")
            f.write("#Bản gốc không còn sử dụng được nữa.\\n")
            f.write("#Do phát hiện có hành vi decode lên file hỏng.\\n")
    except:
        pass
    sys.exit(1)

def verify_signature(code, signature_b64):
    try:
        with open("public.pem", "rb") as f:
            pubkey = rsa.PublicKey.load_pkcs1(f.read())
        signature = base64.b64decode(signature_b64)
        rsa.verify(code.encode(), signature, pubkey)
        return True
    except:
        return False

if detect_debug():
    manhs_glitch()

try:
    encrypted_key = base64.b64decode("{encrypted_key_b64}")

    with open("private.pem", "rb") as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    aes_key = rsa.decrypt(encrypted_key, privkey)

    salt = base64.b64decode("{salt_b64}")
    iv = base64.b64decode("{iv_b64}")
    ciphertext = base64.b64decode("{data_b64}")

    key = PBKDF2(aes_key, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext).decode()
except:
    manhs_glitch()

if not verify_signature(plaintext, "{signature_b64}"):
    manhs_glitch()

exec(plaintext)
''')

    subprocess.run([
        "pyminifier",
        "--obfuscate",
        "--replacement-length=6",
        "--bzip2",
        "--lzma",
        "--gzip",
        junido_kai
    ], stdout=open(output_file, 'w', encoding='utf-8'))

    os.remove(junido_kai)

    manhs_custom = """
#Copyright By MinhAnhs
#WhiteNN & JunidoKai
#Bảo vệ quyền tác giả
#Chống hành vi Decode
"""
    manhs_comment(output_file, manhs_custom)

    print(f"{success} Đã tạo file mã hóa: {output_file}\n\nLưu file tại{trang}: {xla}{ma_}")

def main():
    print(f"{xla}=== AES-PBKDF2 + RSA-SHA256 Encryptor ==={trang}")
    manhs_rsa_key()

    manhs_file = input(f"{xla}Nhập tên file đầu vào (vdu: file.py) gốc: ").strip()
    manhs_out = input("Nhập tên file đầu ra (vdu: file_out.py): ").strip()

    if not os.path.exists(manhs_file):
        print(f"{error} File không tồn tại.")
        return

    manhs_encrypted(manhs_file, manhs_out)

if __name__ == '__main__':
    main()
