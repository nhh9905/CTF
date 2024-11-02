from Crypto.Cipher import DES
import base64

with open("flag.txt", "r") as f:
    flag = f.read().strip()

def encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_text = cipher.encrypt(plaintext.encode())
    return encrypted_text

key = b'PTITCTF{'

cipher = encrypt(flag, key)
print("cipher:", base64.b64encode(cipher).decode())
