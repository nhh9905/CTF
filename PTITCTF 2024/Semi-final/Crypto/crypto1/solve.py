from Crypto.Cipher import DES
import base64

cipher_b64 = b"Xfw54DbCB6IXKg/a1tdlG40kvNy/0z6CYtdmEvrC+2A="

cipher = base64.b64decode(cipher_b64)

def decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text.decode()

key = b'PTITCTF{'

plaintext = decrypt(cipher, key)
print("Decrypted text:", plaintext)