from Crypto.Util.number import *

 
with open("flag.txt", "r") as f:
    flag = f.read().strip()
p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)


message = input("Enter text to encrypt: ")
m = bytes_to_long(message.encode())
c = pow(m, e, n)                                      
print(f"Here is your encrypted message: {c}")
print("Here is the public key for your reference:")
print(f"n = {n}")
print(f"e = {e}")


m = bytes_to_long(flag.encode())
n = p*r
c = pow(m, e, n)
print(f"Here is the encrypted flag: {c}")
print("Here is the public key for your reference:")
print(f"n = {n}")