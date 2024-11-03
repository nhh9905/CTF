# crypto1
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/crypto1/chall)
## Solution
- Đọc file `chall.py`, ta thấy chương trình khởi tạo module `DES` với key được cho sẵn
- Chúng ta có cipher và key -> viết hàm `decrypt` để tìm flag: 
[solve.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/crypto1/solve.py)
## Flag
```PTITCTF{W3lC0m3_T0_Crypt0_D3S!!}```
# crypto2 (Easy)
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/crypto2/chall)
## Solution
- Dựa vào đề bài và đoạn code được cho, ta dễ dàng thấy rằng flag đã được mã hóa bằng thuật toán `RSA`
- Mở kali và `nc 14.225.255.41 1337`, ta thấy đề bài yêu cầu nhập dữ liệu để mã hóa. Nhập bất kì dữ liệu nào đó, ta thu được các thông số:
[key.txt](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/crypto2/solution/key.txt)

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/image-1.png)
- Chúng ta thu được văn bãn đã được mã hóa, public key của dữ liệu vừa nhập vào và flag
- Viết code tìm d để lấy được private key: 
[find_d.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/crypto2/solution/find_d.py)
- Sau khi tìm được `d`, ta lên web `dcode.fr` nhập 4 đầu vào dữ liệu C, N, E, D và thu được flag
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Crypto/image-2.png)
## Flag
``` PTITCTF{y0u_kn0w_4tt4ck1ng_rs4} ```
