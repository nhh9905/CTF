# pwn1
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/pwn1/player)
## Kịch bản
- Đọc qua 1 lượt đoạn mã giả, ta thấy chương trình cho phép chúng ta nhập chuỗi `buffer` tối đa 512 kí tự và biến `a` được khởi tạo với giá trị 1.

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-1.png)
- Nếu `a = 0xDEADBEEF` thì chúng ta sẽ thực thi được hàm `ptr_func`, hàm này ghi đè lên địa chỉ hàm `hello` để trỏ về hàm `win` lấy shell server

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-2.png)

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-7.png)

## Solution
- Ta nhận thấy rằng đây là file ELF 64-bit

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-3.png)
- Tiến hành debug file, ta thu được địa chỉ của biến `buffer` là `0x404060`

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-4.png)

- Địa chỉ của biến `a` là `0x4040e8`

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-5.png)
- Nhập dữ liệu cho biến `buffer`, biến `a` đã được ghi đè

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-6.png)

-> Tìm được khoảng cách từ `buffer` đến `a` là 136, tiến hành viết payload khai thác chương trình

[payload](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/pwn1/solution/solve.py)
## Flag
```PTITCTF{fl0w_fl0w_0v3rfl0w_g3t_w1n}```
## Kết luận
- Đây là dạng bài `ret2win` khá phổ biến trong mảng `pwnable`
# pwn2
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/pwn2/player)
## Solution
- Ta thấy có lệnh `mmap` được dùng để tạo một vùng nhớ ảo với kích thước 50 bytes và cấp quyền đọc, ghi, thực thi cho vùng nhớ đó mà không ánh xạ tới file nào

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-8.png)
- Ghi đè biến `buffer` lên biến `a`

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-9.png)

`0x00404094 - 0x00404060 = 0x34`

-> Vì biến `buffer` đứng trước biến `a` nên chúng ta phải ghi đè 52 bytes + 8 bytes của `0xCAFEBABE`
- Dùng lệnh `file` để kiểm tra tập tin
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-10.png)
- Vì bài này không có hàm `win` nên chúng ta phải chèn `shellcode`. Lệnh `mmap` có thể sử dụng `ret2shellcode` để yêu cầu server gửi flag. Ta có thể sử dụng file [Linux x86-64 shellcode](https://shell-storm.org/shellcode/files/shellcode-806.html)
- Ta có payload `\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05` để tiến hành `ret2shellcode`. Viết code để yêu cầu server gửi flag: 
[solve.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/pwn2/solution/solve.py)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Pwnable/image-11.png)
- Ta đã lấy được shellcode. Remote tới server để lấy flag giống bài `pwn1`
## Flag
```PTITCTF{sk3llc0d3_js_byt3c0d3?}```
## Kết luận
- Đây là dạng bài `ret2shellcode`