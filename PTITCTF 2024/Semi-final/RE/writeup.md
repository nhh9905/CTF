# rev2 (Easy)
- Đọc pseudo code của file `exe`, ta thấy bài yêu cầu nhập 100 giá trị của `v11` và thấy hàm `check_equations` để check các phương trình nếu thỏa mãn thì in ra flag

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-1.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-2.png)

## Solution
- Vậy việc ta cần làm là tính toán các giá trị của `v11`. Viết code tính toán các giá trị của mảng `v11`:
[find_a1.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/find_a1.py)
- Copy hàm mã hóa trong ida và lấy các giá trị của mảng `a1` đưa vào file `C++` để tìm ra flag:
[solve.cpp](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/solve.cpp)
## Flag
``` PTITCTF{14506909c43e869034854821c} ```
# rev3
## Solution
- Ở bài này chúng ta nhận được 1 file `exe` 64 bits và chưa biết file đó viết bằng ngôn ngữ nào
- Sử dụng chức năng Strings của ida64, ta thấy file `exe` được viết bằng ngôn ngữ `Python`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-5.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-6.png)
- Sử dụng `pyinstxtractor` `https://github.com/extremecoders-re/pyinstxtractor` để extract ra các file pyc và các thư viện mà chương trình kia sử dụng
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-7.png)
- Tải file `pyinstxtractor.py` và truyền file `exe` để extract ra các thư viện và hàm sử dụng trong đoạn code
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-8.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-9.png)
- File ta cần phân tích chính là `chall.pyc`. Để decompile file này ta sẽ dùng `pylingual`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-10.png)
- Đây chính là source code của file `exe` kia:
```Python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: chall.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

def main():
    a = [201, 109, 176, 225, 31, 132, 131, 32, 183, 80, 161, 50, 159, 19, 105, 46, 166, 227, 151, 123, 56, 143, 47, 50, 223, 162, 216, 94, 25, 170, 78, 169, 34, 96, 22, 68, 69, 48, 57, 154, 155, 64]
    b = [153, 57, 249, 181, 92, 208, 197, 91, 199, 41, 144, 92, 236, 103, 93, 66, 202, 208, 229, 36, 95, 191, 112, 85, 239, 253, 186, 44, 113, 194, 38, 193, 20, 87, 32, 34, 36, 5, 92, 175, 253, 61]
    flag = [0 for i in range(42)]
    c = input('Flag: ')
    if len(c) != 42:
        print('Incorrect!')
        return -1
    for i in range(42):
        if not b[i] == ord(c[i]) ^ a[i]:
            print('Incorrect!')
            return -1
    else:
        print('Correct!')
        return 0
if __name__ == '__main__':
    main()
```
- Viết code để tìm ra input:
```Python
def main():
    a = [201, 109, 176, 225, 31, 132, 131, 32, 183, 80, 161, 50, 159, 19, 105, 46, 166, 227, 151, 123, 56, 143, 47, 50, 223, 162, 216, 94, 25, 170, 78, 169, 34, 96, 22, 68, 69, 48, 57, 154, 155, 64]
    b = [153, 57, 249, 181, 92, 208, 197, 91, 199, 41, 144, 92, 236, 103, 93, 66, 202, 208, 229, 36, 95, 191, 112, 85, 239, 253, 186, 44, 113, 194, 38, 193, 20, 87, 32, 34, 36, 5, 92, 175, 253, 61]
    flag = [0 for i in range(42)]
    for i in range(42):
        flag[i] = b[i] ^ a[i]
        
    print("".join(chr(i) for i in flag))
if __name__ == '__main__':
    main()
```
## Flag
``` PTITCTF{py1nst4ll3r_g0_g0_brhhhh676fa5e5f} ```
# rev4
## Solution
- Dùng DIE ta kiểm tra được file `exe` 64 bits viết bằng ngôn ngữ `go`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-11.png)
- Debug file `exe`, ta nhập chuỗi `aaa` và nhảy vào hàm `os_Exit()` vì nhập flag không đúng
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-12.png)
=> Flag có kích thước là 36 kí tự
- Nhập lại input và debug hàm `func_1`, ta thu được mảng `ida_chars = [0x32, 0x37, 0x29, 0x35, 0x25, 0x3B, 0x2E, 0xE0, 0xCD, 0x1B, 0xD4, 0x1D, 0xD8, 0xD6, 0xCF, 0x22, 0xE1, 0xD2]`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-13.png)
- Quay trở lại hàm trước đó thì `input` đã được gán giá trị mới bằng thuật toán sau
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-14.png)
- Vậy bây giờ ta sẽ tiến hành viết code để decrypt nửa flag đầu:
```Python
ida_chars = [
  0x32, 0x37, 0x29, 0x35, 0x25, 0x3B,  
  0x2E, 0xE0, 0xCD, 0x1B, 0xD4, 0x1D, 
  0xD8, 0xD6, 0xCF, 0x22,0xE1, 0xD2]
print(len(ida_chars))
for i in range(len(ida_chars)):
    ida_chars[i] ^= 0x42
    ida_chars[i] -= 32 + i
    print(chr(ida_chars[i]), end = '')
```
- Nửa flag đầu:

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-15.png)
- Tương tự với hàm func_2, ta thu được mảng `ida_chars = [0x3E, 0x70, 0x30, 0x38, 0x03, 0x0B, 0x3B, 0x31, 0x3E, 0x22, 0x0D, 0x39, 0x79, 0x30, 0x3E, 0x23, 0x17, 0xD6]`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-16.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-17.png)
- Viết code decrypt nửa flag sau:
```Python
ida_chars = [
    0x3E, 0x70, 0x30, 0x38, 0x03, 0x0B,
    0x3B, 0x31, 0x3E, 0x22, 0x0D, 0x39, 
    0x79, 0x30, 0x3E, 0x23, 0x17, 0xD6]
for i in range(len(ida_chars)):
    ida_chars[i] ^= 0x56
    ida_chars[i] += 32
    ida_chars[i] -= i + 18
    print(chr(ida_chars[i]), end = '')
```
- Nửa flag sau:

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/RE/image-18.png)
- Toàn bộ code decrypt:
```Python
ida_chars = [
  0x32, 0x37, 0x29, 0x35, 0x25, 0x3B,  
  0x2E, 0xE0, 0xCD, 0x1B, 0xD4, 0x1D, 
  0xD8, 0xD6, 0xCF, 0x22,0xE1, 0xD2]
print(len(ida_chars))
for i in range(len(ida_chars)):
    ida_chars[i] ^= 0x42
    ida_chars[i] -= 32 + i
    print(chr(ida_chars[i]), end = '')
print(end = '')
ida_chars = [
    0x3E, 0x70, 0x30, 0x38, 0x03, 0x0B,
    0x3B, 0x31, 0x3E, 0x22, 0x0D, 0x39, 
    0x79, 0x30, 0x3E, 0x23, 0x17, 0xD6]
for i in range(len(ida_chars)):
    ida_chars[i] ^= 0x56
    ida_chars[i] += 32
    ida_chars[i] -= i + 18
    print(chr(ida_chars[i]), end = '')
```
## Flag
`PTITCTF{g0l4ng_1s_v3ry_funny_r1ght?}`
