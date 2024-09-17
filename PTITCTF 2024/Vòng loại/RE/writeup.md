# rev2 (Easy)
- Đọc pseudo code của file `exe`, ta thấy bài yêu cầu nhập 100 giá trị của `v11` và thấy hàm `check_equations` để check các phương trình nếu thỏa mãn thì in ra flag

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-1.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-2.png)

## Solution
- Vậy việc ta cần làm là tính toán các giá trị của `v11`. Viết code tính toán các giá trị của mảng `v11`:
```Python
import sympy as sp

# Khởi tạo 100 biến a1[0] đến a1[99]
a1 = sp.symbols('a1:101')

# Tạo danh sách các phương trình từ hệ đã cho
equations = [
    a1[0] + a1[1] - 4,
    a1[1] + a1[2] - 6,
    a1[2] + a1[3] - 8,
    a1[3] + a1[4] - 10,
    a1[4] + a1[5] - 12,
    a1[5] + a1[6] - 14,
    a1[6] + a1[7] - 16,
    a1[7] + a1[8] - 18,
    a1[8] + a1[9] - 20,
    a1[9] + a1[10] - 22,
    a1[10] + a1[11] - 24,
    a1[11] + a1[12] - 26,
    a1[12] + a1[13] - 28,
    a1[13] + a1[14] - 30,
    a1[14] + a1[15] - 32,
    a1[15] + a1[16] - 34,
    a1[16] + a1[17] - 36,
    a1[17] + a1[18] - 38,
    a1[18] + a1[19] - 40,
    a1[19] + a1[20] - 42,
    a1[20] + a1[21] - 44,
    a1[21] + a1[22] - 46,
    a1[22] + a1[23] - 48,
    a1[23] + a1[24] - 50,
    a1[24] + a1[25] - 52,
    a1[25] + a1[26] - 54,
    a1[26] + a1[27] - 56,
    a1[27] + a1[28] - 58,
    a1[28] + a1[29] - 60,
    a1[29] + a1[30] - 62,
    a1[30] + a1[31] - 64,
    a1[31] + a1[32] - 66,
    a1[32] + a1[33] - 68,
    a1[33] + a1[34] - 70,
    a1[34] + a1[35] - 72,
    a1[35] + a1[36] - 74,
    a1[36] + a1[37] - 76,
    a1[37] + a1[38] - 78,
    a1[38] + a1[39] - 80,
    a1[39] + a1[40] - 82,
    a1[40] + a1[41] - 84,
    a1[41] + a1[42] - 86,
    a1[42] + a1[43] - 88,
    a1[43] + a1[44] - 90,
    a1[44] + a1[45] - 92,
    a1[45] + a1[46] - 94,
    a1[46] + a1[47] - 96,
    a1[47] + a1[48] - 98,
    a1[48] + a1[49] - 100,
    a1[49] + a1[50] - 102,
    a1[50] - a1[51] - 104,
    a1[51] + a1[52] - 106,
    a1[52] + a1[53] - 108,
    a1[53] + a1[54] - 110,
    a1[54] + a1[55] - 112,
    a1[55] + a1[56] - 114,
    a1[56] + a1[57] - 116,
    a1[57] + a1[58] - 118,
    a1[58] + a1[59] - 120,
    a1[59] + a1[60] - 122,
    a1[60] + a1[61] - 124,
    a1[61] + a1[62] - 126,
    a1[62] + a1[63] - 128,
    a1[63] + a1[64] - 130,
    a1[64] + a1[65] - 132,
    a1[65] + a1[66] - 134,
    a1[66] + a1[67] - 136,
    a1[67] + a1[68] - 138,
    a1[68] + a1[69] - 140,
    a1[69] + a1[70] - 142,
    a1[70] + a1[71] - 144,
    a1[71] + a1[72] - 146,
    a1[72] + a1[73] - 148,
    a1[73] + a1[74] - 150,
    a1[74] + a1[75] - 152,
    a1[75] + a1[76] - 154,
    a1[76] + a1[77] - 156,
    a1[77] + a1[78] - 158,
    a1[78] + a1[79] - 160,
    a1[79] + a1[80] - 162,
    a1[80] + a1[81] - 164,
    a1[81] + a1[82] - 166,
    a1[82] + a1[83] - 168,
    a1[83] + a1[84] - 170,
    a1[84] + a1[85] - 172,
    a1[85] + a1[86] - 174,
    a1[86] + a1[87] - 176,
    a1[87] + a1[88] - 178,
    a1[88] + a1[89] - 180,
    a1[89] + a1[90] - 182,
    a1[90] + a1[91] - 184,
    a1[91] + a1[92] - 186,
    a1[92] + a1[93] - 188,
    a1[93] + a1[94] - 190,
    a1[94] + a1[95] - 192,
    a1[95] + a1[96] - 194,
    a1[96] + a1[97] - 196,
    a1[97] + a1[98] - 198,
    a1[98] + a1[99] - 200,
    a1[99] + a1[0] - 202
]

# Giải hệ phương trình
solution = sp.solve(equations, a1)

# In kết quả
for i in range(100):
    print(f'{solution[a1[i]]},', end = ' ')
```
- Copy hàm mã hóa trong ida và lấy các giá trị của mảng `a1` đưa vào file `C++` để tìm ra flag:
```C++
#include <bits/stdc++.h>
using namespace std;
int main() {
    int v11[100] = {104, -100, 106, -98, 108, -96, 110, -94, 112, -92, 114, -90, 116, -88, 118, -86, 120, -84, 122, -82, 124, -80, 126, -78, 128, -76, 130, -74, 132, -72, 134, -70, 136, -68, 138, -66, 140, -64, 142, -62, 144, -60, 146, -58, 148, -56, 150, -54, 152, -52, 154, 50, 56, 52, 58, 54, 60, 56, 62, 58, 64, 60, 66, 62, 68, 64, 70, 66, 72, 68, 74, 70, 76, 72, 78, 74, 80, 76, 82, 78, 84, 80, 86, 82, 88, 84, 90, 86, 92, 88, 94, 90, 96, 92, 98, 94, 100, 96, 102, 98};
    int v20 = 0;
    int v19 = 0;
    int v18 = 0;
    int v17 = 0;
    int v16 = 0;
    int v15 = 0;
    int v14 = 0;
    int v13 = 0;
    for (int j = 0; j <= 99; ++j )
    {
        if ( (v11[j] & 1) == 0 ) //v11 chan
            v20 += v11[j];
        if ( !(v11[j] % 3) )
            v19 += v11[j];
        if ( (v11[j] & 3) == 0 )
            v18 += v11[j];
        if ( !(v11[j] % 5) )
            v17 += v11[j];
        if ( !(v11[j] % 6) )
            v16 += v11[j];
        if ( !(v11[j] % 7) )
            v15 += v11[j];
        if ( (v11[j] & 7) == 0 )
            v14 += v11[j];
        if ( !(v11[j] % 9) )
            v13 += v11[j];
    }
    int v9 = v13;
    int v8 = v14;
    int v7 = v15;
    int v6 = v16;
    int v5 = v17;
    int v4 = v18;
    printf("PTITCTF{%x%x%x%x%x%x%x%x}", v20, v19, v4, v5, v6, v7, v8, v9);
}
```
## Flag
``` PTITCTF{14506909c43e869034854821c} ```
# rev3
## Solution
- Ở bài này chúng ta nhận được 1 file `exe` 64 bits và chưa biết file đó viết bằng ngôn ngữ nào
- Sử dụng chức năng Strings của ida64, ta thấy file `exe` được viết bằng ngôn ngữ `Python`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-5.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-6.png)
- Sử dụng `pyinstxtractor` `https://github.com/extremecoders-re/pyinstxtractor` để extract ra các file pyc và các thư viện mà chương trình kia sử dụng
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-7.png)
- Tải file `pyinstxtractor.py` và truyền file `exe` để extract ra các thư viện và hàm sử dụng trong đoạn code
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-8.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-9.png)
- File ta cần phân tích chính là `chall.pyc`. Để decompile file này ta sẽ dùng `pylingual`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-10.png)
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
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-11.png)
- Debug file `exe`, ta nhập chuỗi `aaa` và nhảy vào hàm `os_Exit()` vì nhập flag không đúng
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-12.png)
=> Flag có kích thước là 36 kí tự
- Nhập lại input và debug hàm `func_1`, ta thu được mảng `ida_chars = [0x32, 0x37, 0x29, 0x35, 0x25, 0x3B, 0x2E, 0xE0, 0xCD, 0x1B, 0xD4, 0x1D, 0xD8, 0xD6, 0xCF, 0x22, 0xE1, 0xD2]`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-13.png)
- Quay trở lại hàm trước đó thì `input` đã được gán giá trị mới bằng thuật toán sau
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-14.png)
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

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-15.png)
- Tương tự với hàm func_2, ta thu được mảng `ida_chars = [0x3E, 0x70, 0x30, 0x38, 0x03, 0x0B, 0x3B, 0x31, 0x3E, 0x22, 0x0D, 0x39, 0x79, 0x30, 0x3E, 0x23, 0x17, 0xD6]`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-16.png)
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-17.png)
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

![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-18.png)
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
