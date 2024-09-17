# FlagChecker
## Solution
- Thử search `flag` trong đoạn code `asm`, ta thu được hàm `sub_140001450` với `String` là chuỗi nhập vào
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/V%C3%B2ng%20lo%E1%BA%A1i/RE/image-1.png)
- Kiểm tra hàm ta thu được 43 phương trình với 51 ẩn, để giải được các phương trình trên chúng ta phải cài đặt một số thư viện
```
pip install z3
pip install z3-solver
```
- Viết code `Python` để thu được flag
!
## Flag
`PTITCTF{Y0u_C4n_Br34k_Equ4tion_Ag41n_6861696e64!!!}`