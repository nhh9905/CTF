# FlagChecker
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Final/RE/FlagChecker/chall)
## Solution
- Thử search `flag` trong đoạn code `asm`, ta thu được hàm `sub_140001450` với `String` là chuỗi nhập vào
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Final/RE/image-1.png)
- Kiểm tra hàm ta thu được 43 phương trình với 51 ẩn, để giải được các phương trình trên chúng ta phải cài đặt một số thư viện
```
pip install z3
pip install z3-solver
```
- Biết format flag được viết dưới dạng `PTITCTF{}` nên chúng ta chỉ cần tìm 42 ẩn còn lại, viết code `Python` để giải hệ phương trình và in ra flag: 
[solve.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Final/RE/FlagChecker/solve.py)
## Flag
`PTITCTF{Y0u_C4n_Br34k_Equ4tion_Ag41n_6861696e64!!!}`