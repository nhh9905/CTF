# BabyShark
## Solution
- Phân tích các gói tin bằng wireshark thì thấy 1 gói tin lạ từ mạng Ethernet
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-1.png)
- Tiến hành xem nội dung của gói tin
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-2.png)
- Copy giá trị và decode dưới dạng `base32`
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-3.png)
## Flag
`PTITCTF{babywirebabysharkkkk}`
# PcapDump
## Solution
- Thực hiện File -> Export Objects -> HTTP để thu thập các file của gói tin, ta thu được 2 file `flag.txt` và `pcap.exe` là 2 file được `curl` tại ip lạ `103.197.185.145:1234`
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-4.png)
- Dump 2 file này về và tiến hành lấy flag. Đây là nội dung file `flag.txt`
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-5.png)
- Phân tích file `pcap.exe`
- Chương trình trên cho chúng ta nhập vào 1 chuỗi và sau đó sẽ check xem chuỗi chúng ta nhập có đúng không. Vì vậy ta sẽ reverse file này
![alt text](https://github.com/nhh9905/CTF/blob/main/V%C3%B2ng%20lo%E1%BA%A1i%20PTITCTF%202024/Forensics/image-6.png)
- Viết code `Python` tìm flag
```Python
v6 = [0]*31
v6[0] = 53
v6[1] = 57
v6[2] = 46
v6[3] = 57
v6[4] = 40
v6[5] = 57
v6[6] = 43
v6[7] = 96
v6[8] = 24
v6[9] = 93
v6[10] = 85
v6[11] = 21
v6[12] = 87
v6[13] = 89
v6[14] = 68
v6[15] = 43
v6[16] = 22
v6[17] = 81
v6[18] = 24
v6[19] = 68
v6[20] = 43
v6[21] = 87
v6[22] = 21
v6[23] = 82
v6[24] = 68
v6[25] = 85
v6[26] = 72
v6[27] = 25
v6[28] = 85
v6[29] = 9
v6[30] = 98
for i in range(31):
    print(chr(v6[i] + 27), end='')
```
## Flag
`PTITCTF{3xp0rt_F1l3_Fr0m_pc4p$}`
