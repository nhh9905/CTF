# BabyShark
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/babyshark)
## Solution
- Phân tích các gói tin bằng wireshark thì thấy 1 gói tin lạ từ mạng Ethernet
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-1.png)
- Tiến hành xem nội dung của gói tin
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-2.png)
- Copy giá trị và decode dưới dạng `base32`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-3.png)
## Flag
`PTITCTF{babywirebabysharkkkk}`
# PcapDump
## Challenge

[chall](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/pcapdump/chall)
## Solution
- Thực hiện File -> Export Objects -> HTTP để thu thập các file của gói tin, ta thu được 2 file `flag.txt` và `pcap.exe` là 2 file được `curl` tại ip lạ `103.197.185.145:1234`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-4.png)
- Dump 2 file này về và tiến hành lấy flag. Đây là nội dung file `flag.txt`
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-5.png)
- Phân tích file `pcap.exe`
- Chương trình trên cho chúng ta nhập vào 1 chuỗi và sau đó sẽ check xem chuỗi chúng ta nhập có đúng không. Vì vậy ta sẽ reverse file này
![alt text](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/image-6.png)
- Viết code `Python` tìm flag: 
[solve.py](https://github.com/nhh9905/CTF/blob/main/PTITCTF%202024/Semi-final/Forensics/pcapdump/solution/solve.py)
## Flag
`PTITCTF{3xp0rt_F1l3_Fr0m_pc4p$}`