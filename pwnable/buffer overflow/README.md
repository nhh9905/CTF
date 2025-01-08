# Tràn biến
## bof1
### Target
- Ghi đè các biến `v5, v6, v7` sao cho khác 0, từ đó chiếm được shell của chương trình
### Exploit
- Nhận thấy rằng chuỗi `buf` được khai báo 16 bytes mà hàm `read` cho phép nhập vào 48 bytes kết hợp với việc kiểm tra các chế độ bảo vệ ta thấy chế độ `canary` được tắt
-> ```Buffer overflow```
- Bài này trong quá trình khai thác, ta nhập ngẫu nhiên 48 bytes đã có thể chiếm được shell. Tuy nhiên, để hiểu rõ bản chất vấn đề nên mình sẽ khai thác 1 cách chính xác
- Ta xác định được rằng các biến v7, v6, v5 tương ứng với các thanh ghi rbp - 0x10, rbp - 0x18, rbp - 0x20. Do đó ta chỉ việc xác định khoảng cách từ buf cho đến rbp - 0x20 là 16 bytes
-> Để ghi đè được 3 biến ta cần ghi đè 32 bytes
- Đọc kĩ pseudo code dòng 16, nếu kí tự cuối của chuỗi là '\n' thì sẽ chuyển thành null, khi đó v5 = 0. Do đó chúng ta phải ghi đè thêm 1 bytes để ghi đè biến v5
## bof2
### Target
- Ghi đè các biến `v7, v6, v5` lần lượt là các giá trị `0x13371337, 0xDEADBEEF, 0xCAFEBABE`
### Exploit
- Hướng khai thác vẫn giống bài trên, chỉ khác ở chỗ giá trị cần phải ghi đè