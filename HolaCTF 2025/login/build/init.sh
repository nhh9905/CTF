#!/bin/bash
cd /challenge

# Xuất flag vào biến môi trường để binary có thể đọc
export FLAG=$(cat flag.txt 2>/dev/null)

# Chạy service bằng socat, lắng nghe trên cổng 1337
exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./chall",pty,stderr,setsid,sigint,sane