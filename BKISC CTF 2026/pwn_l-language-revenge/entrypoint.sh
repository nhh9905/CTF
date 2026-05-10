#!/bin/sh
chmod 444 /home/ctf/flag.txt
exec xinetd -dontfork -f /etc/xinetd.d/chall
