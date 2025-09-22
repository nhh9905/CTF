#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13335,reuseaddr,fork EXEC:./pwnable_2,stderr