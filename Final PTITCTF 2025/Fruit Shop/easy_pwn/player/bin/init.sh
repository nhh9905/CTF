#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13331,reuseaddr,fork EXEC:./pwnable_1,stderr