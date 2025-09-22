#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13339,reuseaddr,fork EXEC:./pwnable_3,stderr