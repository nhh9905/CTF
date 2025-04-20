#!/bin/sh
socat TCP-LISTEN:13331,reuseaddr,fork EXEC:./pwn1,stderr