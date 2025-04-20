#!/bin/sh
socat TCP-LISTEN:13335,reuseaddr,fork EXEC:./pwn3,stderr