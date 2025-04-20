#!/bin/sh
socat TCP-LISTEN:13333,reuseaddr,fork EXEC:./pwn2,stderr