#!/bin/bash

rustc -C opt-level=0 -C panic=abort -C debuginfo=0 \
      -C link-dead-code=yes -C force-frame-pointers=yes \
      -C link-arg=-no-pie -C link-arg=-Wl,-z,relro \
      -o chall chall.rs
