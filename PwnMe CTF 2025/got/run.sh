#!/bin/sh

docker build -t got .
docker run -p 1337:1337 -it got
