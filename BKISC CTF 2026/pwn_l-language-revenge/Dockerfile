FROM ubuntu:24.04

RUN apt-get update && apt-get install -y xinetd && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

COPY ./flag.txt /home/ctf/flag.txt
COPY ./chall_release /home/ctf/chall
COPY ./chall.xinetd /etc/xinetd.d/chall
COPY ./entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh
RUN chmod +x /home/ctf/chall

ENTRYPOINT ["/entrypoint.sh"]
