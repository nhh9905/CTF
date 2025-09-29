FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 ctf
WORKDIR /home/ctf

COPY chall /home/ctf/chall
COPY flag.txt /home/ctf/flag.txt

RUN chown ctf:ctf /home/ctf/chall /home/ctf/flag.txt \
 && chmod 0755 /home/ctf/chall \
 && chmod 0444 /home/ctf/flag.txt

USER ctf
EXPOSE 1337
ENV MALLOC_ARENA_MAX=1

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork,nodelay", "EXEC:/home/ctf/chall,stderr"]
