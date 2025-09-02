FROM ubuntu:22.04

# Install socat and clean up
RUN apt-get update && \
    apt-get install -y socat bash && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create user and set up home directory
RUN useradd -md /home/challenge challenge && \
    echo "challenge:challenge" | chpasswd

WORKDIR /challenge
COPY ./chall .
COPY ./init.sh .

RUN chmod 755 ./chall && \
    chmod 755 ./init.sh && \
    chmod 644 ./flag.txt || true && \
    chown -R challenge:challenge /challenge

USER challenge
ENTRYPOINT ["/challenge/init.sh"]