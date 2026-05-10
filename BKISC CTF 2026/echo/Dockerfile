FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /opt/chal/
WORKDIR /opt/chal

RUN chmod +x chall entrypoint.sh

EXPOSE 5000
CMD ["/opt/chal/entrypoint.sh"]