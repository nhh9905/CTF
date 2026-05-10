FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /opt/chal/
WORKDIR /opt/chal

RUN chmod +x registryd directoryd server.py entrypoint.sh

EXPOSE 5000
CMD ["/opt/chal/entrypoint.sh"]
