FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential socat \
    && rm -rf /var/lib/apt/lists/*

# Copy challenge files (including your local pwninit)
COPY src/ /opt/chal/

WORKDIR /opt/chal

# Make the local pwninit and base challenge files executable
RUN chmod +x powerful-dfs entrypoint.sh

EXPOSE 4058

CMD ["/opt/chal/entrypoint.sh"]