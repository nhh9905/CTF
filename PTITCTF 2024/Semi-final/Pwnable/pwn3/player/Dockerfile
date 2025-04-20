FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y socat

RUN useradd -m pwnshadow

COPY bin/* /home/pwnshadow/

RUN chown -R root:pwnshadow /home/pwnshadow
RUN chmod -R 750 /home/pwnshadow

WORKDIR /home/pwnshadow
USER pwnshadow

EXPOSE 13335
CMD ["sh", "./init.sh"]