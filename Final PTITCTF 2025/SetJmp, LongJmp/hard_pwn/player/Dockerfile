FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y socat

RUN dpkg --add-architecture i386 
RUN apt-get update
RUN apt-get install -y libc6:i386 libstdc++6:i386 lib32gcc-s1
RUN apt-get install -y gdb

RUN useradd -m pwnshadow

COPY bin/* /home/pwnshadow/

RUN chown -R root:pwnshadow /home/pwnshadow
RUN chmod -R 750 /home/pwnshadow

WORKDIR /home/pwnshadow
USER pwnshadow

EXPOSE 13339
CMD ["sh", "./init.sh"]