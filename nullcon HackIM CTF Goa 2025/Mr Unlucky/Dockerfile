FROM debian:latest

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing && apt-get -y upgrade
RUN apt-get -y install socat gcc make

RUN groupadd -r user && useradd -r -g user user

ADD ./init.sh /etc/init.sh
RUN chmod 700 /etc/init.sh

WORKDIR /home/user/
ADD ./mr_unlucky mr_unlucky
ADD ./flag.txt flag.txt
RUN chmod 550 mr_unlucky

RUN chown -R root:user /home/user

#init.sh: socat TCP-LISTEN:4444,fork,nodelay,reuseaddr,pktinfo,pf=ip4 EXEC:./mr_unlucky,su=user
ENTRYPOINT "/etc/init.sh"
