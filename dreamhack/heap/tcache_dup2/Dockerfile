FROM ubuntu:19.10@sha256:f332c4057e21ec71cc8b20b05328d476104a069bfa6882877e0920e8140edcf0

ENV user tcache_dup2
ENV chall_port 31337

RUN sed -i s/archive.ubuntu.com/old-releases.ubuntu.com/g /etc/apt/sources.list
RUN sed -i s/security.ubuntu.com/old-releases.ubuntu.com/g /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y socat

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./$user /home/$user/$user

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD while :; do socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user ; done
