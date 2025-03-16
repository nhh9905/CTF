FROM ubuntu:18.04@sha256:ceed028aae0eac7db9dd33bd89c14d5a9991d73443b0de24ba0db250f47491d2

ENV user fho
ENV chall_port 7182

RUN apt-get update
RUN apt-get -y install socat

RUN adduser $user

WORKDIR /home/$user

ADD $user /home/$user/$user
ADD flag /home/$user/flag

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

USER $user
EXPOSE $chall_port
CMD socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user
