FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

ENV user fsb_overwrite
ENV chall_port 7182

RUN apt-get update
RUN apt-get -y install socat

RUN adduser $user

ADD ./private/flag /home/$user/flag
ADD ./public/$user /home/$user/$user

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user
RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag


WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat -T 10 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user

