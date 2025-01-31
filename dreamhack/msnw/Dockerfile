FROM ubuntu:22.04@sha256:35fb073f9e56eb84041b0745cb714eff0f7b225ea9e024f703cab56aaa5c7720

ENV USER msnw
ENV CHALL_PORT 31337

RUN apt-get update
RUN apt-get install -y xinetd

RUN adduser $USER

ADD ./deploy/xinetd /etc/xinetd.d/chall
ADD ./deploy/flag /home/$USER/flag
ADD ./deploy/$USER /home/$USER/$USER
ADD ./deploy/run.sh /home/$USER/run.sh

RUN chown -R root:root /home/$USER
RUN chown root:$USER /home/$USER/flag
RUN chown root:$USER /home/$USER/$USER
RUN chown root:$USER /home/$USER/run.sh

RUN chmod 755 /home/$USER
RUN chmod 755 /home/$USER/$USER
RUN chmod 440 /home/$USER/flag
RUN chmod 755 /home/$USER/run.sh

RUN service xinetd restart

WORKDIR /home/$user
USER $user
EXPOSE $CHALL_PORT
CMD ["/usr/sbin/xinetd", "-dontfork"]
