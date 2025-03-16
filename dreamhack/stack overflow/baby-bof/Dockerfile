FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update
RUN apt-get install -y socat

ENV user baby-bof
RUN adduser $user 

COPY ./deploy/flag /flag
COPY ./deploy/baby-bof /baby-bof

RUN chown  root:$user /flag
RUN chown  root:$user /baby-bof
RUN chmod 755 /flag /baby-bof

USER $user

EXPOSE 33333
CMD socat TCP-LISTEN:33333,reuseaddr,fork EXEC:/baby-bof
