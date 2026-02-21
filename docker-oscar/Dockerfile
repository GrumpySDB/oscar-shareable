FROM ghcr.io/linuxserver/baseimage-selkies:debiantrixie

COPY /oscar_1.7.0-Debian13_amd64-Qt5.deb /tmp/oscar.deb

RUN apt update

RUN apt install -y /tmp/oscar.deb && \
    rm /tmp/oscar.deb && \
    rm -rf /var/lib/apt/lists

#RUN apk add --no-cache firefox
COPY /root /

# ports and volumes
EXPOSE 3000
