FROM ghcr.io/linuxserver/baseimage-selkies:debiantrixie

ARG OSCAR_VERSION=latest

RUN apt-get update && \
    apt-get install -y wget curl wmctrl && \
    if [ "${OSCAR_VERSION}" = "latest" ]; then \
    export OSCAR_VERSION=$(curl -s https://www.sleepfiles.com/OSCAR/ | grep -o 'OSCAR [0-9]\+\.[0-9]\+\.[0-9]\+' | head -n 1 | awk '{print $2}'); \
    fi && \
    echo "Building with OSCAR version: ${OSCAR_VERSION}" && \
    wget -q -O /tmp/oscar.deb "https://www.sleepfiles.com/OSCAR/${OSCAR_VERSION}/oscar_${OSCAR_VERSION}-Debian13_amd64-Qt5.deb" && \
    apt-get install -y /tmp/oscar.deb && \
    rm /tmp/oscar.deb && \
    apt-get purge -y wget curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY /root /

# ports and volumes
EXPOSE 3000
