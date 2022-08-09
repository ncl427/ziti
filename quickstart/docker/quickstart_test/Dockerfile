FROM --platform=linux/x86_64 ubuntu:rolling

RUN apt update && \
    apt install jq curl netcat-openbsd vim inetutils-ping net-tools psmisc wget -y

COPY local-quickstart-setup.sh "/tmp/"