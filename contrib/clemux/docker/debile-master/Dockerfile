FROM debian:jessie
MAINTAINER Clément Schreiner <clement@mux.me>

RUN adduser --disabled-password --gecos '' --home /srv/debile debile
VOLUME /etc/debile
FROM debian:jessie
MAINTAINER Clément Schreiner <clement@mux.me>

RUN groupadd -r debile && useradd -r -g debile -d /srv/debile debile

COPY sources.list /etc/apt/

COPY *.deb /tmp/debile/

WORKDIR /tmp/debile

RUN apt update && apt install -y python python2.7 python-chardet python-flask
RUN apt install -y python-jinja2 python-psycopg2 python-six
RUN apt install -y python-sqlalchemy python-debian python-requests python-yaml adduser reprepro python-firehose python-chardet vim sudo

RUN dpkg -i python-firewoes*.deb python-debile*.deb debile-master*.deb

COPY master.yaml /etc/debile/
COPY debile.yaml /etc/debile/

COPY slave-keys.tar.gz /tmp/debile
RUN tar xvf slave-keys.tar.gz
RUN gpg --batch --import key.priv
RUN touch debile_master_log
EXPOSE 22017
