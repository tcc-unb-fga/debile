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

RUN apt update && apt install -y python python2.7 python-dev python-chardet python-flask \
libyaml-dev libpq-dev python-jinja2 python-psycopg2 python-six \
python-sqlalchemy python-debian python-requests python-yaml \ 
adduser reprepro python-firehose python-chardet vim sudo python-pip

RUN pip install pymongo virtualenvwrapper

COPY master.yaml /etc/debile/
COPY debile.yaml /etc/debile/

USER debile

EXPOSE 22017
ENV PYTHONPATH="${PYTHONPATH}:/srv/debile/repo/lib/python2.7/site-packages/"
# CMD debile-master --auth simple --debug
