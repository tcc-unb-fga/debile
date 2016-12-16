# Create a Debile slave.
#
# VERSION   0.1
FROM        debian:sid
MAINTAINER  Clément Schreiner <clement@mux.me>
# OK. Enough about that. Let's take our pristine Debian image and
# add our key.

RUN mkdir -p /srv/debile/
RUN groupadd -r debile && useradd -r -g debile -d /srv/debile debile
RUN chown -R debile:debile /srv/debile

COPY sources.list /etc/apt/
COPY *.deb /tmp/

WORKDIR /tmp

RUN apt-get update && apt-get install -y python python-dput dput-ng python-firehose adduser python-debian python-requests python-yaml python-schroot vim python-pip sudo

RUN apt install -y apt-utils dctrl-tools devscripts python-clint

# Use a custom version of sbuild written by Léo Cavaillé that adds an
# option --use-schroot-session, which enables starting sbuild with an
# existing schroot session.
RUN apt-get build-dep --assume-yes sbuild
RUN apt-get source sbuild
COPY support-for-schroot-sessions.patch /tmp/
RUN cd sbuild-* && cp ../support-for-schroot-sessions.patch . && \
    patch -p1 < ../support-for-schroot-sessions.patch && \
    dpkg-buildpackage -us -uc -nc
RUN (dpkg --install *sbuild*.deb || true)
RUN apt-get --assume-yes --fix-broken install

RUN dpkg -i python-debile*.deb debile-slave*.deb

RUN sbuild-adduser debile

RUN chown -R debile:debile /etc/debile/*

COPY slave.yaml /etc/debile/

COPY debile-rebuild.ini /etc/
COPY dput.cf ~/.dput.cf

# GPG_TTY $(tty)
# export $GPG_TTY
# RUN GPG_TTY=$(tty)
# RUN export GPG_TTY
ENV GPG_TTY /dev/console
# USER debile

COPY slave-keys.tar.gz /tmp/
COPY debile-master.json /etc/dput.d/profiles/


# RUN sh -c "tar xvf slave-keys.tar.gz -O | gpg --import --status-fd 1 2&> /dev/null"

# CMD debile-slave --debug --auth simple

#       vim_7.3.547-7.dsc
# debile-upload --dist=unstable --source=vim --version=7.3.547-7 --group=test
