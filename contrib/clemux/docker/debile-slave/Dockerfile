# Create a Debile slave.
#
# VERSION   0.1
FROM        debian:testing
MAINTAINER  Clément Schreiner <clement@mux.me>
# OK. Enough about that. Let's take our pristine Debian image and
# add our key.

RUN mkdir -p /srv/debile/
RUN mkdir -p /etc/debile/
RUN adduser --disabled-password --gecos '' --home /srv/debile debile
RUN chown -R debile:debile /srv/debile
RUN chmod 755 /usr/bin/dpkg

COPY sources.list /etc/apt/
COPY *.deb /tmp/

WORKDIR /tmp

RUN apt-get update && apt-get install -y python dput-ng python-dput
RUN apt install -y adduser
RUN apt install -y python-debian
RUN apt install -y python-requests
RUN apt install -y python-yaml
RUN apt install -y python-schroot

RUN apt install -y apt-utils dctrl-tools devscripts python-clint python-pip vim sudo python-firehose

RUN pip install virtualenvwrapper dput

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

RUN sbuild-adduser debile

RUN chown -R debile:debile /etc/debile

COPY slave.yaml /etc/debile/

COPY debile-rebuild.ini /etc/
COPY dput.cf ~/.dput.cf

ENV GPG_TTY /dev/console

COPY slave-keys.tar.gz /tmp/
COPY debile-master.json /etc/dput.d/profiles/
ENV PYTHONPATH="${PYTHONPATH}:/srv/debile/repo/lib/python2.7/site-packages/"

# RUN sh -c "tar xvf slave-keys.tar.gz -O | gpg --import --status-fd 1 2&> /dev/null"
# CMD debile-slave --debug --auth simple
# debile-upload --dist=unstable --source=vim --version=7.3.547-7 --group=test
