FROM debian:jessie
MAINTAINER Clément Schreiner <clement@mux.me>

RUN mkdir -p /srv/debile/
RUN groupadd -r debile && useradd -r -g debile -d /srv/debile debile

RUN mkdir -p /srv/debile/incoming/UploadQueue
RUN mkdir -p /srv/debile/repo/default/conf /srv/debile/repo/default/logs /srv/debile/files/default
RUN mkdir -p /srv/debile/repo/flaws/conf /srv/debile/repo/flaws/logs /srv/debile/files/flaws

COPY reprepo-conf/default/* /srv/debile/repo/default/conf/
COPY reprepo-conf/flaws/* /srv/debile/repo/flaws/conf/

RUN chown -R debile:debile /srv/debile
RUN chmod a+rwx /srv/debile/incoming/UploadQueue

USER debile
WORKDIR /srv/debile
VOLUME /srv/debile

CMD echo Data-only container for debile-master
