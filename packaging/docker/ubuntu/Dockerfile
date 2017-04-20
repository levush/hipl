FROM ubuntu:14.04
MAINTAINER hipl-dev <hipl-dev@freelists.org>

RUN apt-get update

RUN apt-get install -y autoconf automake libtool make gcc libssl-dev \
                       libnet-ip-perl libnet-dns-perl bzr \
                       libnetfilter-queue-dev xmlto doxygen \
                       check libconfig8-dev fakeroot dpkg-dev debhelper \
                       devscripts w3m openssh-client wget \
                       libnfnetlink-dev rsync
ADD docker-run.sh /tmp/
ADD hipl-*.tar.gz /tmp/

ENTRYPOINT ["/tmp/docker-run.sh"]
