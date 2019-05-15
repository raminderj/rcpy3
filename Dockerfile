#
# Just runs tests
#

FROM python:3

RUN apt-get update -y && apt-get install -y \
	libldap2-dev \
	libssl-dev \
    openssh-client \
	libffi-dev \
	libsasl2-dev \
	gcc \
	sudo

WORKDIR /app

ADD . /app

RUN pip install . && pip install unittest2

RUN mkdir /tmp/defaulthome && mkdir /tmp/ncfhome && groupadd -g 9999 testmkhomedir && useradd -M -p 12345 -d /tmp/defaulthome/howdydoody howdydoody

ENV DEFAULT_HOME_ROOT=/tmp/defaulthome NCF_HOME_ROOT=/tmp/ncfhome

CMD ["nosetests", "-vv"]
