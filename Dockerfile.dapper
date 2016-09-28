FROM ubuntu:16.04
# FROM arm=armhf/ubuntu:16.04

ARG DAPPER_HOST_ARCH
ENV HOST_ARCH=${DAPPER_HOST_ARCH} ARCH=${DAPPER_HOST_ARCH}

RUN apt-get update && apt-get install -y pkg-config

RUN apt-get update && \
    apt-get install -y gcc make ca-certificates git wget curl vim less file && \
    rm -f /bin/sh && ln -s /bin/bash /bin/sh

ENV GOLANG_ARCH_amd64=amd64 GOLANG_ARCH_arm=armv6l GOLANG_ARCH=GOLANG_ARCH_${ARCH} \
    GOPATH=/go PATH=/go/bin:/usr/local/go/bin:${PATH} SHELL=/bin/bash

RUN wget -O - https://storage.googleapis.com/golang/go1.7.1.linux-${!GOLANG_ARCH}.tar.gz | tar -xzf - -C /usr/local && \
    go get github.com/rancher/trash && go get github.com/golang/lint/golint

ENV DOCKER_URL_amd64=https://get.docker.com/builds/Linux/x86_64/docker-1.10.3 \
    DOCKER_URL_arm=https://github.com/rancher/docker/releases/download/v1.10.3-ros1/docker-1.10.3_arm \
    DOCKER_URL=DOCKER_URL_${ARCH}

RUN wget -O - ${!DOCKER_URL} > /usr/bin/docker && chmod +x /usr/bin/docker


RUN curl -sL ftp://xmlsoft.org/libxml2/libxml2-2.9.4.tar.gz | tar -xzf - && \
  cd /libxml2-2.9.4 && \
  ./configure \
    --enable-static \
    --disable-shared \
    --without-gnu-ld \
    --with-c14n \
    --without-catalog \
    --without-debug \
    --without-docbook \
    --without-fexceptions \
    --without-ftp \
    --without-history \
    --without-html \
    --without-http \
    --without-iconv	\
    --without-icu \
    --without-iso8859x \
    --without-legacy \
    --without-mem-debug \
    --without-minimum \
    --with-output \
    --without-pattern \
    --with-push \
    --without-python	\
    --without-reader \
    --without-readline \
    --without-regexps \
    --without-run-debug \
    --with-sax1 \
    --without-schemas \
    --without-schematron \
    --without-threads \
    --without-thread-alloc \
    --with-tree \
    --without-valid \
    --without-writer \
    --without-xinclude \
    --without-xpath \
    --with-xptr \
    --without-modules \
    --without-zlib \
    --without-lzma \
    --without-coverage && \
    make install

RUN \
  curl -f -sL https://www.openssl.org/source/openssl-1.0.2j.tar.gz | tar -xzf - && \
  cd openssl-1.0.2j && \
  ./config \
    no-shared \
    no-weak-ssl-ciphers \
    no-ssl2 \
    no-ssl3 \
    no-comp \
    no-idea \
    no-dtls \
    no-hw \
    no-threads \
    no-dso && \
  make depend install

RUN curl -f -sL https://www.aleksey.com/xmlsec/download/xmlsec1-1.2.22.tar.gz | tar -xzf - && \
	cd xmlsec1-1.2.22 && \
	./configure \
		--enable-static \
		--disable-shared \
		--disable-crypto-dl \
		--disable-apps-crypto-dl \
		--enable-static-linking \
		--without-gnu-ld \
		--with-default-crypto=openssl \
		--with-openssl=/usr/local/ssl \
		--with-libxml=/usr/local \
		--without-nss \
		--without-nspr \
		--without-gcrypt \
		--without-gnutls \
		--without-libxslt && \
	make -C src install && \
	make -C include install && \
	make install-pkgconfigDATA



ENV DAPPER_SOURCE /go/src/github.com/rancher/rancher-auth-service/
ENV DAPPER_OUTPUT ./bin ./dist
ENV DAPPER_DOCKER_SOCKET true
ENV TRASH_CACHE ${DAPPER_SOURCE}/.trash-cache
ENV HOME ${DAPPER_SOURCE}
WORKDIR ${DAPPER_SOURCE}

ENTRYPOINT ["./scripts/entry"]
CMD ["ci"]
