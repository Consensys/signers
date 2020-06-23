FROM alpine:3.8

ENV SOFTHSM2_VERSION=2.5.0 \
    SOFTHSM2_SOURCES=/tmp/softhsm2

# install build dependencies
RUN apk --update add \
        alpine-sdk \
        autoconf \
        automake \
        git \
        libtool \
        openssl-dev

# build and install SoftHSM2
RUN git clone https://github.com/opendnssec/SoftHSMv2.git ${SOFTHSM2_SOURCES}
WORKDIR ${SOFTHSM2_SOURCES}

RUN git checkout ${SOFTHSM2_VERSION} -b ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install

WORKDIR /root
RUN rm -fr ${SOFTHSM2_SOURCES}

# install pkcs11-tool
RUN apk --update add opensc

# initialize a HSM slot
RUN softhsm2-util --init-token --slot 0 --label WALLET-000 --pin us3rs3cur3 --so-pin sup3rs3cur3
RUN softhsm2-util --init-token --slot 1 --label WALLET-001 --pin us3rs3cur3 --so-pin sup3rs3cur3
RUN softhsm2-util --init-token --slot 2 --label WALLET-002 --pin us3rs3cur3 --so-pin sup3rs3cur3
RUN softhsm2-util --init-token --slot 3 --label WALLET-003 --pin us3rs3cur3 --so-pin sup3rs3cur3