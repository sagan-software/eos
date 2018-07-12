FROM ubuntu:18.04

ARG fork=EOSIO
ARG branch=master
ARG symbol=SYS
RUN echo "args: fork=$fork branch=$branch symbol=$symbol"

RUN apt-get update \
    && apt-get install -y git sudo

RUN git clone -b $branch https://github.com/$fork/eos.git

WORKDIR /eos

RUN git submodule update --init --recursive

RUN echo 1 | ./eosio_build.sh -s $symbol

RUN cmake --build /eos/build --target install

ENV DATA_DIR /eos/build/data-dir
ENV CONFIG_DIR /eos/build/data-dir

RUN mkdir -p $DATA_DIR $CONFIG_DIR

COPY ./config.ini $CONFIG_DIR

COPY ./entrypoint.sh /
RUN chmod +x /entrypoint.sh

EXPOSE 8888
EXPOSE 9876

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--data-dir", "$DATA_DIR", "--config-dir", "$CONFIG_DIR", "--enable-stale-production"]
