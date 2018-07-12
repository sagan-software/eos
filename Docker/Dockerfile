FROM eosio/eos-dev as dev

FROM ubuntu:18.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=dev /usr/local/lib/* /usr/local/lib/
COPY --from=dev /usr/local/bin/nodeos /usr/local/bin
COPY --from=dev /usr/local/bin/keosd /usr/local/bin
COPY --from=dev /usr/local/bin/cleos /usr/local/bin

ENV DATA_DIR /eos/build/data-dir
ENV CONFIG_DIR /eos/build/data-dir
RUN mkdir -p $DATA_DIR $CONFIG_DIR

COPY --from=dev /eos/build/data-dir/config.ini $CONFIG_DIR
COPY --from=dev /entrypoint.sh /
RUN chmod +x /entrypoint.sh

EXPOSE 8888
EXPOSE 9876

ENV LD_LIBRARY_PATH /usr/local/lib

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--data-dir", "$DATA_DIR", "--config-dir", "$CONFIG_DIR", "--enable-stale-production"]
