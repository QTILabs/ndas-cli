#!/usr/bin/env bash

cargo clean --release && cd ndas-kernel && \
    make clean && make && cd .. && \
    cp ndas-kernel/xdp-dumper/xdp-dumper-kern.o ./ && \
    cp ndas-kernel/xdp-dumper/xdp-dumper-user ./ && \
    sudo ar rcs /usr/local/lib/libndaskernel-hook.a ndas-kernel/xdp-dumper/xdp-dumper.o && \
    sudo ar rcs /usr/local/lib/libpcapng.a ndas-kernel/xdp-dumper/pcapng.o && \
    cargo build --release && strip target/release/ndas-cli && cp target/release/ndas-cli ./ && \
    cd ndas-kernel && make clean && cd -
