#!/usr/bin/env bash

cd ndas-kernel && make clean && make && cd .. && \
    cp ndas-kernel/xdp-dumper/xdp-dumper-kern.o ./ && \
    sudo ar rcs /usr/local/lib/libndaskernel-hook.a ndas-kernel/xdp-dumper/xdp-dumper.o && \
    sudo ar rcs /usr/local/lib/libpcapng.a ndas-kernel/xdp-dumper/pcapng.o && \
    cargo build --release && cp target/release/ndas-cli ./ && 
    clear && sudo ./ndas-cli
