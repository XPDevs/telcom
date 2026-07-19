# syntax=docker/dockerfile:1
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y -qq \
    clang-14 llvm-14 \
    libbpf-dev libelf-dev \
    linux-headers-generic \
    make \
  && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 \
  && update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-14 100

WORKDIR /src
COPY . .

RUN make version && \
    make build_bpf build_tc build_daemon build_tools && \
    make package

FROM scratch AS export
COPY --from=builder /src/bin/telcomd      /telcomd
COPY --from=builder /src/bin/telcom-peek  /telcom-peek
COPY --from=builder /src/bpf/*.bpf.o      /
COPY --from=builder /src/telcom_*.deb     /
