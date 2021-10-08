FROM rust:1.55.0-buster AS builder
WORKDIR app

RUN rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools musl-dev

COPY . .

#RUN cargo build --target x86_64-unknown-linux-musl --release 
RUN cargo build --release
####################################################################################################
## Final image
####################################################################################################
#FROM alpine:20210212
FROM debian:buster-slim as runtime
#RUN apk add iptables
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    iptables \
    procps \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
WORKDIR app
# Copy our build
#COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/linkerd-tproxy-poc /usr/local/bin/linkerd-tproxy-poc
COPY --from=builder /app/target/release/linkerd-tproxy-poc /usr/local/bin/linkerd-tproxy-poc
ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/linkerd-tproxy-poc"]
