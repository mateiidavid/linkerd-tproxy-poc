ARG RUST_IMAGE=rust:1.55.0

FROM $RUST_IMAGE as build
ARG TARGETARCH
WORKDIR /usr/src/echo-server
COPY . .
RUN --mount=type=cache,target=target \
    --mount=type=cache,from=rust:1.55.0,source=/usr/local/cargo,target=/usr/local/cargo \
    target=$(rustup show | sed -n 's/^Default host: \(.*\)/\1/p' | sed 's/-gnu$/-musl/') ; \
    rustup target add ${target} && \
    cargo build --locked --release --target=$target && \
    mv target/${target}/release/echo-server /tmp

FROM scratch
COPY --from=build /tmp/echo-server /echo-server
ENTRYPOINT ["/echo-server"]
