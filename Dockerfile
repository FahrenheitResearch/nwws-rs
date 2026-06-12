# Static musl build; the final image is the bare binary on scratch (~10 MB).
# rustls + webpki-roots means no OpenSSL and no CA-certificates package needed.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY tests ./tests
COPY README.md ./
RUN cargo build --release --bin nwws --features serve

FROM scratch
COPY --from=build /src/target/release/nwws /nwws
# Archive lives here; mount a volume to persist it.
VOLUME ["/archive"]
EXPOSE 8080
ENTRYPOINT ["/nwws"]
# Credentials come from the environment:
#   docker run -e NWWS_USERNAME=... -e NWWS_PASSWORD=... -v nwws-archive:/archive -p 8080:8080 nwws-rs
CMD ["serve", "/archive", "--bind", "0.0.0.0:8080"]
