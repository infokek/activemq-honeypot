FROM rust:1.74.1-slim-bookworm

ENV TZ Europe/Moscow

WORKDIR /service

COPY ./ /service
RUN apt-get update && apt-get install pkg-config libssl-dev libudev-dev -y
RUN cargo build --release

VOLUME ["/service/logs/"]

ENTRYPOINT ["cargo", "run", "--release"]