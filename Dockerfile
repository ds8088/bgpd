FROM --platform=$BUILDPLATFORM alpine:3.23 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache zig

WORKDIR /opt/build

COPY . .

RUN ZIGARCH=$([ "$TARGETARCH" = "amd64" ] && echo "x86_64" || echo "aarch64") && \
    zig build -Dtarget="${ZIGARCH}-${TARGETOS}-musl" -Drelease=true

FROM scratch

COPY --from=builder /opt/build/zig-out/bin/bgpd /opt/bgpd

WORKDIR /data
VOLUME /data

ENTRYPOINT ["/opt/bgpd"]
