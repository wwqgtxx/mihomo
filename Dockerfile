FROM --platform=${BUILDPLATFORM} golang:alpine as builder

RUN apk add --no-cache make git ca-certificates tzdata && \
    wget -O /Country.mmdb https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb
WORKDIR /workdir
COPY --from=tonistiigi/xx:golang / /
ARG TARGETOS TARGETARCH TARGETVARIANT

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    make BINDIR= ${TARGETOS}-${TARGETARCH}${TARGETVARIANT} && \
    mv /mihomo* /mihomo

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/metacubex/mihomo"

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /Country.mmdb /root/.config/mihomo/
COPY --from=builder /mihomo /
ENTRYPOINT ["/mihomo"]
