FROM nimlang/nim:2.2.6-alpine-regular AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /src
COPY src/ src/

RUN nim c -d:release -d:ssl --opt:size --passL:"-static" \
    -o:/src/pihole_exporter src/pihole_exporter.nim && \
    strip pihole_exporter

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
COPY --from=builder /src/pihole_exporter /usr/local/bin/pihole_exporter

EXPOSE 9617

ENTRYPOINT ["/usr/local/bin/pihole_exporter"]
