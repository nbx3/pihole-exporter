FROM nimlang/nim:2.2.6-alpine-regular AS build

WORKDIR /app
COPY src/ src/
COPY tests/ tests/

# Run tests
RUN nim c -r tests/test_metrics.nim
RUN nim c -r -d:ssl tests/test_collector.nim

ARG VERSION=dev

# Build release binary
RUN nim c \
    -d:Version=$VERSION \
    -d:release \
    -d:ssl \
    --opt:size \
    --threads:on \
    -o:/app/pihole_exporter \
    src/pihole_exporter.nim

FROM alpine:3.21

RUN apk add --no-cache libssl3 libcrypto3 ca-certificates

COPY --from=build /app/pihole_exporter /usr/local/bin/pihole_exporter

EXPOSE 9617

ENTRYPOINT ["/usr/local/bin/pihole_exporter"]
