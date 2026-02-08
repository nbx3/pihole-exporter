FROM nimlang/nim:2.2.4-alpine AS build

WORKDIR /app
COPY src/ src/

RUN nim c \
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
