# Pi-hole Exporter

A comprehensive Prometheus exporter for **Pi-hole v6**, written in Nim with zero external dependencies.

Queries 19 Pi-hole API endpoints concurrently to expose ~40 metrics — covering everything from core DNS stats to DHCP leases, network devices, system health, and database info. Authenticates once per scrape to avoid rate limiting.

## Architecture

This exporter covers **Pi-hole application metrics only** — DNS query stats, blocking status, top domains/clients, upstream performance, DHCP leases, gravity lists, FTL internals, etc.

It does **not** replace system-level monitoring. For host metrics (CPU, memory, disk, network interfaces), run [node_exporter](https://github.com/prometheus/node_exporter) on the Pi-hole host.

A typical setup with [vmagent](https://docs.victoriametrics.com/vmagent/) (or Prometheus) scraping both:

```
┌─────────────────────────────────────────┐
│  Pi-hole host                           │
│                                         │
│  ┌──────────────────┐  ┌─────────────┐  │
│  │ pihole-exporter  │  │node_exporter│  │
│  │ :9617/metrics    │  │:9100/metrics│  │
│  └────────┬─────────┘  └──────┬──────┘  │
│           │                   │         │
└───────────┼───────────────────┼─────────┘
            │                   │
       ┌────▼───────────────────▼────┐
       │  vmagent / prometheus       │
       │  (scrape both targets)      │
       └─────────────────────────────┘
```

## Metrics

| Category | Source Endpoint | Metrics |
|----------|----------------|---------|
| **Core stats** | `/api/stats/summary` | `pihole_dns_queries_total`, `pihole_ads_blocked_total`, `pihole_ads_percentage`, `pihole_unique_domains`, `pihole_queries_forwarded`, `pihole_queries_cached`, `pihole_clients_ever_seen`, `pihole_unique_clients`, `pihole_domains_blocked`, `pihole_query_frequency`, `pihole_query_type{type}`, `pihole_reply_type{type}` |
| **Blocking** | `/api/dns/blocking` | `pihole_blocking_enabled` |
| **Top domains** | `/api/stats/top_domains` | `pihole_top_queries{domain}`, `pihole_top_ads{domain}` |
| **Top clients** | `/api/stats/top_clients` | `pihole_top_sources{client,name}`, `pihole_top_sources_blocked{client,name}` |
| **Upstreams** | `/api/stats/upstreams` | `pihole_upstream_queries{upstream,name}`, `pihole_upstream_response_time_seconds{upstream,name}` |
| **DHCP** | `/api/dhcp/leases` | `pihole_dhcp_leases_total`, `pihole_dhcp_lease{ip,mac,hostname,expires}` |
| **Network** | `/api/network/devices` | `pihole_network_devices_total` |
| **Version** | `/api/info/version` | `pihole_version_info{ftl,web,core}` |
| **System** | `/api/info/system`, `/api/info/sensors` | `pihole_system_uptime_seconds`, `pihole_system_memory_usage_percent`, `pihole_system_cpu_usage_percent`, `pihole_system_temperature_celsius` |
| **Database** | `/api/info/database` | `pihole_database_size_bytes`, `pihole_database_queries` |
| **FTL** | `/api/info/ftl` | `pihole_ftl_pid`, `pihole_ftl_database_gravity`, `pihole_ftl_database_groups`, `pihole_ftl_database_lists`, `pihole_ftl_database_clients`, `pihole_ftl_database_domains` |
| **Management** | `/api/groups`, `/api/lists`, `/api/domains/*` | `pihole_groups_total`, `pihole_gravity_lists_total`, `pihole_domains_allow_total`, `pihole_domains_deny_total` |
| **Messages** | `/api/info/messages/count` | `pihole_messages_total` |
| **Exporter** | — | `pihole_exporter_scrape_duration_seconds`, `pihole_exporter_scrape_success` |

## Quick Start

### Docker

```yaml
services:
  pihole-exporter:
    image: ghcr.io/nbx3/pihole-exporter:latest
    environment:
      PIHOLE_URL: https://pihole.local
      PIHOLE_PASSWORD: your-password
      SKIP_TLS_VERIFY: "true"
    ports:
      - "9617:9617"
```

### Binary

```sh
PIHOLE_URL=https://pihole.local \
PIHOLE_PASSWORD=your-password \
SKIP_TLS_VERIFY=true \
./pihole_exporter
```

Then scrape `http://localhost:9617/metrics` with Prometheus.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PIHOLE_URL` | `http://localhost` | Pi-hole base URL (no trailing slash) |
| `PIHOLE_PASSWORD` | *(required)* | Pi-hole web password |
| `PIHOLE_PORT` | `443` or `80` | Pi-hole port (defaults to `443` for HTTPS URLs, `80` for HTTP; appended if no port present) |
| `EXPORTER_PORT` | `9617` | Metrics server listen port |
| `SKIP_TLS_VERIFY` | `false` | Skip TLS certificate verification |
| `LOG_LEVEL` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`, `NONE` |

## Endpoints

| Path | Description |
|------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | Health check (returns `200 OK`) |
| `/` | Landing page with link to metrics |

## Building

Requires [Nim](https://nim-lang.org/) >= 2.0.

```sh
# Without SSL (for plain HTTP Pi-hole setups)
nim c -d:release --opt:size -o:pihole_exporter src/pihole_exporter.nim

# With SSL (required if Pi-hole uses HTTPS)
nim c -d:release -d:ssl --opt:size -o:pihole_exporter src/pihole_exporter.nim
```

### Docker

```sh
docker build -t pihole-exporter .
```

The Dockerfile runs all unit tests first, then produces a minimal Alpine image with SSL support. If any test fails, the build is aborted.

### Testing

Tests are in `tests/` and run automatically during `docker build`. They can also be run directly with Nim:

```sh
nim c -r tests/test_metrics.nim
nim c -r -d:ssl tests/test_collector.nim
```

- **test_metrics** — Prometheus text format rendering: label escaping, value formatting, metric declaration
- **test_collector** — All collector procs against JSON fixtures, including JNull safety

### CI/CD

A GitHub Actions workflow (`.github/workflows/docker.yml`) automatically builds and pushes multi-arch Docker images (`linux/amd64` and `linux/arm64`) to GHCR on every push to `main` or version tag (`v*`).

Tag a release to publish versioned images:

```sh
git tag v1.0.0
git push origin v1.0.0
# produces: ghcr.io/nbx3/pihole-exporter:1.0.0, :1.0, :1, :latest
```

## Prometheus Config

```yaml
scrape_configs:
  - job_name: pihole
    static_configs:
      - targets: ["pihole-exporter:9617"]
```

## Grafana

These metrics are compatible with existing Pi-hole Grafana dashboards. For full coverage of the additional metrics (DHCP, network, system, database), you'll want to extend your dashboard or build a new one.

## License

MIT
