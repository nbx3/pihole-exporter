import std/[unittest, json, strutils]
import ../src/pihole_exporter/[metrics, collector]

suite "collectSummary":
  test "full summary data":
    var b = newMetricsBuilder()
    let data = parseJson("""
    {
      "queries": {
        "total": 12345,
        "blocked": 1000,
        "percent_blocked": 8.1,
        "unique_domains": 500,
        "forwarded": 9000,
        "cached": 2345,
        "frequency": 1.5
      },
      "clients": {"total": 50, "active": 20},
      "gravity_size": 100000
    }
    """)
    b.collectSummary(data)
    let output = b.output()
    check "pihole_dns_queries_total 12345" in output
    check "pihole_ads_blocked_total 1000" in output
    check "pihole_ads_percentage 8.1" in output
    check "pihole_unique_domains 500" in output
    check "pihole_queries_forwarded 9000" in output
    check "pihole_queries_cached 2345" in output
    check "pihole_clients_ever_seen 50" in output
    check "pihole_unique_clients 20" in output
    check "pihole_domains_blocked 100000" in output

  test "with query types and reply types":
    var b = newMetricsBuilder()
    let data = parseJson("""
    {
      "queries": {"total": 100, "blocked": 10, "percent_blocked": 10.0,
                  "unique_domains": 50, "forwarded": 80, "cached": 10, "frequency": 0.5},
      "clients": {"total": 5, "active": 3},
      "gravity_size": 1000,
      "query_types": {"A": 60, "AAAA": 40},
      "reply_types": {"NODATA": 5, "NXDOMAIN": 2}
    }
    """)
    b.collectSummary(data)
    let output = b.output()
    check "pihole_query_type{type=\"A\"} 60" in output
    check "pihole_query_type{type=\"AAAA\"} 40" in output
    check "pihole_reply_type{type=\"NODATA\"} 5" in output
    check "pihole_reply_type{type=\"NXDOMAIN\"} 2" in output

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectSummary(newJNull())
    check b.output() == ""

suite "collectBlocking":
  test "blocking enabled":
    var b = newMetricsBuilder()
    b.collectBlocking(parseJson("""{"blocking": "enabled"}"""))
    check "pihole_blocking_enabled 1" in b.output()

  test "blocking disabled":
    var b = newMetricsBuilder()
    b.collectBlocking(parseJson("""{"blocking": "disabled"}"""))
    check "pihole_blocking_enabled 0" in b.output()

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectBlocking(newJNull())
    check b.output() == ""

suite "collectTopDomains":
  test "permitted and blocked domains":
    var b = newMetricsBuilder()
    let permitted = parseJson("""
    {"domains": [{"domain": "google.com", "count": 500},
                 {"domain": "github.com", "count": 200}]}
    """)
    let blocked = parseJson("""
    {"domains": [{"domain": "ads.example.com", "count": 100}]}
    """)
    b.collectTopDomains(permitted, blocked)
    let output = b.output()
    check "pihole_top_queries{domain=\"google.com\"} 500" in output
    check "pihole_top_queries{domain=\"github.com\"} 200" in output
    check "pihole_top_ads{domain=\"ads.example.com\"} 100" in output

  test "skips entries with empty domain":
    var b = newMetricsBuilder()
    let data = parseJson("""{"domains": [{"domain": "", "count": 10}]}""")
    b.collectTopDomains(data, newJNull())
    check "pihole_top_queries" notin b.output()

  test "both JNull produces no output":
    var b = newMetricsBuilder()
    b.collectTopDomains(newJNull(), newJNull())
    check b.output() == ""

suite "collectUpstreams":
  test "response time converted to seconds":
    var b = newMetricsBuilder()
    let data = parseJson("""
    {"upstreams": [{"ip": "1.1.1.1", "name": "cloudflare",
                    "count": 5000, "response_time": 25.5}]}
    """)
    b.collectUpstreams(data)
    let output = b.output()
    check "pihole_upstream_queries{upstream=\"1.1.1.1\",name=\"cloudflare\"} 5000" in output
    check "pihole_upstream_response_time_seconds{upstream=\"1.1.1.1\",name=\"cloudflare\"} 0.0255" in output

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectUpstreams(newJNull())
    check b.output() == ""

suite "collectVersion":
  test "version fields":
    var b = newMetricsBuilder()
    let data = parseJson("""{"version": "6.0", "web": "6.0", "core": "6.0"}""")
    b.collectVersion(data)
    check "pihole_version_info{ftl=\"6.0\",web=\"6.0\",core=\"6.0\"} 1" in b.output()

  test "fallback to ftl field":
    var b = newMetricsBuilder()
    let data = parseJson("""{"ftl": "5.25", "web": "5.21", "core": "5.18"}""")
    b.collectVersion(data)
    check "ftl=\"5.25\"" in b.output()

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectVersion(newJNull())
    check b.output() == ""

suite "collectSystem":
  test "memory percentage calculation":
    var b = newMetricsBuilder()
    let system = parseJson("""
    {"uptime": 86400,
     "memory": {"ram": {"used": 512, "total": 1024}},
     "cpu": {"percent_used": 15.5}}
    """)
    b.collectSystem(system, newJNull())
    let output = b.output()
    check "pihole_system_uptime_seconds 86400" in output
    check "pihole_system_memory_usage_percent 50" in output
    check "pihole_system_cpu_usage_percent 15.5" in output

  test "sensor temperature from sensors array":
    var b = newMetricsBuilder()
    let sensors = parseJson("""{"sensors": [{"value": 45.5}]}""")
    b.collectSystem(newJNull(), sensors)
    check "pihole_system_temperature_celsius 45.5" in b.output()

  test "sensor temperature from cpu_temp fallback":
    var b = newMetricsBuilder()
    let sensors = parseJson("""{"cpu_temp": 42.0}""")
    b.collectSystem(newJNull(), sensors)
    check "pihole_system_temperature_celsius 42" in b.output()

  test "both JNull produces no output":
    var b = newMetricsBuilder()
    b.collectSystem(newJNull(), newJNull())
    check b.output() == ""

suite "collectDatabase":
  test "with database sub-object":
    var b = newMetricsBuilder()
    let data = parseJson("""{"database": {"size": 4096000, "queries": 50000}}""")
    b.collectDatabase(data)
    let output = b.output()
    check "pihole_database_size_bytes 4096000" in output
    check "pihole_database_queries 50000" in output

  test "with direct fields (no database sub-object)":
    var b = newMetricsBuilder()
    let data = parseJson("""{"size": 2048000, "queries": 25000}""")
    b.collectDatabase(data)
    let output = b.output()
    check "pihole_database_size_bytes 2048000" in output
    check "pihole_database_queries 25000" in output

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectDatabase(newJNull())
    check b.output() == ""

suite "collectCounts":
  test "all count sources":
    var b = newMetricsBuilder()
    let groups = parseJson("""{"groups": [{"name": "default"}, {"name": "custom"}]}""")
    let lists = parseJson("""{"lists": [{"url": "a"}, {"url": "b"}, {"url": "c"}]}""")
    let allow = parseJson("""{"domains": [{"domain": "ok.com"}]}""")
    let deny = parseJson("""{"domains": [{"domain": "bad.com"}, {"domain": "worse.com"}]}""")
    b.collectCounts(groups, lists, allow, deny)
    let output = b.output()
    check "pihole_groups_total 2" in output
    check "pihole_gravity_lists_total 3" in output
    check "pihole_domains_allow_total 1" in output
    check "pihole_domains_deny_total 2" in output

  test "all JNull produces no output":
    var b = newMetricsBuilder()
    b.collectCounts(newJNull(), newJNull(), newJNull(), newJNull())
    check b.output() == ""

suite "collectMessages":
  test "message count":
    var b = newMetricsBuilder()
    b.collectMessages(parseJson("""{"count": 3}"""))
    check "pihole_messages_total 3" in b.output()

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectMessages(newJNull())
    check b.output() == ""

suite "collectFtl":
  test "FTL info with database stats":
    var b = newMetricsBuilder()
    let data = parseJson("""
    {"pid": 1234,
     "database": {"gravity": 100000, "groups": 5,
                  "lists": 10, "clients": 25, "domains": 50}}
    """)
    b.collectFtl(data)
    let output = b.output()
    check "pihole_ftl_pid 1234" in output
    check "pihole_ftl_database_gravity 100000" in output
    check "pihole_ftl_database_groups 5" in output
    check "pihole_ftl_database_lists 10" in output
    check "pihole_ftl_database_clients 25" in output
    check "pihole_ftl_database_domains 50" in output

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectFtl(newJNull())
    check b.output() == ""

suite "collectDhcp":
  test "lease count and details":
    var b = newMetricsBuilder()
    let data = parseJson("""
    {"leases": [
      {"ip": "192.168.1.10", "hwaddr": "aa:bb:cc:dd:ee:ff",
       "name": "laptop", "expires": 1700000000}
    ]}
    """)
    b.collectDhcp(data)
    let output = b.output()
    check "pihole_dhcp_leases_total 1" in output
    check "pihole_dhcp_lease{ip=\"192.168.1.10\",mac=\"aa:bb:cc:dd:ee:ff\",hostname=\"laptop\"" in output

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectDhcp(newJNull())
    check b.output() == ""

suite "collectNetwork":
  test "device count":
    var b = newMetricsBuilder()
    let data = parseJson("""{"devices": [{}, {}, {}]}""")
    b.collectNetwork(data)
    check "pihole_network_devices_total 3" in b.output()

  test "JNull produces no output":
    var b = newMetricsBuilder()
    b.collectNetwork(newJNull())
    check b.output() == ""

suite "collectTopClients":
  test "clients and blocked clients":
    var b = newMetricsBuilder()
    let clients = parseJson("""
    {"clients": [{"ip": "192.168.1.5", "name": "desktop", "count": 300}]}
    """)
    let blocked = parseJson("""
    {"clients": [{"ip": "192.168.1.10", "name": "phone", "count": 50}]}
    """)
    b.collectTopClients(clients, blocked)
    let output = b.output()
    check "pihole_top_sources{client=\"192.168.1.5\",name=\"desktop\"} 300" in output
    check "pihole_top_sources_blocked{client=\"192.168.1.10\",name=\"phone\"} 50" in output

  test "both JNull produces no output":
    var b = newMetricsBuilder()
    b.collectTopClients(newJNull(), newJNull())
    check b.output() == ""
