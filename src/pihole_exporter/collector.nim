## Fetches all Pi-hole v6 API endpoints and builds Prometheus metrics output.

import std/[asyncdispatch, json, strutils, strformat, times, logging]
import client, metrics

proc safeGet(c: PiholeClient, path: string): Future[JsonNode] {.async.} =
  ## GET that returns JNull on failure instead of raising.
  try:
    result = await c.get(path)
  except:
    warn(&"Failed to fetch {path}: {getCurrentExceptionMsg()}")
    result = newJNull()

proc collectSummary(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let q = data.getOrDefault("queries")
  if q != nil and q.kind == JObject:
    b.addGauge("pihole_dns_queries_total", "Total DNS queries",
      q{"total"}.getFloat())
    b.addGauge("pihole_ads_blocked_total", "Total ads blocked",
      q{"blocked"}.getFloat())
    b.addGauge("pihole_ads_percentage", "Percentage of queries blocked",
      q{"percent_blocked"}.getFloat())
    b.addGauge("pihole_unique_domains", "Unique domains queried",
      q{"unique_domains"}.getFloat())
    b.addGauge("pihole_queries_forwarded", "Queries forwarded to upstream",
      q{"forwarded"}.getFloat())
    b.addGauge("pihole_queries_cached", "Queries answered from cache",
      q{"cached"}.getFloat())
    b.addGauge("pihole_query_frequency", "DNS queries per second",
      q{"frequency"}.getFloat())

  let clients = data.getOrDefault("clients")
  if clients != nil and clients.kind == JObject:
    b.addGauge("pihole_clients_ever_seen", "Total clients ever seen",
      clients{"total"}.getFloat())
    b.addGauge("pihole_unique_clients", "Unique active clients",
      clients{"active"}.getFloat())

  b.addGauge("pihole_domains_blocked", "Domains on blocklist (gravity)",
    data{"gravity_size"}.getFloat())

  # Query types
  let queryTypes = data.getOrDefault("query_types")
  if queryTypes != nil and queryTypes.kind == JObject:
    for key, val in queryTypes:
      b.addGauge("pihole_query_type", "Query count by type", val.getFloat(),
        {"type": key})

  # Reply types
  let replyTypes = data.getOrDefault("reply_types")
  if replyTypes != nil and replyTypes.kind == JObject:
    for key, val in replyTypes:
      b.addGauge("pihole_reply_type", "Reply count by type", val.getFloat(),
        {"type": key})

proc collectBlocking(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let enabled = data{"blocking"}.getStr("") == "enabled"
  b.addGauge("pihole_blocking_enabled", "Whether blocking is enabled (1=yes, 0=no)",
    if enabled: 1.0 else: 0.0)

proc collectTopDomains(b: var MetricsBuilder, permitted, blocked: JsonNode) =
  if permitted.kind != JNull:
    let domains = permitted.getOrDefault("domains")
    if domains != nil and domains.kind == JArray:
      for item in domains:
        let domain = item{"domain"}.getStr("")
        let count = item{"count"}.getFloat()
        if domain != "":
          b.addGauge("pihole_top_queries", "Top permitted domain query count",
            count, {"domain": domain})

  if blocked.kind != JNull:
    let domains = blocked.getOrDefault("domains")
    if domains != nil and domains.kind == JArray:
      for item in domains:
        let domain = item{"domain"}.getStr("")
        let count = item{"count"}.getFloat()
        if domain != "":
          b.addGauge("pihole_top_ads", "Top blocked domain count",
            count, {"domain": domain})

proc collectTopClients(b: var MetricsBuilder, clients, blockedClients: JsonNode) =
  if clients.kind != JNull:
    let arr = clients.getOrDefault("clients")
    if arr != nil and arr.kind == JArray:
      for item in arr:
        let ip = item{"ip"}.getStr("")
        let name = item{"name"}.getStr("")
        let count = item{"count"}.getFloat()
        if ip != "":
          b.addGauge("pihole_top_sources", "Top client query count",
            count, {"client": ip, "name": name})

  if blockedClients.kind != JNull:
    let arr = blockedClients.getOrDefault("clients")
    if arr != nil and arr.kind == JArray:
      for item in arr:
        let ip = item{"ip"}.getStr("")
        let name = item{"name"}.getStr("")
        let count = item{"count"}.getFloat()
        if ip != "":
          b.addGauge("pihole_top_sources_blocked", "Top blocked client count",
            count, {"client": ip, "name": name})

proc collectUpstreams(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let upstreams = data.getOrDefault("upstreams")
  if upstreams != nil and upstreams.kind == JArray:
    for item in upstreams:
      let ip = item{"ip"}.getStr("")
      let name = item{"name"}.getStr("")
      let count = item{"count"}.getFloat()
      let responseTime = item{"response_time"}.getFloat()
      if ip != "":
        b.addGauge("pihole_upstream_queries",
          "Queries sent to upstream", count,
          {"upstream": ip, "name": name})
        b.addGauge("pihole_upstream_response_time_seconds",
          "Upstream avg response time", responseTime / 1000.0,
          {"upstream": ip, "name": name})

proc collectDhcp(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let leases = data.getOrDefault("leases")
  if leases != nil and leases.kind == JArray:
    b.addGauge("pihole_dhcp_leases_total", "Number of active DHCP leases",
      leases.len.float)
    for item in leases:
      let ip = item{"ip"}.getStr("")
      let mac = item{"hwaddr"}.getStr("")
      let hostname = item{"name"}.getStr("")
      let expires = $item{"expires"}.getFloat().int64
      b.addGauge("pihole_dhcp_lease", "DHCP lease info (value=1)", 1.0,
        {"ip": ip, "mac": mac, "hostname": hostname, "expires": expires})

proc collectNetwork(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let devices = data.getOrDefault("devices")
  if devices != nil and devices.kind == JArray:
    b.addGauge("pihole_network_devices_total", "Discovered network devices",
      devices.len.float)

proc collectVersion(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let ftl = data{"version"}.getStr(data{"ftl"}.getStr(""))
  let web = data{"web"}.getStr("")
  let core = data{"core"}.getStr("")
  b.addGauge("pihole_version_info", "Version info (value=1)", 1.0,
    {"ftl": ftl, "web": web, "core": core})

proc collectSystem(b: var MetricsBuilder, system, sensors: JsonNode) =
  if system.kind != JNull:
    b.addGauge("pihole_system_uptime_seconds", "System uptime in seconds",
      system{"uptime"}.getFloat())

    let mem = system.getOrDefault("memory")
    if mem != nil and mem.kind == JObject:
      let used = mem{"ram"}.getOrDefault("used")
      let total = mem{"ram"}.getOrDefault("total")
      if used != nil and total != nil and total.getFloat() > 0:
        b.addGauge("pihole_system_memory_usage_percent", "Memory usage percentage",
          used.getFloat() / total.getFloat() * 100.0)

    let cpu = system.getOrDefault("cpu")
    if cpu != nil and cpu.kind == JObject:
      b.addGauge("pihole_system_cpu_usage_percent", "CPU usage percentage",
        cpu{"percent_used"}.getFloat())

  if sensors.kind != JNull:
    let temps = sensors.getOrDefault("sensors")
    if temps != nil and temps.kind == JArray and temps.len > 0:
      b.addGauge("pihole_system_temperature_celsius", "CPU temperature",
        temps[0]{"value"}.getFloat())
    elif sensors.getOrDefault("cpu_temp") != nil:
      b.addGauge("pihole_system_temperature_celsius", "CPU temperature",
        sensors{"cpu_temp"}.getFloat())

proc collectDatabase(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  let db = data.getOrDefault("database")
  if db != nil and db.kind == JObject:
    b.addGauge("pihole_database_size_bytes", "FTL database size",
      db{"size"}.getFloat())
    b.addGauge("pihole_database_queries", "Queries in database",
      db{"queries"}.getFloat())
  else:
    b.addGauge("pihole_database_size_bytes", "FTL database size",
      data{"size"}.getFloat())
    b.addGauge("pihole_database_queries", "Queries in database",
      data{"queries"}.getFloat())

proc collectCounts(b: var MetricsBuilder, groups, lists, allowDomains, denyDomains: JsonNode) =
  if groups.kind != JNull:
    let arr = groups.getOrDefault("groups")
    if arr != nil and arr.kind == JArray:
      b.addGauge("pihole_groups_total", "Number of groups", arr.len.float)

  if lists.kind != JNull:
    let arr = lists.getOrDefault("lists")
    if arr != nil and arr.kind == JArray:
      b.addGauge("pihole_gravity_lists_total", "Number of configured adlists",
        arr.len.float)

  if allowDomains.kind != JNull:
    let arr = allowDomains.getOrDefault("domains")
    if arr != nil and arr.kind == JArray:
      b.addGauge("pihole_domains_allow_total", "Allowlisted domains",
        arr.len.float)

  if denyDomains.kind != JNull:
    let arr = denyDomains.getOrDefault("domains")
    if arr != nil and arr.kind == JArray:
      b.addGauge("pihole_domains_deny_total", "Denylisted domains",
        arr.len.float)

proc collectMessages(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  b.addGauge("pihole_messages_total", "System messages/warnings",
    data{"count"}.getFloat())

proc collectFtl(b: var MetricsBuilder, data: JsonNode) =
  if data.kind == JNull: return
  b.addGauge("pihole_ftl_pid", "FTL process ID",
    data{"pid"}.getFloat())
  let db = data.getOrDefault("database")
  if db != nil and db.kind == JObject:
    b.addGauge("pihole_ftl_database_gravity", "Gravity database entries",
      db{"gravity"}.getFloat())
    b.addGauge("pihole_ftl_database_groups", "Groups in database",
      db{"groups"}.getFloat())
    b.addGauge("pihole_ftl_database_lists", "Lists in database",
      db{"lists"}.getFloat())
    b.addGauge("pihole_ftl_database_clients", "Clients in database",
      db{"clients"}.getFloat())
    b.addGauge("pihole_ftl_database_domains", "Domains in database",
      db{"domains"}.getFloat())

proc collect*(c: PiholeClient): Future[string] {.async.} =
  ## Fetch all endpoints and return Prometheus text format output.
  let startTime = epochTime()
  var success = 1.0
  var b = newMetricsBuilder()
  debug("Starting metrics collection")

  try:
    # Authenticate once before firing concurrent requests
    await c.authenticate()

    # Fire off all requests concurrently
    let
      fSummary = c.safeGet("/api/stats/summary")
      fBlocking = c.safeGet("/api/dns/blocking")
      fTopPermitted = c.safeGet("/api/stats/top_domains?blocked=false&count=10")
      fTopBlocked = c.safeGet("/api/stats/top_domains?blocked=true&count=10")
      fTopClients = c.safeGet("/api/stats/top_clients?blocked=false&count=10")
      fTopBlockedClients = c.safeGet("/api/stats/top_clients?blocked=true&count=10")
      fUpstreams = c.safeGet("/api/stats/upstreams")
      fDhcp = c.safeGet("/api/dhcp/leases")
      fNetwork = c.safeGet("/api/network/devices")
      fVersion = c.safeGet("/api/info/version")
      fSystem = c.safeGet("/api/info/system")
      fSensors = c.safeGet("/api/info/sensors")
      fDatabase = c.safeGet("/api/info/database")
      fFtl = c.safeGet("/api/info/ftl")
      fMessages = c.safeGet("/api/info/messages/count")
      fGroups = c.safeGet("/api/groups")
      fLists = c.safeGet("/api/lists")
      fAllowDomains = c.safeGet("/api/domains/allow")
      fDenyDomains = c.safeGet("/api/domains/deny")

    # Await all results
    let
      summary = await fSummary
      blocking = await fBlocking
      topPermitted = await fTopPermitted
      topBlocked = await fTopBlocked
      topClients = await fTopClients
      topBlockedClients = await fTopBlockedClients
      upstreams = await fUpstreams
      dhcp = await fDhcp
      network = await fNetwork
      version = await fVersion
      system = await fSystem
      sensors = await fSensors
      database = await fDatabase
      ftl = await fFtl
      messages = await fMessages
      groups = await fGroups
      lists = await fLists
      allowDomains = await fAllowDomains
      denyDomains = await fDenyDomains

    # Build metrics
    b.collectSummary(summary)
    b.collectBlocking(blocking)
    b.collectTopDomains(topPermitted, topBlocked)
    b.collectTopClients(topClients, topBlockedClients)
    b.collectUpstreams(upstreams)
    b.collectDhcp(dhcp)
    b.collectNetwork(network)
    b.collectVersion(version)
    b.collectSystem(system, sensors)
    b.collectDatabase(database)
    b.collectFtl(ftl)
    b.collectCounts(groups, lists, allowDomains, denyDomains)
    b.collectMessages(messages)

  except:
    error(&"Collection failed: {getCurrentExceptionMsg()}")
    success = 0.0

  let duration = epochTime() - startTime
  if success == 1.0:
    info(&"Scrape completed in {duration:.3f}s")
  else:
    warn(&"Scrape completed with errors in {duration:.3f}s")

  b.addGauge("pihole_exporter_scrape_duration_seconds",
    "Time taken to scrape Pi-hole", duration)
  b.addGauge("pihole_exporter_scrape_success",
    "Whether last scrape succeeded (1/0)", success)

  result = b.output()
