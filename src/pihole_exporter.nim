## Pi-hole Prometheus Exporter — comprehensive exporter for Pi-hole v6.
## Configured via environment variables, serves Prometheus metrics on /metrics.

import std/[asyncdispatch, asynchttpserver, os, strutils, strformat, logging, times]
import pihole_exporter/[client, collector]

type
  Config = object
    piholeUrl: string
    piholePassword: string
    piholePort: int
    exporterPort: int
    skipTlsVerify: bool
    cacheTtl: float

proc loadConfig(): Config =
  let url = getEnv("PIHOLE_URL", "http://localhost")
  let password = getEnv("PIHOLE_PASSWORD", "")
  if password == "":
    error("PIHOLE_PASSWORD environment variable is required")
    quit(1)
  let defaultPort = if url.startsWith("https"): "443" else: "80"
  let piholePort = getEnv("PIHOLE_PORT", defaultPort).parseInt()
  let exporterPort = getEnv("EXPORTER_PORT", "9617").parseInt()
  let skipTls = getEnv("SKIP_TLS_VERIFY", "false").toLowerAscii() in ["true", "1", "yes"]
  let cacheTtl = getEnv("CACHE_TTL", "30").parseFloat()

  # Build base URL: append port to URL if not already present
  var baseUrl = url.strip(chars = {'/'})
  if ":" notin baseUrl.split("//", 1)[^1]:
    baseUrl = &"{baseUrl}:{piholePort}"

  Config(
    piholeUrl: baseUrl,
    piholePassword: password,
    piholePort: piholePort,
    exporterPort: exporterPort,
    skipTlsVerify: skipTls,
    cacheTtl: cacheTtl,
  )

const landingPage = """<!DOCTYPE html>
<html><head><title>Pi-hole Exporter</title></head>
<body><h1>Pi-hole Exporter</h1><p><a href="/metrics">Metrics</a></p></body>
</html>"""

proc main() {.async.} =
  let levelStr = getEnv("LOG_LEVEL", "INFO").toUpperAscii()
  let level = case levelStr
    of "DEBUG": lvlDebug
    of "INFO": lvlInfo
    of "WARN", "WARNING": lvlWarn
    of "ERROR": lvlError
    of "FATAL": lvlFatal
    of "NONE": lvlNone
    else: lvlInfo
  let logger = newConsoleLogger(level, fmtStr = "$datetime $levelname ")
  addHandler(logger)

  info("Pi-hole Exporter starting")
  let cfg = loadConfig()
  info(&"  Pi-hole URL: {cfg.piholeUrl}")
  info(&"  Exporter port: {cfg.exporterPort}")
  info(&"  Skip TLS verify: {cfg.skipTlsVerify}")
  info(&"  Cache TTL: {cfg.cacheTtl}s")

  let piholeClient = newPiholeClient(cfg.piholeUrl, cfg.piholePassword,
    cfg.skipTlsVerify)

  var server = newAsyncHttpServer()
  var cachedMetrics = ""
  var cachedAt = 0.0

  proc handler(req: Request) {.async.} =
    debug(&"{req.reqMethod} {req.url.path}")
    try:
      case req.url.path
      of "/metrics":
        let now = epochTime()
        let body = if cfg.cacheTtl > 0 and cachedMetrics.len > 0 and
            now - cachedAt < cfg.cacheTtl:
          debug("Serving cached metrics")
          cachedMetrics
        else:
          let fresh = await piholeClient.collect()
          cachedMetrics = fresh
          cachedAt = now
          fresh
        await req.respond(Http200, body,
          newHttpHeaders({"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}))
      of "/health":
        await req.respond(Http200, "OK")
      of "/":
        await req.respond(Http200, landingPage,
          newHttpHeaders({"Content-Type": "text/html"}))
      else:
        warn(&"404 {req.reqMethod} {req.url.path}")
        await req.respond(Http404, "Not Found")
    except:
      error(&"Error handling {req.reqMethod} {req.url.path}: {getCurrentExceptionMsg()}")
      try:
        await req.respond(Http500, "Internal Server Error")
      except:
        error(&"Failed to send error response: {getCurrentExceptionMsg()}")

  info(&"Listening on :{cfg.exporterPort}")
  server.listen(Port(cfg.exporterPort))
  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(handler)
    else:
      await sleepAsync(500)

when isMainModule:
  waitFor main()
