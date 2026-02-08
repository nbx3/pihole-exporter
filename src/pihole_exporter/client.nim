## Pi-hole v6 API client with session-based authentication.
## Handles auth, re-auth on 401, and authenticated GET requests.

import std/[asyncdispatch, httpclient, json, strformat, strutils, logging]

when defined(ssl):
  import std/net

type
  PiholeClient* = ref object
    baseUrl*: string
    password*: string
    sid: string
    skipTlsVerify: bool
    authenticating: bool

proc newHttpClient(c: PiholeClient): AsyncHttpClient =
  when defined(ssl):
    if c.skipTlsVerify:
      let ctx = newContext(verifyMode = CVerifyNone)
      return newAsyncHttpClient(sslContext = ctx)
  return newAsyncHttpClient()

proc newPiholeClient*(baseUrl, password: string, skipTlsVerify: bool = false): PiholeClient =
  PiholeClient(
    baseUrl: baseUrl,
    password: password,
    sid: "",
    skipTlsVerify: skipTlsVerify,
  )

proc authenticate*(c: PiholeClient) {.async.} =
  ## POST /api/auth to obtain a session SID.
  c.authenticating = true
  defer: c.authenticating = false
  let url = &"{c.baseUrl}/api/auth"
  let body = $(%*{"password": c.password})
  info(&"Authenticating with Pi-hole at {c.baseUrl}")
  let client = c.newHttpClient()
  defer: client.close()
  let resp = await client.request(url, httpMethod = HttpPost,
    body = body,
    headers = newHttpHeaders({"Content-Type": "application/json"}))
  let respBody = await resp.body
  if resp.code != Http200:
    error(&"Authentication failed: HTTP {resp.code}")
    raise newException(IOError, &"Auth failed: HTTP {resp.code} - {respBody}")
  let j = parseJson(respBody)
  let session = j.getOrDefault("session")
  if session.isNil or session.kind != JObject:
    error(&"Authentication response missing session object")
    raise newException(IOError, &"Auth response missing session: {respBody}")
  let validity = session.getOrDefault("validity")
  if validity.isNil or validity.kind != JInt or validity.getInt() <= 0:
    error(&"Authentication failed: invalid session validity")
    raise newException(IOError, &"Auth failed: invalid session validity: {respBody}")
  c.sid = session{"sid"}.getStr("")
  if c.sid == "":
    error(&"Authentication response missing SID")
    raise newException(IOError, &"Auth response missing SID: {respBody}")
  info(&"Authenticated with Pi-hole, SID: {c.sid[0..7]}...")

proc get*(c: PiholeClient, path: string): Future[JsonNode] {.async.} =
  ## Authenticated GET request. Re-authenticates on 401.
  ## Each call creates its own HTTP client for safe concurrent use.
  if c.sid == "":
    if not c.authenticating:
      await c.authenticate()
    else:
      # Another coroutine is already authenticating — wait for it
      while c.authenticating:
        await sleepAsync(50)

  let url = &"{c.baseUrl}{path}"
  let client = c.newHttpClient()
  defer: client.close()
  let headers = newHttpHeaders({"sid": c.sid})
  var resp = await client.request(url, httpMethod = HttpGet, headers = headers)
  var body = await resp.body

  # Re-auth on 401
  if resp.code == Http401:
    if not c.authenticating:
      warn(&"Got 401 for {path}, re-authenticating...")
      await c.authenticate()
    else:
      # Another coroutine is already re-authenticating — wait for it
      debug(&"Got 401 for {path}, waiting for ongoing re-auth...")
      while c.authenticating:
        await sleepAsync(50)
    let retryClient = c.newHttpClient()
    defer: retryClient.close()
    let retryHeaders = newHttpHeaders({"sid": c.sid})
    resp = await retryClient.request(url, httpMethod = HttpGet, headers = retryHeaders)
    body = await resp.body

  if resp.code != Http200:
    error(&"API request failed: {path} — HTTP {resp.code}")
    raise newException(IOError, &"API request failed: {path} — HTTP {resp.code}")

  result = parseJson(body)
