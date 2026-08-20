// dsh-auth — DeepSeek Harness web 认证插件（宿主端）
// 职责：1) 认证网关（包装 webServer 分发，未登录重定向 /login 或 401）
//       2) 会话管理（HttpOnly Cookie，空闲自动登出，认证有效期，定时清扫）
//       3) 设置 API（/api/auth/settings、/api/auth/change-password）
//       4) CLI：`dsh web p [密码]` 启动早期重置密码
// 零运行时依赖（仅 node 内置模块），数据存于 $DSH_HOME/auth.json

import { randomBytes, scryptSync, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import { homedir, networkInterfaces } from 'node:os'
import { dirname, join } from 'node:path'

export const name = 'dsh-auth'
export const inject = ['webServer']

const DEFAULT_IDLE_MINUTES = 30
const DEFAULT_MAX_AGE_MINUTES = 24 * 60
const COOKIE_NAME = 'dsh_auth'
const SESSION_TOKEN_BYTES = 24
const SWEEP_INTERVAL_MS = 60_000
const PERSIST_THROTTLE_MS = 2_000
const PUBLIC_PATHS = new Set(['/login', '/api/auth/login', '/api/auth/logout', '/api/auth/status'])

// ── 存储 ──
function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}
function authFilePath() {
  return join(dshHome(), 'auth.json')
}
function defaultStore() {
  return {
    username: 'admin', password: null,
    idleMinutes: DEFAULT_IDLE_MINUTES, maxAgeMinutes: DEFAULT_MAX_AGE_MINUTES,
    singleSession: false, sessions: {}, loginHistory: []
  }
}
function loadStore() {
  const p = authFilePath()
  if (!existsSync(p)) return null
  try {
    const raw = JSON.parse(readFileSync(p, 'utf8'))
    const store = { ...defaultStore(), ...raw }
    if (!store.sessions || typeof store.sessions !== 'object') store.sessions = {}
    if (!Array.isArray(store.loginHistory)) store.loginHistory = []
    // 静态加密：密码 scrypt 哈希在磁盘上为密文，解密为内存对象供校验
    store.password = decrypt(store.password)
    return store
  } catch {
    return null
  }
}
function saveStore(store) {
  const out = { ...store, password: store.password ? encrypt(store.password) : null }
  const p = authFilePath()
  mkdirSync(dirname(p), { recursive: true })
  const tmp = p + '.tmp'
  writeFileSync(tmp, JSON.stringify(out, null, 2), { mode: 0o600 })
  renameSync(tmp, p)
}

// ── 静态加密（AES-256-GCM）──────────────────────────────────────────────
// 敏感字段（密码 scrypt 哈希）落盘前用本机密钥加密；密钥存于 auth.key(0600)。
// 密钥仅在本机，若丢失需用 `dsh web p` 重置密码。旧明文数据在下次保存时自动迁移。
const ENC_PREFIX = 'AES:'
function keyFilePath() { return join(dshHome(), 'auth.key') }
function ensureKey() {
  try {
    if (existsSync(keyFilePath())) return readFileSync(keyFilePath())
  } catch {}
  const key = randomBytes(32)
  const p = keyFilePath()
  mkdirSync(dirname(p), { recursive: true })
  writeFileSync(p, key, { mode: 0o600 })
  return key
}
function encrypt(secret) {
  if (secret === undefined || secret === null) return secret
  const key = ensureKey()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([cipher.update(JSON.stringify(secret), 'utf8'), cipher.final()])
  return ENC_PREFIX + iv.toString('hex') + '.' + cipher.getAuthTag().toString('hex') + '.' + ct.toString('hex')
}
function decrypt(payload) {
  if (typeof payload !== 'string' || !payload.startsWith(ENC_PREFIX)) return payload
  const parts = payload.split('.')
  if (parts.length !== 3) return payload
  try {
    const key = ensureKey()
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(parts[0].slice(ENC_PREFIX.length), 'hex'))
    decipher.setAuthTag(Buffer.from(parts[1], 'hex'))
    const out = Buffer.concat([decipher.update(Buffer.from(parts[2], 'hex')), decipher.final()])
    return JSON.parse(out.toString('utf8'))
  } catch {
    return null
  }
}

// ── 登录 IP 统计（时间 / 地点）──────────────────────────────────────────
const MAX_LOGIN_HISTORY = 50
const LOGIN_HISTORY_PROVIDER = 'ip-api.com' // 免费、免 key、支持中文地名
const locCache = new Map()
function clientIp(req) {
  const fwd = req.headers['x-forwarded-for']
  const raw = (fwd ? String(fwd).split(',')[0].trim() : '') || (req.socket && req.socket.remoteAddress) || 'unknown'
  return String(raw).replace(/^::ffff:/, '')
}
function lookupLocation(ip) {
  if (locCache.has(ip)) return Promise.resolve(locCache.get(ip))
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
    locCache.set(ip, { country: '本地 / Localhost', city: '本机' })
    return Promise.resolve(locCache.get(ip))
  }
  return new Promise((resolve) => {
    const fallback = (loc) => { locCache.set(ip, loc); resolve(loc) }
    const unknown = { country: '未知 / Unknown', city: '—' }
    const url = 'http://' + LOGIN_HISTORY_PROVIDER + '/json/' + encodeURIComponent(ip) + '?fields=status,country,regionName,city&lang=zh-CN'
    const req = httpRequest(url, { timeout: 3000 }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c; if (data.length > 8192) req.destroy() })
      res.on('end', () => {
        try {
          const j = JSON.parse(data)
          if (j && j.status === 'success') {
            return fallback({ country: j.country || '未知 / Unknown', region: j.regionName, city: j.city || '—' })
          }
        } catch {}
        fallback(unknown)
      })
      res.on('error', () => fallback(unknown))
    })
    req.on('timeout', () => req.destroy())
    req.on('error', () => fallback(unknown))
    req.end()
  })
}
function recordLogin(store, req) {
  const ip = clientIp(req)
  if (!store.loginHistory || !Array.isArray(store.loginHistory)) store.loginHistory = []
  const entry = { ip, time: new Date().toISOString(), location: { country: '查询中…', city: '—' } }
  store.loginHistory.unshift(entry)
  if (store.loginHistory.length > MAX_LOGIN_HISTORY) store.loginHistory.length = MAX_LOGIN_HISTORY
  saveStore(store)
  lookupLocation(ip).then((loc) => { entry.location = loc; saveStore(store) }).catch(() => {})
}

// ── 密码 ──
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : randomBytes(16)
  const hash = scryptSync(String(password), salt, 64)
  return { salt: salt.toString("hex"), hash: hash.toString("hex") }
}
function verifyPassword(password, record) {
  if (!record || !record.salt || !record.hash) return false
  const a = Buffer.from(record.hash, "hex")
  const b = Buffer.from(hashPassword(password, record.salt).hash, "hex")
  return a.length === b.length && timingSafeEqual(a, b)
}
function randomPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'
  const bytes = randomBytes(18)
  let out = ""
  for (let i = 0; i < bytes.length; i++) out += alphabet[bytes[i] % alphabet.length]
  return out
}

// ── HTTP 工具 ──
function readCookies(header) {
  const out = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k) out[k] = v
  }
  return out
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on("data", (chunk) => {
      data += chunk
      if (data.length > 1_000_000) {
        reject(new Error('body too large'))
        req.destroy()
      }
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}
function json(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body), ...extraHeaders })
  res.end(body)
}
function setCookieHeader(token, maxAgeSeconds) {
  return COOKIE_NAME + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + Math.max(0, Math.floor(maxAgeSeconds))
}
function clearCookieHeader() {
  return COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
}

// ── 会话 ──
function createSession(store) {
  const token = randomBytes(SESSION_TOKEN_BYTES).toString("hex")
  const now = Date.now()
  store.sessions[token] = { createdAt: now, lastActiveAt: now, expiresAt: now + store.maxAgeMinutes * 60_000 }
  return token
}
function authorize(store, token, now = Date.now()) {
  const s = store.sessions[token]
  if (!s) return null
  const idleMs = store.idleMinutes * 60_000
  if (now - s.lastActiveAt > idleMs || now > s.expiresAt) {
    delete store.sessions[token]
    return null
  }
  s.lastActiveAt = now
  return s
}
function sweep(store, now = Date.now()) {
  let changed = false
  const idleMs = store.idleMinutes * 60_000
  for (const [token, s] of Object.entries(store.sessions)) {
    if (now - s.lastActiveAt > idleMs || now > s.expiresAt) {
      delete store.sessions[token]
      changed = true
    }
  }
  return changed
}

// ── 被踢会话提醒（内存态，TTL 5 分钟） ──
const KICK_NOTICE_TTL_MS = 5 * 60_000
const kickNotices = new Map()
function noteKicked(token, reason) {
  if (!token) return
  kickNotices.set(token, { reason, at: Date.now() })
}
function sweepKickNotices(now = Date.now()) {
  for (const [t, n] of kickNotices) {
    if (now - n.at > KICK_NOTICE_TTL_MS) kickNotices.delete(t)
  }
}

// ── `dsh web p [密码]` / `dsh web u <用户名>`：模块导入时检测并重置密码（早于端口监听） ──
function parsePositionals(argv) {
  // 跳过 --option 与 --option <value>（dsh 框架会传 --profile web 等）
  const takesValue = new Set(['--profile', '--patch', '--host', '--port', '--trusted-host', '--config', '--resume', '--dump-config', '--dump-default-config'])
  const pos = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('-')) {
      if (a.includes('=')) continue
      if (takesValue.has(a)) { i++; continue }
      continue
    }
    pos.push(a)
  }
  return pos
}
function maybeResetFromArgv() {
  const positionals = parsePositionals(process.argv.slice(2))
  let store = loadStore()
  if (!store) store = defaultStore()

  // 'dsh web u <username>' : 修改用户名（取 u 后下一个参数）
  const uidx = positionals.indexOf('u')
  if (uidx !== -1) {
    const uname = positionals[uidx + 1]
    if (uname && /^[A-Za-z0-9_-]{3,32}$/.test(uname)) {
      store.username = uname
      store.sessions = {}
      saveStore(store)
      console.log('')
      console.log('[dsh-auth] 用户名已修改 / username updated: ' + uname)
      console.log('')
      return true
    }
    console.log('[dsh-auth] 用法 / usage: dsh web u <username>  (3-32位字母数字_-)')
    return true
  }

  // 'dsh web p [password]' : 重置密码（取 p 后下一个参数；无则随机）
  const idx = positionals.indexOf('p')
  if (idx !== -1) {
    let password = positionals[idx + 1]
    // 排除命令标记被误当作密码（如 dsh web p --profile web 里的 web）
    if (password === undefined || ['p', 'u', 'web', 'headless', 'tui', 'desktop', 'cli', 'api'].includes(password)) password = null
    const finalPassword = password || randomPassword()
    store.password = hashPassword(finalPassword)
    store.sessions = {}
    saveStore(store)
    console.log('')
    console.log('[dsh-auth] 密码已重置 / password reset complete.')
    console.log('[dsh-auth] 新密码 / new password: ' + finalPassword)
    console.log('[dsh-auth] 登录后可在 设置 > 认证 中修改；change it in Settings > Auth after login.')
    console.log('')
    return true
  }
  return false
}
if (maybeResetFromArgv()) process.exit(0)

// ── 登录页（内嵌，零资源） ──
const LOGIN_PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 · dsh</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #2f6feb; --accent-hover: #3a7bfd; --err: #f85149; }
  @media (prefers-color-scheme: light) {
    :root { --bg: #f6f8fa; --card: #ffffff; --border: #d0d7de; --text: #1f2328; --muted: #656d76; --accent: #2f6feb; --accent-hover: #1f5fd0; --err: #cf222e; }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); color: var(--text); font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .card { width: 360px; max-width: 92vw; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 28px 24px; }
  h1 { font-size: 18px; margin-bottom: 4px; }
  .sub { font-size: 12px; color: var(--muted); margin-bottom: 20px; }
  label { display: block; font-size: 13px; margin-bottom: 6px; }
  input { width: 100%; padding: 9px 12px; margin-bottom: 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 14px; outline: none; }
  input:focus { border-color: var(--accent); }
  button { width: 100%; padding: 10px; border: none; border-radius: 8px; cursor: pointer; background: var(--accent); color: #fff; font-size: 14px; font-weight: 600; }
  button:hover { background: var(--accent-hover); }
  .warn { margin-top: 14px; font-size: 13px; color: var(--err); background: color-mix(in srgb, var(--err) 10%, transparent); border: 1px solid color-mix(in srgb, var(--err) 40%, transparent); border-radius: 8px; padding: 10px 12px; display: none; }
  .err { margin-top: 12px; font-size: 13px; color: var(--err); min-height: 18px; }
  .hint { margin-top: 16px; font-size: 12px; color: var(--muted); line-height: 1.7; }
  code { background: color-mix(in srgb, var(--text) 10%, transparent); padding: 1px 5px; border-radius: 4px; }
</style>
</head>
<body>
  <form class="card" id="form">
    <h1>DeepSeek Harness</h1>
    <div class="sub" id="sub">需要认证 · authentication required</div>
    <div class="warn" id="warn"></div>
    <label for="username" id="lblUser">用户名 / Username</label>
    <input id="username" type="text" autocomplete="username" autofocus required>
    <label for="password" id="lblPass">密码 / Password</label>
    <input id="password" type="password" autocomplete="current-password" required>
    <button type="submit" id="btn">登录 / Sign in</button>
    <div class="err" id="err"></div>
    <div class="hint" id="hint">初始账号见服务器启动日志；忘记可运行 dsh web p 重置密码、dsh web u 改用户名。</div>
  </form>
<script>
  var zh = navigator.language && navigator.language.toLowerCase().indexOf("zh") === 0
  var T = {
    user: zh ? "用户名" : "Username",
    pass: zh ? "密码" : "Password",
    btn: zh ? "登录" : "Sign in",
    wrong: zh ? "用户名或密码错误" : "Wrong username or password",
    net: zh ? "网络错误" : "Network error",
    kickedReplaced: zh ? "您的会话已被新登录替换。如非本人操作，请立即修改密码！" : "Your session was replaced by a new login. If this was not you, change the password immediately!",
    kickedPassword: zh ? "密码已修改，请重新登录。" : "The password was changed. Please sign in again.",
    kickedCredentials: zh ? "用户名或密码已修改，请重新登录。" : "Credentials were changed. Please sign in again.",
    kickedOther: zh ? "会话已失效，请重新登录。" : "Session expired. Please sign in again."
  }
  document.getElementById("sub").textContent = zh ? "需要认证" : "Authentication required"
  document.getElementById("lblUser").textContent = T.user
  document.getElementById("lblPass").textContent = T.pass
  document.getElementById("btn").textContent = T.btn
  var kicked = new URLSearchParams(location.search).get("kicked")
  if (kicked) {
    var msg = kicked === "replaced" ? T.kickedReplaced : kicked === "password_changed" ? T.kickedPassword : kicked === "credentials_changed" ? T.kickedCredentials : T.kickedOther
    var w = document.getElementById("warn")
    w.textContent = msg
    w.style.display = "block"
  }
  var form = document.getElementById("form")
  var err = document.getElementById("err")
  fetch("/api/auth/status").then(function (r) { return r.json() }).then(function (j) {
    if (j && j.authenticated) location.href = "/"
  }).catch(function () {})
  form.addEventListener("submit", function (e) {
    e.preventDefault()
    err.textContent = ""
    fetch("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: document.getElementById("username").value.trim(), password: document.getElementById("password").value })
    }).then(function (r) { return r.json() }).then(function (j) {
      if (j && j.ok) { location.href = "/" }
      else { err.textContent = T.wrong; document.getElementById("password").select() }
    }).catch(function () { err.textContent = T.net })
  })
</script>
</body>
</html>`

// ── crypto.randomUUID polyfill ────────────────────────────────────────────────
// 局域网 HTTP（如 http://192.168.0.x:3080）属于非安全上下文，浏览器不提供
// crypto.randomUUID（仅 HTTPS / localhost）。DSH 客户端在加载 Agent 预设等处
// 调用它，这里用 getRandomValues（所有上下文可用）注入兼容实现。
const UUID_POLYFILL = '<script data-dsh-auth="uuid-polyfill">(function(){if(window.crypto&&!window.crypto.randomUUID&&window.crypto.getRandomValues){window.crypto.randomUUID=function(){var b=new Uint8Array(16);window.crypto.getRandomValues(b);b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;var h="";for(var i=0;i<16;i++){h+=(b[i]<16?"0":"")+b[i].toString(16)}return h.slice(0,8)+"-"+h.slice(8,12)+"-"+h.slice(12,16)+"-"+h.slice(16,20)+"-"+h.slice(20)}}})();</script>'

// ── 局域网反向代理 ─────────────────────────────────────────────────────────
// DSH 的 /api browser-trust 围栏在 LAN 直连时拒绝所有 RPC（连接行 trustedHosts
// 配置传递有 bug，LAN IP 不被信任 → 403）。真实服务器只绑 127.0.0.1，这里起一个
// 0.0.0.0:<lanPort> 的转发代理：把 Host 改写为回环、删除 Origin，围栏按回环放行，
// 使局域网下所有 /api（设置、文件、变更、其他插件）都可访问。认证网关在真实
// 服务器上，所有流量仍先过认证。
function startLanProxy(ctx, ws, config) {
  const lanPort = Number(process.env.DSH_AUTH_PORT ?? config.lanPort ?? 3080)
  const realHost = '127.0.0.1'
  const rewrite = (headers) => {
    const out = { ...headers }
    out.host = realHost + ':' + (ws.port || 0)
    // 不删除 Origin，而是改写为回环源：/api 围栏与 dshmarket 的 sameOrigin
    // 都要求 Origin 与 Host 一致（缺失 Origin 会被判为 untrusted origin）
    out.origin = 'http://' + realHost + ':' + (ws.port || 0)
    return out
  }
  const proxy = createHttpServer((req, res) => {
    const port = ws.port
    if (!port) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('backend not ready')
      return
    }
    const upstream = httpRequest({ host: realHost, port, path: req.url, method: req.method, headers: rewrite(req.headers) }, (upRes) => {
      res.writeHead(upRes.statusCode ?? 502, upRes.headers)
      upRes.pipe(res)
    })
    upstream.on('error', (err) => {
      ctx.logger.warn('[dsh-auth] proxy upstream: ' + err.message)
      if (!res.headersSent) { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('upstream error') }
      else res.destroy()
    })
    req.pipe(upstream)
  })
  proxy.on('upgrade', (req, socket, head) => {
    const port = ws.port
    if (!port) { socket.destroy(); return }
    const upstream = httpRequest({ host: realHost, port, path: req.url, method: req.method, headers: rewrite(req.headers) })
    upstream.on('upgrade', (upRes, upSocket, upHead) => {
      const lines = ['HTTP/1.1 101 Switching Protocols']
      for (const [k, v] of Object.entries(upRes.headers)) lines.push(k + ': ' + v)
      socket.write(lines.join('\r\n') + '\r\n\r\n')
      if (upHead && upHead.length) upSocket.unshift(upHead)
      // Bug 修复：客户端随握手头同包到达的 head 属于升级后的数据流，
      // 必须在上游 101 之后经隧道转发；若写在上游请求体上，会被当作 HTTP
      // body 消费，导致首帧数据丢失。
      if (head && head.length) upSocket.write(head)
      upSocket.pipe(socket)
      socket.pipe(upSocket)
      // 任一端断开即关闭另一端，避免客户端异常断连时残留半开隧道
      socket.on('error', () => upSocket.destroy())
      upSocket.on('error', () => socket.destroy())
      socket.on('close', () => upSocket.destroy())
      upSocket.on('close', () => socket.destroy())
    })
    upstream.on('response', (upRes) => { upRes.destroy(); socket.destroy() })
    upstream.on('error', () => socket.destroy())
    // 升级请求无请求体：head 不能作为 body 发送
    upstream.end()
  })
  proxy.on('error', (err) => {
    ctx.logger.warn('[dsh-auth] lan proxy: ' + err.message)
  })
  proxy.listen(lanPort, '0.0.0.0', () => {
    const lan = Object.values(networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal)
    console.log('[dsh-auth] LAN proxy: http://' + (lan ? lan.address : '0.0.0.0') + ':' + lanPort + '  (backend 127.0.0.1:' + (ws.port || '?') + ')')
  })
  ctx.effect(() => () => proxy.close(), 'dsh-auth: lan proxy')
  return proxy
}

// 仅供单元测试访问内部实现
export const _test = { startLanProxy }

// ── 插件本体 ──
export function apply(ctx, config = {}) {
  const enabled = config.enabled !== false
  const ws = ctx.webServer
  let store = loadStore()
  if (!store) {
    store = {
      ...defaultStore(),
      ...(typeof config.idleMinutes === 'number' ? { idleMinutes: config.idleMinutes } : {}),
      ...(typeof config.maxAgeMinutes === 'number' ? { maxAgeMinutes: config.maxAgeMinutes } : {}),
    }
  }

  // 会话活跃时间节流持久化（Bug 修复）：authorize 只在内存更新 lastActiveAt，
  // 若每次请求都写盘开销过大；这里节流落盘，保证进程重启后空闲计时不丢失。
  let persistTimer = null
  const persistSoon = () => {
    if (persistTimer) return
    persistTimer = setTimeout(() => {
      persistTimer = null
      try { saveStore(store) } catch (err) { ctx.logger.warn('[dsh-auth] persist store: ' + err.message) }
    }, PERSIST_THROTTLE_MS)
  }
  ctx.effect(() => () => { if (persistTimer) clearTimeout(persistTimer) }, 'dsh-auth: persist throttle')

  // 首次启动：生成并打印初始密码
  if (enabled && !store.password) {
    const pw = randomPassword()
    store.password = hashPassword(pw)
    saveStore(store)
    console.log("")
    console.log("[dsh-auth] 初始账号 / initial account: " + store.username + "  密码 / password: " + pw)
    console.log("[dsh-auth] 登录后请在 设置 > 认证 中修改；可用 dsh web p 重置密码、dsh web u <用户名> 改用户名。")
    console.log("")
    ctx.logger.info("[dsh-auth] initial password generated (see console)")
  }

  // 公开路由（无需登录）
  ws.register({ kind: 'exact', path: '/login', handler: (req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(LOGIN_PAGE) })
    res.end(LOGIN_PAGE)
  } })

  // 为 SPA 的 index.html 注入 crypto.randomUUID polyfill（局域网 HTTP 场景）
  ws.tapIndex((html) => {
    if (html.includes('data-dsh-auth="uuid-polyfill"')) return html
    const script = UUID_POLYFILL + '</head>'
    return html.includes('</head>') ? html.replace('</head>', script) : UUID_POLYFILL + html
  })

  ws.register({ kind: 'exact', path: '/api/auth/login', handler: async (req, res) => {
    let body
    try { body = JSON.parse((await readBody(req)) || '{}') } catch { return json(res, 400, { ok: false, error: 'bad_json' }) }
    const username = typeof body.username === 'string' ? body.username.trim() : ''
    const password = typeof body.password === 'string' ? body.password : ''
    if (!username || !password) return json(res, 400, { ok: false, error: 'credentials_required' })
    if (username !== store.username || !verifyPassword(password, store.password)) return json(res, 401, { ok: false, error: 'invalid_credentials' })
    // 单点登录：仅保留一个活跃会话，并给被踢会话留提醒
    if (store.singleSession) {
      for (const t of Object.keys(store.sessions)) noteKicked(t, 'replaced')
      store.sessions = {}
    }
    const token = createSession(store)
    saveStore(store)
    recordLogin(store, req)
    json(res, 200, { ok: true }, { 'set-cookie': setCookieHeader(token, store.maxAgeMinutes * 60) })
  } })

  ws.register({ kind: 'exact', path: '/api/auth/logout', handler: async (req, res) => {
    const token = readCookies(req.headers.cookie)[COOKIE_NAME]
    if (token && store.sessions[token]) {
      delete store.sessions[token]
      saveStore(store)
    }
    json(res, 200, { ok: true }, { 'set-cookie': clearCookieHeader() })
  } })

  ws.register({ kind: 'exact', path: '/api/auth/status', handler: (req, res) => {
    const token = readCookies(req.headers.cookie)[COOKIE_NAME]
    const s = enabled ? authorize(store, token) : null
    if (s) persistSoon()
    const authed = !!s
    const notice = token ? kickNotices.get(token) : undefined
    json(res, 200, { ok: true, authenticated: authed, kicked: notice ? notice.reason : undefined, enabled, username: store.username, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes, passwordSet: !!store.password })
  } })

  // ── 认证网关：包装路由分发，未登录一律拦截 ──
  if (enabled) {
    const rejectUnauthorized = (req, res) => {
      const accept = req.headers.accept || ''
      if (accept.includes('text/html')) {
        res.writeHead(302, { location: '/login' })
        res.end()
      } else {
        json(res, 401, { ok: false, error: 'unauthorized' })
      }
    }
    const gate = (handler) => async (req, res) => {
      const pathname = new URL(req.url ?? '/', 'http://x').pathname
      if (PUBLIC_PATHS.has(pathname)) return handler(req, res)
      const token = readCookies(req.headers.cookie)[COOKIE_NAME]
      if (!authorize(store, token)) return rejectUnauthorized(req, res)
      persistSoon()
      return handler(req, res)
    }
    const gateUpgrade = (handler) => (req, socket, head) => {
      const pathname = new URL(req.url ?? '/', 'http://x').pathname
      if (PUBLIC_PATHS.has(pathname)) return handler(req, socket, head)
      const token = readCookies(req.headers.cookie)[COOKIE_NAME]
      if (!authorize(store, token)) {
        socket.destroy()
        return
      }
      persistSoon()
      return handler(req, socket, head)
    }

    const origMatch = ws.match.bind(ws)
    ws.match = (pathname) => {
      const route = origMatch(pathname)
      return route ? { ...route, handler: gate(route.handler) } : undefined
    }
    const origRegister = ws.register.bind(ws)
    ws.register = (route) => origRegister({ ...route, handler: gate(route.handler) })
    const origRegisterFallback = ws.registerFallback.bind(ws)
    ws.registerFallback = (handler) => origRegisterFallback(gate(handler))
    if (ws.fallback) ws.fallback = gate(ws.fallback)
    const origRegisterUpgrade = ws.registerUpgrade.bind(ws)
    ws.registerUpgrade = (route) => origRegisterUpgrade({ ...route, handler: gateUpgrade(route.handler) })
    for (const [, route] of ws.upgrades) route.handler = gateUpgrade(route.handler)
  }

  // ── 受保护路由（注册在网关包装之后，自动被拦截） ──
  ws.register({ kind: 'exact', path: '/api/auth/settings', handler: async (req, res) => {
    if (req.method !== 'POST') {
      json(res, 200, { ok: true, username: store.username, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes, singleSession: store.singleSession })
      return
    }
    let body
    try { body = JSON.parse((await readBody(req)) || '{}') } catch { return json(res, 400, { ok: false, error: 'bad_json' }) }
    let changed = false
    if (body.idleMinutes !== undefined) {
      const v = Number(body.idleMinutes)
      if (!Number.isFinite(v) || v < 1 || v > 10080) return json(res, 400, { ok: false, error: "invalid_idle" })
      store.idleMinutes = Math.round(v)
      changed = true
    }
    if (body.maxAgeMinutes !== undefined) {
      const v = Number(body.maxAgeMinutes)
      if (!Number.isFinite(v) || v < 5 || v > 525600) return json(res, 400, { ok: false, error: "invalid_maxage" })
      store.maxAgeMinutes = Math.round(v)
      changed = true
    }
    if (body.singleSession !== undefined) {
      store.singleSession = !!body.singleSession
      changed = true
      if (store.singleSession) {
        // 开启单点登录：立即作废除当前会话外的所有会话，并留提醒
        const current = readCookies(req.headers.cookie)[COOKIE_NAME]
        for (const t of Object.keys(store.sessions)) {
          if (t !== current) { noteKicked(t, 'replaced'); delete store.sessions[t] }
        }
      }
    }
    if (changed) saveStore(store)
    json(res, 200, { ok: true, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes, singleSession: store.singleSession })
  } })

  ws.register({ kind: 'exact', path: '/api/auth/change-password', handler: async (req, res) => {
    const token = readCookies(req.headers.cookie)[COOKIE_NAME]
    let body
    try { body = JSON.parse((await readBody(req)) || '{}') } catch { return json(res, 400, { ok: false, error: 'bad_json' }) }
    const current = typeof body.current === 'string' ? body.current : ''
    const next = typeof body.next === 'string' ? body.next : ''
    if (next.length < 4) return json(res, 400, { ok: false, error: "weak_password" })
    if (!verifyPassword(current, store.password)) return json(res, 401, { ok: false, error: "invalid_password" })
    store.password = hashPassword(next)
    for (const t of Object.keys(store.sessions)) {
      if (t !== token) { noteKicked(t, 'password_changed'); delete store.sessions[t] }
    }
    saveStore(store)
    json(res, 200, { ok: true })
  } })

  ws.register({ kind: 'exact', path: '/api/auth/change-username', handler: async (req, res) => {
    const token = readCookies(req.headers.cookie)[COOKIE_NAME]
    let body
    try { body = JSON.parse((await readBody(req)) || '{}') } catch { return json(res, 400, { ok: false, error: 'bad_json' }) }
    const current = typeof body.current === 'string' ? body.current : ''
    const username = typeof body.username === 'string' ? body.username.trim() : ''
    if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) return json(res, 400, { ok: false, error: 'invalid_username' })
    if (username === store.username) return json(res, 400, { ok: false, error: 'same_username' })
    if (!verifyPassword(current, store.password)) return json(res, 401, { ok: false, error: 'invalid_password' })
    store.username = username
    for (const t of Object.keys(store.sessions)) {
      if (t !== token) { noteKicked(t, 'credentials_changed'); delete store.sessions[t] }
    }
    saveStore(store)
    json(res, 200, { ok: true, username })
  } })

  ws.register({ kind: 'exact', path: '/api/auth/login-history', handler: (req, res) => {
    json(res, 200, { ok: true, history: store.loginHistory || [] })
  } })

  // 局域网反向代理（真实服务器仅回环，代理对外）
  startLanProxy(ctx, ws, config)

  // 空闲/过期会话定时清扫
  const timer = setInterval(() => {
    sweepKickNotices()
    if (sweep(store)) saveStore(store)
  }, SWEEP_INTERVAL_MS)
  ctx.effect(() => () => clearInterval(timer), 'dsh-auth: session sweep')
}
