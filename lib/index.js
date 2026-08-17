// dsh-auth — DeepSeek Harness web 认证插件（宿主端）
// 职责：1) 认证网关（包装 webServer 分发，未登录重定向 /login 或 401）
//       2) 会话管理（HttpOnly Cookie，空闲自动登出，认证有效期，定时清扫）
//       3) 设置 API（/api/auth/settings、/api/auth/change-password）
//       4) CLI：`dsh web p [密码]` 启动早期重置密码
// 零运行时依赖（仅 node 内置模块），数据存于 $DSH_HOME/auth.json

import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export const name = 'dsh-auth'
export const inject = ['webServer']

const DEFAULT_IDLE_MINUTES = 30
const DEFAULT_MAX_AGE_MINUTES = 24 * 60
const COOKIE_NAME = 'dsh_auth'
const SESSION_TOKEN_BYTES = 24
const SWEEP_INTERVAL_MS = 60_000
const PUBLIC_PATHS = new Set(['/login', '/api/auth/login', '/api/auth/logout', '/api/auth/status'])

// ── 存储 ──
function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}
function authFilePath() {
  return join(dshHome(), 'auth.json')
}
function defaultStore() {
  return { password: null, idleMinutes: DEFAULT_IDLE_MINUTES, maxAgeMinutes: DEFAULT_MAX_AGE_MINUTES, sessions: {} }
}
function loadStore() {
  const p = authFilePath()
  if (!existsSync(p)) return null
  try {
    const raw = JSON.parse(readFileSync(p, 'utf8'))
    const store = { ...defaultStore(), ...raw }
    if (!store.sessions || typeof store.sessions !== 'object') store.sessions = {}
    return store
  } catch {
    return null
  }
}
function saveStore(store) {
  const p = authFilePath()
  mkdirSync(dirname(p), { recursive: true })
  const tmp = p + '.tmp'
  writeFileSync(tmp, JSON.stringify(store, null, 2))
  renameSync(tmp, p)
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

// ── `dsh web p [密码]`：模块导入时检测并重置密码（早于端口监听） ──
function maybeResetFromArgv() {
  const positionals = process.argv.slice(2).filter((a) => !a.startsWith('-'))
  const idx = positionals.indexOf('p')
  if (idx === -1) return false
  let store = loadStore()
  if (!store) store = defaultStore()
  let password = null
  if (idx + 1 < positionals.length && idx === positionals.length - 2) {
    password = positionals[positionals.length - 1]
  }
  const finalPassword = password || randomPassword()
  store.password = hashPassword(finalPassword)
  store.sessions = {}
  saveStore(store)
  console.log("")
  console.log("[dsh-auth] 密码已重置 / password reset complete.")
  console.log("[dsh-auth] 新密码 / new password: " + finalPassword)
  console.log("[dsh-auth] 登录后可在 设置 > 认证 中修改；change it in Settings > Auth after login.")
  console.log("")
  return true
}
if (maybeResetFromArgv()) process.exit(0)

// ── 登录页（内嵌，零资源） ──
const LOGIN_PAGE = "<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>登录 · dsh</title>\n<style>\n  * { box-sizing: border-box; margin: 0; padding: 0; }\n  body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0d1117; color: #e6edf3; font-family: -apple-system, \"Segoe UI\", \"PingFang SC\", \"Microsoft YaHei\", sans-serif; }\n  .card { width: 340px; max-width: 92vw; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px 24px; }\n  h1 { font-size: 18px; margin-bottom: 4px; }\n  .sub { font-size: 12px; color: #8b949e; margin-bottom: 22px; }\n  label { display: block; font-size: 13px; color: #c9d1d9; margin-bottom: 6px; }\n  input { width: 100%; padding: 9px 12px; margin-bottom: 16px; border-radius: 8px; border: 1px solid #30363d; background: #0d1117; color: #e6edf3; font-size: 14px; outline: none; }\n  input:focus { border-color: #4f8cff; }\n  button { width: 100%; padding: 10px; border: none; border-radius: 8px; cursor: pointer; background: #2f6feb; color: #fff; font-size: 14px; font-weight: 600; }\n  button:hover { background: #3a7bfd; }\n  .err { margin-top: 14px; font-size: 13px; color: #f85149; min-height: 18px; }\n  .hint { margin-top: 16px; font-size: 12px; color: #8b949e; line-height: 1.7; }\n  code { background: #21262d; padding: 1px 5px; border-radius: 4px; }\n</style>\n</head>\n<body>\n  <form class=\"card\" id=\"form\">\n    <h1>DeepSeek Harness</h1>\n    <div class=\"sub\">需要认证 · authentication required</div>\n    <label for=\"password\">密码 / Password</label>\n    <input id=\"password\" type=\"password\" autocomplete=\"current-password\" autofocus required>\n    <button type=\"submit\">登录 / Sign in</button>\n    <div class=\"err\" id=\"err\"></div>\n    <div class=\"hint\">初始密码见服务器启动日志；忘记可运行 <code>dsh web p</code> 重置。<br>\n    Initial password is printed in the server log; reset with <code>dsh web p</code>.</div>\n  </form>\n<script>\n  var form = document.getElementById('form')\n  var err = document.getElementById('err')\n  var input = document.getElementById('password')\n  fetch('/api/auth/status').then(function (r) { return r.json() }).then(function (j) {\n    if (j && j.authenticated) location.href = '/'\n  }).catch(function () {})\n  form.addEventListener('submit', function (e) {\n    e.preventDefault()\n    err.textContent = ''\n    fetch('/api/auth/login', {\n      method: 'POST',\n      headers: { 'content-type': 'application/json' },\n      body: JSON.stringify({ password: input.value })\n    }).then(function (r) { return r.json() }).then(function (j) {\n      if (j && j.ok) { location.href = '/' }\n      else { err.textContent = '密码错误 / wrong password'; input.select() }\n    }).catch(function () { err.textContent = '网络错误 / network error' })\n  })\n</script>\n</body>\n</html>\n"

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

  // 首次启动：生成并打印初始密码
  if (enabled && !store.password) {
    const pw = randomPassword()
    store.password = hashPassword(pw)
    saveStore(store)
    console.log("")
    console.log("[dsh-auth] 首次启动已生成初始密码 / initial password generated: " + pw)
    console.log("[dsh-auth] 登录后请在 设置 > 认证 中修改；可用 dsh web p 重置。")
    console.log("")
    ctx.logger.info("[dsh-auth] initial password generated (see console)")
  }

  // 公开路由（无需登录）
  ws.register({ kind: 'exact', path: '/login', handler: (req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(LOGIN_PAGE) })
    res.end(LOGIN_PAGE)
  } })

  ws.register({ kind: 'exact', path: '/api/auth/login', handler: async (req, res) => {
    let body
    try { body = JSON.parse((await readBody(req)) || '{}') } catch { return json(res, 400, { ok: false, error: 'bad_json' }) }
    const password = typeof body.password === 'string' ? body.password : ''
    if (!password) return json(res, 400, { ok: false, error: 'password_required' })
    if (!verifyPassword(password, store.password)) return json(res, 401, { ok: false, error: 'invalid_password' })
    const token = createSession(store)
    saveStore(store)
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
    const authed = enabled && !!authorize(store, token)
    json(res, 200, { ok: true, authenticated: authed, enabled, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes, passwordSet: !!store.password })
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
      json(res, 200, { ok: true, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes })
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
    if (changed) saveStore(store)
    json(res, 200, { ok: true, idleMinutes: store.idleMinutes, maxAgeMinutes: store.maxAgeMinutes })
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
      if (t !== token) delete store.sessions[t]
    }
    saveStore(store)
    json(res, 200, { ok: true })
  } })

  // 空闲/过期会话定时清扫
  const timer = setInterval(() => {
    if (sweep(store)) saveStore(store)
  }, SWEEP_INTERVAL_MS)
  ctx.effect(() => () => clearInterval(timer), 'dsh-auth: session sweep')
}
