// dsh-auth 单元测试（node:test，零依赖，运行：npm test / node --test test/）
// 验证两项 Bug 修复：
//   Bug 1 — WebSocket 升级时客户端 head 数据经代理隧道透传（不再被当作 HTTP 请求体）
//   Bug 2 — 会话 lastActiveAt 节流持久化（进程重启后空闲计时不丢失）
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createServer as createHttpServer } from 'node:http'
import { connect as netConnect } from 'node:net'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply, _test } from '../lib/index.js'

// ── 工具 ──
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function makeWebServer() {
  const routes = []
  const server = {
    port: undefined,
    routes,
    upgrades: new Map(),
    register(route) { routes.push(route) },
    match() { return undefined },
    registerFallback() {},
    fallback: undefined,
    registerUpgrade(route) { this.upgrades.set(route.path, route) },
    tapIndex(html) { return html }
  }
  return server
}

function makeCtx(ws) {
  const ctx = { webServer: ws, effects: [], logger: { warn() {}, info() {} } }
  // dsh 约定：ctx.effect(fn) 注册时调用 fn()，返回值为清理函数
  ctx.effect = (fn) => { ctx.effects.push(fn()) }
  return ctx
}

function findRoute(ws, path) {
  return ws.routes.find((r) => r.path === path)
}

function makeReq({ method = 'GET', url = '/', headers = {}, body } = {}) {
  const req = new EventEmitter()
  req.method = method
  req.url = url
  req.headers = headers
  setImmediate(() => {
    if (body) req.emit('data', String(body))
    req.emit('end')
  })
  return req
}

function makeRes() {
  const res = { statusCode: null, headers: null, body: '' }
  res.writeHead = function (status, headers) { this.statusCode = status; this.headers = headers; return this }
  res.end = function (chunk) { this.body = (chunk ?? '').toString(); return this }
  return res
}

function collectUntil(socket, predicate, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let timer
    const finish = () => { clearTimeout(timer); socket.off('data', onData); socket.off('error', onError) }
    const onData = (d) => {
      chunks.push(d)
      if (predicate(Buffer.concat(chunks))) { finish(); resolve(Buffer.concat(chunks)) }
    }
    const onError = (e) => { finish(); reject(e) }
    timer = setTimeout(() => {
      finish()
      reject(new Error('timeout, got: ' + Buffer.concat(chunks).toString('hex')))
    }, timeoutMs)
    socket.on('data', onData)
    socket.on('error', onError)
  })
}

// 关闭服务器：优雅关闭（FIN 级联），超时兜底避免测试挂起
function closeServer(server, timeoutMs = 2000) {
  return new Promise((resolve) => {
    let done = false
    const finish = () => { if (!done) { done = true; clearTimeout(t); resolve() } }
    const t = setTimeout(finish, timeoutMs)
    server.close(finish)
  })
}

// ── 夹具：隔离的 DSH_HOME，避免污染真实数据 ──
let homeDir
let storeFile
const savedEnv = {}

before(() => {
  homeDir = mkdtempSync(join(tmpdir(), 'dsh-auth-test-'))
  savedEnv.DSH_HOME = process.env.DSH_HOME
  savedEnv.DSH_AUTH_PORT = process.env.DSH_AUTH_PORT
  process.env.DSH_HOME = homeDir
  delete process.env.DSH_AUTH_PORT
  storeFile = join(homeDir, 'auth.json')
})

after(() => {
  if (savedEnv.DSH_HOME === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = savedEnv.DSH_HOME
  if (savedEnv.DSH_AUTH_PORT === undefined) delete process.env.DSH_AUTH_PORT
  else process.env.DSH_AUTH_PORT = savedEnv.DSH_AUTH_PORT
  rmSync(homeDir, { recursive: true, force: true })
})

// ── Bug 2：会话 lastActiveAt 节流持久化 ──
test('Bug 2: 会话活跃时间 lastActiveAt 会被节流持久化', async () => {
  const ws = makeWebServer()
  const ctx = makeCtx(ws)

  // apply 首次运行会生成并打印初始密码，捕获它用于登录
  const logs = []
  const origLog = console.log
  console.log = (...args) => logs.push(args.join(' '))
  try {
    apply(ctx, { enabled: true, lanPort: 0, idleMinutes: 30, maxAgeMinutes: 1440 })
  } finally {
    console.log = origLog
  }
  const initLine = logs.find((l) => l.includes('初始账号'))
  assert.ok(initLine, '首次启动应打印初始账号')
  const password = initLine.match(/password:\s*(\S+)/)[1]

  // 登录 → 获得会话 cookie
  const loginRes = makeRes()
  await findRoute(ws, '/api/auth/login').handler(
    makeReq({
      method: 'POST',
      url: '/api/auth/login',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password })
    }),
    loginRes
  )
  assert.equal(loginRes.statusCode, 200, '登录应成功')
  const cookie = loginRes.headers['set-cookie']
  assert.ok(cookie.includes('dsh_auth='))
  const token = cookie.split(';')[0].split('=')[1]

  // 登录已落盘：lastActiveAt = 登录时刻
  const store0 = JSON.parse(readFileSync(storeFile, 'utf8'))
  assert.ok(store0.sessions[token], 'auth.json 应包含新会话')
  const lastActiveAt0 = store0.sessions[token].lastActiveAt

  // 等待超过节流间隔，令盘上 lastActiveAt 变“陈旧”
  await sleep(2500)

  // 未带 cookie 访问受保护路由应 401（认证网关生效的冒烟检查）
  const denied = makeRes()
  await findRoute(ws, '/api/auth/settings').handler(makeReq({ url: '/api/auth/settings' }), denied)
  assert.equal(denied.statusCode, 401, '未登录访问受保护路由应 401')

  // 带 cookie 访问受保护路由 → 网关 authorize 更新 lastActiveAt → 节流落盘
  const okRes = makeRes()
  await findRoute(ws, '/api/auth/settings').handler(
    makeReq({ url: '/api/auth/settings', headers: { cookie } }),
    okRes
  )
  assert.equal(okRes.statusCode, 200, '已登录访问受保护路由应 200')

  // 等待节流落盘完成
  await sleep(2500)

  // 验证：盘上 lastActiveAt 已更新为最近活跃时间（> 登录时刻 + 2000）
  const store1 = JSON.parse(readFileSync(storeFile, 'utf8'))
  assert.ok(store1.sessions[token], '会话在“重启”后仍存在')
  assert.ok(
    store1.sessions[token].lastActiveAt > lastActiveAt0 + 2000,
    `lastActiveAt 应被持久化更新（登录时=${lastActiveAt0}，持久化后=${store1.sessions[token].lastActiveAt}）`
  )
  assert.ok(
    Date.now() - store1.sessions[token].lastActiveAt < 5000,
    '持久化的 lastActiveAt 应为最近活跃时间（而非登录时刻）'
  )

  // 清理 apply 注册的资源（LAN 代理 / 定时器）
  for (const cleanup of [...ctx.effects].reverse()) {
    if (typeof cleanup === 'function') cleanup()
  }
})

// ── Bug 1：WebSocket 升级时 head 数据透传 ──
test('Bug 1: WebSocket 升级时客户端 head 数据经隧道透传', async () => {
  // 后端：接受升级，只回显“握手之后”到达的数据；忽略升级时的 head。
  // 真实 WS 服务器只在握手后收到数据帧；若 head 被当作请求体发来，这里不会回显。
  const headBytes = Buffer.from('hello-head-forwarded')
  const backendUpgraded = new Set()
  const backend = createHttpServer((req, res) => res.end('ok'))
  backend.on('upgrade', (req, socket) => {
    backendUpgraded.add(socket)
    socket.on('close', () => backendUpgraded.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
    socket.on('data', (d) => socket.write(d))
  })
  await new Promise((r) => backend.listen(0, '127.0.0.1', r))
  const backendPort = backend.address().port

  // 启动局域网代理（lanPort=0 → 随机端口）
  const ctx = { logger: { warn() {}, info() {} }, effect() {} }
  const proxy = _test.startLanProxy(ctx, { port: backendPort }, { lanPort: 0 })
  await new Promise((r) => proxy.once('listening', r))
  const proxyPort = proxy.address().port

  let client
  try {
    // 原始 TCP 直连代理：握手头与 head 数据一次性写出（模拟首帧随握手同包到达）
    client = netConnect(proxyPort, '127.0.0.1')
    const reqText = [
      'GET /ws HTTP/1.1',
      'Host: 127.0.0.1:' + proxyPort,
      'Connection: Upgrade',
      'Upgrade: websocket',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
      '',
      ''
    ].join('\r\n')

    const received = collectUntil(client, (buf) => buf.includes(headBytes))
    client.write(Buffer.concat([Buffer.from(reqText, 'utf8'), headBytes]))

    const buf = await received
    assert.ok(buf.toString('latin1').includes('101 Switching Protocols'), '应收到 101 升级响应')
    assert.ok(buf.includes(headBytes), 'head 数据应经代理隧道回显（修复后行为）')
  } finally {
    // 断开客户端并显式销毁后端升级连接（其关闭会级联关闭代理隧道）
    if (client) client.destroy()
    for (const s of backendUpgraded) s.destroy()
    backendUpgraded.clear()
    await sleep(100)
    await closeServer(backend)
    await closeServer(proxy)
  }
})
