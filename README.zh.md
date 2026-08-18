# dsh-auth

[English](./README.md) | 中文

DeepSeek Harness 认证插件：访问 dsh web 需要登录（用户名+密码）；空闲 N 分钟自动登出；
认证有效期；单点登录；设置界面可改用户名/密码/过期时间；`dsh web p` 重置密码、
`dsh web u` 改用户名。

- GitHub: https://github.com/optttt/dsh-auth
- npm: https://www.npmjs.com/package/@tyler9061/dsh-auth

## 安装

从 npm 安装（推荐）：

```
dsh plugin --profile web add @tyler9061/dsh-auth
```

从源码目录安装（开发调试，实时联动本地代码）：

```
dsh plugin --profile web add link:/path/to/dsh-auth
```

安装后重启 dsh web 生效。

## 使用

- 首次启动会在服务器控制台打印**用户名和密码**（默认用户名 `admin`）。之后访问
  `127.0.0.1:3080`（或局域网地址）会被重定向到 /login。
- **设置 > 认证**：修改用户名 / 密码、空闲登出分钟数、认证有效期、单点登录、退出登录。
- **单点登录**：开启后每次新登录会使其他所有会话失效；被踢的旧客户端回到登录页并显示
  提醒——「如非本人操作，请立即修改密码」。
- 忘记凭据：`dsh web p` 生成随机密码并打印（或 `dsh web p 我的密码`）；
  `dsh web u 新用户名` 修改用户名（3-32 位字母数字 `_``-`）。

## 网络访问（局域网）

真实服务器只绑 `127.0.0.1`，插件另起一个 `0.0.0.0:<lanPort>` 的反向代理
（默认 3080，可用环境变量 `DSH_AUTH_PORT` 覆盖）把请求转给回环，并改写 Host/Origin，
使 DSH 自带的 /api 信任围栏按回环放行——**局域网下所有 /api（设置、文件、变更、
其他插件）都可用**。认证网关仍保护整个表面（登录后才能访问）。

- 局域网地址：`http://<本机IP>:3080`（启动日志会打印）
- `--host 0.0.0.0` 仍被 CLI 拒绝；对外访问走代理默认配置即可
- 代理正确透传 WebSocket 升级首帧数据（不作为 HTTP 请求体发送），任一端断开即关闭
  另一端，避免残留半开隧道

## 国际化与主题

- 插件 UI 文案跟随主客户端语言（中/英，`ctx.locale`）；登录页按浏览器语言切换
- 设置界面颜色使用主客户端设计令牌（`--dsw-alias-*`），亮/暗主题自动适配

## 数据

认证数据存于 `$DSH_HOME/auth.json`（默认 `~/.dsh/auth.json`）：

- 密码：scrypt 加盐哈希（node:crypto，零运行时依赖）
- 会话：随机 token + HttpOnly/SameSite Cookie；空闲超时与有效期到期自动失效；
  改密码/改用户名/单点登录会作废其他会话并给被踢客户端留提醒；
  空闲活跃时间会节流持久化，进程重启后空闲计时不丢失
- 用户名：默认 `admin`，可用 CLI 或设置界面修改

## 开发

```
npm test        # node:test 单元测试
```

## 安全说明

- 认证保护整个 web 表面（HTTP/API/WebSocket 升级均过网关）
- 初始密码务必在首次登录后修改；生产环境建议配合 HTTPS 反代
