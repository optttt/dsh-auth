# dsh-auth

DeepSeek Harness 认证插件：访问 dsh web 需要登录；空闲 N 分钟自动登出；
认证有效期（会话最长存活）；设置界面可改密码与过期时间；`dsh web p` 重置密码。

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

- 首次启动会在服务器控制台打印初始密码（之后访问 127.0.0.1:3080 会被重定向到 /login）。
- **设置 > 认证**：修改空闲登出分钟数、认证有效期、修改密码、退出登录。
- 忘记密码：`dsh web p`（生成随机密码并打印）或 `dsh web p 我的密码`（指定新密码）。

## 数据

认证数据存于 `$DSH_HOME/auth.json`（默认 `~/.dsh/auth.json`）：

- 密码：scrypt 加盐哈希（node:crypto，零运行时依赖）
- 会话：随机 token + HttpOnly/SameSite Cookie，空闲超时与有效期到期自动失效
- 修改密码后其余会话全部作废，仅保留当前会话

## 安全说明

- 认证仅保护 web 表面（HTTP/API/WebSocket 升级均在网关上拦截）
- 初始密码务必在首次登录后修改；生产环境请配合 HTTPS 反代使用
