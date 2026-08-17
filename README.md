# dsh-auth

DeepSeek Harness 认证插件：访问 dsh web 需要登录；空闲 N 分钟自动登出；
认证有效期（会话最长存活）；设置界面可改密码与过期时间；`dsh web p` 重置密码。

## 安装

```
dsh plugin --profile web add <本目录或 npm 包名>
```

## 使用

- 首次启动会在服务器控制台打印初始密码。
- 浏览器访问被重定向到 /login，登录后进入主界面。
- 设置 > 认证：修改空闲登出分钟数、认证有效期、修改密码。
- 重置密码：`dsh web p`（生成随机密码并打印）或 `dsh web p 我的密码`。

数据存于 `$DSH_HOME/auth.json`（密码为 scrypt 加盐哈希，会话为随机 token + HttpOnly Cookie）。
