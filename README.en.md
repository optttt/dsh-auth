# dsh-auth

Authentication plugin for DeepSeek Harness: accessing dsh web requires sign-in
(username + password); idle sessions log out automatically; sessions expire
after a configurable max age; single sign-on mode; the settings UI changes the
username / password / expiry times; `dsh web p` resets the password and
`dsh web u` changes the username.

- GitHub: https://github.com/optttt/dsh-auth
- npm: https://www.npmjs.com/package/@tyler9061/dsh-auth

## Install

From npm (recommended):

```
dsh plugin --profile web add @tyler9061/dsh-auth
```

From a source directory (development; live-links local code):

```
dsh plugin --profile web add link:/path/to/dsh-auth
```

Restart dsh web after installing.

## Usage

- On first start the server console prints the initial **username** and
  **password** (default username `admin`). Visiting the web UI redirects to /login.
- **Settings > Auth**: change username / password, idle logout minutes,
  session max age (minutes), single sign-on, and sign out.
- **Single sign-on**: when enabled, every new login invalidates all other
  sessions. Kicked clients land on the login page with a warning —
  "if this was not you, change the password immediately".
- Forgot credentials: `dsh web p` prints a new random password (or
  `dsh web p mypass`); `dsh web u newname` changes the username
  (3-32 chars, letters/digits/`_``-`).

## Network access (LAN)

The real server binds `127.0.0.1` only; the plugin runs a reverse proxy on
`0.0.0.0:<lanPort>` (default 3080, override with `DSH_AUTH_PORT`) that
forwards to loopback and rewrites Host/Origin, so the built-in /api trust fence
accepts every request — **all /api RPCs (settings, files, SCM, other plugins)
work from LAN clients**. The auth gateway still protects everything.

- LAN URL: `http://<LAN-IP>:3080` (printed at startup).
- `--host 0.0.0.0` stays rejected by the CLI; use the proxy defaults.

## i18n & theme

- UI strings follow the main client language (zh/en via `ctx.locale`);
  the login page follows the browser language.
- The settings UI uses the main client design tokens (`--dsw-alias-*`) and
  adapts to light/dark themes automatically.

## Data

Stored in `$DSH_HOME/auth.json` (default `~/.dsh/auth.json`):

- Password: scrypt salted hash (node:crypto, zero runtime dependencies)
- Sessions: random tokens + HttpOnly/SameSite cookies; idle timeout and
  max-age expiry are enforced; password/username changes and single sign-on
  invalidate other sessions and notify the kicked clients
- Username: default `admin`; change via CLI or the settings UI

## Security notes

- Auth protects the whole web surface (HTTP/API/WebSocket upgrades pass the gateway)
- Change the initial password after first login; use HTTPS in production
