// dsh-auth — 浏览器端：设置 > 认证 区块（用户名/密码/单点登录/过期时间/登出）。
// 国际化跟随主客户端（ctx.locale），颜色跟随主客户端主题（--dsw-alias-* 令牌）。
window.__ModuleLoader__.load({
  id: '@tyler9061/dsh-auth',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    var react = require('react')
    var jsxRuntime = require('react/jsx-runtime')

    var NS = "dsh-auth"
    var DICTS = {
      zh: {
        authTitle: "认证设置", idleLabel: "空闲登出（分钟）· Idle logout (min)", maxAgeLabel: "认证有效期（分钟）· Session max age (min)",
        save: "保存 / Save", saved: "已保存 / saved", ssoTitle: "单点登录 / Single sign-on", ssoOn: "已开启：每次新登录会使其他所有会话失效",
        ssoOff: "已关闭：允许多个设备同时在线", ssoTurnOn: "开启单点登录 / Turn SSO on", ssoTurnOff: "关闭单点登录 / Turn SSO off",
        ssoEnabledMsg: "已开启单点登录：新登录会踢掉旧会话", ssoDisabledMsg: "已关闭单点登录",
        pwTitle: "修改密码 / Change password", curPw: "当前密码 / Current password", newPw: "新密码 / New password", confirmPw: "确认新密码 / Confirm new password",
        updatePw: "修改密码 / Update", pwUpdated: "密码已修改 / password updated", pwMismatch: "两次输入的新密码不一致 / passwords do not match",
        userTitle: "用户名 / Username", changeUser: "修改用户名 / Change username", userUpdated: "用户名已修改 / username updated",
        curPwForUser: "当前密码（验证）/ Current password (verify)", newUser: "新用户名（3-32位字母数字_-）/ New username",
        logout: "退出登录 / Log out", failed: "操作失败 / failed", net: "网络错误 / network error",
        loginHistoryTitle: "登录记录 / Login history", loginHistorySub: "最近成功登录的 IP、时间与地点",
        loginEmpty: "暂无登录记录", historyTime: "时间", historyIp: "IP", historyLoc: "地点"
      },
      en: {
        authTitle: "Authentication", idleLabel: "Idle logout (min)", maxAgeLabel: "Session max age (min)",
        save: "Save", saved: "Saved", ssoTitle: "Single sign-on", ssoOn: "ON: each new login invalidates all other sessions",
        ssoOff: "OFF: multiple devices allowed", ssoTurnOn: "Turn SSO on", ssoTurnOff: "Turn SSO off",
        ssoEnabledMsg: "SSO on: new logins kick old sessions", ssoDisabledMsg: "SSO off",
        pwTitle: "Change password", curPw: "Current password", newPw: "New password", confirmPw: "Confirm new password",
        updatePw: "Update", pwUpdated: "Password updated", pwMismatch: "Passwords do not match",
        userTitle: "Username", changeUser: "Change username", userUpdated: "Username updated",
        curPwForUser: "Current password (verify)", newUser: "New username (3-32 chars, letters/digits/_-)",
        logout: "Log out", failed: "Failed", net: "Network error",
        loginHistoryTitle: "Login history", loginHistorySub: "Recent successful logins (IP, time, location)",
        loginEmpty: "No logins yet", historyTime: "Time", historyIp: "IP", historyLoc: "Location"
      }
    };

    var inputStyle = { width: "100%", padding: "8px 10px", margin: "6px 0 12px", borderRadius: 8, border: "1px solid var(--dsw-alias-border-l2, #30363d)", background: "var(--dsw-alias-bg-base, #0d1117)", color: "var(--dsw-alias-label-primary, #e6edf3)", fontSize: 14, boxSizing: "border-box" }
    var labelStyle = { display: "block", fontSize: 13, color: "var(--dsw-alias-label-secondary, #c9d1d9)", marginTop: 2 }
    var okStyle = { marginTop: 10, fontSize: 13, color: "var(--dsw-alias-state-success-primary, #3fb950)" }
    var errStyle = { marginTop: 10, fontSize: 13, color: "var(--dsw-alias-state-error-primary, #f85149)" }
    var btnStyle = { padding: "8px 18px", borderRadius: 8, border: "none", background: "var(--dsw-alias-button-primary-fill, #2f6feb)", color: "var(--dsw-alias-label-primary-foreground, #fff)", fontSize: 14, cursor: "pointer" }
    var btnPlain = { padding: "8px 18px", borderRadius: 8, border: "1px solid var(--dsw-alias-border-l2, #30363d)", background: "transparent", color: "var(--dsw-alias-label-primary, #e6edf3)", fontSize: 14, cursor: "pointer" }
    var btnDanger = { padding: "8px 18px", borderRadius: 8, border: "1px solid var(--dsw-alias-state-error-primary, #f85149)", background: "transparent", color: "var(--dsw-alias-state-error-primary, #f85149)", fontSize: 14, cursor: "pointer" }
    var hStyle = { fontSize: 14, fontWeight: 600, margin: "0 0 12px", color: "var(--dsw-alias-label-primary, #e6edf3)" }
    var boxStyle = { background: "var(--dsw-alias-bg-layer-1, #161b22)", border: "1px solid var(--dsw-alias-border-l2, #30363d)", borderRadius: 10, padding: "16px 18px", marginBottom: 16, maxWidth: 520 }
    var mutedStyle = { fontSize: 13, color: "var(--dsw-alias-label-tertiary, #8b949e)", marginBottom: 10 }

    function fmtTime(iso) { try { return new Date(iso).toLocaleString() } catch (e) { return iso || "" } }
    function locText(entry) { var l = entry && entry.location; if (!l) return "—"; return [l.country, l.region, l.city].filter(Boolean).join(" ") || "—" }

    function makeSection(t) {
      return function AuthSection() {
        var settings = react.useState({ idle: 30, maxAge: 1440, sso: false, username: "", msg: "", err: "" })
        var s = settings[0], setS = settings[1]
        var pw = react.useState({ cur: "", next: "", next2: "", msg: "", err: "" })
        var p = pw[0], setP = pw[1]
        var un = react.useState({ cur: "", name: "", msg: "", err: "" })
        var u = un[0], setU = un[1]
        var his = react.useState({ list: [] })
        var h = his[0], setH = his[1]
        function patch(setter, patchObj) { setter(function (prev) { return Object.assign({}, prev, patchObj) }) }

        react.useEffect(function () {
          fetch('/api/auth/settings', { credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j && typeof j.idleMinutes === "number") patch(setS, { idle: j.idleMinutes, maxAge: j.maxAgeMinutes, sso: !!j.singleSession, username: j.username || "" }) })
          .catch(function () {})
        }, [])

        react.useEffect(function () {
          fetch('/api/auth/login-history', { credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j && Array.isArray(j.history)) setH({ list: j.history }) })
          .catch(function () {})
        }, [])

        function saveSettings(ev) {
          ev.preventDefault()
          patch(setS, { msg: "", err: "" })
          fetch('/api/auth/settings', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idleMinutes: Number(s.idle), maxAgeMinutes: Number(s.maxAge) }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) patch(setS, { msg: t("saved") }); else patch(setS, { err: j.error || t("failed") }) })
          .catch(function () { patch(setS, { err: t("net") }) })
        }

        function toggleSso() {
          patch(setS, { msg: "", err: "" })
          var next = !s.sso
          fetch('/api/auth/settings', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ singleSession: next }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) patch(setS, { sso: !!j.singleSession, msg: next ? t("ssoEnabledMsg") : t("ssoDisabledMsg") }); else patch(setS, { err: j.error || t("failed") }) })
          .catch(function () { patch(setS, { err: t("net") }) })
        }

        function changePassword(ev) {
          ev.preventDefault()
          patch(setP, { msg: "", err: "" })
          if (p.next !== p.next2) { patch(setP, { err: t("pwMismatch") }); return }
          fetch('/api/auth/change-password', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ current: p.cur, next: p.next }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) setP({ cur: "", next: "", next2: "", msg: t("pwUpdated"), err: "" }); else patch(setP, { err: j.error || t("failed") }) })
          .catch(function () { patch(setP, { err: t("net") }) })
        }

        function changeUsername(ev) {
          ev.preventDefault()
          patch(setU, { msg: "", err: "" })
          fetch('/api/auth/change-username', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ current: u.cur, username: u.name }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) { patch(setU, { cur: "", name: "", msg: t("userUpdated"), err: "" }); patch(setS, { username: j.username }) } else patch(setU, { err: j.error || t("failed") }) })
          .catch(function () { patch(setU, { err: t("net") }) })
        }

        function logout() {
          fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j && j.ok) window.location.href = "/login" })
          .catch(function () {})
        }

        return jsxRuntime.jsxs("div", { style: { maxWidth: 520 }, children: [
          jsxRuntime.jsxs("form", { onSubmit: saveSettings, style: boxStyle, children: [
            jsxRuntime.jsx("h4", { style: hStyle, children: t("authTitle") }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("idleLabel"), jsxRuntime.jsx("input", { type: "number", min: 1, max: 10080, value: s.idle, onChange: function (e) { patch(setS, { idle: e.target.value }) }, style: inputStyle })] }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("maxAgeLabel"), jsxRuntime.jsx("input", { type: "number", min: 5, max: 525600, value: s.maxAge, onChange: function (e) { patch(setS, { maxAge: e.target.value }) }, style: inputStyle })] }),
            jsxRuntime.jsx("button", { type: "submit", style: btnStyle, children: t("save") }),
            s.msg ? jsxRuntime.jsx("div", { style: okStyle, children: s.msg }) : null,
            s.err ? jsxRuntime.jsx("div", { style: errStyle, children: s.err }) : null
          ] }),
          jsxRuntime.jsxs("div", { style: boxStyle, children: [
            jsxRuntime.jsx("h4", { style: hStyle, children: t("ssoTitle") }),
            jsxRuntime.jsx("div", { style: mutedStyle, children: s.sso ? t("ssoOn") : t("ssoOff") }),
            jsxRuntime.jsx("button", { type: "button", onClick: toggleSso, style: s.sso ? btnPlain : btnStyle, children: s.sso ? t("ssoTurnOff") : t("ssoTurnOn") })
          ] }),
          jsxRuntime.jsxs("form", { onSubmit: changeUsername, style: boxStyle, children: [
            jsxRuntime.jsx("h4", { style: hStyle, children: t("userTitle") + (s.username ? ": " + s.username : "") }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("curPwForUser"), jsxRuntime.jsx("input", { type: "password", value: u.cur, onChange: function (e) { patch(setU, { cur: e.target.value }) }, style: inputStyle, autoComplete: "current-password" })] }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("newUser"), jsxRuntime.jsx("input", { type: "text", value: u.name, onChange: function (e) { patch(setU, { name: e.target.value }) }, style: inputStyle })] }),
            jsxRuntime.jsx("button", { type: "submit", style: btnStyle, children: t("changeUser") }),
            u.msg ? jsxRuntime.jsx("div", { style: okStyle, children: u.msg }) : null,
            u.err ? jsxRuntime.jsx("div", { style: errStyle, children: u.err }) : null
          ] }),
          jsxRuntime.jsxs("form", { onSubmit: changePassword, style: boxStyle, children: [
            jsxRuntime.jsx("h4", { style: hStyle, children: t("pwTitle") }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("curPw"), jsxRuntime.jsx("input", { type: "password", value: p.cur, onChange: function (e) { patch(setP, { cur: e.target.value }) }, style: inputStyle, autoComplete: "current-password" })] }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("newPw"), jsxRuntime.jsx("input", { type: "password", value: p.next, onChange: function (e) { patch(setP, { next: e.target.value }) }, style: inputStyle, autoComplete: "new-password" })] }),
            jsxRuntime.jsxs("label", { style: labelStyle, children: [t("confirmPw"), jsxRuntime.jsx("input", { type: "password", value: p.next2, onChange: function (e) { patch(setP, { next2: e.target.value }) }, style: inputStyle, autoComplete: "new-password" })] }),
            jsxRuntime.jsx("button", { type: "submit", style: btnStyle, children: t("updatePw") }),
            p.msg ? jsxRuntime.jsx("div", { style: okStyle, children: p.msg }) : null,
            p.err ? jsxRuntime.jsx("div", { style: errStyle, children: p.err }) : null
          ] }),
          jsxRuntime.jsxs("div", { style: boxStyle, children: [
            jsxRuntime.jsx("h4", { style: hStyle, children: t("loginHistoryTitle") }),
            jsxRuntime.jsx("div", { style: mutedStyle, children: t("loginHistorySub") }),
            h.list.length === 0 ? jsxRuntime.jsx("div", { style: mutedStyle, children: t("loginEmpty") })
            : jsxRuntime.jsxs("div", { children: h.list.map(function (e, i) {
                return jsxRuntime.jsx("div", { style: { display: "flex", justifyContent: "space-between", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--dsw-alias-border-l2, #30363d)", fontSize: 13 }, children: [
                  jsxRuntime.jsx("span", { style: { minWidth: 130 }, children: fmtTime(e.time) }),
                  jsxRuntime.jsx("span", { style: { minWidth: 90, textAlign: "center" }, children: e.ip }),
                  jsxRuntime.jsx("span", { style: { textAlign: "right", color: "var(--dsw-alias-label-tertiary, #8b949e)", marginLeft: "auto" }, children: locText(e) })
                ] }, "hist-" + i)
              }) })
          ] }),
          jsxRuntime.jsx("div", { style: { marginBottom: 16 }, children: jsxRuntime.jsx("button", { type: "button", onClick: logout, style: btnDanger, children: t("logout") }) })
        ] })
      }
    }

    // 会话失效（空闲登出/被踢/到期）自动回登录页；kicked 带原因提示
    function startIdleKick(ctx) {
      var timer = setInterval(function () {
        fetch('/api/auth/status', { credentials: 'same-origin' })
        .then(function (r) { return r.json() })
        .then(function (j) {
          if (!j || j.authenticated) return
          if (window.location.pathname === "/login") return
          var q = j.kicked ? "?kicked=" + encodeURIComponent(j.kicked) : ""
          window.location.href = "/login" + q
        })
        .catch(function () {})
      }, 30000)
      return function () { clearInterval(timer) }
    }

    function apply(ctx) {
      ctx.effect(function () { return ctx.locale.register(NS, DICTS) }, "dsh-auth: dictionaries")
      var t = ctx.locale.bind(NS)
      var Section = makeSection(t)
      ctx.effect(function () {
        return ctx.slots.register({ name: "settings.section", id: "auth", order: 50, label: function () { return t("authTitle") }, locale: NS, children: { "settings.auth.item": { kind: "list", scope: "root" } } }, Section)
      }, "dsh-auth: settings section")
      ctx.effect(startIdleKick, "dsh-auth: idle kick")
    }

    exports.apply = apply
    exports.inject = ['slots', 'locale', 'connection']
    return module.exports
  }
})
