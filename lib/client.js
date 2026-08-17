// dsh-auth — 浏览器端：在 设置 中注册「认证」区块（改密码 / 空闲登出 / 有效期）。
// lazy-CJS bundle 协议（同 modlens），零构建；React 由客户端模块表提供。
window.__ModuleLoader__.load({
  id: 'dsh-auth',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    var react = require('react')
    var jsxRuntime = require('react/jsx-runtime')

    var inputStyle = { width: '100%', padding: '8px 10px', margin: '6px 0 12px', borderRadius: 8, border: '1px solid #30363d', background: '#0d1117', color: '#e6edf3', fontSize: 14, boxSizing: 'border-box' }
    var labelStyle = { display: 'block', fontSize: 13, color: '#c9d1d9', marginTop: 2 }
    var okStyle = { marginTop: 10, fontSize: 13, color: '#3fb950' }
    var errStyle = { marginTop: 10, fontSize: 13, color: '#f85149' }
    var btnStyle = { padding: '8px 18px', borderRadius: 8, border: 'none', background: '#2f6feb', color: '#fff', fontSize: 14, cursor: 'pointer' }
    var hStyle = { fontSize: 14, fontWeight: 600, margin: '0 0 12px' }
    var boxStyle = { background: '#161b22', border: '1px solid #30363d', borderRadius: 10, padding: '16px 18px', marginBottom: 16, maxWidth: 520 }
    var dangerBtnStyle = { padding: '8px 18px', borderRadius: 8, border: '1px solid #f85149', background: 'transparent', color: '#f85149', fontSize: 14, cursor: 'pointer' }

    function AuthSection() {
      var settings = react.useState({ idle: 30, maxAge: 1440, msg: "", err: "" })
      var s = settings[0], setS = settings[1]
      var pw = react.useState({ cur: "", next: "", next2: "", msg: "", err: "" })
      var p = pw[0], setP = pw[1]
      function patch(setter, patchObj) { setter(function (prev) { return Object.assign({}, prev, patchObj) }) }

      react.useEffect(function () {
        fetch('/api/auth/settings', { credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j && typeof j.idleMinutes === "number") patch(setS, { idle: j.idleMinutes, maxAge: j.maxAgeMinutes }) })
          .catch(function () {})
      }, [])

      function saveSettings(ev) {
        ev.preventDefault()
        patch(setS, { msg: "", err: "" })
        fetch('/api/auth/settings', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idleMinutes: Number(s.idle), maxAgeMinutes: Number(s.maxAge) }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) patch(setS, { msg: "已保存 / saved" }); else patch(setS, { err: j.error || "failed" }) })
          .catch(function () { patch(setS, { err: "network error" }) })
      }

      function logout() {
        fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j && j.ok) window.location.href = '/login' })
          .catch(function () {})
      }

      function changePassword(ev) {
        ev.preventDefault()
        patch(setP, { msg: "", err: "" })
        if (p.next !== p.next2) { patch(setP, { err: "两次输入的新密码不一致 / passwords do not match" }); return }
        fetch('/api/auth/change-password', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ current: p.cur, next: p.next }) })
          .then(function (r) { return r.json() })
          .then(function (j) { if (j.ok) setP({ cur: "", next: "", next2: "", msg: "密码已修改 / password updated", err: "" }); else patch(setP, { err: j.error || "failed" }) })
          .catch(function () { patch(setP, { err: "network error" }) })
      }

      return jsxRuntime.jsxs("div", { style: { maxWidth: 520 }, children: [
        jsxRuntime.jsxs("form", { onSubmit: saveSettings, style: boxStyle, children: [
          jsxRuntime.jsx("h4", { style: hStyle, children: "认证设置 / Authentication" }),
          jsxRuntime.jsxs("label", { style: labelStyle, children: ["空闲登出（分钟）· Idle logout (min)", jsxRuntime.jsx("input", { type: "number", min: 1, max: 10080, value: s.idle, onChange: function (e) { patch(setS, { idle: e.target.value }) }, style: inputStyle })] }),
          jsxRuntime.jsxs("label", { style: labelStyle, children: ["认证有效期（分钟）· Session max age (min)", jsxRuntime.jsx("input", { type: "number", min: 5, max: 525600, value: s.maxAge, onChange: function (e) { patch(setS, { maxAge: e.target.value }) }, style: inputStyle })] }),
          jsxRuntime.jsx("button", { type: "submit", style: btnStyle, children: "保存 / Save" }),
          s.msg ? jsxRuntime.jsx("div", { style: okStyle, children: s.msg }) : null,
          s.err ? jsxRuntime.jsx("div", { style: errStyle, children: s.err }) : null
        ] }),
        jsxRuntime.jsxs("form", { onSubmit: changePassword, style: boxStyle, children: [
          jsxRuntime.jsx("h4", { style: hStyle, children: "修改密码 / Change password" }),
          jsxRuntime.jsxs("label", { style: labelStyle, children: ["当前密码 / Current password", jsxRuntime.jsx("input", { type: "password", value: p.cur, onChange: function (e) { patch(setP, { cur: e.target.value }) }, style: inputStyle, autoComplete: "current-password" })] }),
          jsxRuntime.jsxs("label", { style: labelStyle, children: ["新密码 / New password", jsxRuntime.jsx("input", { type: "password", value: p.next, onChange: function (e) { patch(setP, { next: e.target.value }) }, style: inputStyle, autoComplete: "new-password" })] }),
          jsxRuntime.jsxs("label", { style: labelStyle, children: ["确认新密码 / Confirm new password", jsxRuntime.jsx("input", { type: "password", value: p.next2, onChange: function (e) { patch(setP, { next2: e.target.value }) }, style: inputStyle, autoComplete: "new-password" })] }),
          jsxRuntime.jsx("button", { type: "submit", style: btnStyle, children: "修改密码 / Update" }),
          p.msg ? jsxRuntime.jsx("div", { style: okStyle, children: p.msg }) : null,
          p.err ? jsxRuntime.jsx("div", { style: errStyle, children: p.err }) : null
        ] }),
        jsxRuntime.jsx("div", { style: { marginBottom: 16 }, children: jsxRuntime.jsx("button", { type: "button", onClick: logout, style: dangerBtnStyle, children: "退出登录 / Log out" }) })
      ] })
    }

    // 会话过期（空闲登出 / 认证到期）后自动回到登录页：30s 轮询公开状态接口。
    function startIdleKick(ctx) {
      var timer = setInterval(function () {
        fetch('/api/auth/status', { credentials: 'same-origin' })
          .then(function (r) { return r.json() })
          .then(function (j) {
            if (j && !j.authenticated && window.location.pathname !== '/login') window.location.href = '/login'
          })
          .catch(function () {})
      }, 30000)
      return function () { clearInterval(timer) }
    }

    function apply(ctx) {
      ctx.effect(function () {
        return ctx.slots.register({ name: "settings.section", id: "auth", order: 50, label: "认证 / Auth", locale: "dsh-auth", children: { "settings.auth.item": { kind: "list", scope: "root" } } }, AuthSection)
      }, "dsh-auth: settings section")
      ctx.effect(startIdleKick, "dsh-auth: idle kick")
    }

    exports.apply = apply
    exports.inject = ['slots', 'locale', 'connection']
    return module.exports
  }
})
