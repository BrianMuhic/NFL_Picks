// Template functions for rendering HTML
function tplLayout(title, body, req, extras = '') {
  const user = req.session.user;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#0f172a; --card:#111827; --muted:#e5e7eb; --pri:#22c55e; --red:#ef4444; }
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:#e5e7eb;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto}
    a{color:#93c5fd;text-decoration:none} a:hover{text-decoration:underline}
    .wrap{max-width:960px;margin:0 auto;padding:24px}
    .nav{display:flex;gap:16px;align-items:center;justify-content:space-between;margin-bottom:16px}
    .card{background:var(--card);border:1px solid #1f2937;border-radius:16px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
    .btn{display:inline-block;padding:10px 14px;border-radius:10px;border:1px solid #374151;background:#1f2937;color:#e5e7eb;cursor:pointer}
    .btn-primary{background:var(--pri);border-color:#16a34a;color:#08180d;font-weight:700}
    .btn-danger{background:var(--red);border-color:#b91c1c;color:white}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
    .muted{color:var(--muted)}
    label{display:block;margin:10px 0 6px}
    input, select{width:100%;padding:10px;border-radius:8px;border:1px solid #374151;background:#0b1220;color:#e5e7eb}
    table{width:100%;border-collapse:separate;border-spacing:0 8px}
    th, td{padding:10px 12px;text-align:left}
    tr{background:#0b1220}
    tr td:first-child, tr th:first-child{border-top-left-radius:12px;border-bottom-left-radius:12px}
    tr td:last-child, tr th:last-child{border-top-right-radius:12px;border-bottom-right-radius:12px}
    .row{display:flex;gap:10px;align-items:center}
    .right{margin-left:auto}
    .pill{padding:4px 8px;border-radius:999px;background:#0b1220;border:1px solid #374151}
    .alert{padding:12px;border-radius:8px;margin-bottom:16px}
    .alert-success{background:#d1fae5;border:1px solid #10b981;color:#064e3b}
    .alert-warning{background:#fef3c7;border:1px solid #f59e0b;color:#78350f}
    .alert-error{background:#fecaca;border:1px solid #f87171;color:#7f1d1d}
  </style>
  ${extras}
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="row" style="gap:12px">
        <a href="/" class="btn">Home</a>
        <a href="/leaderboard" class="btn">Leaderboard</a>
        <a href="/games" class="btn">Games</a>
        <a href="/all-picks" class="btn">All Picks</a>
        ${user && user.is_admin ? `<a href="/admin" class="btn" style="background:#7c3aed;border-color:#6d28d9">Admin</a>` : ''}
      </div>
      <div class="row">
        ${user ? `<span class="pill">@${user.username}${user.is_admin ? ' (Admin)' : ''}</span> <form method="POST" action="/logout" style="margin:0"><input type="hidden" name="_csrf" value="${req.csrfToken()}"><button class="btn btn-danger">Logout</button></form>` : `<a class="btn" href="/login">Login</a><a class="btn btn-primary" href="/register">Sign up</a>`}
      </div>
    </div>
    ${body}
  </div>
</body>
</html>`;
}

function tplAuth(title, action, csrfToken, errorMsg = '') {
  return `
    <div class="card" style="max-width:480px;margin:40px auto;">
      <h1 style="margin-top:0">${title}</h1>
      ${errorMsg ? `<p class="muted" style="color:#fda4af">${errorMsg}</p>` : ''}
      <form method="POST" action="/${action}">
        <input type="hidden" name="_csrf" value="${csrfToken}">
        <label>Username</label>
        <input name="username" required minlength="3" maxlength="32" />
        <label>Password</label>
        <input name="password" type="password" required minlength="6" maxlength="72" />
        <div style="margin-top:14px" class="row">
          <button class="btn btn-primary">${title}</button>
          <span class="right muted">${action === 'login' ? 'No account?' : 'Already have an account?'} <a href="/${action === 'login' ? 'register' : 'login'}">${action === 'login' ? 'Sign up' : 'Log in'}</a></span>
        </div>
      </form>
    </div>
  `;
}

module.exports = { tplLayout, tplAuth };
