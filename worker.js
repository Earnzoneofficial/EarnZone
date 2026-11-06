
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...extra
    }
  });
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );

  return {
    salt: toBase64(salt),
    hash: toBase64(new Uint8Array(bits))
  };
}

async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;

  const salt = fromBase64(parts[1]);
  const expected = fromBase64(parts[2]);
  const result = await hashPassword(password, salt);
  const actual = fromBase64(result.hash);

  if (actual.length !== expected.length) return false;

  let difference = 0;
  for (let i = 0; i < actual.length; i++) {
    difference |= actual[i] ^ expected[i];
  }
  return difference === 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64(new Uint8Array(digest));
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : null;
}

async function createSession(env, userId) {
  const token = toBase64(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  ).bind(userId, tokenHash, expires).run();

  return {
    "Set-Cookie": `ez_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  };
}

async function getUser(request, env) {
  const token = getCookie(request, "ez_session");
  if (!token) return null;

  const tokenHash = await sha256(token);

  return await env.DB.prepare(`
    SELECT users.id, users.username, users.email,
           users.coins, users.balance_usd, users.status
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
      AND users.status = 'active'
  `).bind(tokenHash, new Date().toISOString()).first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/api/health") {
        return json({ status: "online", project: "EarnZone" });
      }

      if (path === "/api/db-test") {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type='table'"
        ).all();

        return json({
          status: "success",
          database: "connected",
          tables: result.results
        });
      }

      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (username.length < 3 || username.length > 30) {
          return json({ error: "Username must be 3-30 characters." }, 400);
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ error: "Enter a valid email address." }, 400);
        }

        if (password.length < 8 || password.length > 128) {
          return json({ error: "Password must be 8-128 characters." }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE email = ? OR username = ?"
        ).bind(email, username).first();

        if (existing) {
          return json({ error: "Email or username already exists." }, 409);
        }

        const passwordData = await hashPassword(password);
        const passwordHash = `pbkdf2$${passwordData.salt}$${passwordData.hash}`;

        const result = await env.DB.prepare(
          "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
        ).bind(username, email, passwordHash).run();

        const headers = await createSession(env, result.meta.last_row_id);

        return json({ success: true, message: "Account created." }, 201, headers);
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        const user = await env.DB.prepare(
          "SELECT id, password_hash, status FROM users WHERE email = ?"
        ).bind(email).first();

        if (!user || user.status !== "active" ||
            !(await verifyPassword(password, user.password_hash))) {
          return json({ error: "Invalid email or password." }, 401);
        }

        const headers = await createSession(env, user.id);
        return json({ success: true, message: "Login successful." }, 200, headers);
      }

      if (path === "/api/me" && request.method === "GET") {
        const user = await getUser(request, env);

        if (!user) return json({ error: "Please login." }, 401);

        return json({ success: true, user });
      }

      if (path === "/api/logout" && request.method === "POST") {
        const token = getCookie(request, "ez_session");

        if (token) {
          const tokenHash = await sha256(token);
          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(tokenHash).run();
        }

        return json(
          { success: true, message: "Logged out." },
          200,
          { "Set-Cookie": "ez_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" }
        );
      }

      return env.ASSETS.fetch(request);

    } catch (error) {
      return json({ error: "Server error. Please try again." }, 500);
    }
  }
};
