
const encoder = new TextEncoder();
const ADMIN_EMAIL = "rhbdgamer111@gmail.com";

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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
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
  if (!stored) return false;

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
async function generateReferralCode(env) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  for (let attempt = 0; attempt < 10; attempt++) {
    const bytes = crypto.getRandomValues(new Uint8Array(8));

    const code = Array.from(
      bytes,
      byte => chars[byte % chars.length]
    ).join("");

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE referral_code = ?"
    ).bind(code).first();

    if (!existing) return code;
  }

  throw new Error("Could not generate unique referral code.");
}
function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : null;
}

async function createUserSession(env, userId) {
  const token = toBase64(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + 7 * 86400000).toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)"
  ).bind(userId, tokenHash, expires).run();

  return {
    "Set-Cookie": `ez_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  };
}

async function createAdminSession(env, email) {
  const token = toBase64(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256(token);
  const expires = new Date(Date.now() + 7 * 86400000).toISOString();

  await env.DB.prepare(
    "INSERT INTO admin_sessions (token_hash, admin_email, expires_at) VALUES (?, ?, ?)"
  ).bind(tokenHash, email, expires).run();

  return {
    "Set-Cookie": `ez_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
  };
}

async function getUser(request, env) {
  const token = getCookie(request, "ez_session");
  if (!token) return null;

  const tokenHash = await sha256(token);

  return await env.DB.prepare(`
    SELECT users.id, users.username, users.email,
           users.coins, users.balance_usd, users.status,
           users.referral_code
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
      AND users.status = 'active'
  `).bind(tokenHash, new Date().toISOString()).first();
}

async function getAdmin(request, env) {
  const token = getCookie(request, "ez_admin");
  if (!token) return null;

  const tokenHash = await sha256(token);

  return await env.DB.prepare(`
    SELECT admins.id, admins.email, admins.role
    FROM admin_sessions
    JOIN admins ON admins.email = admin_sessions.admin_email
    WHERE admin_sessions.token_hash = ?
      AND admin_sessions.expires_at > ?
      AND admins.status = 'active'
  `).bind(tokenHash, new Date().toISOString()).first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Health check
      if (path === "/api/health") {
        return json({ status: "online", project: "EarnZone" });
      }

      // Database test
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

      // USER REGISTRATION
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


        const referralCode = await generateReferralCode(env);
const usedReferralCode = String(body.referralCode || "").trim().toUpperCase();

let referrer = null;

if (usedReferralCode) {
  referrer = await env.DB.prepare(
    "SELECT id FROM users WHERE referral_code = ?"
  ).bind(usedReferralCode).first();

  if (!referrer) {
    return json({ error: "Invalid referral code." }, 400);
  }
}

const passwordData = await hashPassword(password);
const passwordHash = `pbkdf2$${passwordData.salt}$${passwordData.hash}`;

const result = await env.DB.prepare(
  "INSERT INTO users (username, email, password_hash, referral_code, referred_by) VALUES (?, ?, ?, ?, ?)"
).bind(
  username,
  email,
  passwordHash,
  referralCode,
  referrer ? usedReferralCode : null
).run();

const newUserId = result.meta.last_row_id;

if (referrer) {
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO referrals (referrer_user_id, referred_user_id, referral_code, referrer_reward_usd, referred_reward_usd) VALUES (?, ?, ?, 4.00, 1.00)"
    ).bind(referrer.id, newUserId, usedReferralCode),

    env.DB.prepare(
      "UPDATE users SET balance_usd = COALESCE(balance_usd, 0) + 4.00 WHERE id = ?"
    ).bind(referrer.id),

    env.DB.prepare(
      "UPDATE users SET balance_usd = COALESCE(balance_usd, 0) + 1.00 WHERE id = ?"
    ).bind(newUserId)
  ]);
}

const headers = await createUserSession(env, newUserId);

return json({ success: true, message: "Account created." }, 201, headers);

      }

      // USER LOGIN
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

        const headers = await createUserSession(env, user.id);
        return json({ success: true, message: "Login successful." }, 200, headers);
      }

      // USER PROFILE
      if (path === "/api/me" && request.method === "GET") {
        const user = await getUser(request, env);
        if (!user) return json({ error: "Please login." }, 401);
        return json({ success: true, user });
      }
// USER WITHDRAWAL REQUEST
if (path === "/api/withdraw" && request.method === "POST") {
  const user = await getUser(request, env);

  if (!user) {
    return json({ error: "Please login." }, 401);
  }

  const body = await request.json();

  const amount = Number(body.amount);
  const method = String(body.method || "").trim();
  const account = String(body.account || "").trim();

  if (!Number.isFinite(amount) || amount < 50) {
    return json({ error: "Minimum withdrawal is $50." }, 400);
  }

  if (!["bKash", "Nagad", "Binance Pay", "USDT TRC20"].includes(method)) {
    return json({ error: "Invalid payment method." }, 400);
  }

  if (account.length < 5 || account.length > 200) {
    return json({ error: "Enter valid account details." }, 400);
  }

  const result = await env.DB.prepare(`
    UPDATE users
    SET balance_usd = balance_usd - ?
    WHERE id = ? AND balance_usd >= ?
  `).bind(amount, user.id, amount).run();

  if (result.meta.changes !== 1) {
    return json({ error: "Insufficient balance." }, 400);
  }

  try {
    await env.DB.prepare(`
      INSERT INTO withdrawals
      (user_id, amount_usd, method, account_details, status)
      VALUES (?, ?, ?, ?, 'pending')
    `).bind(user.id, amount, method, account).run();
  } catch (error) {
    await env.DB.prepare(`
      UPDATE users
      SET balance_usd = balance_usd + ?
      WHERE id = ?
    `).bind(amount, user.id).run();

    return json({ error: "Withdrawal request failed." }, 500);
  }

  return json({
    success: true,
    message: "Withdrawal request submitted.",
    status: "pending"
  });
}
      // USER LOGOUT
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

      // MAIN ADMIN FIRST-TIME SETUP
      if (path === "/api/admin/setup" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const setupKey = String(body.setupKey || "");

        if (!env.ADMIN_SETUP_KEY) {
          return json({ error: "Admin setup is not configured." }, 500);
        }

        if (setupKey !== env.ADMIN_SETUP_KEY) {
          return json({ error: "Invalid setup key." }, 403);
        }

        if (email !== ADMIN_EMAIL) {
          return json({ error: "Unauthorized admin email." }, 403);
        }

        if (password.length < 12 || password.length > 128) {
          return json({ error: "Password must be 12-128 characters." }, 400);
        }

        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM admins"
        ).first();

        if (count.total > 0) {
          return json({ error: "Admin setup has already been completed." }, 409);
        }

        const passwordData = await hashPassword(password);
        const passwordHash = `pbkdf2$${passwordData.salt}$${passwordData.hash}`;

        await env.DB.prepare(
          "INSERT INTO admins (email, password_hash, role) VALUES (?, ?, 'main_admin')"
        ).bind(email, passwordHash).run();

        const headers = await createAdminSession(env, email);

        return json(
          { success: true, message: "Main Admin created." },
          201,
          headers
        );
      }

      // ADMIN LOGIN
      if (path === "/api/admin/login" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        const admin = await env.DB.prepare(
          "SELECT email, password_hash, role, status FROM admins WHERE email = ?"
        ).bind(email).first();

        if (!admin || admin.status !== "active" ||
            !(await verifyPassword(password, admin.password_hash))) {
          return json({ error: "Invalid admin email or password." }, 401);
        }

        const headers = await createAdminSession(env, admin.email);

        return json(
          { success: true, message: "Admin login successful." },
          200,
          headers
        );
      }

      // ADMIN PROFILE / ACCESS CHECK
      if (path === "/api/admin/me" && request.method === "GET") {
        const admin = await getAdmin(request, env);

        if (!admin) return json({ error: "Admin access required." }, 401);

        return json({ success: true, admin });
      }
// ADMIN WITHDRAWAL REQUESTS
if (path === "/api/admin/withdrawals" && request.method === "GET") {
  const admin = await getAdmin(request, env);

  if (!admin) {
    return json({ error: "Admin access required." }, 401);
  }

  const withdrawals = await env.DB.prepare(`
    SELECT
      withdrawals.id,
      withdrawals.user_id,
      users.username,
      users.email,
      withdrawals.amount_usd,
      withdrawals.method,
      withdrawals.account_details,
      withdrawals.status,
      withdrawals.created_at
    FROM withdrawals
    JOIN users ON users.id = withdrawals.user_id
    ORDER BY withdrawals.id DESC
  `).all();

  return json({
    success: true,
    withdrawals: withdrawals.results
  });
}
      // ADMIN LOGOUT
      if (path === "/api/admin/logout" && request.method === "POST") {
        const token = getCookie(request, "ez_admin");

        if (token) {
          const tokenHash = await sha256(token);
          await env.DB.prepare(
            "DELETE FROM admin_sessions WHERE token_hash = ?"
          ).bind(tokenHash).run();
        }

        return json(
          { success: true, message: "Admin logged out." },
          200,
          { "Set-Cookie": "ez_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" }
        );
      }
if (path === "/api/admin-secret-test") {
  return json({
    configured: Boolean(env.ADMIN_SETUP_KEY),
    secretType: typeof env.ADMIN_SETUP_KEY
  });
}
      return env.ASSETS.fetch(request);

    } catch (error) {
      return json({ error: "Server error. Please try again." }, 500);
    }
  }
};
