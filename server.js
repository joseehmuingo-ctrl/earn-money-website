require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PRICE = Number(process.env.MEMBERSHIP_PRICE_KES || 150);
const db = new Database(process.env.DB_PATH || "earn-money.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'member',
 paid INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 phone TEXT NOT NULL,
 amount INTEGER NOT NULL,
 checkout_request_id TEXT UNIQUE,
 merchant_request_id TEXT,
 receipt TEXT,
 status TEXT NOT NULL DEFAULT 'pending',
 result_description TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.warn("WARNING: Set SESSION_SECRET to a random secret of at least 32 characters before deployment.");
}
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const exists = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!exists) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,paid) VALUES(?,?,?,?,1)")
      .run("Administrator", email, hash, "admin", 1);
    console.log("Initial admin account created from environment settings.");
  }
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  name: "earnmoney.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret-123456",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));

function cleanUser(row) {
  return row ? { id: row.id, name: row.name, email: row.email, role: row.role, paid: Boolean(row.paid) } : null;
}
function requireLogin(req, res, next) {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: "Please log in first." });
  const fresh = db.prepare("SELECT * FROM users WHERE id=?").get(user.id);
  if (!fresh) { req.session.destroy(() => {}); return res.status(401).json({ error: "Please log in again." }); }
  req.currentUser = fresh;
  next();
}
function requirePaid(req, res, next) {
  if (req.currentUser.role !== "admin" && !req.currentUser.paid) {
    return res.status(402).json({ error: "Membership payment is required.", paymentRequired: true });
  }
  next();
}
function normalizePhone(input) {
  let n = String(input || "").replace(/[^\d+]/g, "");
  if (n.startsWith("+")) n = n.slice(1);
  if (n.startsWith("0") && n.length === 10) n = "254" + n.slice(1);
  if (n.length === 9) n = "254" + n;
  if (!/^254[17]\d{8}$/.test(n)) throw new Error("Enter a valid Kenyan mobile number, e.g. 0712345678.");
  return n;
}
function darajaBase() {
  return process.env.MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";
}
function requiredMpesaSettings() {
  const keys = ["MPESA_CONSUMER_KEY","MPESA_CONSUMER_SECRET","MPESA_SHORTCODE","MPESA_PASSKEY","BASE_URL"];
  const missing = keys.filter(k => !process.env[k]);
  if (missing.length) throw new Error("M-Pesa is not configured yet. Missing: " + missing.join(", "));
  if (!process.env.BASE_URL.startsWith("https://")) throw new Error("BASE_URL must be a public HTTPS URL.");
}
async function getDarajaToken() {
  const auth = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString("base64");
  const response = await fetch(`${darajaBase()}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${auth}` }
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) throw new Error("Could not authenticate with Daraja. Check your credentials and environment.");
  return data.access_token;
}

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  const row = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
  if (!row) return res.json({ user: null });
  req.session.user = cleanUser(row);
  res.json({ user: req.session.user, price: PRICE });
});

app.post("/api/signup", rateLimit({ windowMs: 15 * 60 * 1000, limit: 8 }), async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 80);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2) return res.status(400).json({ error: "Enter your name." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 190) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 10) return res.status(400).json({ error: "Use a password of at least 10 characters." });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name, email, hash);
    req.session.user = cleanUser(db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid));
    res.json({ user: req.session.user, price: PRICE });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "An account with that email already exists. Please log in." });
    res.status(500).json({ error: "Could not create account. Please try again." });
  }
});

app.post("/api/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }), async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) return res.status(401).json({ error: "Incorrect email or password." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start a secure session." });
    req.session.user = cleanUser(row);
    res.json({ user: req.session.user, price: PRICE });
  });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => {
  res.clearCookie("earnmoney.sid");
  res.json({ ok: true });
}));

app.post("/api/payment/stk-push", requireLogin, async (req, res) => {
  try {
    requiredMpesaSettings();
    const fresh = db.prepare("SELECT * FROM users WHERE id=?").get(req.session.user.id);
    if (fresh.paid || fresh.role === "admin") return res.json({ ok: true, alreadyPaid: true });
    const phone = normalizePhone(req.body.phone);
    const token = await getDarajaToken();
    const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
    const shortcode = process.env.MPESA_SHORTCODE;
    const password = Buffer.from(`${shortcode}${process.env.MPESA_PASSKEY}${timestamp}`).toString("base64");
    const reference = `EM${fresh.id}`.slice(0, 12);
    const payload = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: process.env.MPESA_TRANSACTION_TYPE || "CustomerPayBillOnline",
      Amount: PRICE,
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: `${process.env.BASE_URL.replace(/\/$/, "")}/api/payment/callback?token=${encodeURIComponent(process.env.MPESA_CALLBACK_TOKEN || "")}`,
      AccountReference: reference,
      TransactionDesc: "Earn Money membership"
    };
    const response = await fetch(`${darajaBase()}/mpesa/stkpush/v1/processrequest`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok || data.ResponseCode !== "0" || !data.CheckoutRequestID) {
      console.error("Daraja STK response:", data);
      return res.status(502).json({ error: data.errorMessage || data.ResponseDescription || "M-Pesa could not start the payment. Check Daraja setup." });
    }
    db.prepare(`INSERT INTO payments(user_id,phone,amount,checkout_request_id,merchant_request_id,status)
      VALUES(?,?,?,?,?,'pending')`).run(fresh.id, phone, PRICE, data.CheckoutRequestID, data.MerchantRequestID || null);
    res.json({ ok: true, status: "pending", message: "Payment prompt sent. Enter your M-Pesa PIN on your phone, then check payment status.", checkoutRequestId: data.CheckoutRequestID });
  } catch (e) {
    res.status(400).json({ error: e.message || "Unable to start payment." });
  }
});

app.post("/api/payment/callback", (req, res) => {
  const supplied = String(req.query.token || "");
  const expected = String(process.env.MPESA_CALLBACK_TOKEN || "");
  if (!expected || !supplied || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(403).json({ Result: "Rejected" });
  }
  try {
    const callback = req.body?.Body?.stkCallback;
    if (!callback?.CheckoutRequestID) return res.json({ Result: "Received" });
    const payment = db.prepare("SELECT * FROM payments WHERE checkout_request_id=?").get(callback.CheckoutRequestID);
    if (!payment) return res.json({ Result: "Received" });
    if (Number(callback.ResultCode) === 0) {
      const items = callback.CallbackMetadata?.Item || [];
      const get = key => items.find(i => i.Name === key)?.Value;
      const amount = Number(get("Amount"));
      const receipt = String(get("MpesaReceiptNumber") || "");
      // Do not grant access unless the callback reports success and amount/receipt match expectations.
      if (amount === payment.amount && receipt) {
        const transaction = db.transaction(() => {
          db.prepare("UPDATE payments SET status='success',receipt=?,result_description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
            .run(receipt, String(callback.ResultDesc || "Success"), payment.id);
          db.prepare("UPDATE users SET paid=1 WHERE id=?").run(payment.user_id);
        });
        transaction();
      } else {
        db.prepare("UPDATE payments SET status='review',result_description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
          .run("Success callback received but amount or receipt did not match; manual review required.", payment.id);
      }
    } else {
      db.prepare("UPDATE payments SET status='failed',result_description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .run(String(callback.ResultDesc || "Payment failed").slice(0, 250), payment.id);
    }
    res.json({ Result: "Received" });
  } catch (e) {
    console.error("Payment callback processing failed:", e);
    res.status(500).json({ Result: "Error" });
  }
});

app.get("/api/payment/status", requireLogin, (req, res) => {
  const payment = db.prepare("SELECT status,receipt,amount,created_at FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 1").get(req.session.user.id);
  const user = db.prepare("SELECT paid,role FROM users WHERE id=?").get(req.session.user.id);
  res.json({ paid: Boolean(user.paid) || user.role === "admin", payment: payment || null });
});

app.get("/api/dashboard", requireLogin, requirePaid, (req, res) => {
  if (req.currentUser.role === "admin") {
    const stats = {
      users: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='member'").get().n,
      paidMembers: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='member' AND paid=1").get().n,
      pendingPayments: db.prepare("SELECT COUNT(*) AS n FROM payments WHERE status='pending'").get().n,
      recentUsers: db.prepare("SELECT id,name,email,role,paid,created_at FROM users ORDER BY id DESC LIMIT 20").all(),
      recentPayments: db.prepare("SELECT p.id,p.amount,p.phone,p.status,p.receipt,p.created_at,u.email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 20").all()
    };
    return res.json({ role: "admin", stats });
  }
  res.json({ role: "member", message: "Welcome to your Earn Money member dashboard.", user: cleanUser(req.currentUser) });
});

// Admin can view member/payment records. Never allow the browser to set its own role or paid status.
app.get("/api/admin/data", requireLogin, (req, res) => {
  if (req.currentUser.role !== "admin") return res.status(403).json({ error: "Admin access only." });
  res.json({
    users: db.prepare("SELECT id,name,email,role,paid,created_at FROM users ORDER BY id DESC LIMIT 200").all(),
    payments: db.prepare("SELECT p.id,p.user_id,p.amount,p.phone,p.status,p.receipt,p.created_at,u.email FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 200").all()
  });
});

app.post("/api/admin/users/:id/revoke", requireLogin, (req, res) => {
  if (req.currentUser.role !== "admin") return res.status(403).json({ error: "Admin access only." });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id === req.currentUser.id) return res.status(400).json({ error: "Invalid user." });
  db.prepare("UPDATE users SET paid=0 WHERE id=? AND role='member'").run(id);
  res.json({ ok: true });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log(`Earn Money website running on port ${PORT}`));
