// server.js — backend Shadow MBL 3D (tanpa framework; hanya Node 18+)
// Menyajikan game, akun email (OTP), simpan progres, verifikasi hasil match,
// hadiah follow sosmed, hapus akun, dan top up diamond (Midtrans).
// Opsional: `npm i nodemailer` untuk mengirim email OTP lewat SMTP.

const http = require("http");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");

// ---- konfigurasi (isi lewat environment variable, lihat .env.example) ----
const env = process.env;
const PORT = +env.PORT || 3000;
const DATA_DIR = env.DATA_DIR || path.join(__dirname, "data");
const PUBLIC_URL = (env.PUBLIC_URL || "").replace(/\/+$/, "");
const OTP_DEMO = env.OTP_DEMO === "1"; // HANYA untuk uji coba: kode OTP dikirim ke layar, jangan aktifkan saat rilis
const ALLOW_ORIGIN = env.ALLOW_ORIGIN || ""; // isi jika game dibuka dari domain lain
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---- penyimpanan JSON (atomik, ditulis berkala) ----
const DB_FILE = path.join(DATA_DIR, "db.json");
let db = { users: {}, matches: {}, recover: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); } catch (e) {}
let dirty = false;
const touch = () => { dirty = true; };
function flush() {
  if (!dirty) return;
  dirty = false;
  try { fs.writeFileSync(DB_FILE + ".tmp", JSON.stringify(db)); fs.renameSync(DB_FILE + ".tmp", DB_FILE); } catch (e) { dirty = true; console.error("simpan gagal", e.message); }
}
setInterval(flush, 3000).unref();
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { flush(); process.exit(0); });

// ---- util ----
const sha = x => crypto.createHash("sha256").update(String(x)).digest("hex");
const emailOk = e => typeof e === "string" && e.length < 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const norm = e => String(e || "").trim().toLowerCase();
const cleanName = n => String(n || "").replace(/[<>&"'`]/g, "").trim().slice(0, 12);
const pwOk = p => typeof p === "string" && p.length >= 8 && p.length <= 100 && /[A-Za-z]/.test(p) && /\d/.test(p);
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hashPw = (p, salt) => crypto.scryptSync(p, salt, 32).toString("hex");

// batas permintaan sederhana (per IP + kunci) — di memori
const hits = new Map();
function limited(key, max, ms) {
  const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms);
  a.push(n); hits.set(key, a);
  return a.length > max;
}
setInterval(() => { const n = Date.now(); for (const [k, a] of hits) if (!a.some(t => n - t < 36e5)) hits.delete(k); }, 6e5).unref();

// ---- email OTP ----
const otps = new Map(); // key: type:email -> {h, exp, tries}
let mailer = null;
async function sendMail(to, subject, text) {
  if (!env.SMTP_HOST) return false;
  if (!mailer) {
    const nm = require("nodemailer");
    mailer = nm.createTransport({ host: env.SMTP_HOST, port: +env.SMTP_PORT || 587, secure: env.SMTP_SECURE === "1", auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined });
  }
  await mailer.sendMail({ from: env.MAIL_FROM || env.SMTP_USER, to, subject, text });
  return true;
}
async function issueOtp(type, email) {
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, "0");
  otps.set(type + ":" + email, { h: sha(code + email), exp: Date.now() + 10 * 6e4, tries: 0 });
  const label = type === "reset" ? "reset kata sandi" : "pendaftaran akun";
  try {
    if (await sendMail(email, "Kode Shadow MBL 3D", `Kode ${label} Shadow MBL 3D kamu: ${code}\nBerlaku 10 menit. Jangan bagikan kode ini ke siapa pun.`)) return { ok: true };
  } catch (e) { console.error("email gagal", e.message); return { ok: false, err: "Gagal mengirim email, coba lagi nanti" }; }
  if (OTP_DEMO) return { ok: true, demo: code };
  return { ok: false, err: "Pengiriman email belum dikonfigurasi di server" };
}
function checkOtp(type, email, code) {
  const k = type + ":" + email, o = otps.get(k);
  if (!o || Date.now() > o.exp) { otps.delete(k); return "Kode kedaluwarsa, minta kode baru"; }
  if (++o.tries > 5) { otps.delete(k); return "Terlalu banyak percobaan, minta kode baru"; }
  if (!safeEq(o.h, sha(String(code) + email))) return "Kode salah";
  otps.delete(k);
  return "";
}

// ---- token login ----
function newToken(u) {
  const t = crypto.randomBytes(32).toString("hex");
  u.tokens = (u.tokens || []).concat(sha(t)).slice(-10);
  return t;
}
async function verifyToken(email, token) {
  const u = db.users[norm(email)];
  return !!(u && token && (u.tokens || []).some(h => safeEq(h, sha(token))));
}

// ---- hadiah follow sosmed (server yang memutuskan) ----
const SOCIAL = { f_tt: 50, f_wa: 50, f_dc: 50, f_ig: 50 };

// ---- top up diamond (Midtrans) ----
let payments = null;
if (env.MIDTRANS_SERVER_KEY) {
  payments = require("./payment")({
    serverKey: env.MIDTRANS_SERVER_KEY,
    isProd: env.MIDTRANS_ENV === "production",
    publicUrl: PUBLIC_URL || undefined,
    verifyToken,
    file: path.join(DATA_DIR, "payments.json"),
  });
} else console.warn("MIDTRANS_SERVER_KEY belum diisi: top up otomatis nonaktif");

// ---- handler API: (body, req) -> objek JSON ----
const A = {
  async "/auth/otp"(b, req) {
    const email = norm(b.email);
    if (!emailOk(email)) return { ok: false, err: "Email tidak valid" };
    if (limited(req.ip + ":otp", 8, 36e5) || limited(email + ":otp", 5, 36e5)) return { ok: false, err: "Terlalu sering meminta kode, coba lagi nanti" };
    if (db.users[email]) return { ok: false, err: "Email sudah terdaftar, silakan Masuk" };
    return issueOtp("up", email);
  },
  async "/auth/verify"(b, req) {
    const email = norm(b.email);
    if (!emailOk(email) || !pwOk(b.password)) return { ok: false, err: "Data tidak valid" };
    if (limited(req.ip + ":ver", 30, 36e5)) return { ok: false, err: "Terlalu banyak percobaan" };
    const type = b.reset ? "reset" : "up";
    const bad = checkOtp(type, email, b.otp);
    if (bad) return { ok: false, err: bad };
    const salt = crypto.randomBytes(16).toString("hex");
    if (b.reset) {
      const u = db.users[email];
      if (!u) return { ok: false, err: "Akun tidak ditemukan" };
      u.salt = salt; u.hash = hashPw(b.password, salt); u.tokens = []; touch();
      return { ok: true };
    }
    if (db.users[email]) return { ok: false, err: "Email sudah terdaftar, silakan Masuk" };
    const data = b.data && typeof b.data === "object" ? b.data : undefined;
    const u = db.users[email] = { name: cleanName(b.name) || "Pemain", salt, hash: hashPw(b.password, salt), tokens: [], data, social: {}, created: Date.now() };
    const token = newToken(u); touch();
    return { ok: true, token, data: u.data };
  },
  async "/auth/login"(b, req) {
    const email = norm(b.email);
    if (limited(req.ip + ":login", 20, 9e5) || limited(email + ":login", 10, 9e5)) return { ok: false, err: "Terlalu banyak percobaan, tunggu 15 menit" };
    const u = db.users[email];
    // hash tetap dihitung agar waktu respons tidak membocorkan keberadaan akun
    const h = hashPw(String(b.password || ""), u ? u.salt : "0".repeat(32));
    if (!u || !safeEq(h, u.hash)) return { ok: false, err: "Email atau sandi salah" };
    const token = newToken(u); touch();
    return { ok: true, token, name: u.name, data: u.data };
  },
  async "/auth/reset"(b, req) {
    const email = norm(b.email);
    if (!emailOk(email)) return { ok: false, err: "Email tidak valid" };
    if (limited(req.ip + ":rs", 8, 36e5) || limited(email + ":rs", 5, 36e5)) return { ok: false, err: "Terlalu sering meminta kode, coba lagi nanti" };
    if (!db.users[email]) return { ok: true }; // tidak membocorkan apakah email terdaftar
    return issueOtp("reset", email);
  },
  async "/auth/save"(b) {
    if (!(await verifyToken(b.email, b.token))) return { ok: false, err: "Sesi tidak valid" };
    if (!b.data || typeof b.data !== "object") return { ok: false, err: "Data kosong" };
    const u = db.users[norm(b.email)];
    u.data = b.data; u.name = cleanName(b.data.name) || u.name; u.saved = Date.now(); touch();
    return { ok: true };
  },
  async "/auth/delete"(b) {
    if (!(await verifyToken(b.email, b.token))) return { ok: false, err: "Sesi tidak valid" };
    const email = norm(b.email);
    delete db.users[email];
    for (const id in db.matches) if (db.matches[id].email === email) delete db.matches[id];
    touch(); flush();
    return { ok: true };
  },
  async "/auth/claim"(b) {
    if (!(await verifyToken(b.email, b.token))) return { ok: false, err: "Sesi tidak valid" };
    const u = db.users[norm(b.email)], k = String(b.k || "");
    if (!(k in SOCIAL)) return { ok: false, err: "Hadiah tidak ditemukan" };
    const s = u.social[k] = u.social[k] || {};
    if (b.phase === "start") { if (!s.start) { s.start = Date.now(); touch(); } return { ok: true }; }
    if (s.claimed) return { ok: true, dia: 0 };
    if (!s.start || Date.now() - s.start < 8000) return { ok: false, err: "Buka dan follow akunnya dulu, lalu kembali ke game" };
    s.claimed = Date.now(); touch();
    return { ok: true, dia: SOCIAL[k] };
  },
  async "/auth/recover"(b, req) {
    if (limited(req.ip + ":rec", 5, 36e5)) return { ok: false, err: "Terlalu banyak permintaan" };
    const t = x => String(x || "").replace(/[<>]/g, "").slice(0, 300);
    db.recover.push({ ts: Date.now(), name: t(b.name), id: t(b.id), oldEmail: t(b.oldEmail), contact: t(b.contact), code: t(b.code), info: t(b.info) });
    db.recover = db.recover.slice(-500); touch();
    return { ok: true };
  },
  // Verifikasi hasil pertandingan: hadiah hanya sah untuk match yang benar-benar dimulai & cukup lama
  async "/match/start"(b) {
    if (!(await verifyToken(b.email, b.token))) return { ok: false };
    const email = norm(b.email), n = Date.now();
    for (const id in db.matches) if (n - db.matches[id].ts > 36e5) delete db.matches[id];
    if (Object.values(db.matches).filter(m => m.email === email).length > 20) return { ok: false };
    const mid = crypto.randomBytes(9).toString("hex");
    db.matches[mid] = { email, mode: String(b.mode || "rank").slice(0, 10), ts: n }; touch();
    return { ok: true, mid };
  },
  async "/match/finish"(b) {
    if (!(await verifyToken(b.email, b.token))) return { ok: false };
    const m = db.matches[b.mid];
    if (!m || m.email !== norm(b.email)) return { ok: false };
    delete db.matches[b.mid]; touch();
    const win = !!b.win;
    if (Date.now() - m.ts < 30000) return { ok: true, add: 0, note: "Pertandingan terlalu singkat, hadiah tidak diberikan" };
    return { ok: true, add: win ? 300 : 100 };
  },
};

// ---- HTTP ----
const PUB = path.join(__dirname, "public");
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".json": "application/json", ".mp3": "audio/mpeg", ".webp": "image/webp" };
const gz = new Map();
const SEC = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(self), microphone=(self), geolocation=()",
};

function readBody(req, max) {
  return new Promise((ok, no) => {
    let n = 0; const c = [];
    req.on("data", d => { n += d.length; if (n > max) { no(new Error("big")); req.destroy(); } else c.push(d); });
    req.on("end", () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString("utf8")) : {}); } catch (e) { no(new Error("json")); } });
    req.on("error", no);
  });
}
function send(res, code, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, SEC));
  res.end(s);
}
// adaptor kecil agar handler payment.js (gaya Express) bisa dipakai tanpa Express
function expressRes(res) {
  const r = { code: 200, status(c) { r.code = c; return r; }, json(o) { send(res, r.code, o); return r; } };
  return r;
}

async function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p === "/" ) p = "/index.html";
  let f = path.normalize(path.join(PUB, p));
  if (!f.startsWith(PUB + path.sep) && f !== PUB) { res.writeHead(403); return res.end(); }
  // Boleh juga menaruh index.html langsung di folder yang sama dengan server.js (tanpa folder public)
  if (p === "/index.html" && !fs.existsSync(f)) f = path.join(__dirname, "index.html");
  let st;
  try { st = fs.statSync(f); if (st.isDirectory()) throw 0; } catch (e) { res.writeHead(404, SEC); return res.end("Tidak ditemukan"); }
  const ext = path.extname(f).toLowerCase();
  const h = Object.assign({ "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=86400" }, SEC);
  const wantGz = /\bgzip\b/.test(req.headers["accept-encoding"] || "") && /^(\.html|\.js|\.css|\.json|\.svg)$/.test(ext);
  if (wantGz) {
    const key = f + ":" + st.mtimeMs;
    if (!gz.has(key)) gz.set(key, zlib.gzipSync(fs.readFileSync(f), { level: 6 }));
    const buf = gz.get(key);
    res.writeHead(200, Object.assign(h, { "Content-Encoding": "gzip", "Content-Length": buf.length, Vary: "Accept-Encoding" }));
    return res.end(buf);
  }
  res.writeHead(200, Object.assign(h, { "Content-Length": st.size }));
  fs.createReadStream(f).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    req.ip = String((env.TRUST_PROXY === "1" && req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")).split(",")[0].trim();
    if (ALLOW_ORIGIN) {
      res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    }
    if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
    if (url.pathname === "/healthz") return send(res, 200, { ok: true });

    const isPay = url.pathname === "/pay/create" || url.pathname === "/pay/notify" || url.pathname === "/pay/claim";
    if (req.method === "POST" && (url.pathname.startsWith("/auth/") || url.pathname.startsWith("/match/") || isPay)) {
      let body;
      try { body = await readBody(req, url.pathname === "/auth/save" ? 3e6 : 6e4); } catch (e) { return send(res, 400, { ok: false, err: "Permintaan tidak valid" }); }
      if (isPay) {
        if (!payments) return send(res, 404, { ok: false });
        if (url.pathname !== "/pay/notify" && limited(req.ip + ":pay", 40, 36e5)) return send(res, 429, { ok: false, err: "Terlalu banyak permintaan" });
        const fn = payments[url.pathname.slice(5)];
        return fn({ body }, expressRes(res));
      }
      const h = A[url.pathname];
      if (!h) return send(res, 404, { ok: false });
      return send(res, 200, await h(body, req));
    }
    if (req.method === "GET" || req.method === "HEAD") return serveStatic(req, res, url);
    res.writeHead(405); res.end();
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { ok: false, err: "Kesalahan server" });
  }
});

if (require.main === module) server.listen(PORT, () => console.log("Shadow MBL 3D berjalan di http://localhost:" + PORT));
module.exports = { server, db, flush };
