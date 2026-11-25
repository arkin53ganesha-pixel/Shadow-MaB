// payment.js — top up diamond via Midtrans Snap untuk Shadow MBL 3D
// Butuh Node 18+ (fetch bawaan). Express hanya dibutuhkan untuk router().
//
// Pasang di server.js:
//   const express = require("express");
//   const payments = require("./payment")({
//     serverKey: process.env.MIDTRANS_SERVER_KEY,   // JANGAN taruh di game / HTML
//     isProd: process.env.MIDTRANS_ENV === "production",
//     publicUrl: "https://domain-kamu.com",         // alamat game (untuk redirect setelah bayar)
//     verifyToken: async (email, token) => { /* true jika token login valid */ },
//   });
//   app.use("/pay", express.json(), payments.router(express));
//
// Di dashboard Midtrans: Settings > Configuration > Payment Notification URL
//   = https://domain-kamu.com/pay/notify
//
// Alur: /pay/create -> pemain bayar di Midtrans -> Midtrans memanggil /pay/notify
//       -> server mencatat diamond -> game memanggil /pay/claim dan menambah saldo.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Harga & isi paket ditentukan di SERVER (jangan percaya angka dari game).
// Urutan harus sama dengan TOPUP.packs di game: [diamond, rupiah]
const PACKS = [
  [50, 10000],
  [120, 25000],
  [250, 50000],
  [520, 100000],
  [1100, 200000],
];

module.exports = function createPayments(opts) {
  opts = opts || {};
  if (!opts.serverKey) throw new Error("payment: serverKey wajib diisi");
  if (typeof opts.verifyToken !== "function") throw new Error("payment: verifyToken wajib diisi");

  const SNAP = opts.isProd ? "https://app.midtrans.com/snap/v1/transactions" : "https://app.sandbox.midtrans.com/snap/v1/transactions";
  const API = opts.isProd ? "https://api.midtrans.com" : "https://api.sandbox.midtrans.com";
  const auth = "Basic " + Buffer.from(opts.serverKey + ":").toString("base64");
  const file = opts.file || path.join(__dirname, "payments.json");
  const MAX_PENDING = 5; // batas order pending per email (anti spam)

  // ---- penyimpanan sederhana (JSON, ditulis atomik) ----
  let db = { orders: {} };
  try { db = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) {}
  db.orders = db.orders || {};
  function persist() {
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, file);
  }

  const emailOk = e => typeof e === "string" && e.length < 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
  const norm = e => String(e).trim().toLowerCase();
  const eq = (a, b) => {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };

  async function authed(body) {
    if (!body || !emailOk(body.email) || !body.token) return false;
    try { return !!(await opts.verifyToken(norm(body.email), String(body.token))); } catch (e) { return false; }
  }

  // ---- POST /create  {email, token, pack} ----
  async function create(req, res) {
    try {
      const b = req.body || {};
      if (!(await authed(b))) return res.status(401).json({ ok: false, err: "Login email dulu untuk top up" });
      const i = b.pack | 0, p = PACKS[i];
      if (!p) return res.status(400).json({ ok: false, err: "Paket tidak valid" });
      const email = norm(b.email);
      const pending = Object.values(db.orders).filter(o => o.email === email && o.status === "pending" && Date.now() - o.ts < 36e5).length;
      if (pending >= MAX_PENDING) return res.status(429).json({ ok: false, err: "Terlalu banyak pesanan tertunda, selesaikan atau tunggu 1 jam" });

      const orderId = "SMBL-" + Date.now().toString(36).toUpperCase() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
      const r = await fetch(SNAP, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json", Authorization: auth },
        body: JSON.stringify({
          transaction_details: { order_id: orderId, gross_amount: p[1] },
          item_details: [{ id: "dia" + p[0], price: p[1], quantity: 1, name: p[0] + " Diamond" }],
          customer_details: { email },
          callbacks: opts.publicUrl ? { finish: opts.publicUrl } : undefined,
        }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.redirect_url) return res.status(502).json({ ok: false, err: "Gateway pembayaran sedang bermasalah" });
      db.orders[orderId] = { email, dia: p[0], amount: p[1], status: "pending", claimed: false, ts: Date.now() };
      persist();
      res.json({ ok: true, url: j.redirect_url, order_id: orderId });
    } catch (e) {
      res.status(500).json({ ok: false, err: "Gagal membuat pesanan" });
    }
  }

  // ---- POST /notify  (dipanggil Midtrans) ----
  async function notify(req, res) {
    try {
      const n = req.body || {};
      const sig = crypto.createHash("sha512").update(String(n.order_id) + String(n.status_code) + String(n.gross_amount) + opts.serverKey).digest("hex");
      if (!eq(sig, n.signature_key || "")) return res.status(403).json({ ok: false });
      const o = db.orders[n.order_id];
      if (!o) return res.json({ ok: true }); // order asing: abaikan
      // konfirmasi ulang langsung ke Midtrans (jangan percaya isi notifikasi saja)
      const r = await fetch(API + "/v2/" + encodeURIComponent(n.order_id) + "/status", { headers: { Accept: "application/json", Authorization: auth } });
      const s = await r.json().catch(() => ({}));
      const paid = (s.transaction_status === "settlement" || (s.transaction_status === "capture" && s.fraud_status === "accept"));
      const amountOk = Math.round(parseFloat(s.gross_amount)) === o.amount;
      if (paid && amountOk && o.status !== "paid") { o.status = "paid"; o.paidAt = Date.now(); persist(); }
      else if (!paid && ["deny", "cancel", "expire", "failure"].includes(s.transaction_status) && o.status === "pending") { o.status = "failed"; persist(); }
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ ok: false }); // Midtrans akan mencoba lagi
    }
  }

  // ---- POST /claim  {email, token}  -> diamond yang sudah dibayar & belum diklaim ----
  async function claim(req, res) {
    try {
      const b = req.body || {};
      if (!(await authed(b))) return res.status(401).json({ ok: false, err: "Sesi login tidak valid" });
      const email = norm(b.email);
      let dia = 0, n = 0;
      for (const id in db.orders) {
        const o = db.orders[id];
        if (o.email === email && o.status === "paid" && !o.claimed) { o.claimed = true; o.claimedAt = Date.now(); dia += o.dia; n++; }
      }
      if (n) persist();
      res.json({ ok: true, dia, orders: n });
    } catch (e) {
      res.status(500).json({ ok: false });
    }
  }

  function router(express) {
    const r = express.Router();
    r.post("/create", create);
    r.post("/notify", notify);
    r.post("/claim", claim);
    return r;
  }

  return { create, notify, claim, router, PACKS };
};
