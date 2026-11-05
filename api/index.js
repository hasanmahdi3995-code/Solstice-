// Solstice - server (Express on Vercel). Only needs: index.html, index.js, package.json
//
// Environment variables (Vercel -> Project -> Settings -> Environment Variables):
//   SESSION_SECRET            long random string
//   UPSTASH_REDIS_REST_URL    } free database: Vercel Marketplace -> Upstash Redis
//   UPSTASH_REDIS_REST_TOKEN  } (KV_REST_API_URL / KV_REST_API_TOKEN also work)
//   RESEND_API_KEY            sends the 6-digit email codes (resend.com)
//   EMAIL_FROM                e.g. "Solstice <no-reply@yourdomain.com>"
//   DEPOSIT_ADDR_BTC          your Exodus receive address for each coin you accept
//   DEPOSIT_ADDR_ETH          (a coin with no address set is hidden from the Deposit page)
//   DEPOSIT_ADDR_LTC
//   DEPOSIT_ADDR_DOGE
//   ADMIN_EMAILS              comma-separated account emails allowed to process withdrawals
//   WITHDRAW_WEBHOOK_URL      optional: gets a JSON POST ({text}) for every new withdrawal
//                             (works with Discord / Slack / Make / Zapier webhooks)

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
// Some Vercel runtimes parse the body before Express sees it; don't parse it twice.
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object' && Object.keys(req.body).length) req._body = true;
  next();
});
app.use(express.json({ limit: '50kb' }));

let HTML;
for (const dir of [__dirname, process.cwd(), path.join(process.cwd(), 'public')]) {
  try { HTML = fs.readFileSync(path.join(dir, 'index.html'), 'utf8'); break; } catch (e) { /* try next */ }
}
if (!HTML) HTML = '<h1>index.html is missing from the deployment</h1>';

/* ---------- helpers ---------- */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    if (!err.status) console.error(err);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Something went wrong. Try again.' });
  });
const bad = (msg, status = 400) => { throw new HttpError(status, msg); };

async function R(...cmd) {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const tok = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  if (!url || !tok) throw new HttpError(500, 'Database is not configured yet.');
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + tok },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const normEmail = (e) => {
  e = String(e || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120 ? e : null;
};
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
async function limit(key, max, secs) {
  const n = await R('INCR', 'rl:' + key);
  if (n === 1) await R('EXPIRE', 'rl:' + key, secs);
  if (n > max) bad('Too many attempts. Please wait a bit and try again.', 429);
}
const isAdmin = (email) =>
  String(process.env.ADMIN_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean).includes(email);

/* ---------- sessions (signed cookie) ---------- */
const SECRET = () => process.env.SESSION_SECRET || bad('SESSION_SECRET is not set.', 500);
const sign = (data) => crypto.createHmac('sha256', SECRET()).update(data).digest('base64url');
function setSession(res, email) {
  const exp = Date.now() + 7 * 864e5;
  const body = Buffer.from(JSON.stringify({ e: email, x: exp })).toString('base64url');
  res.setHeader('Set-Cookie',
    `sid=${body}.${sign(body)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 86400}`);
}
function getSession(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig || !safeEq(sig, sign(body))) return null;
  try {
    const d = JSON.parse(Buffer.from(body, 'base64url').toString());
    return d.x > Date.now() ? d.e : null;
  } catch { return null; }
}
const authed = (fn) => wrap(async (req, res) => {
  const email = getSession(req);
  if (!email) bad('Please sign in.', 401);
  req.email = email;
  return fn(req, res);
});
const adminOnly = (fn) => authed(async (req, res) => {
  if (!isAdmin(req.email)) bad('Not allowed.', 403);
  return fn(req, res);
});

/* ---------- email code ---------- */
async function sendCode(email, code) {
  // Free option (no domain needed): Gmail SMTP with an App Password.
  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    const nodemailer = require('nodemailer');
    const tx = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } });
    try {
      await tx.sendMail({
        from: 'Solstice <' + process.env.GMAIL_USER + '>',
        to: email,
        subject: `${code} is your Solstice verification code`,
        text: `Your Solstice verification code is ${code}. It expires in 15 minutes. If you did not request this, ignore this email.`,
        html: `<div style="font-family:Georgia,serif;background:#0a0a0b;color:#eee;padding:32px;text-align:center">
        <h2 style="color:#e8b931;letter-spacing:6px;margin:0 0 16px">SOLSTICE</h2>
        <p>Use this code to verify your email:</p>
        <p style="font-size:34px;letter-spacing:10px;color:#e8b931;margin:18px 0"><b>${code}</b></p>
        <p style="color:#8b8778;font-size:13px">It expires in 15 minutes. If this wasn't you, ignore this email.</p></div>`,
      });
    } catch (e) { console.error('Gmail:', e.message); bad('Could not send the email. Try again later.', 502); }
    return;
  }
  if (!process.env.RESEND_API_KEY) bad('Email service is not configured yet.', 500);
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'Solstice <onboarding@resend.dev>',
      to: [email],
      subject: `${code} is your Solstice verification code`,
        text: `Your Solstice verification code is ${code}. It expires in 15 minutes. If you did not request this, ignore this email.`,
      html: `<div style="font-family:Georgia,serif;background:#0a0a0b;color:#eee;padding:32px;text-align:center">
        <h2 style="color:#e8b931;letter-spacing:6px;margin:0 0 16px">SOLSTICE</h2>
        <p>Use this code to verify your email:</p>
        <p style="font-size:34px;letter-spacing:10px;color:#e8b931;margin:18px 0"><b>${code}</b></p>
        <p style="color:#8b8778;font-size:13px">It expires in 15 minutes. If this wasn't you, ignore this email.</p></div>`,
    }),
  });
  if (!r.ok) { console.error('Resend:', await r.text()); bad('Could not send the email. Try again later.', 502); }
}

async function startSignup(email, pw) {
  await limit('send:' + email, 5, 3600);
  const code = String(crypto.randomInt(100000, 1000000));
  const salt = crypto.randomBytes(16).toString('hex');
  await R('SET', 'pending:' + email,
    JSON.stringify({ salt, hash: hashPw(pw, salt), code: sha(code), tries: 0 }), 'EX', 900);
  await sendCode(email, code);
}

/* ---------- auth routes ---------- */
app.post('/api/register', wrap(async (req, res) => {
  const email = normEmail(req.body.email), pw = String(req.body.password || '');
  if (!email) bad('Enter a valid email address.');
  if (pw.length < 8 || pw.length > 100) bad('Password must be 8 to 100 characters.');
  if (await R('EXISTS', 'user:' + email)) bad('An account with this email already exists.');
  await startSignup(email, pw);
  res.json({ ok: true });
}));

app.post('/api/resend', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  if (!email) bad('Enter a valid email address.');
  await limit('send:' + email, 5, 3600);
  const raw = await R('GET', 'pending:' + email);
  if (!raw) bad('Please start sign up again.');
  const p = JSON.parse(raw);
  const code = String(crypto.randomInt(100000, 1000000));
  p.code = sha(code); p.tries = 0;
  await R('SET', 'pending:' + email, JSON.stringify(p), 'EX', 900);
  await sendCode(email, code);
  res.json({ ok: true });
}));

app.post('/api/verify', wrap(async (req, res) => {
  const email = normEmail(req.body.email), code = String(req.body.code || '').trim();
  if (!email || !/^\d{6}$/.test(code)) bad('Enter the 6-digit code.');
  const raw = await R('GET', 'pending:' + email);
  if (!raw) bad('Code expired. Please sign up again.');
  const p = JSON.parse(raw);
  if (p.tries >= 5) { await R('DEL', 'pending:' + email); bad('Too many wrong codes. Please sign up again.', 429); }
  if (!safeEq(sha(code), p.code)) {
    p.tries++;
    await R('SET', 'pending:' + email, JSON.stringify(p), 'EX', 900);
    bad('Wrong code. Try again.');
  }
  const made = await R('SET', 'user:' + email,
    JSON.stringify({ salt: p.salt, hash: p.hash, created: Date.now() }), 'NX');
  if (!made) bad('An account with this email already exists.');
  await R('DEL', 'pending:' + email);
  setSession(res, email);
  res.json({ ok: true });
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = normEmail(req.body.email), pw = String(req.body.password || '');
  if (!email || !pw) bad('Enter your email and password.');
  await limit('login:' + email, 10, 900);
  const raw = await R('GET', 'user:' + email);
  const u = raw && JSON.parse(raw);
  if (!u || !safeEq(hashPw(pw, u.salt), u.hash)) bad('Wrong email or password.', 401);
  setSession(res, email);
  res.json({ ok: true });
}));

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

/* ---------- prices ---------- */
const COINS = {
  BTC: { id: 'bitcoin', name: 'Bitcoin' },
  ETH: { id: 'ethereum', name: 'Ethereum' },
  LTC: { id: 'litecoin', name: 'Litecoin' },
  DOGE: { id: 'dogecoin', name: 'Dogecoin' },
};
let priceCache = { t: 0, data: null };
async function getPrices() {
  if (priceCache.data && Date.now() - priceCache.t < 30000) return priceCache.data;
  try {
    const ids = Object.values(COINS).map((c) => c.id).join(',');
    const r = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true`);
    if (!r.ok) throw new Error('price http ' + r.status);
    const j = await r.json();
    const data = {};
    for (const [sym, c] of Object.entries(COINS)) {
      if (j[c.id]) data[sym] = { name: c.name, price: j[c.id].usd, change: j[c.id].usd_24h_change || 0 };
    }
    priceCache = { t: Date.now(), data };
    return data;
  } catch (e) {
    if (priceCache.data) return priceCache.data; // serve stale
    throw new HttpError(503, 'Prices are unavailable right now.');
  }
}
app.get('/api/prices', wrap(async (req, res) => res.json(await getPrices())));

/* ---------- account / wallet ---------- */
const G = require('./games');
const cents = (usd) => Math.round(Number(usd) * 100);
const MIN_BET = 10, MAX_BET = 100000; // cents ($0.10 - $1,000)
const betCents = (v) => { const c = cents(v); if (!isFinite(c) || c < MIN_BET || c > MAX_BET) bad('Bet must be between $0.10 and $1,000.'); return c; };
async function debit(email, c) {
  const left = await R('DECRBY', 'bal:' + email, c);
  if (left < 0) { await R('INCRBY', 'bal:' + email, c); bad('Not enough balance. Open Wallet to deposit.'); }
}
const credit = (email, c) => c > 0 ? R('INCRBY', 'bal:' + email, c) : null;
async function record(email, game, bet, payout) {
  await R('HINCRBY', 'stats', 'wagered', bet); await R('HINCRBY', 'stats', 'paid', payout); await R('HINCRBY', 'stats', 'bets', 1);
  await R('LPUSH', 'bets:' + email, JSON.stringify({ t: Date.now(), game, bet: bet / 100, payout: payout / 100 }));
  await R('LTRIM', 'bets:' + email, 0, 29);
  await R('LPUSH', 'bets:all', JSON.stringify({ t: Date.now(), u: email.replace(/^(.).*(@.*)$/, '$1***$2'), game, bet: bet / 100, payout: payout / 100 }));
  await R('LTRIM', 'bets:all', 0, 19);
}
async function lockUser(email) {
  if (!(await R('SET', 'glock:' + email, '1', 'NX', 'EX', 5))) bad('Slow down - previous action still running.', 429);
}
const unlock = (email) => R('DEL', 'glock:' + email);

app.get('/api/me', authed(async (req, res) => {
  const bal = await R('GET', 'bal:' + req.email);
  res.json({ email: req.email, balance: Number(bal || 0) / 100, admin: isAdmin(req.email) });
}));
app.get('/api/history', authed(async (req, res) => {
  res.json(((await R('LRANGE', 'bets:' + req.email, 0, 29)) || []).map((x) => JSON.parse(x)));
}));
app.get('/api/feed', wrap(async (req, res) => {
  res.json(((await R('LRANGE', 'bets:all', 0, 19)) || []).map((x) => JSON.parse(x)));
}));
app.get('/api/info', (req, res) => res.json({
  minesEdge: G.MINES_EDGE, slotsRTP: Number(G.slotsRTP().toFixed(4)), pay: G.PAY, lines: G.LINES.length,
}));

/* ---------- MINES ---------- */
const mkey = (e) => 'mines:' + e;
const minesView = (g, over) => ({
  bet: g.bet / 100, mines: g.mines, revealed: g.revealed, safe: g.revealed.length,
  mult: G.minesMult(g.mines, g.revealed.length), next: G.minesMult(g.mines, g.revealed.length + 1),
  ...(over ? { minePositions: g.positions } : {}),
});
app.get('/api/mines/state', authed(async (req, res) => {
  const raw = await R('GET', mkey(req.email));
  res.json(raw ? { active: true, ...minesView(JSON.parse(raw)) } : { active: false });
}));
app.post('/api/mines/start', authed(async (req, res) => {
  const bet = betCents(req.body.bet), mines = Math.floor(Number(req.body.mines));
  if (!(mines >= 1 && mines <= 24)) bad('Choose 1 to 24 mines.');
  await lockUser(req.email);
  try {
    if (await R('EXISTS', mkey(req.email))) bad('Finish your current game first.');
    await debit(req.email, bet);
    const g = { bet, mines, positions: G.placeMines(mines), revealed: [] };
    await R('SET', mkey(req.email), JSON.stringify(g));
    res.json({ active: true, ...minesView(g) });
  } finally { await unlock(req.email); }
}));
app.post('/api/mines/reveal', authed(async (req, res) => {
  const tile = Math.floor(Number(req.body.tile));
  if (!(tile >= 0 && tile < G.TILES)) bad('Bad tile.');
  await lockUser(req.email);
  try {
    const raw = await R('GET', mkey(req.email));
    if (!raw) bad('No active game.');
    const g = JSON.parse(raw);
    if (g.revealed.includes(tile)) bad('Already revealed.');
    if (g.positions.includes(tile)) {
      await R('DEL', mkey(req.email));
      await record(req.email, 'mines', g.bet, 0);
      return res.json({ active: false, boom: true, tile, payout: 0, ...minesView(g, true) });
    }
    g.revealed.push(tile);
    if (g.revealed.length === G.TILES - g.mines) { // cleared the board: auto cash out
      const pay = Math.floor(g.bet * G.minesMult(g.mines, g.revealed.length));
      await R('DEL', mkey(req.email)); await credit(req.email, pay); await record(req.email, 'mines', g.bet, pay);
      return res.json({ active: false, cashed: true, payout: pay / 100, ...minesView(g, true) });
    }
    await R('SET', mkey(req.email), JSON.stringify(g));
    res.json({ active: true, tile, ...minesView(g) });
  } finally { await unlock(req.email); }
}));
app.post('/api/mines/cashout', authed(async (req, res) => {
  await lockUser(req.email);
  try {
    const raw = await R('GET', mkey(req.email));
    if (!raw) bad('No active game.');
    const g = JSON.parse(raw);
    if (!g.revealed.length) bad('Reveal at least one tile before cashing out.');
    const pay = Math.floor(g.bet * G.minesMult(g.mines, g.revealed.length));
    await R('DEL', mkey(req.email)); await credit(req.email, pay); await record(req.email, 'mines', g.bet, pay);
    res.json({ active: false, cashed: true, payout: pay / 100, ...minesView(g, true) });
  } finally { await unlock(req.email); }
}));

/* ---------- SLOTS ---------- */
app.post('/api/slots/spin', authed(async (req, res) => {
  const bet = betCents(req.body.bet);
  await lockUser(req.email);
  try {
    await debit(req.email, bet);
    const r = G.spin();
    const pay = Math.floor(bet * r.mult);
    await credit(req.email, pay); await record(req.email, 'slots', bet, pay);
    res.json({ grid: r.grid, wins: r.wins, payout: pay / 100, bet: bet / 100 });
  } finally { await unlock(req.email); }
}));

/* ---------- supported chains (deposit + withdraw) ---------- */
// dec = decimals of the smallest unit, conf = confirmations needed before crediting,
// bc = BlockCypher chain path used to verify deposits, fee = flat withdrawal fee in USD.
const CHAINS = {
  btc:  { sym: 'BTC',  label: 'Bitcoin (BTC)',   dec: 8,  conf: 2,  bc: 'btc/main',  fee: 3,
          addr: /^(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/ },
  eth:  { sym: 'ETH',  label: 'Ethereum (ETH)',  dec: 18, conf: 12, bc: 'eth/main',  fee: 3,
          addr: /^0x[a-fA-F0-9]{40}$/ },
  ltc:  { sym: 'LTC',  label: 'Litecoin (LTC)',  dec: 8,  conf: 3,  bc: 'ltc/main',  fee: 0.5,
          addr: /^(ltc1[a-z0-9]{25,60}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$/ },
  doge: { sym: 'DOGE', label: 'Dogecoin (DOGE)', dec: 8,  conf: 6,  bc: 'doge/main', fee: 0.5,
          addr: /^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/ },
};
const depositAddress = (code) => process.env['DEPOSIT_ADDR_' + CHAINS[code].sym] || '';
const toUnits = (usd, price, dec) => BigInt(Math.ceil((usd / price) * 10 ** Math.min(dec, 8))) * 10n ** BigInt(dec - Math.min(dec, 8));
const fmtUnits = (u, dec) => {
  const s = u.toString().padStart(dec + 1, '0');
  return (s.slice(0, -dec) + '.' + s.slice(-dec)).replace(/0+$/, '').replace(/\.$/, '');
};

app.get('/api/coins', (req, res) =>
  res.json(Object.entries(CHAINS).map(([code, c]) => ({ code, label: c.label, sym: c.sym, fee: c.fee, deposit: !!depositAddress(code) }))));

/* ---------- deposits (your Exodus addresses, auto-verified on-chain) ---------- */
// Every deposit gets a unique exact amount (a few tiny extra units). Only a transaction that sends
// exactly that amount to your address can claim it, so nobody can claim someone else's transfer.
const DEP_TTL = 2 * 3600;

app.post('/api/deposit', authed(async (req, res) => {
  const code = String(req.body.coin || ''), chain = CHAINS[code];
  const amount = Number(req.body.amount);
  if (!chain) bad('Choose a coin.');
  const address = depositAddress(code);
  if (!address) bad('Deposits for this coin are not available.');
  if (!isFinite(amount) || amount < 10 || amount > 100000) bad('Deposit amount must be between $10 and $100,000.');
  await limit('dep:' + req.email, 10, 3600);

  const price = ((await getPrices())[chain.sym] || {}).price;
  if (!price) bad('Price unavailable. Try again.', 503);
  const base = toUnits(amount, price, chain.dec);
  const step = 10n ** BigInt(chain.dec - Math.min(chain.dec, 8)); // 1 satoshi-equivalent (>= 1e-8 coin)
  const id = crypto.randomBytes(12).toString('hex');
  let units = null;
  for (let i = 0; i < 25 && !units; i++) {
    const cand = base + BigInt(crypto.randomInt(1, 1000)) * step;
    if (await R('SET', `claim:${code}:${cand}`, id, 'NX', 'EX', DEP_TTL)) units = cand;
  }
  if (!units) bad('Busy right now. Try again in a moment.', 503);

  const dep = {
    id, email: req.email, coin: chain.label, code, usd: amount, status: 'waiting', ts: Date.now(),
    address, units: units.toString(), payAmount: fmtUnits(units, chain.dec), payCurrency: chain.sym, txid: null,
  };
  await R('SET', 'dep:' + id, JSON.stringify(dep), 'EX', 30 * 86400);
  await R('LPUSH', 'deps:' + req.email, id);
  await R('LTRIM', 'deps:' + req.email, 0, 19);
  res.json(dep);
}));

// Look the transaction up on-chain. Big integers are quoted first so ETH wei values keep full precision.
async function lookupTx(chain, txid) {
  const r = await fetch(`https://api.blockcypher.com/v1/${chain.bc}/txs/${txid}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new HttpError(502, 'Blockchain lookup failed. Try again in a minute.');
  return JSON.parse((await r.text()).replace(/"(value|total|fees)":\s*(\d+)/g, '"$1":"$2"'));
}

// Checks one deposit and credits it when it has enough confirmations. Safe to call repeatedly.
async function checkDeposit(dep) {
  if (dep.status !== 'confirming' || !dep.txid) return dep;
  const chain = CHAINS[dep.code];
  const tx = await lookupTx(chain, dep.txid);
  if (!tx) return dep;
  const want = BigInt(dep.units);
  const addr = dep.address.toLowerCase().replace(/^0x/, '');
  const paid = (tx.outputs || []).some((o) =>
    BigInt(o.value || 0) === want && (o.addresses || []).some((a) => a.toLowerCase().replace(/^0x/, '') === addr));
  if (!paid) {
    dep.status = 'failed';
    await R('SET', 'dep:' + dep.id, JSON.stringify(dep), 'EX', 30 * 86400);
    return dep;
  }
  dep.confirmations = tx.confirmations || 0;
  if (dep.confirmations >= chain.conf) {
    dep.status = 'finished';
    const first = await R('SET', 'credited:' + dep.id, '1', 'NX'); // never credit twice
    if (first) await R('INCRBY', 'bal:' + dep.email, Math.round(dep.usd * 100));
  }
  await R('SET', 'dep:' + dep.id, JSON.stringify(dep), 'EX', 30 * 86400);
  return dep;
}

app.post('/api/deposit/tx', authed(async (req, res) => {
  const id = String(req.body.id || '');
  const raw = await R('GET', 'dep:' + id);
  const dep = raw && JSON.parse(raw);
  if (!dep || dep.email !== req.email) bad('Deposit not found.', 404);
  if (dep.status !== 'waiting') bad('This deposit already has a transaction.');
  const chain = CHAINS[dep.code];
  const txid = String(req.body.txid || '').trim().replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(txid)) bad('Paste the full transaction ID (hash).');
  await limit('deptx:' + req.email, 20, 3600);

  const tx = await lookupTx(chain, txid);
  if (!tx) bad('Transaction not found yet. Wait a minute and try again.');
  if (!(await R('SET', 'txused:' + dep.code + ':' + txid, dep.id, 'NX'))) bad('That transaction was already submitted.');
  dep.txid = txid; dep.status = 'confirming';
  await R('SET', 'dep:' + dep.id, JSON.stringify(dep), 'EX', 30 * 86400);
  const out = await checkDeposit(dep);
  if (out.status === 'failed') bad('That transaction does not pay the exact amount to the deposit address.');
  res.json(out);
}));

app.get('/api/deposits', authed(async (req, res) => {
  const ids = await R('LRANGE', 'deps:' + req.email, 0, 19);
  if (!ids || !ids.length) return res.json([]);
  const rows = await R('MGET', ...ids.map((i) => 'dep:' + i));
  const out = [];
  let checks = 0;
  for (let d of rows.filter(Boolean).map((x) => JSON.parse(x))) {
    if (d.status === 'confirming' && checks++ < 3) { try { d = await checkDeposit(d); } catch (e) { /* retry on next poll */ } }
    if (d.status === 'waiting' && Date.now() - d.ts > DEP_TTL * 1000) d.status = 'expired';
    delete d.email;
    out.push(d);
  }
  res.json(out);
}));

/* ---------- withdrawals ---------- */
async function notify(text) {
  const u = process.env.WITHDRAW_WEBHOOK_URL;
  if (!u) return;
  try {
    await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, content: text }) });
  } catch (e) { console.error('webhook:', e.message); }
}

app.post('/api/withdraw', authed(async (req, res) => {
  const code = String(req.body.coin || ''), chain = CHAINS[code];
  const amount = Number(req.body.amount), address = String(req.body.address || '').trim();
  if (!chain) bad('Choose a coin.');
  if (!isFinite(amount) || amount < 10 || amount > 100000) bad('Withdrawal amount must be between $10 and $100,000.');
  if (!chain.addr.test(address)) bad('That is not a valid ' + chain.sym + ' address.');
  if (amount <= chain.fee) bad('Amount must be more than the network fee.');
  await limit('wd:' + req.email, 10, 3600);

  const price = ((await getPrices())[chain.sym] || {}).price;
  if (!price) bad('Price unavailable. Try again.', 503);
  const cents = Math.round(amount * 100);
  const left = await R('DECRBY', 'bal:' + req.email, cents);
  if (left < 0) { await R('INCRBY', 'bal:' + req.email, cents); bad('Not enough balance.'); }

  const send = Number(((amount - chain.fee) / price).toFixed(8));
  const id = crypto.randomBytes(12).toString('hex');
  const w = {
    id, email: req.email, code, coin: chain.label, sym: chain.sym, usd: cents / 100, fee: chain.fee,
    amount: send, address, status: 'pending', ts: Date.now(), txid: null,
  };
  await R('SET', 'wd:' + id, JSON.stringify(w));
  await R('LPUSH', 'wds:' + req.email, id);
  await R('LTRIM', 'wds:' + req.email, 0, 29);
  await R('LPUSH', 'wd:pending', id);
  await notify(`Solstice withdrawal: send ${send} ${chain.sym} to ${address} (user ${req.email}, $${w.usd}). Approve in the Admin page.`);
  res.json(w);
}));

app.get('/api/withdrawals', authed(async (req, res) => {
  const ids = await R('LRANGE', 'wds:' + req.email, 0, 29);
  if (!ids || !ids.length) return res.json([]);
  const rows = await R('MGET', ...ids.map((i) => 'wd:' + i));
  res.json(rows.filter(Boolean).map((x) => { const w = JSON.parse(x); delete w.email; return w; }));
}));

/* ---------- admin: process withdrawals ---------- */
app.get('/api/admin/withdrawals', adminOnly(async (req, res) => {
  const ids = await R('LRANGE', 'wd:pending', 0, 99);
  if (!ids || !ids.length) return res.json([]);
  const rows = await R('MGET', ...ids.map((i) => 'wd:' + i));
  res.json(rows.filter(Boolean).map((x) => JSON.parse(x)).filter((w) => w.status === 'pending'));
}));

async function claimWithdrawal(id) {
  const raw = await R('GET', 'wd:' + id);
  const w = raw && JSON.parse(raw);
  if (!w) bad('Withdrawal not found.', 404);
  if (!(await R('SET', 'wdlock:' + id, '1', 'NX'))) bad('Already processed.');
  return w;
}

app.post('/api/admin/withdrawals/sent', adminOnly(async (req, res) => {
  const w = await claimWithdrawal(String(req.body.id || ''));
  w.status = 'sent'; w.txid = String(req.body.txid || '').trim().slice(0, 140) || null; w.done = Date.now();
  await R('SET', 'wd:' + w.id, JSON.stringify(w));
  await R('LREM', 'wd:pending', 0, w.id);
  res.json({ ok: true });
}));

app.post('/api/admin/withdrawals/reject', adminOnly(async (req, res) => {
  const w = await claimWithdrawal(String(req.body.id || ''));
  w.status = 'rejected'; w.done = Date.now();
  await R('INCRBY', 'bal:' + w.email, Math.round(w.usd * 100)); // full refund incl. fee
  await R('SET', 'wd:' + w.id, JSON.stringify(w));
  await R('LREM', 'wd:pending', 0, w.id);
  res.json({ ok: true });
}));


/* ---------- admin: stats, users, balance adjust ---------- */
async function scanKeys(match) {
  let cur = '0'; const out = [];
  do { const [n, keys] = await R('SCAN', cur, 'MATCH', match, 'COUNT', 200); cur = n; out.push(...keys); } while (cur !== '0' && out.length < 2000);
  return out;
}
app.get('/api/admin/stats', adminOnly(async (req, res) => {
  const [st, users, pend] = await Promise.all([R('HGETALL', 'stats'), scanKeys('user:*'), R('LLEN', 'wd:pending')]);
  const s = flat(st); const wagered = (s.wagered || 0) / 100, paid = (s.paid || 0) / 100;
  res.json({ users: users.length, bets: s.bets || 0, wagered, paid, profit: wagered - paid, pendingWithdrawals: pend || 0 });
}));
app.get('/api/admin/users', adminOnly(async (req, res) => {
  const keys = await scanKeys('user:*');
  const emails = keys.map((k) => k.slice(5));
  const bals = emails.length ? await R('MGET', ...emails.map((e) => 'bal:' + e)) : [];
  res.json(emails.map((e, i) => ({ email: e, balance: Number(bals[i] || 0) / 100 })).sort((a, b) => b.balance - a.balance));
}));
app.post('/api/admin/adjust', adminOnly(async (req, res) => {
  const email = normEmail(req.body.email), amt = cents(req.body.amount);
  if (!email || !isFinite(amt) || amt === 0 || Math.abs(amt) > 1e7) bad('Enter an email and a non-zero amount.');
  if (!(await R('EXISTS', 'user:' + email))) bad('User not found.', 404);
  const left = await R('INCRBY', 'bal:' + email, amt);
  if (left < 0) { await R('INCRBY', 'bal:' + email, -amt); bad('That would make the balance negative.'); }
  await R('LPUSH', 'adminlog', JSON.stringify({ t: Date.now(), by: req.email, email, amount: amt / 100, note: String(req.body.note || '').slice(0, 100) }));
  await R('LTRIM', 'adminlog', 0, 99);
  res.json({ ok: true, balance: left / 100 });
}));
app.get('/api/admin/log', adminOnly(async (req, res) => res.json(((await R('LRANGE', 'adminlog', 0, 49)) || []).map((x) => JSON.parse(x)))));

/* ---------- health check: open /api/health to see what is configured (no secrets shown) ---------- */
app.get('/api/health', (req, res) => res.json({
  ok: true,
  database: !!((process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) || (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN)),
  session_secret: !!process.env.SESSION_SECRET,
  email_service: !!(process.env.RESEND_API_KEY || (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD)),
}));

/* ---------- page ---------- */
// Anything under /api that doesn't exist, or a bad request body, must answer in JSON (never an HTML page).
app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown API route.' }));
app.use((err, req, res, next) => {
  if (req.path.startsWith('/api')) return res.status(err.status || 400).json({ error: 'Bad request.' });
  next(err);
});
app.use(express.static(path.join(__dirname, '..', 'public'), { index: false }));
app.get('/', (req, res) => res.type('html').send(HTML));
app.use((req, res) => res.status(404).type('html').send(HTML));

module.exports = app;
if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log('Solstice on http://localhost:' + (process.env.PORT || 3000)));
}
