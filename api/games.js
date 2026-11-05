// Solstice casino game logic. All randomness is server-side (crypto.randomInt).
const crypto = require('crypto');

/* ---------- MINES (5x5 grid, house edge 3%) ---------- */
const MINES_EDGE = 0.03;
const TILES = 25;
function comb(n, k) { let r = 1; for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i; return r; }
// multiplier after `safe` safe reveals with `mines` mines
function minesMult(mines, safe) {
  if (safe <= 0) return 1;
  return Math.floor((1 - MINES_EDGE) * (comb(TILES, safe) / comb(TILES - mines, safe)) * 100) / 100;
}
function placeMines(count) {
  const pool = [...Array(TILES).keys()];
  for (let i = pool.length - 1; i > 0; i--) { const j = crypto.randomInt(0, i + 1); [pool[i], pool[j]] = [pool[j], pool[i]]; }
  return pool.slice(0, count).sort((a, b) => a - b);
}

/* ---------- SLOTS (3 reels x 3 rows, 5 paylines) ---------- */
const SYMBOLS = ['💎', '7️⃣', '🔔', '🍇', '🍋', '🍒'];
const STRIP_COUNTS = { '💎': 1, '7️⃣': 2, '🔔': 3, '🍇': 4, '🍋': 5, '🍒': 5 };
const PAY = { '💎': 360, '7️⃣': 135, '🔔': 47, '🍇': 26, '🍋': 17, '🍒': 10 }; // x line bet for 3 in a row
const STRIP = [];
for (const s of SYMBOLS) for (let i = 0; i < STRIP_COUNTS[s]; i++) STRIP.push(s);
// deterministic interleave so identical symbols are spread out
STRIP.sort((a, b) => (SYMBOLS.indexOf(a) * 7 % 11) - (SYMBOLS.indexOf(b) * 7 % 11));
const LINES = [[0, 0, 0], [1, 1, 1], [2, 2, 2], [0, 1, 2], [2, 1, 0]];
const NL = LINES.length;
function window3(pos) { const L = STRIP.length; return [0, 1, 2].map((r) => STRIP[(pos + r) % L]); }
function scoreSpin(stops) {
  const cols = stops.map(window3); // cols[reel][row]
  const wins = [];
  let mult = 0;
  LINES.forEach((ln, i) => {
    const s = ln.map((row, reel) => cols[reel][row]);
    if (s[0] === s[1] && s[1] === s[2]) { wins.push({ line: i, symbol: s[0], pay: PAY[s[0]] }); mult += PAY[s[0]]; }
  });
  return { grid: cols, wins, mult: mult / NL }; // mult is relative to TOTAL bet
}
function spin() {
  const stops = [0, 1, 2].map(() => crypto.randomInt(0, STRIP.length));
  return { stops, ...scoreSpin(stops) };
}
function slotsRTP() {
  const L = STRIP.length; let t = 0;
  for (let a = 0; a < L; a++) for (let b = 0; b < L; b++) for (let c = 0; c < L; c++) t += scoreSpin([a, b, c]).mult;
  return t / L ** 3;
}

/* ---------- INSTANT GAMES (3% house edge) ---------- */
const EDGE = 0.97;
const fl = (x, d) => Math.floor(x * 10 ** d + 1e-9) / 10 ** d;
// DICE: roll 0.00-99.99. over: win if roll > target; under: win if roll < target
function diceChance(target, over) {
  const T = Math.round(target * 100);
  return over ? (9999 - T) / 10000 : T / 10000;
}
function diceMult(target, over) { return fl(EDGE / diceChance(target, over), 4); }
function dice(target, over) {
  target = Number(target);
  if (!(target >= 2 && target <= 98)) return null;
  const r = crypto.randomInt(0, 10000), roll = r / 100;
  return { roll, win: over ? roll > target : roll < target, mult: diceMult(target, over) };
}
// LIMBO: result = 0.97 / U, floored to 2dp, min 1.00. Win if result >= target.
function limbo(target) {
  target = Number(target);
  if (!(target >= 1.01 && target <= 1000)) return null;
  const u = crypto.randomInt(1, 1e9 + 1) / 1e9;
  const result = Math.min(1e6, Math.max(1, fl(EDGE / u, 2)));
  return { result, win: result >= target, mult: fl(target, 2) };
}
// COIN FLIP
function coin(pick) {
  if (pick !== 'h' && pick !== 't') return null;
  const result = crypto.randomInt(0, 2) ? 'h' : 't';
  return { result, win: result === pick, mult: 1.94 };
}
// PLINKO: rows 8/12/16, risk low/medium/high. Table is scaled so RTP = 97%.
const PL_ROWS = [8, 12, 16];
const PL_RISK = { low: [10, 0.5, 2.4], medium: [250, 0.15, 3.6], high: [4000, 0.04, 5] };
const plCache = {};
function plinkoTable(rows, risk) {
  const key = rows + risk; if (plCache[key]) return plCache[key];
  const [A, B, gam] = PL_RISK[risk], n = rows;
  const raw = [...Array(n + 1)].map((_, k) => B + A * Math.pow(Math.abs(k - n / 2) / (n / 2), gam));
  const p = [...Array(n + 1)].map((_, k) => comb(n, k) / 2 ** n);
  const s = EDGE / raw.reduce((t, r, k) => t + r * p[k], 0);
  return (plCache[key] = raw.map((r) => fl(r * s, 2)));
}
function plinko(rows, risk) {
  rows = Number(rows);
  if (!PL_ROWS.includes(rows) || !PL_RISK[risk]) return null;
  const path = [...Array(rows)].map(() => crypto.randomInt(0, 2));
  const bucket = path.reduce((a, b) => a + b, 0);
  return { path, bucket, mult: plinkoTable(rows, risk)[bucket] };
}

module.exports = { MINES_EDGE, TILES, minesMult, placeMines, spin, slotsRTP, STRIP, PAY, SYMBOLS, LINES, dice, diceMult, diceChance, limbo, coin, plinko, plinkoTable, PL_ROWS };
