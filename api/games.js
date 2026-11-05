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

module.exports = { MINES_EDGE, TILES, minesMult, placeMines, spin, slotsRTP, STRIP, PAY, SYMBOLS, LINES };
