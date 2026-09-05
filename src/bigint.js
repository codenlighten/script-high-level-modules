'use strict'

// The reference maths, in plain BigInt. Every module's model() is written
// against this, so the specification of a module is readable by someone who
// knows the mathematics and nothing about Script.

/** Non-negative representative of a mod n — NOT what OP_MOD alone gives. */
function mod (a, n) { const r = a % n; return r < 0n ? r + n : r }

function powmod (base, exp, n) {
  if (exp < 0n) throw new Error('powmod: negative exponent')
  let b = mod(base, n); let r = 1n; let e = exp
  while (e > 0n) { if (e & 1n) r = (r * b) % n; b = (b * b) % n; e >>= 1n }
  return r
}

function egcd (a, b) { if (b === 0n) return [a, 1n, 0n]; const [g, x, y] = egcd(b, a % b); return [g, y, x - (a / b) * y] }

/** The canonical inverse in [0, n): the only value the modinv module accepts. */
function invmod (a, n) {
  const [g, x] = egcd(mod(a, n), n)
  if (g !== 1n && g !== -1n) throw new Error(`invmod: ${a} is not invertible mod ${n}`)
  return mod(x, n)
}

/** Bits of e, most-significant first — the order square-and-multiply unrolls in. */
function bitsOf (e) {
  if (e <= 0n) throw new Error('bitsOf: expects a positive exponent')
  return e.toString(2).split('').map((c) => c === '1')
}

module.exports = { mod, powmod, egcd, invmod, bitsOf }
