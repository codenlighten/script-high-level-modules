'use strict'

const bsv = require('@smartledger/bsv')

// secp256k1 in plain BigInt — the reference the Script modules are checked
// against, and itself checked against the library's own implementation
// (tools/ec-crosscheck.js), which is the one Bitcoin signatures are verified
// with. Two independent implementations agreeing is evidence; one
// implementation agreeing with itself is not.

const P = 2n ** 256n - 2n ** 32n - 977n                    // the field prime
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n  // the group order
const A = 0n
const B = 7n
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
const G = { x: Gx, y: Gy }
const INFINITY = null

const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r }

function inv (a, m = P) {
  let [old_r, r] = [mod(a, m), m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) { const q = old_r / r;[old_r, r] = [r, old_r - q * r];[old_s, s] = [s, old_s - q * s] }
  if (old_r !== 1n) throw new Error('ec.inv: not invertible')
  return mod(old_s, m)
}

function isOnCurve (Pt) { return Pt === INFINITY || mod(Pt.y * Pt.y - Pt.x * Pt.x * Pt.x - A * Pt.x - B) === 0n }

/** Affine addition of two DISTINCT points with distinct x — the case the Script
 *  module covers, and the only case it can cover without a branch. */
function add (p1, p2) {
  if (p1 === INFINITY) return p2
  if (p2 === INFINITY) return p1
  if (p1.x === p2.x) return p1.y === p2.y ? double(p1) : INFINITY
  const lam = mod((p2.y - p1.y) * inv(p2.x - p1.x))
  const x3 = mod(lam * lam - p1.x - p2.x)
  return { x: x3, y: mod(lam * (p1.x - x3) - p1.y) }
}

function double (p1) {
  if (p1 === INFINITY || p1.y === 0n) return INFINITY
  const lam = mod(3n * p1.x * p1.x * inv(2n * p1.y))
  const x3 = mod(lam * lam - 2n * p1.x)
  return { x: x3, y: mod(lam * (p1.x - x3) - p1.y) }
}

/** Double-and-add, least-significant bit first. */
function mul (k, p1 = G) {
  let acc = INFINITY
  let cur = p1
  let e = mod(k, N)
  while (e > 0n) { if (e & 1n) acc = add(acc, cur); cur = double(cur); e >>= 1n }
  return acc
}

/**
 * A nothing-up-my-sleeve point: hash a tag, treat it as an x coordinate, walk
 * forward until one is on the curve. Nobody knows its discrete logarithm, which
 * is what makes it safe to use as the accumulator's starting offset in a
 * double-and-add ladder that has no representation for the point at infinity.
 */
function numsPoint (tag) {
  const crypto = require('crypto')
  let x = BigInt('0x' + crypto.createHash('sha256').update(tag).digest('hex')) % P
  for (let i = 0; i < 1000; i++, x = (x + 1n) % P) {
    const y2 = mod(x * x % P * x + B)
    const y = powmod(y2, (P + 1n) / 4n, P)                 // p ≡ 3 (mod 4)
    if (mod(y * y) === y2) return { x, y: y % 2n === 0n ? y : P - y }
  }
  throw new Error('numsPoint: no point found')
}

function powmod (b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n } return r }

/** The negation of a point — subtraction is addition of this. */
function neg (p1) { return p1 === INFINITY ? INFINITY : { x: p1.x, y: mod(-p1.y) } }

/** The library's point, for cross-checking. */
function toBsv (p1) {
  return new bsv.crypto.Point(new bsv.crypto.BN(p1.x.toString(16), 16), new bsv.crypto.BN(p1.y.toString(16), 16))
}
function fromBsv (pt) { return { x: BigInt('0x' + pt.getX().toString(16)), y: BigInt('0x' + pt.getY().toString(16)) } }

module.exports = { P, N, A, B, G, INFINITY, mod, inv, add, double, mul, neg, numsPoint, powmod, isOnCurve, toBsv, fromBsv }
