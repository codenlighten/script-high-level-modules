'use strict'

const bsv = require('@smartledger/bsv')

// SHORT WEIERSTRASS CURVES in plain BigInt — y² = x³ + ax + b over GF(p).
//
// This started as secp256k1 alone, and it is still secp256k1 at module level:
// every existing caller sees exactly the constants and functions it did before.
// What is new is that those are one instance of `curve()`, because the pairing
// work needed the same arithmetic over BLS12-381's G1 — a 381-bit prime and
// b = 4 rather than a 256-bit prime and b = 7 — and hard-coding one curve into
// the reference implementation would have meant hard-coding it into every
// module checked against it.
//
// The secp256k1 instance is itself checked against the library's own
// implementation (tools/ec-crosscheck.js), which is the one Bitcoin signatures
// are verified with. Two independent implementations agreeing is evidence; one
// implementation agreeing with itself is not.

function powmod (b, e, m) { let r = ((b % m) + m) % m; r = 1n; b = ((b % m) + m) % m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n } return r }

const INFINITY = null

/**
 * A curve, and every operation on it bound to its own parameters.
 *
 * @param p  the field prime — must be ≡ 3 (mod 4) for `numsPoint`'s square root
 * @param n  the group order
 * @param a  the curve's a, 0 for both curves used here
 * @param b  the curve's b
 * @param G  the generator
 */
function curve ({ p, n, a = 0n, b, G, name = 'curve' }) {
  const mod = (v, m = p) => { const r = v % m; return r < 0n ? r + m : r }

  function inv (v, m = p) {
    let oldR = mod(v, m); let r = m
    let oldS = 1n; let s = 0n
    while (r !== 0n) { const q = oldR / r; [oldR, r] = [r, oldR - q * r]; [oldS, s] = [s, oldS - q * s] }
    if (oldR !== 1n) throw new Error(`${name}.inv: not invertible`)
    return mod(oldS, m)
  }

  const isOnCurve = (Pt) => Pt === INFINITY || mod(Pt.y * Pt.y - Pt.x * Pt.x * Pt.x - a * Pt.x - b) === 0n

  /** Affine addition of two points with distinct x — the case the Script module
   *  covers, and the only case it can cover without a branch. */
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
    const lam = mod((3n * p1.x * p1.x + a) * inv(2n * p1.y))
    const x3 = mod(lam * lam - 2n * p1.x)
    return { x: x3, y: mod(lam * (p1.x - x3) - p1.y) }
  }

  /** Double-and-add, least-significant bit first. */
  function mul (k, p1 = G) {
    let acc = INFINITY
    let cur = p1
    let e = mod(k, n)
    while (e > 0n) { if (e & 1n) acc = add(acc, cur); cur = double(cur); e >>= 1n }
    return acc
  }

  /**
   * A nothing-up-my-sleeve point: hash a tag, treat it as an x coordinate, walk
   * forward until one is on the curve. Nobody knows its discrete logarithm,
   * which is what makes it safe to use as the accumulator's starting offset in
   * a double-and-add ladder that has no representation for the point at
   * infinity.
   */
  function numsPoint (tag) {
    const crypto = require('crypto')
    if (mod(p, 4n) !== 3n) throw new Error(`${name}.numsPoint: needs p ≡ 3 (mod 4) for the square root`)
    let x = BigInt('0x' + crypto.createHash('sha256').update(tag).digest('hex')) % p
    for (let i = 0; i < 1000; i++, x = (x + 1n) % p) {
      const y2 = mod(x * x % p * x + a * x + b)
      const y = powmod(y2, (p + 1n) / 4n, p)
      if (mod(y * y) === y2) return { x, y: y % 2n === 0n ? y : p - y }
    }
    throw new Error(`${name}.numsPoint: no point found`)
  }

  /** The negation of a point — subtraction is addition of this. */
  const neg = (p1) => (p1 === INFINITY ? INFINITY : { x: p1.x, y: mod(-p1.y) })

  return { name, P: p, N: n, A: a, B: b, G, INFINITY, mod, inv, add, double, mul, neg, numsPoint, powmod, isOnCurve }
}

const secp256k1 = curve({
  name: 'secp256k1',
  p: 2n ** 256n - 2n ** 32n - 977n,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  a: 0n,
  b: 7n,
  G: {
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
  }
})

/**
 * BLS12-381's G1: y² = x³ + 4 over the 381-bit prime, group order r.
 *
 * The same arithmetic, a different set of numbers. What a Groth16 verifier
 * needs it for is combining public inputs — L = IC₀ + Σ xᵢ·ICᵢ — which is
 * ordinary fixed-base scalar multiplication and has nothing to do with pairings.
 */
const bls12381G1 = curve({
  name: 'bls12381.G1',
  p: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
  n: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
  a: 0n,
  b: 4n,
  G: {
    x: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
    y: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
  }
})

/** The library's point, for cross-checking. secp256k1 only — it is bsv's curve. */
function toBsv (p1) {
  return new bsv.crypto.Point(new bsv.crypto.BN(p1.x.toString(16), 16), new bsv.crypto.BN(p1.y.toString(16), 16))
}
function fromBsv (pt) { return { x: BigInt('0x' + pt.getX().toString(16)), y: BigInt('0x' + pt.getY().toString(16)) } }

// secp256k1 at module level, so that every caller written before curves were a
// parameter reads exactly as it did.
module.exports = { ...secp256k1, curve, secp256k1, bls12381G1, toBsv, fromBsv }
