'use strict'

// WHY THE SUBGROUP CHECKS ARE SOUND, computed rather than recalled.
//
// g1.inSubgroup accepts P when φ(P) = [−x²]P, and g2.inSubgroup accepts Q when
// ψ(Q) = [x]Q. Each comparison is cheaper than [r]P = O, and each is only worth
// having if it IMPLIES [r]P = O. The implications are short (src/bls12381.js
// states them), and they rest on a handful of facts about BLS12-381 that are
// easy to state and easy to misremember:
//
//     r = x⁴ − x² + 1            p = (x − 1)²·r/3 + x        #E(Fp) = h₁·r
//     φ² + φ + 1 = 0             ψ² − tψ + p = 0, t = x + 1
//     p − x = h₁·r               gcd(h₁, h₂) = 1              r ∤ h₁, r ∤ h₂
//
// This file computes every one of them. It uses its own arithmetic — extended
// Euclid inverses, a plain double-and-add — rather than the library's, so the
// constants the library derived (β, and ψ's two coefficients) are checked
// against a second derivation rather than against themselves. And it asks
// @noble/curves, an implementation that shares no code with this one, whether
// the points the Script modules refuse are really outside the subgroup.
//
// The twist order h₂·r is not assumed either. A sextic twist over Fp2 has one of
// six possible orders; all six are computed and exactly one annihilates random
// twist points.

const assert = require('assert')
const bls = require('../src/bls12381')
const points = require('../src/modules/points')
const { invmod } = require('../src/bigint')

const { P, R, X } = bls
const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r }
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n } return r }
const inv = (a) => invmod(mod(a), P)
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a }

let checks = 0
const ok = (cond, what) => {
  assert.ok(cond, what)
  checks++
  console.log(`    · ${what}`)
}

// ── independent arithmetic ──────────────────────────────────────────────────
const F2 = {
  mul: (a, b) => [mod(a[0] * b[0] - a[1] * b[1]), mod(a[0] * b[1] + a[1] * b[0])],
  add: (a, b) => [mod(a[0] + b[0]), mod(a[1] + b[1])],
  sub: (a, b) => [mod(a[0] - b[0]), mod(a[1] - b[1])],
  neg: (a) => [mod(-a[0]), mod(-a[1])],
  conj: (a) => [a[0], mod(-a[1])],
  eq: (a, b) => a[0] === b[0] && a[1] === b[1],
  zero: (a) => a[0] === 0n && a[1] === 0n,
  inv: (a) => { const d = inv(a[0] * a[0] + a[1] * a[1]); return [mod(a[0] * d), mod(-a[1] * d)] }
}
F2.pow = (a, e) => { let r = [1n, 0n]; let b = a; while (e > 0n) { if (e & 1n) r = F2.mul(r, b); b = F2.mul(b, b); e >>= 1n } return r }

const E1 = {
  add (a, b) {
    if (!a) return b
    if (!b) return a
    let l
    if (a.x === b.x) {
      if (mod(a.y + b.y) === 0n) return null
      l = mod(3n * a.x * a.x * inv(2n * a.y))
    } else l = mod((b.y - a.y) * inv(b.x - a.x))
    const x = mod(l * l - a.x - b.x)
    return { x, y: mod(l * (a.x - x) - a.y) }
  },
  neg: (a) => a && { x: a.x, y: mod(-a.y) },
  eq: (a, b) => (!a && !b) || (!!a && !!b && a.x === b.x && a.y === b.y)
}
const E2 = {
  add (a, b) {
    if (!a) return b
    if (!b) return a
    let l
    if (F2.eq(a.x, b.x)) {
      if (F2.zero(F2.add(a.y, b.y))) return null
      l = F2.mul(F2.mul(F2.mul(a.x, a.x), [3n, 0n]), F2.inv(F2.add(a.y, a.y)))
    } else l = F2.mul(F2.sub(b.y, a.y), F2.inv(F2.sub(b.x, a.x)))
    const x = F2.sub(F2.sub(F2.mul(l, l), a.x), b.x)
    return { x, y: F2.sub(F2.mul(l, F2.sub(a.x, x)), a.y) }
  },
  neg: (a) => a && { x: a.x, y: F2.neg(a.y) },
  eq: (a, b) => (!a && !b) || (!!a && !!b && F2.eq(a.x, b.x) && F2.eq(a.y, b.y))
}
const mul = (E) => (k, pt) => {
  let acc = null; let cur = pt; let e = k < 0n ? -k : k
  while (e > 0n) { if (e & 1n) acc = E.add(acc, cur); cur = E.add(cur, cur); e >>= 1n }
  return k < 0n ? E.neg(acc) : acc
}
const mul1 = mul(E1)
const mul2 = mul(E2)
const add1 = (...ps) => ps.reduce((s, p) => E1.add(s, p), null)
const add2 = (...ps) => ps.reduce((s, p) => E2.add(s, p), null)

const XI = [1n, 1n]
const B2 = F2.mul(XI, [4n, 0n])
const onE1 = (p) => mod(p.y * p.y) === mod(p.x ** 3n + 4n)
const onE2 = (q) => F2.eq(F2.mul(q.y, q.y), F2.add(F2.mul(F2.mul(q.x, q.x), q.x), B2))

async function main () {
  console.log('\n  1. THE CURVE FAMILY\n')
  const t = X + 1n
  const h1 = (X - 1n) ** 2n / 3n
  ok((X - 1n) ** 2n % 3n === 0n, 'h₁ = (x − 1)²/3 is an integer')
  ok(R === X ** 4n - X ** 2n + 1n, 'r = x⁴ − x² + 1')
  ok(P === (X - 1n) ** 2n * R / 3n + X, 'p = (x − 1)²·r/3 + x')
  ok(P - X === h1 * R, 'p − x = h₁·r')
  ok(P + 1n - t === h1 * R, '#E(Fp) = p + 1 − t = h₁·r, with t = x + 1')
  ok(h1 % R !== 0n, 'r ∤ h₁, so the points of E(Fp) that r kills are exactly G1')

  // Points of E(Fp) that are NOT in G1, found by lifting small x.
  const lifted = []
  for (let x = 1n; lifted.length < 5; x++) {
    const rhs = mod(x ** 3n + 4n)
    const y = pow(rhs, (P + 1n) / 4n)
    if (mod(y * y) === rhs) lifted.push({ x, y })
  }
  ok(lifted.every((pt) => mul1(h1 * R, pt) === null), '[h₁·r]R = O on five lifted points — the group order is right')
  ok(lifted.every((pt) => mul1(R, pt) !== null), 'none of them is in G1')

  console.log('\n  2. G1: φ(P) = [−x²]P\n')
  let root = 1n
  for (let g = 2n; root === 1n; g++) root = pow(g, (P - 1n) / 3n)
  const roots = [root, mod(root * root)]
  ok(roots.every((b) => pow(b, 3n) === 1n && b !== 1n), 'two primitive cube roots of unity in Fp')
  const phi = (b) => (pt) => pt && { x: mod(b * pt.x), y: pt.y }
  const minusX2G = mul1(-(X * X), bls.G1)
  const chosen = roots.filter((b) => E1.eq(phi(b)(bls.G1), minusX2G))
  ok(chosen.length === 1 && chosen[0] === bls.BETA, 'exactly one acts on G1 as [−x²], and it is the library\'s β')
  const other = roots.find((b) => b !== bls.BETA)
  ok(E1.eq(phi(other)(bls.G1), mul1(X * X - 1n, bls.G1)), 'the other acts as [x² − 1] — the second root of t² + t + 1 mod r')
  const phiB = phi(bls.BETA)
  ok(lifted.every((pt) => add1(phiB(phiB(pt)), phiB(pt), pt) === null),
    'φ² + φ + 1 = O on points OUTSIDE G1 — an identity of the endomorphism, not of the subgroup')
  ok(lifted.every((pt) => !E1.eq(phiB(pt), mul1(-(X * X), pt))), 'and φ(P) ≠ [−x²]P on every one of them')

  console.log('\n  3. G2: ψ(Q) = [x]Q\n')
  const cx = F2.inv(F2.pow(XI, (P - 1n) / 3n))
  const cy = F2.inv(F2.pow(XI, (P - 1n) / 2n))
  ok(F2.eq(cx, bls.PSI_X) && F2.eq(cy, bls.PSI_Y), 'ψ\'s constants, derived again from the untwisting map, match the library')
  ok(cx[0] === 0n, 'ψ\'s x-constant has no real part — which g2.inSubgroup\'s two-product form relies on')
  const psi = (q) => q && { x: F2.mul(F2.conj(q.x), cx), y: F2.mul(F2.conj(q.y), cy) }
  ok(E2.eq(psi(bls.G2), mul2(X, bls.G2)), 'ψ(G2) = [x]G2')

  const twistPoints = []
  for (let a = 1n; twistPoints.length < 4; a++) {
    const x = [a, 1n]
    const q = bls.g2lift(x)
    if (q) twistPoints.push(q)
  }
  ok(twistPoints.every(onE2), 'four points lifted onto the twist, and they are on it')
  ok(twistPoints.every((q) => add2(psi(psi(q)), mul2(-t, psi(q)), mul2(P, q)) === null),
    'ψ² − tψ + p = O on twist points outside G2 — Frobenius\'s characteristic polynomial')

  // #E′(Fp2): the sextic twists of E over Fp2 have six possible orders.
  const t2 = t * t - 2n * P
  const f2sq = (4n * P * P - t2 * t2) / 3n
  const isqrt = (n) => { let x = n; let y = (x + 1n) / 2n; while (y < x) { x = y; y = (x + n / x) / 2n } return x }
  const f2 = isqrt(f2sq)
  ok(f2 * f2 === f2sq, '4p² − t₂² = 3f₂² for an integer f₂')
  const q2 = P * P + 1n
  const candidates = [q2 - t2, q2 + t2, q2 - (t2 + 3n * f2) / 2n, q2 - (t2 - 3n * f2) / 2n, q2 + (t2 + 3n * f2) / 2n, q2 + (t2 - 3n * f2) / 2n]
  const annihilating = candidates.filter((N) => twistPoints.every((q) => mul2(N, q) === null))
  ok(annihilating.length === 1, 'exactly one of the six candidate orders annihilates the twist points')
  const N2 = annihilating[0]
  ok(N2 % R === 0n, 'r divides it')
  const h2 = N2 / R
  ok(h2 % R !== 0n, 'r ∤ h₂, so the points of E′(Fp2) that r kills are exactly G2')
  ok(gcd(h1, h2) === 1n, 'gcd(h₁, h₂) = 1 — so ψ(Q) = [x]Q, which forces [h₁·r]Q = O, forces [r]Q = O')
  ok(twistPoints.every((q) => !E2.eq(psi(q), mul2(X, q))), 'and ψ(Q) ≠ [x]Q on every twist point outside G2')

  console.log('\n  4. AN IMPLEMENTATION THAT SHARES NO CODE WITH THIS ONE\n')
  const { bls12_381: noble } = await import('@noble/curves/bls12-381.js')
  const n1 = (pt) => noble.G1.Point.fromAffine({ x: pt.x, y: pt.y })
  const Fp2 = noble.fields.Fp2
  const n2 = (q) => noble.G2.Point.fromAffine({ x: Fp2.create({ c0: q.x[0], c1: q.x[1] }), y: Fp2.create({ c0: q.y[0], c1: q.y[1] }) })

  const cof1 = mul1(R, lifted[0])
  const g1Cases = [
    ['the generator', bls.G1, true],
    ['a random multiple', mul1(0x9a3b5c7d1e2f40516273849506a7b8c9n, bls.G1), true],
    ['−G1', mul1(R - 1n, bls.G1), true],
    ['(0, 2), order 3', { x: 0n, y: 2n }, false],
    ['a lifted point', lifted[1], false],
    ['a cofactor point, [r]R', cof1, false],
    ['G1 + a cofactor point', E1.add(bls.G1, cof1), false]
  ]
  for (const [name, pt, want] of g1Cases) {
    const theirs = n1(pt).isTorsionFree()
    const mine = bls.g1InSubgroup(pt)
    const script = points.isG1(pt)
    ok(theirs === want && mine === want && script === want, `G1 ${name.padEnd(24)} noble ${theirs}, library ${mine}, module helper ${script}`)
  }
  const cof2 = mul2(R, twistPoints[0])
  const g2Cases = [
    ['the generator', bls.G2, true],
    ['a random multiple', mul2(0x1f2e3d4c5b6a79880123456789abcdefn, bls.G2), true],
    ['a lifted twist point', twistPoints[1], false],
    ['a cofactor point, [r]R', cof2, false],
    ['G2 + a cofactor point', E2.add(bls.G2, cof2), false]
  ]
  for (const [name, q, want] of g2Cases) {
    const theirs = n2(q).isTorsionFree()
    const mine = bls.g2InSubgroup(q)
    const script = points.isG2(q)
    ok(theirs === want && mine === want && script === want, `G2 ${name.padEnd(24)} noble ${theirs}, library ${mine}, module helper ${script}`)
  }

  console.log(`\n  ${checks} checks. Both endomorphism tests decide subgroup membership on BLS12-381,`)
  console.log('  for reasons computed here rather than remembered.\n')
}

main().catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
