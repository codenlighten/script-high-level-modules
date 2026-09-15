'use strict'

// BLS12-381, in plain BigInt, INSTRUMENTED.
//
// This exists to answer one question the rest of this repository has been
// unable to answer honestly: what would a pairing cost in Bitcoin Script?
//
// Every other number here is measured. That one has only ever been asserted —
// "ZK verification is not magic, it reduces to field arithmetic" — which is true
// and is not a number. So: a real pairing, correct enough to agree with an
// independent implementation on bilinearity, with a counter on every field
// operation it performs. Multiply the count by the measured cost of one
// operation in Script and the answer stops being a claim.
//
// The tower is the standard one:
//
//     Fp    = GF(p)
//     Fp2   = Fp[u]  / (u² + 1)
//     Fp6   = Fp2[v] / (v³ − ξ),   ξ = u + 1
//     Fp12  = Fp6[w] / (w² − v)
//
// Nothing here is optimised for speed in JavaScript. It is written to be
// countable and to be checkable against @noble/curves, and the operation counts
// are the product.

const P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n
// The BLS parameter. Negative, which is why the Miller loop conjugates at the end.
const X = -0xd201000000010000n

// ── the counter ─────────────────────────────────────────────────────────────
const ops = { mul: 0, add: 0, sub: 0, inv: 0 }
// The SAME work counted a second time, one level up. Fp is the wrong unit to
// price a pairing in: src/modules/fp2.js implements Fp2 operations as fused
// modules, and a fused Fp2 multiply is not three Fp multiplies plus two Fp
// adds bolted together — it shares reductions and skips a correction term the
// separate pieces would each need. So both counters run, the Fp2 one gives the
// number, and the Fp one is there to check it against.
const ops2 = { mul: 0, sqr: 0, add: 0, sub: 0, neg: 0, conj: 0, mulFp: 0, mulXi: 0, inv: 0 }
// And a third counter, at the level the four expensive modules live at. These
// are NOT disjoint from ops2 — an Fp12 product is eighteen Fp2 products and both
// counters see them — which is what makes the decomposition checkable: the Fp2
// ops a pairing performs minus the ones these four account for must come out
// non-negative, and tools/pairing-cost.js asserts that it does.
const ops12 = { mul: 0, sqr: 0, cycSqr: 0, mulLine: 0 }
const reset = () => {
  for (const k of Object.keys(ops)) ops[k] = 0
  for (const k of Object.keys(ops2)) ops2[k] = 0
  for (const k of Object.keys(ops12)) ops12[k] = 0
}
const count = () => ({ ...ops })
const count2 = () => ({ ...ops2 })
const count12 = () => ({ ...ops12 })

const mod = (a) => { const r = a % P; return r < 0n ? r + P : r }
const fpMul = (a, b) => { ops.mul++; return mod(a * b) }
const fpAdd = (a, b) => { ops.add++; const s = a + b; return s >= P ? s - P : s }
const fpSub = (a, b) => { ops.sub++; const d = a - b; return d < 0n ? d + P : d }
const fpNeg = (a) => (a === 0n ? 0n : fpSub(0n, a))
function fpPow (a, e) { let r = 1n; let b = a; let x = e; while (x > 0n) { if (x & 1n) r = fpMul(r, b); b = fpMul(b, b); x >>= 1n } return r }
// Inversion counts as ONE operation, not as the 610 multiplications this
// exponentiation happens to take, because Script does not invert by
// exponentiating. `int.modinv` takes the inverse as a WITNESS and checks
// a·a⁻¹ ≡ 1 (mod p) — one multiply and one comparison, at any width. The
// exponentiation below is an implementation detail of the JavaScript model, so
// its operations are rolled back out of the count deliberately.
const fpInv = (a) => {
  const m = ops.mul; const ad = ops.add; const sb = ops.sub
  const r = fpPow(a, P - 2n)
  ops.mul = m; ops.add = ad; ops.sub = sb; ops.inv++
  return r
}

// ── Fp2 = Fp[u]/(u² + 1) ────────────────────────────────────────────────────
const f2 = (c0 = 0n, c1 = 0n) => [c0, c1]
const F2_ZERO = f2(0n, 0n)
const F2_ONE = f2(1n, 0n)
const f2add = (a, b) => { ops2.add++; return [fpAdd(a[0], b[0]), fpAdd(a[1], b[1])] }
const f2sub = (a, b) => { ops2.sub++; return [fpSub(a[0], b[0]), fpSub(a[1], b[1])] }
const f2neg = (a) => { ops2.neg++; return [fpNeg(a[0]), fpNeg(a[1])] }
const f2conj = (a) => { ops2.conj++; return [a[0], fpNeg(a[1])] }
const f2eq = (a, b) => a[0] === b[0] && a[1] === b[1]
const f2isZero = (a) => a[0] === 0n && a[1] === 0n

/** Karatsuba: three Fp multiplications rather than four. */
function f2mul (a, b) {
  ops2.mul++
  const t0 = fpMul(a[0], b[0])
  const t1 = fpMul(a[1], b[1])
  const t2 = fpMul(fpAdd(a[0], a[1]), fpAdd(b[0], b[1]))
  return [fpSub(t0, t1), fpSub(fpSub(t2, t0), t1)]
}
/** (a0 + a1u)² = (a0 + a1)(a0 − a1) + 2a0a1·u — two multiplications. */
function f2sqr (a) {
  ops2.sqr++
  const t = fpMul(fpAdd(a[0], a[1]), fpSub(a[0], a[1]))
  const s = fpMul(a[0], a[1])
  return [t, fpAdd(s, s)]
}
function f2inv (a) {
  ops2.inv++
  const n = fpAdd(fpMul(a[0], a[0]), fpMul(a[1], a[1]))
  const i = fpInv(n)
  return [fpMul(a[0], i), fpNeg(fpMul(a[1], i))]
}
const f2mulFp = (a, k) => { ops2.mulFp++; return [fpMul(a[0], k), fpMul(a[1], k)] }
/** Multiply by ξ = u + 1. */
const f2mulXi = (a) => { ops2.mulXi++; return [fpSub(a[0], a[1]), fpAdd(a[0], a[1])] }
function f2pow (a, e) { let r = F2_ONE; let b = a; let x = e; while (x > 0n) { if (x & 1n) r = f2mul(r, b); b = f2sqr(b); x >>= 1n } return r }

// ── Fp6 = Fp2[v]/(v³ − ξ) ───────────────────────────────────────────────────
const f6 = (c0 = F2_ZERO, c1 = F2_ZERO, c2 = F2_ZERO) => [c0, c1, c2]
const F6_ZERO = f6()
const F6_ONE = f6(F2_ONE, F2_ZERO, F2_ZERO)
const f6add = (a, b) => [f2add(a[0], b[0]), f2add(a[1], b[1]), f2add(a[2], b[2])]
const f6sub = (a, b) => [f2sub(a[0], b[0]), f2sub(a[1], b[1]), f2sub(a[2], b[2])]
const f6neg = (a) => [f2neg(a[0]), f2neg(a[1]), f2neg(a[2])]
const f6eq = (a, b) => f2eq(a[0], b[0]) && f2eq(a[1], b[1]) && f2eq(a[2], b[2])
/** Multiply by v: (a0, a1, a2) → (ξa2, a0, a1). */
const f6mulV = (a) => [f2mulXi(a[2]), a[0], a[1]]

/** Karatsuba over Fp2: six Fp2 multiplications. */
function f6mul (a, b) {
  const t0 = f2mul(a[0], b[0])
  const t1 = f2mul(a[1], b[1])
  const t2 = f2mul(a[2], b[2])
  const c0 = f2add(t0, f2mulXi(f2sub(f2sub(f2mul(f2add(a[1], a[2]), f2add(b[1], b[2])), t1), t2)))
  const c1 = f2add(f2sub(f2sub(f2mul(f2add(a[0], a[1]), f2add(b[0], b[1])), t0), t1), f2mulXi(t2))
  const c2 = f2add(f2sub(f2sub(f2mul(f2add(a[0], a[2]), f2add(b[0], b[2])), t0), t2), t1)
  return [c0, c1, c2]
}
/** Chung–Hasan SQR3: three Fp2 squarings and two multiplications. */
function f6sqr (a) {
  const s0 = f2sqr(a[0])
  const ab = f2mul(a[0], a[1]); const s1 = f2add(ab, ab)
  const s2 = f2sqr(f2add(f2sub(a[0], a[1]), a[2]))
  const bc = f2mul(a[1], a[2]); const s3 = f2add(bc, bc)
  const s4 = f2sqr(a[2])
  return [
    f2add(s0, f2mulXi(s3)),
    f2add(s1, f2mulXi(s4)),
    f2sub(f2sub(f2add(f2add(s1, s2), s3), s0), s4)
  ]
}
function f6inv (a) {
  const c0 = f2sub(f2sqr(a[0]), f2mulXi(f2mul(a[1], a[2])))
  const c1 = f2sub(f2mulXi(f2sqr(a[2])), f2mul(a[0], a[1]))
  const c2 = f2sub(f2sqr(a[1]), f2mul(a[0], a[2]))
  const t = f2add(f2mulXi(f2add(f2mul(a[2], c1), f2mul(a[1], c2))), f2mul(a[0], c0))
  const ti = f2inv(t)
  return [f2mul(c0, ti), f2mul(c1, ti), f2mul(c2, ti)]
}

// ── Fp12 = Fp6[w]/(w² − v) ──────────────────────────────────────────────────
const f12 = (c0 = F6_ZERO, c1 = F6_ZERO) => [c0, c1]
const F12_ONE = f12(F6_ONE, F6_ZERO)
const f12mulRaw = (a, b) => {
  ops12.mul++
  const t0 = f6mul(a[0], b[0])
  const t1 = f6mul(a[1], b[1])
  const c0 = f6add(t0, f6mulV(t1))
  const c1 = f6sub(f6sub(f6mul(f6add(a[0], a[1]), f6add(b[0], b[1])), t0), t1)
  return [c0, c1]
}
/** Karatsuba squaring: two Fp6 multiplications rather than three. */
function f12sqr (a) {
  ops12.sqr++
  const t = f6mul(a[0], a[1])
  const c0 = f6sub(f6sub(f6mul(f6add(a[0], a[1]), f6add(a[0], f6mulV(a[1]))), t), f6mulV(t))
  return [c0, f6add(t, t)]
}
const f12conj = (a) => [a[0], f6neg(a[1])]
const f12eq = (a, b) => f6eq(a[0], b[0]) && f6eq(a[1], b[1])
function f12inv (a) {
  const t = f6sub(f6sqr(a[0]), f6mulV(f6sqr(a[1])))
  const ti = f6inv(t)
  return [f6mul(a[0], ti), f6neg(f6mul(a[1], ti))]
}
function f12pow (a, e) { let r = F12_ONE; let b = a; let x = e; while (x > 0n) { if (x & 1n) r = f12mulRaw(r, b); b = f12sqr(b); x >>= 1n } return r }

// ── Frobenius ───────────────────────────────────────────────────────────────
// The coefficients are DERIVED rather than transcribed: γ_{1,i} = ξ^(i(p−1)/6),
// computed once with the same Fp2 arithmetic everything else uses. A table of
// hex constants copied from somewhere is a table that can be copied wrongly.
const XI = f2(1n, 1n)
const FROB = []
for (let i = 1; i < 6; i++) FROB.push(f2pow(XI, (BigInt(i) * (P - 1n)) / 6n))
const G1_ = FROB[0]; const G2_ = FROB[1]; const G3_ = FROB[2]; const G4_ = FROB[3]; const G5_ = FROB[4]

// v^p = v·ξ^((p−1)/3) and v^2p = v²·ξ^(2(p−1)/3); the Fp2 Frobenius is conjugation
// because p ≡ 3 (mod 4).
const f6frob = (a) => [f2conj(a[0]), f2mul(f2conj(a[1]), G2_), f2mul(f2conj(a[2]), G4_)]
// w^p = w·ξ^((p−1)/6). In a NESTED tower the Fp6 part has already taken its own
// constants, and what remains is one Fp2 scalar applied to the whole of it —
// not a different constant per coefficient, which is what a flat Fp2[w]/(w⁶−ξ)
// presentation would want and is the shape this had first.
const f12frob = (a) => {
  const hi = f6frob(a[1])
  return [f6frob(a[0]), [f2mul(hi[0], G1_), f2mul(hi[1], G1_), f2mul(hi[2], G1_)]]
}
function f12frobN (a, n) { let r = a; for (let i = 0; i < n; i++) r = f12frob(r); return r }

// ── the curve ───────────────────────────────────────────────────────────────
const B = 4n
const B2 = f2mulXi(f2(B, 0n))                                  // 4(u + 1)
const G1 = {
  x: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
  y: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
}
const G2 = {
  x: f2(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
    0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en),
  y: f2(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
    0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben)
}

/** k·P in G1, affine, double-and-add. */
function g1mul (k, p = G1) {
  let acc = null; let cur = p; let e = ((k % R) + R) % R
  while (e > 0n) {
    if (e & 1n) acc = g1add(acc, cur)
    cur = g1add(cur, cur)
    e >>= 1n
  }
  return acc
}
function g1add (a, b) {
  if (!a) return b
  if (!b) return a
  if (a.x === b.x) {
    if (a.y !== b.y || a.y === 0n) return null
    const l = fpMul(fpMul(3n, fpMul(a.x, a.x)), fpInv(fpAdd(a.y, a.y)))
    const x = fpSub(fpMul(l, l), fpAdd(a.x, a.x))
    return { x, y: fpSub(fpMul(l, fpSub(a.x, x)), a.y) }
  }
  const l = fpMul(fpSub(b.y, a.y), fpInv(fpSub(b.x, a.x)))
  const x = fpSub(fpSub(fpMul(l, l), a.x), b.x)
  return { x, y: fpSub(fpMul(l, fpSub(a.x, x)), a.y) }
}
function g2add (a, b) {
  if (!a) return b
  if (!b) return a
  if (f2eq(a.x, b.x)) {
    if (!f2eq(a.y, b.y) || f2isZero(a.y)) return null
    const l = f2mul(f2mulFp(f2sqr(a.x), 3n), f2inv(f2add(a.y, a.y)))
    const x = f2sub(f2sqr(l), f2add(a.x, a.x))
    return { x, y: f2sub(f2mul(l, f2sub(a.x, x)), a.y) }
  }
  const l = f2mul(f2sub(b.y, a.y), f2inv(f2sub(b.x, a.x)))
  const x = f2sub(f2sub(f2sqr(l), a.x), b.x)
  return { x, y: f2sub(f2mul(l, f2sub(a.x, x)), a.y) }
}
function g2mul (k, q = G2) {
  let acc = null; let cur = q; let e = ((k % R) + R) % R
  while (e > 0n) {
    if (e & 1n) acc = g2add(acc, cur)
    cur = g2add(cur, cur)
    e >>= 1n
  }
  return acc
}
const g1neg = (p) => (p ? { x: p.x, y: fpNeg(p.y) } : null)
const g2neg = (q) => (q ? { x: q.x, y: f2neg(q.y) } : null)

// ── SUBGROUP MEMBERSHIP, by endomorphism ────────────────────────────────────
//
// E(Fp) has h₁·r points and the twist E′(Fp2) has h₂·r, so a point can satisfy
// its curve equation and lie outside the order-r subgroup a pairing is defined
// on. [r]P = O decides membership and costs a 255-bit ladder. Each curve has an
// endomorphism that acts on the subgroup as multiplication by a SMALL power of
// x, and comparing the two is the same decision for a fraction of the ladder.
//
//   G1   φ(x, y) = (βx, y), β a cube root of 1.     P ∈ G1  ⟺  φ(P) = [−x²]P
//   G2   ψ = untwist ∘ Frobenius ∘ twist.            Q ∈ G2  ⟺  ψ(Q) = [x]Q
//
// Why each "⟸" holds is short enough to state, and every fact it uses is checked
// numerically by tools/subgroup-derive.js rather than taken on trust:
//
//   G1.  φ³ = 1 and φ ≠ 1, so φ² + φ + 1 = 0 in End(E). If φ(P) = [−x²]P then
//        O = (φ² + φ + 1)P = [x⁴ − x² + 1]P = [r]P. Since r ∤ h₁, the points of
//        E(Fp) killed by r are exactly G1.
//
//   G2.  ψ satisfies Frobenius's characteristic polynomial ψ² − tψ + p = 0 with
//        t = x + 1. If ψ(Q) = [x]Q then O = [x² − tx + p]Q = [p − x]Q, and
//        p − x = h₁·r. Q also has [h₂·r]Q = O, and gcd(h₁, h₂) = 1, so [r]Q = O.
//        r ∤ h₂, so that is G2.
//
// Which cube root β is, and the two ψ constants, are DERIVED here — β by trying
// both roots against the generator, ψ from the untwisting map — not copied from
// a table. The G2 argument turns on gcd(h₁, h₂) = 1, which is a property of
// BLS12-381 rather than of every curve, and the tool computes h₂ to check it.

/** k·P for any k and any point on E(Fp) — NOT reduced mod r, which g1mul does. */
function g1mulAny (k, p) {
  let acc = null; let cur = p; let e = k < 0n ? -k : k
  while (e > 0n) { if (e & 1n) acc = g1add(acc, cur); cur = g1add(cur, cur); e >>= 1n }
  return k < 0n ? g1neg(acc) : acc
}
/** k·Q for any k and any point on E′(Fp2). */
function g2mulAny (k, q) {
  let acc = null; let cur = q; let e = k < 0n ? -k : k
  while (e > 0n) { if (e & 1n) acc = g2add(acc, cur); cur = g2add(cur, cur); e >>= 1n }
  return k < 0n ? g2neg(acc) : acc
}
const g1eq = (a, b) => (!a && !b) || (!!a && !!b && a.x === b.x && a.y === b.y)
const g2eq = (a, b) => (!a && !b) || (!!a && !!b && f2eq(a.x, b.x) && f2eq(a.y, b.y))
const g1onCurve = (p) => mod(p.y * p.y) === mod(p.x * p.x * p.x + B)
const g2onCurve = (q) => f2eq(f2sqr(q.y), f2add(f2mul(f2sqr(q.x), q.x), B2))

/** √a in Fp, or null. p ≡ 3 (mod 4), so the candidate is a^((p+1)/4) — and it is checked. */
function sqrtFp (a) {
  const s = fpPow(mod(a), (P + 1n) / 4n)
  return mod(s * s) === mod(a) ? s : null
}
/**
 * √a in Fp2, or null. Algorithm 9 of Adj and Rodríguez-Henríquez for p ≡ 3
 * (mod 4); the result is squared and compared before it is returned, so a
 * misremembered step returns null rather than a wrong root.
 */
function sqrtFp2 (a) {
  if (f2isZero(a)) return F2_ZERO
  const a1 = f2pow(a, (P - 3n) / 4n)
  const alpha = f2mul(f2sqr(a1), a)
  const MINUS_ONE = f2(P - 1n, 0n)
  if (f2eq(f2mul(f2conj(alpha), alpha), MINUS_ONE)) return null
  const x0 = f2mul(a1, a)
  const x = f2eq(alpha, MINUS_ONE)
    ? f2mul(f2(0n, 1n), x0)
    : f2mul(f2pow(f2add(F2_ONE, alpha), (P - 1n) / 2n), x0)
  return f2eq(f2sqr(x), a) ? x : null
}
/** The point on E(Fp) with this x, if there is one. */
function g1lift (x) {
  const y = sqrtFp(mod(x * x * x + B))
  return y === null ? null : { x: mod(x), y }
}
/** The point on E′(Fp2) with this x, if there is one. */
function g2lift (x) {
  const y = sqrtFp2(f2add(f2mul(f2sqr(x), x), B2))
  return y === null ? null : { x, y }
}

// β: both primitive cube roots of unity satisfy φ³ = 1, and they act on G1 as
// the two roots of t² + t + 1 mod r, which are −x² and x² − 1. Only one of them
// is −x², and the generator says which.
const BETA = (() => {
  let root = 1n
  for (let g = 2n; root === 1n; g++) root = fpPow(g, (P - 1n) / 3n)
  const want = g1mulAny(-(X * X), G1)
  const found = [root, mod(root * root)].filter((b) => g1eq({ x: mod(b * G1.x), y: G1.y }, want))
  if (found.length !== 1) throw new Error('bls12381: no cube root of unity acts on G1 as [−x²]')
  return found[0]
})()

// ψ(x, y) = (x̄·ξ^((1−p)/3), ȳ·ξ^((1−p)/2)). The twist is D-type, so a point
// untwists by DIVISION: (x, y) ↦ (x/w², y/w³). Apply the p-power Frobenius and
// twist back by multiplying by w², w³: the x-coordinate picks up
// w^(2−2p) = (w⁶)^((1−p)/3) = ξ^((1−p)/3), the y-coordinate w^(3−3p) = ξ^((1−p)/2).
const PSI_X = f2inv(f2pow(XI, (P - 1n) / 3n))
const PSI_Y = f2inv(f2pow(XI, (P - 1n) / 2n))

const g1phi = (p) => ({ x: mod(BETA * p.x), y: p.y })
const g2psi = (q) => ({ x: f2mul(f2conj(q.x), PSI_X), y: f2mul(f2conj(q.y), PSI_Y) })

if (!g2eq(g2psi(G2), g2mulAny(X, G2))) throw new Error('bls12381: ψ does not act on G2 as [x] — the untwisting map is wrong')
// Deriving β and checking ψ ran the group law, and the operation counters are
// module state a cost measurement reads. They start from zero for whoever
// measures first.
reset()

/** The reference test the Script modules are checked against. */
const g1InSubgroup = (p) => !!p && g1onCurve(p) && g1eq(g1phi(p), g1mulAny(-(X * X), p))
const g2InSubgroup = (q) => !!q && g2onCurve(q) && g2eq(g2psi(q), g2mulAny(X, q))

// ── the Miller loop ─────────────────────────────────────────────────────────
//
// Affine, with the line evaluated as a full Fp12 element rather than a sparse
// one. A production implementation uses projective coordinates and sparse
// multiplication and is perhaps twice as cheap; this one is written to be
// obviously correct, and tools/pairing-cost.js says plainly which it counted.

// The line, untwisted, in the basis this tower actually uses.
//
// Fp12 = Fp6[w]/(w² − v) over Fp6 = Fp2[v]/(v³ − ξ), so w⁶ = ξ and the twelve
// coefficients sit at
//
//     w⁰ → c0[0]   w² → c0[1]   w⁴ → c0[2]
//     w¹ → c1[0]   w³ → c1[1]   w⁵ → c1[2]
//
// BLS12-381's twist is D-TYPE, which decides everything below and is worth
// deriving rather than recalling. If a point of E'(Fp2) untwisted by
// MULTIPLICATION — ψ(x, y) = (x·w², y·w³) — then y²w⁶ = x³w⁶ + 4 would put the
// twist at y² = x³ + 4/ξ. BLS12-381's twist is y² = x³ + 4ξ, which comes out of
// DIVISION: ψ(x, y) = (x/w², y/w³) gives y² = x³ + 4w⁶ = x³ + 4ξ. So the map is
// division, the slope of the untwisted curve at ψ(T) is λ·w⁻¹, and
//
//     l(P) = y_P − λ·x_P·w⁻¹ + (λ·x_T − y_T)·w⁻³
//
// Scaled through by ξ — a constant in Fp2, which the final exponentiation kills,
// since (p⁶ − 1) annihilates anything whose order divides p² − 1 — and using
// w⁻¹ = w⁵/ξ, w⁻³ = w³/ξ:
//
//     ξ·l(P) = ξ·y_P + (λ·x_T − y_T)·w³ − λ·x_P·w⁵
//
// The first version of this assumed multiplication and put −λx_P at w¹. It was
// non-degenerate, it produced values of order r, and it was not bilinear —
// every component test passed and the whole thing was wrong, which is the only
// interesting kind of bug.
//
// Only THREE of the twelve Fp2 coefficients are ever non-zero, so the line is
// carried as those three and multiplied in sparsely — 14 Fp2 multiplications
// instead of the 18 a general Fp12 product costs. f12mulLine is checked against
// f12mulRaw on the dense form in tools/bls-crosscheck.js.
function lineAt (lambda, T, P, next) {
  return {
    l0: f2mulXi(f2(P.y, 0n)),                                  // ξ·y_P          at w⁰
    l1: f2sub(f2mul(lambda, T.x), T.y),                        // λx_T − y_T     at w³
    l2: f2neg(f2mulFp(lambda, P.x)),                           // −λx_P          at w⁵
    next
  }
}
/** The dense Fp12 the three coefficients stand for — for checking, not for use. */
const lineDense = (l) => f12(f6(l.l0, F2_ZERO, F2_ZERO), f6(F2_ZERO, l.l1, l.l2))

/** (a0, a1, a2) · (b, 0, 0) — three Fp2 multiplications. */
const f6mulC0 = (a, b) => [f2mul(a[0], b), f2mul(a[1], b), f2mul(a[2], b)]
/** (a0, a1, a2) · (0, b1, b2) — five, with Karatsuba on the cross term. */
function f6mulC12 (a, b1, b2) {
  const t1 = f2mul(a[1], b1)
  const t2 = f2mul(a[2], b2)
  const cross = f2sub(f2sub(f2mul(f2add(a[1], a[2]), f2add(b1, b2)), t1), t2)   // a1b2 + a2b1
  return [
    f2mulXi(cross),
    f2add(f2mul(a[0], b1), f2mulXi(t2)),
    f2add(f2mul(a[0], b2), t1)
  ]
}
/** f · (l0 + l1w³ + l2w⁵), by Karatsuba over Fp6: 3 + 5 + 6 = 14 Fp2 muls. */
function f12mulLine (f, l) {
  ops12.mulLine++
  const t0 = f6mulC0(f[0], l.l0)
  const t1 = f6mulC12(f[1], l.l1, l.l2)
  const t2 = f6mul(f6add(f[0], f[1]), f6(l.l0, l.l1, l.l2))
  return [f6add(t0, f6mulV(t1)), f6sub(f6sub(t2, t0), t1)]
}
/**
 * The third intersection, from the slope that was already computed.
 *
 * g2add would find this too, and would find λ a second time to do it — which is
 * a second modular inversion for a number the caller is holding. Both line
 * functions below already have λ, so the loop takes 68 inversions rather than
 * 136, and in Script an inversion is a witness that has to be supplied,
 * bounded and checked. Halving them halves that.
 */
const chord = (l, T, bx) => {
  const x = f2sub(f2sub(f2sqr(l), T.x), bx)
  return { x, y: f2sub(f2mul(l, f2sub(T.x, x)), T.y) }
}
/** The tangent at T, evaluated at P. */
function lineDouble (T, P) {
  const l = f2mul(f2mulFp(f2sqr(T.x), 3n), f2inv(f2add(T.y, T.y)))
  return lineAt(l, T, P, chord(l, T, T.x))
}
/** The line through T and Q, evaluated at P. */
function lineAdd (T, Q, P) {
  const l = f2mul(f2sub(Q.y, T.y), f2inv(f2sub(Q.x, T.x)))
  return lineAt(l, T, P, chord(l, T, Q.x))
}

function millerLoop (P, Q) {
  const n = X < 0n ? -X : X
  const bits = n.toString(2)
  let f = F12_ONE
  let T = Q
  for (let i = 1; i < bits.length; i++) {
    f = f12sqr(f)
    const d = lineDouble(T, P); T = d.next
    f = f12mulLine(f, d)
    if (bits[i] === '1') {
      const a = lineAdd(T, Q, P); T = a.next
      f = f12mulLine(f, a)
    }
  }
  return X < 0n ? f12conj(f) : f
}

// ── the final exponentiation ────────────────────────────────────────────────
// SQUARING IN THE CYCLOTOMIC SUBGROUP.
//
// After the easy part the value lies in G_Φ6(Fp2), where a square costs half a
// general one. Two earlier attempts at this formula disagreed with general
// squaring and were thrown away rather than published; what makes this one work
// is presenting the tower FLAT instead of nested.
//
// Fp12 is written here as Fp6[w]/(w² − v) over Fp2[v]/(v³ − ξ), so w² = v and
// w⁶ = ξ — which means it is equally Fp2[w]/(w⁶ − ξ), with basis 1, w, …, w⁵:
//
//     f = g0 + g1w + g2w² + g3w³ + g4w⁴ + g5w⁵
//
// and (w³)² = ξ, so s = w³ generates an Fp4 = Fp2[s]/(s² − ξ). In THAT basis f
// is three Fp4 coefficients — (g0,g3), (g1,g4), (g2,g5) — and the Granger–Scott
// identities apply directly. Those pairs are what the nested indexing hides,
// and having them wrong is what sank both earlier attempts.
//
// Three Fp4 squarings, nine Fp2 SQUARINGS in all, against the twelve Fp2
// MULTIPLICATIONS a general Fp12 squaring costs. That is the whole saving, and
// tools/bls-crosscheck.js checks it against f12sqr on a genuine cyclotomic
// element rather than assuming it.
//
// Inversion in the subgroup is conjugation, and that is checked too.

/** Flat w-basis coefficients g0…g5, and back. */
const flat6 = (f) => [f[0][0], f[1][0], f[0][1], f[1][1], f[0][2], f[1][2]]
const nest6 = (g) => [[g[0], g[2], g[4]], [g[1], g[3], g[5]]]
const f2x2 = (a) => f2add(a, a)
const f2x3 = (a) => f2add(f2add(a, a), a)
/** (x + ys)² in Fp4 = Fp2[s]/(s² − ξ) — three Fp2 squarings, no multiplications. */
function f4sqr (x, y) {
  const t0 = f2sqr(x); const t1 = f2sqr(y)
  return [f2add(t0, f2mulXi(t1)), f2sub(f2sub(f2sqr(f2add(x, y)), t0), t1)]
}
function cyclotomicSqr (f) {
  ops12.cycSqr++
  const g = flat6(f)
  const [t0, t1] = f4sqr(g[0], g[3])
  const [t2, t3] = f4sqr(g[1], g[4])
  const [t4, t5] = f4sqr(g[2], g[5])
  return nest6([
    f2sub(f2x3(t0), f2x2(g[0])),
    f2add(f2x3(f2mulXi(t5)), f2x2(g[1])),
    f2sub(f2x3(t2), f2x2(g[2])),
    f2add(f2x3(t1), f2x2(g[3])),
    f2sub(f2x3(t4), f2x2(g[4])),
    f2add(f2x3(t3), f2x2(g[5]))
  ])
}
// COMPRESSED SQUARING, and why it is worth more here than on a processor.
//
// Read the Granger–Scott formulas above in the Fp4 basis and something falls
// out: writing f as c0 + c1w + c2w² over Fp4 = Fp2[s]/(s² − ξ) with s = w³,
//
//     c0' depends only on c0
//     c1' depends only on c1 and c2
//     c2' depends only on c1 and c2
//
// so {c1, c2} is CLOSED under squaring and c0 can be dropped. That is a 2/6
// compression — four Fp2 coefficients instead of six — and its squaring costs
// two Fp4 squarings rather than three.
//
// Compression is only useful if you can come back, and decompression is where
// this normally stops being worth it: it costs an inversion, so the technique
// pays only across long runs of squarings. In Script an inversion is a witness
// and four multiplications, which moves the break-even a long way down. This is
// the same reversal as affine-beats-projective, in a second place.
//
// The recovery is DERIVED rather than recalled. For f in the cyclotomic
// subgroup f·f̄ = 1, and with f̄ = c̄0 − c̄1w + c̄2w² that gives three Fp4
// equations. Two of them are LINEAR in c0 = x + ys:
//
//     w²:   2(c0c̄2)₀ = N(c1)      ⟹   c2ᵣ·x − ξ·c2ₛ·y =  N(c1)/2
//     w¹:   2(c1c̄0)₁ = −N(c2)     ⟹   c1ₛ·x −    c1ᵣ·y = −N(c2)/2
//
// writing u = uᵣ + uₛ·s and N(u) = uᵣ² − ξuₛ². Solving the 2×2 system needs one
// Fp2 inversion of its determinant. Both equations are scaled by two so that no
// halving is emitted.
//
// The determinant ξ·c1ₛc2ₛ − c1ᵣc2ᵣ can be zero, and then this recovers nothing.
// That is a COMPLETENESS limit, not a soundness one: a spender cannot use it to
// make a wrong pairing verify, only to make a right one fail, and the values it
// depends on are determined by the computation rather than chosen.

/** (c1, c2) as four Fp2 coefficients: flat indices 1, 4, 2, 5. */
const compress = (f) => { const g = flat6(f); return [g[1], g[4], g[2], g[5]] }

/** Squaring in the compressed form — two Fp4 squarings, not three. */
function compressedSqr (c) {
  const [t2, t3] = f4sqr(c[0], c[1])
  const [t4, t5] = f4sqr(c[2], c[3])
  return [
    f2add(f2x3(f2mulXi(t5)), f2x2(c[0])),
    f2sub(f2x3(t4), f2x2(c[1])),
    f2sub(f2x3(t2), f2x2(c[2])),
    f2add(f2x3(t3), f2x2(c[3]))
  ]
}

/** The Fp4 norm N(uᵣ + uₛs) = uᵣ² − ξuₛ². */
const f4norm = (r, sPart) => f2sub(f2sqr(r), f2mulXi(f2sqr(sPart)))

/**
 * Back to twelve coefficients. Returns null when the determinant vanishes,
 * which the caller must treat as "this element cannot be recovered" rather
 * than as an answer.
 */
function decompress (c) {
  const [c1r, c1s, c2r, c2s] = c
  const det = f2x2(f2sub(f2mulXi(f2mul(c1s, c2s)), f2mul(c1r, c2r)))
  if (det[0] === 0n && det[1] === 0n) return null
  const b1 = f4norm(c1r, c1s)                                  // = 2·(rhs of w²)
  const b2 = f2sub(F2_ZERO, f4norm(c2r, c2s))                  // = 2·(rhs of w¹)
  const di = f2inv(det)
  //  [ c2r   −ξc2s ] [x]   [b1]
  //  [ c1s   −c1r  ] [y] = [b2]
  const x = f2mul(f2sub(f2mul(b2, f2mulXi(c2s)), f2mul(b1, c1r)), di)
  const y = f2mul(f2sub(f2mul(c2r, b2), f2mul(c1s, b1)), di)
  return nest6([x, c1r, c2r, y, c1s, c2s])
}

function cyclotomicPow (a, e) {
  let r = F12_ONE; let b = a; let x = e < 0n ? -e : e
  while (x > 0n) { if (x & 1n) r = f12mulRaw(r, b); b = cyclotomicSqr(b); x >>= 1n }
  return e < 0n ? f12conj(r) : r
}

// The hard part's exponent, as an ADDITION CHAIN in the curve parameter.
//
// λ = 3(p⁴ − p² + 1)/r is 1,270 bits, and exponentiating by it directly is
// 1,270 squarings. It does not have to be. Two structural facts collapse it:
//
//   · p is a Frobenius map, not an exponentiation. So write λ in base p and the
//     four digits are applied by φ, which costs five Fp2 multiplications.
//   · every one of those digits is a small polynomial in the 63-bit curve
//     parameter y = |x|. So write each digit in base y and what is left is five
//     exponentiations by y — shared across all four digits — and a handful of
//     multiplications by coefficients no larger than 3.
//
// Both expansions are BALANCED (digits in (−m/2, m/2]), which is free here:
// after the easy part the value lies in the cyclotomic subgroup, where
// inversion is conjugation. That is checked rather than assumed.
//
// The result is 5 × 63 = 315 squarings where the naive chain took 1,270 and the
// base-p-only chain this replaced took 887. Nothing is transcribed: the digits
// are derived at load time by the same arithmetic everything else here uses, so
// a wrong constant is not a thing that can happen.
//
// The exponent carries a factor of 3. The plain hard part is (p⁴ − p² + 1)/r;
// every optimized BLS12 chain (Scott et al., Fuentes-Castañeda) computes
// 3·(p⁴ − p² + 1)/r instead, because the 3 falls out of the chain for free and
// gcd(3, r) = 1 makes cubing a bijection on μ_r — so the result is still a
// pairing. @noble/curves computes the ×3 form; taking it here too makes the
// cross-check an exact equality rather than an equality up to a cube.
const Y = X < 0n ? -X : X

/** Balanced digits of v in base m: each in (−m/2, m/2], least significant first. */
function balanced (v, m) {
  const out = []
  while (v !== 0n) {
    let r = v % m
    if (r < 0n) r += m
    if (r > m / 2n) r -= m
    out.push(r)
    v = (v - r) / m
  }
  return out
}

// { i: power of p, j: power of y, a: coefficient } — λ = Σ a·y^j·p^i
const HARD_TERMS = (() => {
  const terms = []
  balanced(3n * (P ** 4n - P ** 2n + 1n) / R, P)
    .forEach((c, i) => balanced(c, Y).forEach((a, j) => { if (a !== 0n) terms.push({ i, j, a }) }))
  return terms
})()
const HARD_MAX_J = HARD_TERMS.reduce((m, t) => Math.max(m, t.j), 0)

function finalExponentiate (f) {
  // easy part: f^(p⁶ − 1)(p² + 1), after which conjugation is inversion
  let r = f12mulRaw(f12conj(f), f12inv(f))
  r = f12mulRaw(f12frobN(r, 2), r)

  // the shared ladder r^(y^j) — the only expensive thing in here
  const pow = [r]
  for (let j = 1; j <= HARD_MAX_J; j++) pow.push(cyclotomicPow(pow[j - 1], Y))

  let acc = F12_ONE
  for (const t of HARD_TERMS) acc = f12mulRaw(acc, cyclotomicPow(f12frobN(pow[t.j], t.i), t.a))
  return acc
}

/** The optimal ate pairing. */
function pairing (P, Q) { return finalExponentiate(millerLoop(P, Q)) }

module.exports = {
  P, R, X, B, B2, G1, G2, ops, ops2, ops12, reset, count, count2, count12,
  mod, fpMul, fpAdd, fpSub, fpInv, fpPow,
  f2, f2add, f2sub, f2mul, f2sqr, f2inv, f2conj, f2mulXi, f2pow, f2eq, F2_ONE, F2_ZERO, FROB, f2x2, f2x3,
  f6, f6mul, f6sqr, f6inv, F6_ONE,
  f12, f12mulRaw, f12sqr, f12inv, f12conj, f12frob, f12frobN, f12pow, f12eq, F12_ONE,
  cyclotomicPow, cyclotomicSqr, compress, compressedSqr, decompress, HARD_TERMS, Y,
  g1add, g1mul, g1neg, g2add, g2mul, g2neg,
  g1mulAny, g2mulAny, g1eq, g2eq, g1onCurve, g2onCurve, sqrtFp, sqrtFp2, g1lift, g2lift,
  BETA, PSI_X, PSI_Y, g1phi, g2psi, g1InSubgroup, g2InSubgroup,
  lineDouble, lineAdd, lineDense, f12mulLine,
  millerLoop, finalExponentiate, pairing
}
