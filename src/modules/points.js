'use strict'

const { defineModule, apply } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')
const ec = require('./ec')
const bls = require('../bls12381')
const { mod, invmod } = require('../bigint')

// ARE THESE POINTS WHAT THEY CLAIM TO BE?
//
// A verifier that reads a proof out of an unlocking script is reading numbers a
// spender chose. Bounding them into [0, p) makes each of them ONE field element
// rather than a congruence class, which is necessary and is not sufficient: a
// pair of field elements is not a curve point, and a curve point is not
// necessarily an element of the prime-order subgroup a pairing is defined on.
//
// Groth16 requires both, and this file supplies both.
//
//     y² = x³ + 4            on G1, over Fp
//     y² = x³ + 4(u + 1)     on G2, over Fp2, the D-type twist
//
// SUBGROUP MEMBERSHIP. E(Fp) has order h₁·r and the twist has order h₂·r, so a
// point can satisfy the curve equation and lie outside the r-order subgroup,
// where a pairing is not the bilinear map the security argument is about. The
// direct test is [r]P = O, a 255-bit ladder. Both curves have an endomorphism
// that acts on the subgroup as a small power of x, and comparing the two decides
// membership for a fraction of that:
//
//     g1.inSubgroup   φ(P) = [−x²]P    two 63-bit ladders
//     g2.inSubgroup   ψ(Q) = [x]Q      NO ladder — see below
//
// Why each comparison implies membership is in src/bls12381.js, and every fact
// that argument uses — φ² + φ + 1 = 0, ψ² − tψ + p = 0, p − x = h₁·r,
// gcd(h₁, h₂) = 1 — is computed by tools/subgroup-derive.js rather than recalled.
// This repository has twice written a cyclotomic squaring formula from memory
// and twice thrown it away; a subgroup check written that way would be worse
// than none, because it would be believed.
//
// THE G2 CHECK IS NEARLY FREE, and the reason is worth more than the bytes. A
// Miller loop over Q starts T at Q and runs the bits of |x| through it: a
// doubling per bit, an addition per set bit. When the loop ends, T IS [|x|]Q,
// computed by exactly the witnessed ladder a standalone check would have
// emitted. So wherever a spender's G2 point enters a pairing — B in a Groth16
// proof, σ in a BLS signature — its subgroup check is a comparison against a
// value the loop already produced: one Fp2 conjugate-and-scale and four
// congruences.

const P381 = bls.P
const { op, dup, numericModulus, residues, pushModulus, modulusName, dropModulus, inner } = fp6

const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}

/**
 * y² = x³ + b over Fp — the G1 curve equation, as a predicate.
 *
 * Three multiplications and two reductions. On a 1.24 MB verifier this is not a
 * cost, it is a rounding error, and its absence was a soundness gap.
 */
const onCurveG1 = defineModule({
  name: 'g1.onCurve',
  doc: 'y² = x³ + b over Fp — refuses a pair of field elements that is not a point',
  inputs: ['x', 'y'],
  outputs: [],
  requires: inField('g1.onCurve', 'x', 'y'),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n, b = 4n } = params
    const N = modulusName(n)
    asm.pick('y', '_y1'); asm.roll('y'); asm.mul('_yy')
    asm.pick(N, '_n'); asm.mod('_y2')
    asm.pick('x', '_x1'); asm.pick('x', '_x2'); asm.mul('_xx')
    asm.pick(N, '_n'); asm.mod('_x2r')
    asm.roll('x'); asm.mul('_xxx')
    asm.num(b, '_b'); asm.add('_rhs')
    asm.pick(N, '_n'); asm.mod('_rhsr')
    asm.numEqualVerify()
    dropModulus(asm, n)
  },
  cases: (() => {
    const G1 = bls.G1
    const two = bls.g1mul(2n)
    return [
      { name: 'the generator', inputs: { x: G1.x, y: G1.y }, params: { n: P381 } },
      { name: '2G1', inputs: { x: two.x, y: two.y }, params: { n: P381 } },
      { name: 'y negated is still on it', inputs: { x: G1.x, y: P381 - G1.y }, params: { n: P381 } },
      { name: 'x off by one', refuse: 'not a point on the curve', inputs: { x: G1.x + 1n, y: G1.y }, params: { n: P381 } },
      { name: 'y off by one', refuse: 'not a point on the curve', inputs: { x: G1.x, y: G1.y + 1n }, params: { n: P381 } },
      { name: 'both zero', refuse: 'the point at infinity has no affine coordinates', inputs: { x: 0n, y: 0n }, params: { n: P381 } }
    ]
  })(),
  notes: ['necessary and not sufficient: says nothing about the prime-order subgroup — g1.inSubgroup does']
})

/**
 * y² = x³ + 4(u + 1) over Fp2 — the twist's curve equation, as a predicate.
 *
 * The constant is derived, not written: B2 = ξ·4 with ξ = u + 1, computed by
 * bls12381.js with the same Fp2 arithmetic everything else uses.
 */
const onCurveG2 = defineModule({
  name: 'g2.onCurve',
  doc: 'y² = x³ + 4(u + 1) over Fp2 — refuses coordinates that are not a twist point',
  inputs: ['x0', 'x1', 'y0', 'y1'],
  outputs: [],
  requires: inField('g2.onCurve', 'x0', 'x1', 'y0', 'y1'),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'g2.onCurve')
    const lhs = op(asm, fp2.sqr, p, ['y'])
    const x3 = op(asm, fp2.mul, p, [op(asm, fp2.sqr, p, [dup(asm, 'x')]), 'x'])
    asm.num(bls.B2[0], '_b0'); asm.num(bls.B2[1], '_b1')
    const rhs = op(asm, fp2.add, p, [x3, '_b'])
    asm.roll(rhs + '0'); asm.roll(lhs + '0'); asm.numEqualVerify()
    asm.roll(rhs + '1'); asm.roll(lhs + '1'); asm.numEqualVerify()
    dropModulus(asm, n)
  },
  cases: (() => {
    const Q = bls.G2
    const two = bls.g2mul(2n)
    return [
      { name: 'the generator', inputs: { x0: Q.x[0], x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] }, params: { n: P381 } },
      { name: '2G2', inputs: { x0: two.x[0], x1: two.x[1], y0: two.y[0], y1: two.y[1] }, params: { n: P381 } },
      { name: 'x0 off by one', refuse: 'not a point on the twist', inputs: { x0: Q.x[0] + 1n, x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] }, params: { n: P381 } },
      { name: 'y1 off by one', refuse: 'not a point on the twist', inputs: { x0: Q.x[0], x1: Q.x[1], y0: Q.y[0], y1: Q.y[1] + 1n }, params: { n: P381 } },
      { name: 'the untwisted G1 coordinates', refuse: 'a G1 point is not a twist point', inputs: { x0: bls.G1.x, x1: 0n, y0: bls.G1.y, y1: 0n }, params: { n: P381 } }
    ]
  })(),
  notes: ['necessary and not sufficient: says nothing about the prime-order subgroup — g2.inSubgroup does']
})

// ── fast affine arithmetic, for witnesses and test points only ──────────────
//
// bls12381.js inverts by exponentiation so that its operation counters mean
// something. Nothing here is counted, and a 255-bit ladder that inverts by
// extended Euclid instead is the difference between a module that loads at
// once and one that makes every tool in the repository wait.
const fast = (() => {
  const inv = (a) => invmod(mod(a, P381), P381)
  const g1add = (a, b) => {
    if (!a) return b
    if (!b) return a
    if (a.x === b.x) {
      if (mod(a.y + b.y, P381) === 0n) return null
      const l = mod(3n * a.x * a.x * inv(2n * a.y), P381)
      const x = mod(l * l - 2n * a.x, P381)
      return { x, y: mod(l * (a.x - x) - a.y, P381) }
    }
    const l = mod((b.y - a.y) * inv(b.x - a.x), P381)
    const x = mod(l * l - a.x - b.x, P381)
    return { x, y: mod(l * (a.x - x) - a.y, P381) }
  }
  const m2 = (a, b) => [mod(a[0] * b[0] - a[1] * b[1], P381), mod(a[0] * b[1] + a[1] * b[0], P381)]
  const s2 = (a, b) => [mod(a[0] - b[0], P381), mod(a[1] - b[1], P381)]
  const i2 = (a) => { const d = inv(a[0] * a[0] + a[1] * a[1]); return [mod(a[0] * d, P381), mod(-a[1] * d, P381)] }
  const z2 = (a) => a[0] === 0n && a[1] === 0n
  const g2add = (a, b) => {
    if (!a) return b
    if (!b) return a
    let l
    if (a.x[0] === b.x[0] && a.x[1] === b.x[1]) {
      if (z2([mod(a.y[0] + b.y[0], P381), mod(a.y[1] + b.y[1], P381)])) return null
      const xx = m2(a.x, a.x)
      l = m2([mod(3n * xx[0], P381), mod(3n * xx[1], P381)], i2([mod(2n * a.y[0], P381), mod(2n * a.y[1], P381)]))
    } else {
      l = m2(s2(b.y, a.y), i2(s2(b.x, a.x)))
    }
    const x = s2(s2(m2(l, l), a.x), b.x)
    return { x, y: s2(m2(l, s2(a.x, x)), a.y) }
  }
  const ladder = (add, neg) => (k, pt) => {
    let acc = null; let cur = pt; let e = k < 0n ? -k : k
    while (e > 0n) { if (e & 1n) acc = add(acc, cur); cur = add(cur, cur); e >>= 1n }
    return k < 0n && acc ? neg(acc) : acc
  }
  return {
    inv,
    g1add,
    g1mul: ladder(g1add, (p) => ({ x: p.x, y: mod(-p.y, P381) })),
    g2add,
    g2mul: ladder(g2add, (q) => ({ x: q.x, y: [mod(-q.y[0], P381), mod(-q.y[1], P381)] }))
  }
})()

// ── G1: φ(P) = [−x²]P ───────────────────────────────────────────────────────
//
// [x²]P as two ladders by |x| rather than one by x², because |x| has six set
// bits and x² has many more: 63 doublings and 5 additions, twice, is 136 point
// operations where a single 126-bit ladder would be about 190. The scalar is a
// compile-time constant, so neither ladder branches and neither needs the
// offset point a runtime scalar does — every step is known to be a doubling or
// an addition before the script is written.
//
// Then −[x²]P = φ(P) is two comparisons: x-coordinates by β·x, and y-coordinates
// that must sum to exactly p.
//
// THE CURVE CHECK IS PART OF THIS, NOT A NEIGHBOUR OF IT. Short Weierstrass
// doubling and addition with a = 0 never read b. Given coordinates that are not
// on y² = x³ + 4, the ladder runs perfectly well — on y² = x³ + b′ for whatever
// b′ they imply, a curve with its own group order and its own copy of φ. The
// argument that φ(P) = [−x²]P forces [r]P = O holds on THAT curve too. So
// without the curve check this module would certify that a point had order r on
// some curve, which is not a statement anybody needs.

const XABS = bls.X < 0n ? -bls.X : bls.X
const XBITS = XABS.toString(2)
const LADDER = []
for (let i = 1; i < XBITS.length; i++) {
  LADDER.push('double')
  if (XBITS[i] === '1') LADDER.push('add')
}
const G1_WITNESSES = 2 * LADDER.length
/**
 * Declared deepest-first — s135 … s0 — so the next inverse a step needs is
 * always the one directly beneath the running point, a two-byte OP_ROLL.
 */
const g1WitnessNames = (prefix = 's') => Array.from({ length: G1_WITNESSES }, (_, k) => `${prefix}${G1_WITNESSES - 1 - k}`)

/**
 * The inverses both ladders consume, in the order they consume them.
 *
 * For a point the ladder cannot finish on — (0, 2) has order 3, and 2·(0, 2)
 * has the same x as (0, 2) — an undefined inverse is given as zero. No witness
 * inverts zero, so the script refuses; that is the right answer and the hint
 * does not need to pretend otherwise.
 */
function g1LadderWitnesses (pt, prefix = 's') {
  const out = {}
  let k = 0
  let base = pt
  for (let round = 0; round < 2; round++) {
    let T = base
    for (const step of LADDER) {
      if (!T || !base) { out[`${prefix}${k++}`] = 0n; continue }
      const den = step === 'double' ? mod(2n * T.y, P381) : mod(base.x - T.x, P381)
      out[`${prefix}${k++}`] = den === 0n ? 0n : fast.inv(den)
      T = den === 0n ? null : fast.g1add(T, step === 'double' ? T : base)
    }
    base = T
  }
  return out
}

const inG1 = defineModule({
  name: 'g1.inSubgroup',
  doc: 'P ∈ G1: P is on y² = x³ + 4 and φ(P) = [−x²]P — two 63-bit ladders instead of one 255-bit one',
  inputs: [...g1WitnessNames().map((name) => ({ name, witness: true })), 'x', 'y'],
  outputs: [],
  requires: inField('g1.inSubgroup', 'x', 'y'),
  maxWitnessAttacks: 6,
  hint: ({ x, y }) => g1LadderWitnesses({ x, y }),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const N = modulusName(n)
    const nn = numericModulus(params, 'g1.inSubgroup')

    asm.pick('x', '_cx'); asm.pick('y', '_cy')
    apply(asm, onCurveG1, { n: N, nn }, ['_cx', '_cy'], [])

    // ec.double and ec.add are the secp256k1 modules, and they are this curve's
    // too: a = 0 for both, and the prime arrives by name.
    asm.num(2n * nn, '_p2')
    const pp = { p: N, p2: '_p2', pn: nn }
    let k = 0
    const ladder = (bx, by) => {
      asm.pick(bx, '_Tx'); asm.pick(by, '_Ty')
      for (const step of LADDER) {
        if (step === 'add') { asm.pick(bx, '_ax'); asm.pick(by, '_ay') }
        // The arguments are now the top of the stack in the callee's order, so
        // apply() moves nothing; the results are relabelled rather than rolled,
        // which is two bytes a step a ladder of 136 steps notices.
        asm.roll(`s${k}`)
        if (step === 'double') apply(asm, ec.double, pp, ['_Tx', '_Ty', `s${k}`])
        else apply(asm, ec.add, pp, ['_Tx', '_Ty', '_ax', '_ay', `s${k}`])
        asm.relabel('x3', '_Tx'); asm.relabel('y3', '_Ty')
        k++
      }
    }
    ladder('x', 'y')                                               // [|x|]P
    asm.relabel('_Tx', '_Bx'); asm.relabel('_Ty', '_By')
    ladder('_Bx', '_By')                                           // [x²]P
    asm.discard('_Bx'); asm.discard('_By')

    // −[x²]P = φ(P) = (βx, y). Both y-coordinates are in [0, p) and neither is
    // zero on this curve, so "they negate each other" is "they sum to p".
    asm.roll('_Ty'); asm.roll('y'); asm.add('_ysum')
    asm.pick(N, '_pp'); asm.numEqualVerify()
    asm.roll('x'); asm.num(bls.BETA, '_beta'); asm.mul('_bx')
    asm.pick(N, '_pq'); asm.mod('_bxr')
    asm.roll('_Tx'); asm.numEqualVerify()
    asm.discard('_p2')
    dropModulus(asm, n)
  },
  fuzz: (rnd) => {
    let k = 0n
    for (let i = 0; i < 9; i++) k = (k << 30n) | BigInt(Math.floor(rnd() * (1 << 30)))
    const pt = bls.g1mul(k % (bls.R - 1n) + 1n)
    return { inputs: { x: pt.x, y: pt.y }, params: { n: P381 } }
  },
  cases: (() => {
    const params = { n: P381 }
    const at = (pt, name) => ({ name, inputs: { x: pt.x, y: pt.y }, params })
    const refused = (pt, name, why) => ({ name, refuse: why, inputs: { ...g1LadderWitnesses(pt), x: pt.x, y: pt.y }, params })
    // A point of the cofactor group: anything on the curve, times r.
    const cofactor = fast.g1mul(bls.R, bls.g1lift(4n))
    const mixed = fast.g1add(bls.G1, cofactor)
    const offCurve = { x: bls.G1.x, y: mod(bls.G1.y + 1n, P381) }
    return [
      at(bls.G1, 'the generator'),
      at(fast.g1mul(2n, bls.G1), '2G1'),
      at(fast.g1mul(bls.R - 1n, bls.G1), '−G1'),
      at(fast.g1mul(0x5eed0f1c2b3a49586776a5b4c3d2e1f0n, bls.G1), 'a random multiple'),
      refused({ x: 0n, y: 2n }, '(0, 2), a point of order 3', 'on the curve and not in G1 — its ladder meets the point at infinity'),
      refused(cofactor, 'a point of the cofactor group', 'on the curve, the ladder completes, and φ does not act on it as [−x²]'),
      refused(mixed, 'G1 plus a cofactor point', 'on the curve, of order divisible by r, and still not in G1'),
      refused(offCurve, 'coordinates off the curve', 'the ladder never reads b, so the curve check is what refuses these')
    ]
  })(),
  notes: [
    '136 witnessed inverses, each bounded into [0, p) by the ec module that reads it',
    'includes the curve equation: without it the ladder would run on whichever curve y² = x³ + b′ the coordinates happen to lie on'
  ]
})

// ── points that are on their curve and not in their subgroup ────────────────
//
// For tests that need a proof whose point is malformed in exactly one way.
//
//   G1   (0, 2) is on y² = x³ + 4 — x = 0 makes the tangent horizontal, so it
//        is a point of order 3. P + (0, 2) is on the curve and of order 3r.
//   G2   [r]R for a twist point R is killed by h₂ and not by r. Q + [r]R is on
//        the twist and outside G2.
const ORDER3 = { x: 0n, y: 2n }
let twistCofactor = null
function cofactorTwistPoint () {
  if (twistCofactor) return twistCofactor
  for (let a = 1n; ; a++) {
    const R = bls.g2lift([a, 1n])
    if (R) { twistCofactor = fast.g2mul(bls.R, R); return twistCofactor }
  }
}
const outside = {
  g1: (pt) => fast.g1add(pt, ORDER3),
  g2: (q) => fast.g2add(q, cofactorTwistPoint())
}

// ── G2: ψ(Q) = [x]Q, given the [|x|]Q a Miller loop already computed ────────
//
// Because x is negative, ψ(Q) = [x]Q is T = −ψ(Q) for T = [|x|]Q, and ψ is
// (x̄·c_x, ȳ·c_y) with c_x and c_y derived in bls12381.js. c_x happens to have
// no real part — which is checked here at load time, not assumed — so its half
// of ψ is two Fp products:
//
//     conj(x)·(c·u) = (x₀ − x₁u)·c·u = c·x₁ + c·x₀·u
//
// and c_y is general:
//
//     conj(y)·c_y = (y₀c₀ + y₁c₁) + (y₀c₁ − y₁c₀)·u
//
// Every comparison is a congruence, (a − b) mod p = 0, which truncated OP_MOD
// decides correctly whatever the sign of a − b.
//
// THE PRECONDITION IS THE WHOLE CONTRACT. This module is sound only if T really
// is [|x|]Q. It does not compute T and cannot tell; the caller must hand it the
// T its own Miller loop finished with, never a value the spender supplied.
// groth16.verify and groth16.split do; test.js checks that they do.

const PSI_XC = (() => {
  if (bls.PSI_X[0] !== 0n) throw new Error('points: ψ\'s x-constant has a real part, and g2.inSubgroup was written for one without')
  return bls.PSI_X[1]
})()
const [PSI_Y0, PSI_Y1] = bls.PSI_Y

const inG2 = defineModule({
  name: 'g2.inSubgroup',
  doc: 'Q ∈ G2, given T = [|x|]Q from a Miller loop over Q: Q is on the twist and T = −ψ(Q)',
  inputs: ['x0', 'x1', 'y0', 'y1', 'tx0', 'tx1', 'ty0', 'ty1'],
  outputs: [],
  requires: inField('g2.inSubgroup', 'x0', 'x1', 'y0', 'y1', 'tx0', 'tx1', 'ty0', 'ty1'),
  model: () => ({}),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const N = modulusName(n)
    const nn = numericModulus(params, 'g2.inSubgroup')

    for (const c of ['x0', 'x1', 'y0', 'y1']) asm.pick(c, '_q' + c)
    apply(asm, onCurveG2, { n: N, nn }, ['_qx0', '_qx1', '_qy0', '_qy1'], [])

    const zero = (name) => { asm.pick(N, '_n'); asm.mod(name); asm.num(0, '_z'); asm.numEqualVerify() }

    // T.x = ψ(Q).x: tx0 ≡ c·x1 and tx1 ≡ c·x0
    asm.num(PSI_XC, '_c')
    asm.roll('x1'); asm.pick('_c', '_c1'); asm.mul('_cx1'); asm.roll('tx0'); asm.sub('_d0'); zero('_e0')
    asm.roll('x0'); asm.roll('_c'); asm.mul('_cx0'); asm.roll('tx1'); asm.sub('_d1'); zero('_e1')

    // T.y = −ψ(Q).y: ty0 + y0c0 + y1c1 ≡ 0 and ty1 + y0c1 − y1c0 ≡ 0
    asm.num(PSI_Y0, '_k0'); asm.num(PSI_Y1, '_k1')
    asm.pick('y0', '_a'); asm.pick('_k0', '_b'); asm.mul('_y0k0')
    asm.pick('y1', '_a'); asm.pick('_k1', '_b'); asm.mul('_y1k1'); asm.add('_re')
    asm.roll('ty0'); asm.add('_re2'); zero('_e2')
    asm.roll('y0'); asm.roll('_k1'); asm.mul('_y0k1')
    asm.roll('y1'); asm.roll('_k0'); asm.mul('_y1k0'); asm.sub('_im')
    asm.roll('ty1'); asm.add('_im2'); zero('_e3')

    dropModulus(asm, n)
  },
  fuzz: (rnd) => {
    let k = 0n
    for (let i = 0; i < 9; i++) k = (k << 30n) | BigInt(Math.floor(rnd() * (1 << 30)))
    const Q = bls.g2mul(k % (bls.R - 1n) + 1n)
    const T = fast.g2mul(XABS, Q)
    return { inputs: g2Inputs(Q, T), params: { n: P381 } }
  },
  cases: (() => {
    const params = { n: P381 }
    const withT = (Q, name, extra = {}) => ({ name, inputs: g2Inputs(Q, fast.g2mul(XABS, Q)), params, ...extra })
    const cofactor = cofactorTwistPoint()
    const mixed = fast.g2add(bls.G2, cofactor)
    const Q = bls.G2
    const T = fast.g2mul(XABS, Q)
    return [
      withT(Q, 'the generator'),
      withT(fast.g2mul(3n, Q), '3G2'),
      withT(fast.g2mul(0x0ddba11cafef00d5eed1234567890abn, Q), 'a random multiple'),
      withT(cofactor, 'a point of the cofactor group', { refuse: 'on the twist, T = [|x|]Q honestly, and ψ does not act on it as [x]' }),
      withT(mixed, 'G2 plus a cofactor point', { refuse: 'on the twist, of order divisible by r, and still not in G2' }),
      { name: 'T of the wrong sign', refuse: 'ψ(Q) = [x]Q with x negative — [|x|]Q is its negation, not it', inputs: g2Inputs(Q, { x: T.x, y: [mod(-T.y[0], P381), mod(-T.y[1], P381)] }), params },
      { name: 'Q off the twist', refuse: 'a pair of Fp2 elements is not a twist point', inputs: { ...g2Inputs(Q, T), y1: mod(Q.y[1] + 1n, P381) }, params }
    ]
  })(),
  notes: [
    'PRECONDITION: tx0…ty1 must be [|x|]Q as computed by the caller — a Miller loop over Q ends with exactly that; a spender-supplied T makes this check meaningless',
    'includes the twist equation, which the argument that ψ(Q) = [x]Q forces [r]Q = O depends on'
  ]
})

function g2Inputs (Q, T) {
  return {
    x0: Q.x[0], x1: Q.x[1], y0: Q.y[0], y1: Q.y[1],
    tx0: T.x[0], tx1: T.x[1], ty0: T.y[0], ty1: T.y[1]
  }
}

/**
 * The same two decisions in JavaScript, for points that are checked once when
 * a coin is BUILT rather than every time it is spent — a verifying key's α, β,
 * γ, δ and IC. A key with a point outside its subgroup is not a key, and the
 * verifier refuses to compile one.
 */
const isG1 = (p) => !!p && bls.g1onCurve(p) && bls.g1eq(bls.g1phi(p), fast.g1mul(-(bls.X * bls.X), p))
const isG2 = (q) => !!q && bls.g2onCurve(q) && bls.g2eq(bls.g2psi(q), fast.g2mul(bls.X, q))

module.exports = { onCurveG1, onCurveG2, inG1, inG2, isG1, isG2, g1LadderWitnesses, g1WitnessNames, g2Inputs, outside, ORDER3, G1_WITNESSES, LADDER, XABS, fast }
