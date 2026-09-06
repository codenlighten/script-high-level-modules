'use strict'

const { defineModule } = require('../module')
const { mod, invmod } = require('../bigint')

// Fp2 = Fp[u]/(u² + 1) — the quadratic extension a pairing lives in.
//
// Everything above this in a pairing tower — Fp6, Fp12, the Miller loop, the
// final exponentiation — is Fp2 arithmetic and nothing else. So this is the
// layer worth building as modules and measuring: count the Fp2 operations a
// real pairing performs (src/bls12381.js does that), multiply by what one costs
// here, and the cost of a pairing in Script stops being a claim.
//
// The prime is a compile-time parameter and may be a NAME of a value already on
// the stack, exactly as in int.js. That matters more here than anywhere else in
// this repository: the BLS12-381 prime is a 49-byte push and a pairing performs
// tens of thousands of reductions. Pushed once and OP_PICKed, each reference
// costs two bytes; pushed per operation it would add three megabytes.

function numericModulus (params, who) {
  const nn = params.nn !== undefined ? params.nn : params.n
  if (typeof nn === 'bigint' || typeof nn === 'number') return BigInt(nn)
  throw new Error(`${who}: the modulus is '${params.n}', a value on the stack, so its number is not known here — ` +
    'pass nn: <the prime> alongside it, or the contract this module states would quietly mean nothing')
}
const residues = (params, who) => ({ range: { lo: 0n, hi: numericModulus(params, who) } })
/** Both coefficients of an Fp2 element are reduced, or nothing below is correct. */
const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}

const PN = '_pn'
const pushModulus = (asm, n) => { if (typeof n !== 'string') asm.num(n, PN) }
const modulusName = (n) => (typeof n === 'string' ? n : PN)
const pushedItself = (n) => typeof n !== 'string'
const dropModulus = (asm, n) => { if (pushedItself(n)) asm.discard(PN) }
/** Reduce whatever is on top, by a modulus that is somewhere below it. */
const reduce = (asm, n, out) => { asm.pick(modulusName(n), '_n'); asm.mod(out) }

/**
 * (a0 + a1u)(b0 + b1u) = (a0b0 − a1b1) + (a0b1 + a1b0)u
 *
 * Karatsuba, three OP_MULs rather than four:
 *
 *     t0 = a0b0        t1 = a1b1        t2 = (a0 + a1)(b0 + b1)
 *     r0 = t0 − t1     r1 = t2 − t0 − t1
 *
 * t0 and t1 are deliberately left UNREDUCED. OP_MOD is truncated, so anything
 * that might be negative when it reaches it has to have the modulus added
 * first — and the whole point of keeping the raw products is that the
 * imaginary part never can be: t2 − t0 − t1 is identically a0b1 + a1b0, a sum
 * of two non-negative numbers. It needs no correction term at all. Only the
 * real part is a genuine difference, and it pays for one reduction and one
 * addition of p to become non-negative before its own OP_MOD.
 *
 * Reducing t0 and t1 up front instead would cost two extra OP_MODs and would
 * still need a 2p correction on the imaginary part, because the reduced
 * difference no longer carries the identity that makes it positive.
 */
const mul = defineModule({
  name: 'fp2.mul',
  doc: 'r = a·b in Fp2 = Fp[u]/(u² + 1), for coefficients already in [0, p)',
  inputs: ['a0', 'a1', 'b0', 'b1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.mul', 'a0', 'a1', 'b0', 'b1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.mul'), r1: residues(p, 'fp2.mul') }),
  model: ({ a0, a1, b0, b1 }, { n }) => ({
    r0: mod(a0 * b0 - a1 * b1, n),
    r1: mod(a0 * b1 + a1 * b0, n)
  }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.pick('a0', '_x'); asm.pick('b0', '_y'); asm.mul('t0')      // a0b0, raw
    asm.pick('a1', '_x'); asm.pick('b1', '_y'); asm.mul('t1')      // a1b1, raw
    asm.roll('a0'); asm.roll('a1'); asm.add('_sa')                 // last use of a
    asm.roll('b0'); asm.roll('b1'); asm.add('_sb')                 // last use of b
    asm.mul('t2')
    // imaginary part: t2 − t0 − t1 IS a0b1 + a1b0, so it is never negative
    asm.pick('t0', '_u'); asm.sub('_d'); asm.pick('t1', '_v'); asm.sub('_e')
    reduce(asm, n, 'r1')
    // real part: a genuine difference, so t1 is reduced and p added
    asm.toAlt()
    reduce(asm, n, '_t1r')
    asm.sub('_d0')                                                 // ∈ (−p, p²)
    asm.pick(modulusName(n), '_n'); asm.add('_d0p')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  notes: [
    'three OP_MULs and three OP_MODs: the products stay raw so that the imaginary part is non-negative by construction'
  ],
  cases: (() => {
    const p = 11n
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: 'small', inputs: { a0: 3n, a1: 4n, b0: 5n, b1: 6n }, params: { n: p } },
      { name: 'u·u = −1', inputs: { a0: 0n, a1: 1n, b0: 0n, b1: 1n }, params: { n: p } },
      { name: 'by one', inputs: { a0: 7n, a1: 9n, b0: 1n, b1: 0n }, params: { n: p } },
      { name: 'by zero', inputs: { a0: 7n, a1: 9n, b0: 0n, b1: 0n }, params: { n: p } },
      { name: 'real part borrows', inputs: { a0: 1n, a1: 10n, b0: 1n, b1: 10n }, params: { n: p } },
      {
        name: 'BLS12-381 Fp2',
        inputs: {
          a0: 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
          a1: 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en,
          b0: 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
          b1: 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben
        },
        params: { n: P381 }
      },
      { name: 'BLS12-381 extremes', inputs: { a0: P381 - 1n, a1: P381 - 1n, b0: P381 - 1n, b1: P381 - 1n }, params: { n: P381 } }
    ]
  })()
})

/**
 * (a0 + a1u)² = (a0 + a1)(a0 − a1) + 2a0a1·u — two OP_MULs, not three.
 *
 * The real part is a product of a sum and a DIFFERENCE, and the difference can
 * be negative. Adding p to it is free of consequence — (a0 + a1)·p ≡ 0 (mod p)
 * — so the correction goes inside the multiplication rather than after it, and
 * the result reaches OP_MOD already non-negative without a second reduction.
 */
const sqr = defineModule({
  name: 'fp2.sqr',
  doc: 'r = a² in Fp2, for coefficients already in [0, p)',
  inputs: ['a0', 'a1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.sqr', 'a0', 'a1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.sqr'), r1: residues(p, 'fp2.sqr') }),
  model: ({ a0, a1 }, { n }) => ({ r0: mod(a0 * a0 - a1 * a1, n), r1: mod(2n * a0 * a1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.pick('a0', '_x'); asm.pick('a1', '_y'); asm.mul('_p')      // a0a1 ≥ 0
    asm.pick('_p', '_p2'); asm.add('_2p')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.pick('a0', '_x'); asm.pick('a1', '_y'); asm.sub('_d')      // ∈ (−p, p)
    asm.pick(modulusName(n), '_n'); asm.add('_dp')                 // ∈ (0, 2p)
    asm.roll('a0'); asm.roll('a1'); asm.add('_s')                  // ∈ [0, 2p)
    asm.mul('_prod')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: (() => {
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: 'small', inputs: { a0: 3n, a1: 4n }, params: { n: 11n } },
      { name: 'u² = −1', inputs: { a0: 0n, a1: 1n }, params: { n: 11n } },
      { name: 'real only', inputs: { a0: 5n, a1: 0n }, params: { n: 11n } },
      { name: 'zero', inputs: { a0: 0n, a1: 0n }, params: { n: 11n } },
      { name: 'a1 > a0', inputs: { a0: 2n, a1: 9n }, params: { n: 11n } },
      { name: 'BLS12-381', inputs: { a0: P381 - 7n, a1: 3n }, params: { n: P381 } }
    ]
  })()
})

const addm = defineModule({
  name: 'fp2.add',
  doc: 'r = a + b in Fp2',
  inputs: ['a0', 'a1', 'b0', 'b1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.add', 'a0', 'a1', 'b0', 'b1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.add'), r1: residues(p, 'fp2.add') }),
  model: ({ a0, a1, b0, b1 }, { n }) => ({ r0: mod(a0 + b0, n), r1: mod(a1 + b1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.roll('a1'); asm.roll('b1'); asm.add('_s1')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.roll('a0'); asm.roll('b0'); asm.add('_s0')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: [
    { name: 'small', inputs: { a0: 3n, a1: 4n, b0: 5n, b1: 6n }, params: { n: 11n } },
    { name: 'both wrap', inputs: { a0: 10n, a1: 10n, b0: 10n, b1: 10n }, params: { n: 11n } },
    { name: 'zero', inputs: { a0: 0n, a1: 0n, b0: 0n, b1: 0n }, params: { n: 11n } }
  ]
})

const subm = defineModule({
  name: 'fp2.sub',
  doc: 'r = a − b in Fp2, non-negative — OP_MOD is truncated, so p goes in first',
  inputs: ['a0', 'a1', 'b0', 'b1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.sub', 'a0', 'a1', 'b0', 'b1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.sub'), r1: residues(p, 'fp2.sub') }),
  model: ({ a0, a1, b0, b1 }, { n }) => ({ r0: mod(a0 - b0, n), r1: mod(a1 - b1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.roll('a1'); asm.roll('b1'); asm.sub('_d1')
    asm.pick(modulusName(n), '_n'); asm.add('_d1p')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.roll('a0'); asm.roll('b0'); asm.sub('_d0')
    asm.pick(modulusName(n), '_n'); asm.add('_d0p')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: [
    { name: 'small', inputs: { a0: 9n, a1: 8n, b0: 3n, b1: 4n }, params: { n: 11n } },
    { name: 'both borrow', inputs: { a0: 1n, a1: 2n, b0: 9n, b1: 10n }, params: { n: 11n } },
    { name: 'to zero', inputs: { a0: 5n, a1: 5n, b0: 5n, b1: 5n }, params: { n: 11n } }
  ]
})

/**
 * r = a·ξ where ξ = u + 1 — the non-residue the rest of the tower is built on.
 *
 * (a0 + a1u)(1 + u) = (a0 − a1) + (a0 + a1)u. NO multiplications at all, which
 * is the entire reason ξ is chosen this shape: Fp6 multiplication uses it three
 * times per product and it costs an add, a subtract and two reductions.
 */
const mulXi = defineModule({
  name: 'fp2.mulXi',
  doc: 'r = a·(u + 1), the tower non-residue — no multiplications',
  inputs: ['a0', 'a1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.mulXi', 'a0', 'a1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.mulXi'), r1: residues(p, 'fp2.mulXi') }),
  model: ({ a0, a1 }, { n }) => ({ r0: mod(a0 - a1, n), r1: mod(a0 + a1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.pick('a0', '_x'); asm.pick('a1', '_y'); asm.add('_s')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.roll('a0'); asm.roll('a1'); asm.sub('_d')
    asm.pick(modulusName(n), '_n'); asm.add('_dp')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: [
    { name: 'small', inputs: { a0: 3n, a1: 4n }, params: { n: 11n } },
    { name: 'one', inputs: { a0: 1n, a1: 0n }, params: { n: 11n } },
    { name: 'borrows', inputs: { a0: 2n, a1: 9n }, params: { n: 11n } }
  ]
})

/**
 * r = −a in Fp2, canonically: (p − a0, p − a1) reduced.
 *
 * Correct at zero without a branch, which is the only interesting thing about
 * it: p − 0 is p, and p mod p is 0. The OP_MOD that would otherwise look like
 * belt-and-braces is what makes the negation of zero come back as zero rather
 * than as p, and a downstream comparison would notice the difference.
 */
const neg = defineModule({
  name: 'fp2.neg',
  doc: 'r = −a in Fp2',
  inputs: ['a0', 'a1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.neg', 'a0', 'a1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.neg'), r1: residues(p, 'fp2.neg') }),
  model: ({ a0, a1 }, { n }) => ({ r0: mod(-a0, n), r1: mod(-a1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.pick(modulusName(n), '_n'); asm.roll('a1'); asm.sub('_d1')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.pick(modulusName(n), '_n'); asm.roll('a0'); asm.sub('_d0')
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: (() => {
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: 'small', inputs: { a0: 3n, a1: 4n }, params: { n: 11n } },
      { name: 'zero stays zero', inputs: { a0: 0n, a1: 0n }, params: { n: 11n } },
      { name: 'one coefficient zero', inputs: { a0: 5n, a1: 0n }, params: { n: 11n } },
      { name: 'BLS12-381', inputs: { a0: P381 - 1n, a1: 1n }, params: { n: P381 } }
    ]
  })()
})

/**
 * r = ā in Fp2 — the conjugate, which is also the Frobenius here.
 *
 * p ≡ 3 (mod 4) for every pairing-friendly prime this tower works over, so
 * a^p = ā: raising to the p-th power in Fp2 is negating one coefficient. That
 * is the whole reason a degree-12 Frobenius costs seven multiplications rather
 * than a 381-bit exponentiation, and fp12.frob is built on it.
 */
const conj = defineModule({
  name: 'fp2.conj',
  doc: 'r = ā in Fp2 — the conjugate, and the Frobenius when p ≡ 3 (mod 4)',
  inputs: ['a0', 'a1'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.conj', 'a0', 'a1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.conj'), r1: residues(p, 'fp2.conj') }),
  model: ({ a0, a1 }, { n }) => ({ r0: mod(a0, n), r1: mod(-a1, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.pick(modulusName(n), '_n'); asm.roll('a1'); asm.sub('_d1')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.roll('a0'); asm.rename('r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: (() => {
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: 'small', inputs: { a0: 3n, a1: 4n }, params: { n: 11n } },
      { name: 'real stays put', inputs: { a0: 7n, a1: 0n }, params: { n: 11n } },
      { name: 'zero', inputs: { a0: 0n, a1: 0n }, params: { n: 11n } },
      { name: 'BLS12-381', inputs: { a0: 5n, a1: P381 - 1n }, params: { n: P381 } }
    ]
  })()
})

/**
 * r = a·k where k is a plain Fp scalar — two OP_MULs, no cross terms.
 *
 * The Frobenius map and the Miller loop's line function both scale an Fp2
 * element by something that lives in the base field, and paying for a full Fp2
 * multiplication to do it would be paying for two products that are zero.
 */
const mulFp = defineModule({
  name: 'fp2.mulFp',
  doc: 'r = a·k for a in Fp2 and k in Fp',
  inputs: ['a0', 'a1', 'k'],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.mulFp', 'a0', 'a1', 'k'),
  ensures: (p) => ({ r0: residues(p, 'fp2.mulFp'), r1: residues(p, 'fp2.mulFp') }),
  model: ({ a0, a1, k }, { n }) => ({ r0: mod(a0 * k, n), r1: mod(a1 * k, n) }),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, { n }) => {
    asm.roll('a1'); asm.pick('k', '_k'); asm.mul('_m1')
    reduce(asm, n, 'r1')
    asm.toAlt()
    asm.roll('a0'); asm.roll('k'); asm.mul('_m0')                  // both last used here
    reduce(asm, n, 'r0')
    asm.fromAlt()
    dropModulus(asm, n)
  },
  cases: (() => {
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: 'small', inputs: { a0: 3n, a1: 4n, k: 5n }, params: { n: 11n } },
      { name: 'by zero', inputs: { a0: 3n, a1: 4n, k: 0n }, params: { n: 11n } },
      { name: 'by one', inputs: { a0: 3n, a1: 4n, k: 1n }, params: { n: 11n } },
      { name: 'BLS12-381', inputs: { a0: P381 - 7n, a1: 3n, k: P381 - 2n }, params: { n: P381 } }
    ]
  })()
})

/**
 * r = a⁻¹ in Fp2, SUPPLIED BY THE SPENDER and checked.
 *
 * This is the reason a pairing is affordable in Script at all. Every fast
 * implementation of a Miller loop uses projective coordinates specifically to
 * avoid inversions, paying several extra multiplications per step to do it —
 * because on a CPU an inversion is a few hundred multiplications.
 *
 * Here it is four. The spender computes a⁻¹ off-chain and the script checks
 * a·a⁻¹ = 1, which is one Fp2 multiplication written out. So the usual trade
 * inverts: AFFINE arithmetic is the cheap choice in Script, and the projective
 * formulas everyone reaches for would make a pairing bigger, not smaller.
 *
 * Both coefficients are bounded into [0, p) first. Without that a spender has
 * infinitely many encodings of the same inverse — r and r + p verify the
 * identical multiplication — and a downstream module comparing results would
 * be comparing numbers that are congruent rather than equal.
 */
const inv = defineModule({
  name: 'fp2.inv',
  doc: 'r = a⁻¹ in Fp2, witnessed and checked (a·r = 1, both coefficients in [0, p))',
  inputs: ['a0', 'a1', { name: 'i0', witness: true }, { name: 'i1', witness: true }],
  outputs: ['r0', 'r1'],
  requires: inField('fp2.inv', 'a0', 'a1'),
  ensures: (p) => ({ r0: residues(p, 'fp2.inv'), r1: residues(p, 'fp2.inv') }),
  hint: ({ a0, a1 }, { n }) => {
    const d = invmod(mod(a0 * a0 + a1 * a1, n), n)
    return { i0: mod(a0 * d, n), i1: mod(-a1 * d, n) }
  },
  model: ({ a0, a1 }, { n }) => {
    const d = invmod(mod(a0 * a0 + a1 * a1, n), n)
    return { r0: mod(a0 * d, n), r1: mod(-a1 * d, n) }
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const nn = numericModulus(params, 'fp2.inv')
    asm.bound('i0', 0n, nn, '_b0')
    asm.bound('i1', 0n, nn, '_b1')
    // real part: a0i0 − a1i1 ≡ 1. a1i1 is reduced first so that one added p
    // is enough to clear the sign before a truncated OP_MOD sees it.
    asm.pick('a0', '_x'); asm.pick('i0', '_y'); asm.mul('_m0')
    asm.pick('a1', '_x'); asm.pick('i1', '_y'); asm.mul('_m1')
    reduce(asm, n, '_m1r')
    asm.sub('_re')
    asm.pick(modulusName(n), '_n'); asm.add('_rep')
    reduce(asm, n, '_rer')
    asm.num(1, '_one'); asm.numEqualVerify()
    // imaginary part: a0i1 + a1i0 ≡ 0. Both terms non-negative, so no correction.
    asm.roll('a0'); asm.pick('i1', '_y'); asm.mul('_m2')
    asm.roll('a1'); asm.pick('i0', '_y'); asm.mul('_m3')
    asm.add('_im')
    reduce(asm, n, '_imr')
    asm.num(0, '_zero'); asm.numEqualVerify()
    asm.roll('i0'); asm.rename('r0')
    asm.roll('i1'); asm.rename('r1')
    dropModulus(asm, n)
  },
  cases: (() => {
    const P381 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
    return [
      { name: '(3 + 4u)⁻¹ mod 11', inputs: { a0: 3n, a1: 4n }, params: { n: 11n } },
      { name: 'u⁻¹ mod 11', inputs: { a0: 0n, a1: 1n }, params: { n: 11n } },
      { name: '1⁻¹ mod 11', inputs: { a0: 1n, a1: 0n }, params: { n: 11n } },
      { name: 'BLS12-381', inputs: { a0: P381 - 7n, a1: 3n }, params: { n: P381 } },
      // Zero has no inverse in Fp2 either, and no witness makes it look as though it does.
      { name: 'zero', refuse: 'zero is not invertible', inputs: { a0: 0n, a1: 0n, i0: 1n, i1: 0n }, params: { n: 11n } },
      // p ≡ 3 (mod 4) is what makes u² + 1 irreducible; over p ≡ 1 (mod 4) it is
      // not a field and elements of norm zero exist. 4 + 3u has norm 25 ≡ 0 mod 5.
      { name: 'norm zero mod 5', refuse: 'u² + 1 splits mod 5, so this has no inverse', inputs: { a0: 4n, a1: 3n, i0: 1n, i1: 0n }, params: { n: 5n } }
    ]
  })()
})

module.exports = { mul, sqr, add: addm, sub: subm, neg, conj, mulXi, mulFp, inv }
