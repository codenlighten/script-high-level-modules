'use strict'

const { defineModule, apply } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')

// Fp12 = Fp6[w]/(w² − v) — the field a pairing's accumulator lives in, as
// twelve stack values and four modules.
//
// These four carry essentially the whole cost of a pairing: 63 squarings and
// ~70 sparse line products in the Miller loop, ~343 cyclotomic squarings and
// ~40 general products in the final exponentiation. Everything else — the G2
// point arithmetic, the Frobenius maps, the one inversion — is noise beside
// them. So these are the ones worth building and measuring exactly, and
// tools/pairing-cost.js prices the remainder at the Fp2 level.

const { six, two, dup, park, unpark, fresh, op, numericModulus, residues,
  PN, pushModulus, modulusName, dropModulus, inner, f2m, f2a, f2s, f2xi } = fp6

const twelve = (p) => [...six(p + 'A'), ...six(p + 'B')]
const SUF = ['00', '01', '10', '11', '20', '21']
/** The twelve suffixes of an Fp12 value, in the order `twelve()` names them. */
const SUF12 = [...SUF.map((x) => 'A' + x), ...SUF.map((x) => 'B' + x)]

/** The same three helpers as Fp6, a level up. */
function op6 (asm, m, p, ins, out = fresh()) {
  apply(asm, m, p, ins.flatMap(six), six(out))
  return out
}
function dup6 (asm, from, to = fresh()) {
  for (const s of SUF) asm.pick(from + s, to + s)
  return to
}
const park6 = (asm) => { for (let i = 0; i < 6; i++) asm.toAlt() }
const unpark6 = (asm) => { for (let i = 0; i < 6; i++) asm.fromAlt() }

const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}
const ensures12 = (who) => (p) => {
  const r = residues(p, who)
  const out = {}
  for (const k of twelve('r')) out[k] = r
  return out
}

// ── the model, in plain BigInt ──────────────────────────────────────────────
const F6 = {
  mul: (a, b, n) => [
    f2a(f2m(a[0], b[0], n), f2xi(f2a(f2m(a[1], b[2], n), f2m(a[2], b[1], n), n), n), n),
    f2a(f2a(f2m(a[0], b[1], n), f2m(a[1], b[0], n), n), f2xi(f2m(a[2], b[2], n), n), n),
    f2a(f2a(f2m(a[0], b[2], n), f2m(a[1], b[1], n), n), f2m(a[2], b[0], n), n)
  ],
  add: (a, b, n) => [f2a(a[0], b[0], n), f2a(a[1], b[1], n), f2a(a[2], b[2], n)],
  mulV: (a, n) => [f2xi(a[2], n), a[0], a[1]]
}
/** (a0 + a1w)(b0 + b1w) with w² = v — the definition, not the schedule. */
const F12mul = (a, b, n) => [
  F6.add(F6.mul(a[0], b[0], n), F6.mulV(F6.mul(a[1], b[1], n), n), n),
  F6.add(F6.mul(a[0], b[1], n), F6.mul(a[1], b[0], n), n)
]
const load6 = (v, p) => [[v[p + '00'], v[p + '01']], [v[p + '10'], v[p + '11']], [v[p + '20'], v[p + '21']]]
const load12 = (v, p) => [load6(v, p + 'A'), load6(v, p + 'B')]
const store12 = (c) => {
  const out = {}
  twelve('r').forEach((name, i) => { out[name] = c[i < 6 ? 0 : 1][Math.floor((i % 6) / 2)][i % 2] })
  return out
}

// Cyclotomic test vectors: real elements of G_Φ6(Fp2), produced the only way
// there is to produce one — by running the easy part of a final exponentiation.
const bls = require('../bls12381')

/**
 * The determinant fp12.powXc's decompression inverts, and an Fp2 inverse — both
 * only for producing hints. The script recomputes the determinant itself and
 * checks the inverse; nothing here is trusted.
 */
const detOf = (c) => bls.f2x2(bls.f2sub(bls.f2mulXi(bls.f2mul(c[1], c[3])), bls.f2mul(c[0], c[2])))
const cyclotomic = (k) => {
  const f = bls.millerLoop(bls.g1mul(k), bls.g2mul(k + 1n))
  let e = bls.f12mulRaw(bls.f12conj(f), bls.f12inv(f))
  return bls.f12mulRaw(bls.f12frobN(e, 2), e)
}
/**
 * A random element of the cyclotomic subgroup.
 *
 * There is no way to write one down: the subgroup is the image of the easy part
 * of a final exponentiation, so the only way to get an element of it is to run
 * one. That is exactly why fp12.cycSqr and fp12.powX declare a `fuzz` hook —
 * their precondition is membership of a subgroup, which the interval-based
 * contract system cannot state, so the fuzzer would otherwise generate inputs
 * outside the domain and report a disagreement that is the module telling the
 * truth about where it is defined.
 */
function randomCyclotomic (rnd) {
  const rf = () => {
    let x = 0n
    for (let i = 0; i < 12; i++) x = (x << 32n) | BigInt(Math.floor(rnd() * 0x100000000))
    return x % BLS
  }
  const g = [[[rf(), rf()], [rf(), rf()], [rf(), rf()]], [[rf(), rf()], [rf(), rf()], [rf(), rf()]]]
  let e = bls.f12mulRaw(bls.f12conj(g), bls.f12inv(g))
  e = bls.f12mulRaw(bls.f12frobN(e, 2), e)
  // f·f̄ = 1 is what being there means; a generator that quietly produced
  // something else would make the fuzz rounds vacuous.
  if (!bls.f12eq(bls.f12mulRaw(e, bls.f12conj(e)), bls.F12_ONE)) {
    throw new Error('randomCyclotomic: the easy part did not land in the subgroup')
  }
  return e
}

const spread = (f, p) => {
  const out = {}
  twelve(p).forEach((name, i) => { out[name] = f[i < 6 ? 0 : 1][Math.floor((i % 6) / 2)][i % 2] })
  return out
}
const BLS = bls.P

/**
 * a·b in Fp12 — Karatsuba over Fp6: three Fp6 products rather than four.
 *
 *     t0 = a0b0    t1 = a1b1    t2 = (a0 + a1)(b0 + b1)
 *     c0 = t0 + v·t1           c1 = t2 − t0 − t1
 *
 * Which is eighteen Fp2 multiplications. The alternative schedule — four Fp6
 * products — is twenty-four, and the sum that Karatsuba costs instead is six
 * Fp2 additions, every one of them an OP_ADD and an OP_MOD.
 */
const mul = defineModule({
  name: 'fp12.mul',
  doc: 'r = a·b in Fp12 = Fp6[w]/(w² − v)',
  inputs: [...twelve('a'), ...twelve('b')],
  outputs: twelve('r'),
  requires: inField('fp12.mul', ...twelve('a'), ...twelve('b')),
  ensures: ensures12('fp12.mul'),
  model: (v, { n }) => store12(F12mul(load12(v, 'a'), load12(v, 'b'), n)),
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.mul')
    const t2 = op6(asm, fp6.mul, p, [
      op6(asm, fp6.add, p, [dup6(asm, 'aA'), dup6(asm, 'aB')]),
      op6(asm, fp6.add, p, [dup6(asm, 'bA'), dup6(asm, 'bB')])
    ])
    const t0 = op6(asm, fp6.mul, p, ['aA', 'bA'])                  // last use
    const t1 = op6(asm, fp6.mul, p, ['aB', 'bB'])
    op6(asm, fp6.sub, p, [op6(asm, fp6.sub, p, [t2, dup6(asm, t0)]), dup6(asm, t1)], 'rB')
    park6(asm)
    op6(asm, fp6.add, p, [t0, op6(asm, fp6.mulV, p, [t1])], 'rA')
    unpark6(asm)
    dropModulus(asm, n)
  },
  cases: [
    { name: 'small', inputs: { ...spread(cyclotomic(2n), 'a'), ...spread(cyclotomic(3n), 'b') }, params: { n: BLS } },
    {
      name: 'by one',
      inputs: {
        ...spread(cyclotomic(5n), 'a'),
        ...(() => { const o = {}; twelve('b').forEach((k) => { o[k] = 0n }); o.bA00 = 1n; return o })()
      },
      params: { n: BLS }
    },
    { name: 'both extreme', inputs: { ...spread(cyclotomic(7n), 'a'), ...spread(cyclotomic(11n), 'b') }, params: { n: BLS } }
  ]
})

/**
 * a² in Fp12 — Karatsuba squaring: two Fp6 products, not three.
 *
 *     t = a0a1
 *     c0 = (a0 + a1)(a0 + v·a1) − t − v·t        c1 = 2t
 *
 * This is the general square. Inside the final exponentiation the value is
 * cyclotomic and fp12.cycSqr below is half the price, but the Miller loop's
 * accumulator is not in that subgroup and has to pay full rate.
 */
const sqr = defineModule({
  name: 'fp12.sqr',
  doc: 'r = a² in Fp12',
  inputs: twelve('a'),
  outputs: twelve('r'),
  requires: inField('fp12.sqr', ...twelve('a')),
  ensures: ensures12('fp12.sqr'),
  model: (v, { n }) => { const a = load12(v, 'a'); return store12(F12mul(a, a, n)) },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.sqr')
    const t = op6(asm, fp6.mul, p, [dup6(asm, 'aA'), dup6(asm, 'aB')])
    const s = op6(asm, fp6.add, p, [dup6(asm, 'aA'), dup6(asm, 'aB')])
    const u = op6(asm, fp6.add, p, ['aA', op6(asm, fp6.mulV, p, ['aB'])])   // last use of a
    const t2 = op6(asm, fp6.mul, p, [s, u])
    op6(asm, fp6.add, p, [dup6(asm, t), dup6(asm, t)], 'rB')
    park6(asm)
    op6(asm, fp6.sub, p, [
      op6(asm, fp6.sub, p, [t2, dup6(asm, t)]),
      op6(asm, fp6.mulV, p, [t])
    ], 'rA')
    unpark6(asm)
    dropModulus(asm, n)
  },
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'another', inputs: spread(cyclotomic(9n), 'a'), params: { n: BLS } },
    {
      name: 'one',
      inputs: (() => { const o = {}; twelve('a').forEach((k) => { o[k] = 0n }); o.aA00 = 1n; return o })(),
      params: { n: BLS }
    }
  ]
})

/**
 * a² for a in the cyclotomic subgroup G_Φ6(Fp2) — Granger–Scott.
 *
 * CORRECT ONLY THERE. On a general Fp12 element this returns something that is
 * not the square, and no bound the fact system can express says otherwise: the
 * requirement is membership of a subgroup, not a range. In a pairing that is
 * discharged structurally — the easy part of the final exponentiation raises to
 * (p⁶ − 1)(p² + 1) and everything after it is cyclotomic by construction — and
 * the cases below are real elements of the subgroup for the same reason: they
 * are produced by running an easy part.
 *
 * Written flat, Fp12 = Fp2[w]/(w⁶ − ξ) with coefficients g0…g5, and s = w³
 * generates an Fp4 in which the three coefficients are (g0,g3), (g1,g4),
 * (g2,g5). Three Fp4 squarings, so nine Fp2 SQUARINGS — against the eighteen
 * Fp2 MULTIPLICATIONS fp12.sqr costs, and an OP_MUL is an OP_MUL either way.
 */
const cycSqr = defineModule({
  name: 'fp12.cycSqr',
  doc: 'r = a² for a in the cyclotomic subgroup — half the price of fp12.sqr',
  inputs: twelve('a'),
  outputs: twelve('r'),
  requires: inField('fp12.cycSqr', ...twelve('a')),
  ensures: ensures12('fp12.cycSqr'),
  model: (v, { n }) => { const a = load12(v, 'a'); return store12(F12mul(a, a, n)) },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.cycSqr')
    // (x + ys)² = (x² + ξy²) + 2xy·s, by the sum-of-squares route: no OP_MUL
    // that is not an OP_MUL of something with itself.
    const f4sqr = (x, y) => {
      const t0 = op(asm, fp2.sqr, p, [dup(asm, x)])
      const t1 = op(asm, fp2.sqr, p, [dup(asm, y)])
      const s = op(asm, fp2.sqr, p, [op(asm, fp2.add, p, [dup(asm, x), dup(asm, y)])])
      const even = op(asm, fp2.add, p, [dup(asm, t0), op(asm, fp2.mulXi, p, [dup(asm, t1)])])
      const odd = op(asm, fp2.sub, p, [op(asm, fp2.sub, p, [s, t0]), t1])
      return [even, odd]
    }
    const x2 = (v) => op(asm, fp2.add, p, [dup(asm, v), v])
    const x3 = (v) => op(asm, fp2.add, p, [op(asm, fp2.add, p, [dup(asm, v), dup(asm, v)]), v])

    const [t0, t1] = f4sqr('aA0', 'aB1')
    const [t2, t3] = f4sqr('aB0', 'aA2')
    const [t4, t5] = f4sqr('aA1', 'aB2')

    // built in reverse: the altstack hands them back in the declared order
    op(asm, fp2.add, p, [x3(t3), x2('aB2')], 'rB2'); park(asm)
    op(asm, fp2.add, p, [x3(t1), x2('aB1')], 'rB1'); park(asm)
    op(asm, fp2.add, p, [x3(op(asm, fp2.mulXi, p, [t5])), x2('aB0')], 'rB0'); park(asm)
    op(asm, fp2.sub, p, [x3(t4), x2('aA2')], 'rA2'); park(asm)
    op(asm, fp2.sub, p, [x3(t2), x2('aA1')], 'rA1'); park(asm)
    op(asm, fp2.sub, p, [x3(t0), x2('aA0')], 'rA0')
    unpark(asm); unpark(asm); unpark(asm); unpark(asm); unpark(asm)
    dropModulus(asm, n)
  },
  notes: ['correct only on the cyclotomic subgroup, which a pairing establishes structurally and no range can express'],
  fuzz: (rnd) => spread(randomCyclotomic(rnd), 'a'),
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'another', inputs: spread(cyclotomic(3n), 'a'), params: { n: BLS } },
    { name: 'a third', inputs: spread(cyclotomic(12345n), 'a'), params: { n: BLS } }
  ]
})

/**
 * a · (l0 + l1w³ + l2w⁵) — multiplication by a Miller-loop line.
 *
 * Nine of the twelve Fp2 coefficients of a line are zero, and multiplying by
 * zero is still an OP_MUL. Skipping them takes the product from eighteen Fp2
 * multiplications to fourteen: three for a0·(l0,0,0), five for a1·(0,l1,l2)
 * with Karatsuba on the cross term, and six for the Karatsuba sum, which is
 * dense and cannot be helped.
 */
const mulLine = defineModule({
  name: 'fp12.mulLine',
  doc: 'r = a·(l0 + l1w³ + l2w⁵) — the sparse product a Miller loop actually needs',
  inputs: [...twelve('a'), ...two('l0'), ...two('l1'), ...two('l2')],
  outputs: twelve('r'),
  requires: inField('fp12.mulLine', ...twelve('a'), ...two('l0'), ...two('l1'), ...two('l2')),
  ensures: ensures12('fp12.mulLine'),
  model: (v, { n }) => {
    const Z = [0n, 0n]
    const line = [[[v.l00, v.l01], Z, Z], [Z, [v.l10, v.l11], [v.l20, v.l21]]]
    return store12(F12mul(load12(v, 'a'), line, n))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.mulLine')

    // the dense Fp6 (l0, l1, l2), assembled by naming rather than by moving
    const L = fresh()
    dup(asm, 'l0', L + '0'); dup(asm, 'l1', L + '1'); dup(asm, 'l2', L + '2')

    // t0 = aA · (l0, 0, 0) — three Fp2 multiplications
    const T0 = fresh()
    op(asm, fp2.mul, p, [dup(asm, 'aA0'), dup(asm, 'l0')], T0 + '0')
    op(asm, fp2.mul, p, [dup(asm, 'aA1'), dup(asm, 'l0')], T0 + '1')
    op(asm, fp2.mul, p, [dup(asm, 'aA2'), 'l0'], T0 + '2')                 // last use of l0

    // t1 = aB · (0, l1, l2) — five, with Karatsuba on a1l2 + a2l1
    const u1 = op(asm, fp2.mul, p, [dup(asm, 'aB1'), dup(asm, 'l1')])
    const u2 = op(asm, fp2.mul, p, [dup(asm, 'aB2'), dup(asm, 'l2')])
    const cross = op(asm, fp2.sub, p, [
      op(asm, fp2.sub, p, [
        op(asm, fp2.mul, p, [
          op(asm, fp2.add, p, [dup(asm, 'aB1'), dup(asm, 'aB2')]),
          op(asm, fp2.add, p, [dup(asm, 'l1'), dup(asm, 'l2')])
        ]),
        dup(asm, u1)
      ]),
      dup(asm, u2)
    ])
    const T1 = fresh()
    op(asm, fp2.mulXi, p, [cross], T1 + '0')
    op(asm, fp2.add, p, [op(asm, fp2.mul, p, [dup(asm, 'aB0'), 'l1']), op(asm, fp2.mulXi, p, [u2])], T1 + '1')
    op(asm, fp2.add, p, [op(asm, fp2.mul, p, [dup(asm, 'aB0'), 'l2']), u1], T1 + '2')

    // t2 = (aA + aB)·(l0, l1, l2) — dense, six
    const t2 = op6(asm, fp6.mul, p, [op6(asm, fp6.add, p, ['aA', 'aB']), L])

    op6(asm, fp6.sub, p, [op6(asm, fp6.sub, p, [t2, dup6(asm, T0)]), dup6(asm, T1)], 'rB')
    park6(asm)
    op6(asm, fp6.add, p, [T0, op6(asm, fp6.mulV, p, [T1])], 'rA')
    unpark6(asm)
    dropModulus(asm, n)
  },
  cases: (() => {
    const l = bls.lineDouble(bls.G2, bls.G1)
    const l2 = bls.lineAdd(bls.g2mul(3n), bls.G2, bls.G1)
    const lineOf = (x) => ({ l00: x.l0[0], l01: x.l0[1], l10: x.l1[0], l11: x.l1[1], l20: x.l2[0], l21: x.l2[1] })
    return [
      { name: 'a doubling line', inputs: { ...spread(bls.millerLoop(bls.G1, bls.G2), 'a'), ...lineOf(l) }, params: { n: BLS } },
      { name: 'an addition line', inputs: { ...spread(bls.millerLoop(bls.G1, bls.G2), 'a'), ...lineOf(l2) }, params: { n: BLS } },
      {
        name: 'the identity line',
        inputs: { ...spread(cyclotomic(4n), 'a'), l00: 1n, l01: 0n, l10: 0n, l11: 0n, l20: 0n, l21: 0n },
        params: { n: BLS }
      }
    ]
  })()
})

/**
 * r = f̄ — the Fp12 conjugate, which is the p⁶-th power.
 *
 * Negate the w-odd half and nothing else. In the cyclotomic subgroup this is
 * the INVERSE, which is why the final exponentiation's balanced digits are free:
 * a negative digit costs a negation, not an inversion.
 */
const conj = defineModule({
  name: 'fp12.conj',
  doc: 'r = f̄ in Fp12 — the p⁶ Frobenius, and inversion on the cyclotomic subgroup',
  inputs: twelve('a'),
  outputs: twelve('r'),
  requires: inField('fp12.conj', ...twelve('a')),
  ensures: ensures12('fp12.conj'),
  model: (v, { n }) => {
    const a = load12(v, 'a')
    return store12([a[0], a[1].map((c) => [f2s([0n, 0n], c, n)[0], f2s([0n, 0n], c, n)[1]])])
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.conj')
    for (const c of ['B0', 'B1', 'B2']) op(asm, fp2.neg, p, ['a' + c], 'r' + c)
    for (const c of ['A00', 'A01', 'A10', 'A11', 'A20', 'A21']) asm.relabel('a' + c, 'r' + c)
    dropModulus(asm, n)
    for (const name of twelve('r')) asm.roll(name)
  },
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'one', inputs: (() => { const o = {}; twelve('a').forEach((k) => { o[k] = 0n }); o.aA00 = 1n; return o })(), params: { n: BLS } }
  ]
})

/**
 * r = f^p — the Frobenius, as seven multiplications instead of an exponentiation.
 *
 * Raising to the p-th power is a field automorphism, so it distributes over the
 * tower and lands on the coefficients:
 *
 *     (Σ cᵢvⁱ)^p = Σ c̄ᵢ · ξ^(i(p−1)/3) vⁱ        in Fp6
 *     (c0 + c1w)^p = c0^p + c1^p · ξ^((p−1)/6) w  in Fp12
 *
 * because p ≡ 3 (mod 4) makes the Fp2 Frobenius a conjugation. Six conjugations
 * and seven Fp2 multiplications by fixed constants, against the 381 squarings a
 * literal f^p would cost.
 *
 * The constants are DERIVED — bls12381.js computes ξ^(i(p−1)/6) with the same
 * Fp2 arithmetic everything else uses — and the model here is the literal
 * exponentiation f^p, so what is proven is that the shortcut equals the thing
 * it is a shortcut for, not that it equals another copy of itself.
 */
const frob = defineModule({
  name: 'fp12.frob',
  doc: 'r = f^p in Fp12 — the Frobenius, by conjugation and fixed constants',
  inputs: twelve('a'),
  outputs: twelve('r'),
  requires: inField('fp12.frob', ...twelve('a')),
  ensures: ensures12('fp12.frob'),
  model: (v, { n }) => {
    if (n !== BLS) throw new Error('fp12.frob: the Frobenius constants are derived for the BLS12-381 prime')
    return store12(bls.f12pow(load12(v, 'a'), n))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    if (numericModulus(params, 'fp12.frob') !== BLS) {
      throw new Error('fp12.frob: the Frobenius constants are derived for the BLS12-381 prime')
    }
    const p = inner(params, 'fp12.frob')
    const G1 = bls.FROB[0]; const G2 = bls.FROB[1]; const G4 = bls.FROB[3]
    const push = (c, name) => { asm.num(c[0], name + '0'); asm.num(c[1], name + '1'); return name }
    const g1 = push(G1, '_g1'); const g2 = push(G2, '_g2'); const g4 = push(G4, '_g4')

    // the w-odd half first, so the altstack hands the halves back in order
    op(asm, fp2.mul, p, [op(asm, fp2.mul, p, [op(asm, fp2.conj, p, ['aB2']), dup(asm, g4)]), dup(asm, g1)], 'rB2')
    park(asm)
    op(asm, fp2.mul, p, [op(asm, fp2.mul, p, [op(asm, fp2.conj, p, ['aB1']), dup(asm, g2)]), dup(asm, g1)], 'rB1')
    park(asm)
    op(asm, fp2.mul, p, [op(asm, fp2.conj, p, ['aB0']), g1], 'rB0')
    park(asm)
    op(asm, fp2.mul, p, [op(asm, fp2.conj, p, ['aA2']), g4], 'rA2')
    park(asm)
    op(asm, fp2.mul, p, [op(asm, fp2.conj, p, ['aA1']), g2], 'rA1')
    park(asm)
    op(asm, fp2.conj, p, ['aA0'], 'rA0')
    for (let i = 0; i < 5; i++) unpark(asm)
    dropModulus(asm, n)
    for (const name of twelve('r')) asm.roll(name)
  },
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'a Miller output', inputs: spread(bls.millerLoop(bls.G1, bls.G2), 'a'), params: { n: BLS } },
    { name: 'one', inputs: (() => { const o = {}; twelve('a').forEach((k) => { o[k] = 0n }); o.aA00 = 1n; return o })(), params: { n: BLS } }
  ]
})

/**
 * r = f⁻¹, SUPPLIED BY THE SPENDER and checked: one Fp12 multiplication.
 *
 * The final exponentiation needs exactly one inversion, and computing it in
 * Script would mean an Fp6 inversion, an Fp2 inversion and a base-field
 * exponentiation. Instead the spender supplies twelve numbers and the script
 * multiplies: f·f⁻¹ must be one, which is twelve comparisons after one
 * fp12.mul. Each of the twelve is bounded into [0, p) first, because otherwise
 * a coefficient and that coefficient plus p are two witnesses for one inverse.
 */
const inv = defineModule({
  name: 'fp12.inv',
  doc: 'r = f⁻¹ in Fp12, witnessed and checked (f·r = 1, every coefficient in [0, p))',
  inputs: [...twelve('a'), ...twelve('i').map((name) => ({ name, witness: true }))],
  outputs: twelve('r'),
  requires: inField('fp12.inv', ...twelve('a')),
  ensures: ensures12('fp12.inv'),
  hint: (v, { n }) => {
    const out = spread(bls.f12inv(load12(v, 'a')), 'i')
    if (n !== BLS) throw new Error('fp12.inv: the hint inverts over the BLS12-381 prime')
    return out
  },
  model: (v, { n }) => {
    if (n !== BLS) throw new Error('fp12.inv: the model inverts over the BLS12-381 prime')
    return store12(bls.f12inv(load12(v, 'a')))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.inv')
    const nn = numericModulus(params, 'fp12.inv')
    for (const name of twelve('i')) asm.bound(name, 0n, nn, '_b')
    // The product consumes what it multiplies, and the witness IS the result,
    // so it goes in as a copy. Twelve OP_PICKs to keep the answer.
    for (const name of twelve('i')) asm.pick(name, 'j' + name.slice(1))
    apply(asm, mul, p, [...twelve('a'), ...twelve('j')], twelve('c'))
    twelve('c').forEach((name, k) => {
      asm.roll(name)
      asm.num(k === 0 ? 1n : 0n, '_want')
      asm.numEqualVerify()
    })
    dropModulus(asm, n)
    for (const name of twelve('i')) { asm.roll(name); asm.rename('r' + name.slice(1)) }
  },
  cases: [
    { name: 'a Miller output', inputs: spread(bls.millerLoop(bls.G1, bls.G2), 'a'), params: { n: BLS } },
    { name: 'cyclotomic', inputs: spread(cyclotomic(3n), 'a'), params: { n: BLS } },
    {
      name: 'zero has no inverse',
      refuse: 'zero is not invertible in Fp12 either',
      inputs: (() => {
        const o = {}
        twelve('a').forEach((k) => { o[k] = 0n })
        twelve('i').forEach((k) => { o[k] = 0n })
        o.iA00 = 1n
        return o
      })(),
      params: { n: BLS }
    }
  ]
})

/**
 * r = f^|x| for the 63-bit BLS curve parameter, f in the cyclotomic subgroup.
 *
 * The final exponentiation's whole cost is five of these, chained: λ written in
 * balanced base p and then in balanced base |x| leaves nothing but a ladder of
 * r, r^y, r^y², … and a handful of multiplications by coefficients no larger
 * than 3 (see docs/optimization.md §11).
 *
 * MSB-FIRST AND UNROLLED, which is the whole reason it is 96 KB and not 99.
 * Square-and-multiply written from the least significant bit starts with an
 * accumulator of one and multiplies into it, so the first multiplication is by
 * one — free at runtime, and 3,110 bytes of Fp12 multiplication that provably
 * does nothing when it is unrolled into a script. Consuming the leading bit as
 * the initial value instead costs 63 squarings and 5 multiplications where the
 * obvious loop costs 64 and 6.
 *
 * CORRECT ONLY ON THE CYCLOTOMIC SUBGROUP, because that is where cycSqr is
 * correct. In a pairing that is discharged structurally by the easy part of the
 * final exponentiation, and the cases below are subgroup elements for the same
 * reason: they are produced by running one. The model is the literal f^|x| by
 * general exponentiation, so what is proven is that the cheap ladder equals the
 * thing it is a cheap version of.
 */
const powX = defineModule({
  name: 'fp12.powX',
  doc: 'r = f^|x| for the BLS12-381 curve parameter, f cyclotomic — the ladder the final exponentiation runs five times',
  inputs: twelve('a'),
  outputs: twelve('r'),
  requires: inField('fp12.powX', ...twelve('a')),
  ensures: ensures12('fp12.powX'),
  model: (v, { n }) => {
    if (n !== BLS) throw new Error('fp12.powX: the curve parameter belongs to BLS12-381')
    return store12(bls.f12pow(load12(v, 'a'), bls.Y))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.powX')
    const bits = bls.Y.toString(2)
    const acc = 'acc'
    // the leading bit IS the initial value; nothing is multiplied by one
    for (const x of SUF12) asm.pick('a' + x, acc + x)
    for (let i = 1; i < bits.length; i++) {
      apply(asm, cycSqr, p, twelve(acc), twelve(acc))
      if (bits[i] === '1') {
        const c = `_c${i}`
        for (const x of SUF12) asm.pick('a' + x, c + x)
        apply(asm, mul, p, [...twelve(acc), ...twelve(c)], twelve(acc))
      }
    }
    for (const x of SUF12) asm.discard('a' + x)
    dropModulus(asm, n)
    for (const x of SUF12) { asm.roll(acc + x); asm.rename('r' + x) }
  },
  notes: [
    'correct only on the cyclotomic subgroup, which a pairing establishes structurally and no range can express',
    '63 squarings and 5 multiplications — MSB-first, so nothing is multiplied by one'
  ],
  fuzz: (rnd) => spread(randomCyclotomic(rnd), 'a'),
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'another', inputs: spread(cyclotomic(7n), 'a'), params: { n: BLS } }
  ]
})

// ── COMPRESSED SQUARING, at the Asm level ───────────────────────────────────
//
// These are helpers rather than modules on purpose. A compressed squaring's
// specification is "the square, projected" and the only way to write that down
// is the formula the emitter uses, so a module built around it would have a
// model that could not disagree with its own schedule. Used inside fp12.powXc,
// whose model IS independent — the literal f^|x| by general exponentiation —
// they are checked against something that did not come from them.
//
// The reference implementations are in src/bls12381.js with the derivation, and
// tools/bls-crosscheck.js checks both against cyclotomicSqr and against the
// elements they claim to recover.

/** Two Fp4 squarings instead of three: c is four Fp2 names, four come back. */
function emitCompSqr (asm, p, c) {
  const f4 = (x, y) => {
    const t0 = op(asm, fp2.sqr, p, [dup(asm, x)])
    const t1 = op(asm, fp2.sqr, p, [dup(asm, y)])
    const sq = op(asm, fp2.sqr, p, [op(asm, fp2.add, p, [dup(asm, x), dup(asm, y)])])
    const even = op(asm, fp2.add, p, [dup(asm, t0), op(asm, fp2.mulXi, p, [dup(asm, t1)])])
    const odd = op(asm, fp2.sub, p, [op(asm, fp2.sub, p, [sq, t0]), t1])
    return [even, odd]
  }
  const x3 = (v) => op(asm, fp2.add, p, [op(asm, fp2.add, p, [dup(asm, v), dup(asm, v)]), v])
  const x2 = (v) => op(asm, fp2.add, p, [dup(asm, v), v])
  const [t2, t3] = f4(c[0], c[1])
  const [t4, t5] = f4(c[2], c[3])
  return [
    op(asm, fp2.add, p, [x3(op(asm, fp2.mulXi, p, [t5])), x2(c[0])]),
    op(asm, fp2.sub, p, [x3(t4), x2(c[1])]),
    op(asm, fp2.sub, p, [x3(t2), x2(c[2])]),
    op(asm, fp2.add, p, [x3(t3), x2(c[3])])
  ]
}

/**
 * Back to twelve, by the two linear equations f·f̄ = 1 gives for c0.
 *
 * `wit` names the two coefficients of the determinant's inverse, which the
 * spender supplies and fp2.inv checks. Both equations are scaled by two so
 * nothing is halved. Returns the twelve names in `twelve()` order.
 */
function emitDecompress (asm, p, c, wit) {
  const [c1r, c1s, c2r, c2s] = c
  const norm = (r, sp) => op(asm, fp2.sub, p, [op(asm, fp2.sqr, p, [dup(asm, r)]),
    op(asm, fp2.mulXi, p, [op(asm, fp2.sqr, p, [dup(asm, sp)])])])
  const b1 = norm(c1r, c1s)
  const nb2 = norm(c2r, c2s)
  const det = (() => {
    const d = op(asm, fp2.sub, p, [op(asm, fp2.mulXi, p, [op(asm, fp2.mul, p, [dup(asm, c1s), dup(asm, c2s)])]),
      op(asm, fp2.mul, p, [dup(asm, c1r), dup(asm, c2r)])])
    return op(asm, fp2.add, p, [dup(asm, d), d])
  })()
  const di = op(asm, fp2.inv, p, [det], undefined, wit)
  const b2 = op(asm, fp2.neg, p, [nb2])
  //  [ c2r   −ξc2s ] [x]   [b1]
  //  [ c1s   −c1r  ] [y] = [b2]
  const x = op(asm, fp2.mul, p, [
    op(asm, fp2.sub, p, [
      op(asm, fp2.mul, p, [dup(asm, b2), op(asm, fp2.mulXi, p, [dup(asm, c2s)])]),
      op(asm, fp2.mul, p, [dup(asm, b1), dup(asm, c1r)])
    ]), dup(asm, di)])
  const y = op(asm, fp2.mul, p, [
    op(asm, fp2.sub, p, [op(asm, fp2.mul, p, [dup(asm, c2r), b2]), op(asm, fp2.mul, p, [dup(asm, c1s), b1])]),
    di])
  // flat = [x, c1r, c2r, y, c1s, c2s]; twelve() wants A0 A1 A2 B0 B1 B2
  return [...two(x), ...two(c2r), ...two(c1s), ...two(c1r), ...two(y), ...two(c2s)]
}

/**
 * r = f^|x|, the same as fp12.powX, with the squarings done COMPRESSED.
 *
 * Four Fp2 coefficients instead of six, two Fp4 squarings instead of three, and
 * one decompression before each of the five multiplications plus one at the
 * end. Six decompressions, each costing a witnessed Fp2 inversion.
 *
 * The model is the literal f^|x| by general exponentiation — the same
 * specification fp12.powX has — so the compressed schedule is checked against
 * something no part of it produced.
 *
 * Correct only on the cyclotomic subgroup, twice over: the squaring identities
 * hold there, and the decompression uses f·f̄ = 1. And INCOMPLETE where the
 * determinant ξ·c1ₛc2ₛ − c1ᵣc2ᵣ vanishes, which cannot make a wrong answer
 * verify — only a right one fail.
 */
const powXc = defineModule({
  name: 'fp12.powXc',
  doc: 'r = f^|x| with compressed squaring — four Fp2 coefficients instead of six',
  inputs: [
    ...twelve('a'),
    ...Array.from({ length: 6 }, (_, k) => [`d${k}i0`, `d${k}i1`]).flat().map((name) => ({ name, witness: true }))
  ],
  outputs: twelve('r'),
  maxWitnessAttacks: 6,
  requires: inField('fp12.powXc', ...twelve('a')),
  ensures: ensures12('fp12.powXc'),
  hint: (v, { n }) => {
    if (n !== BLS) throw new Error('fp12.powXc: the curve parameter belongs to BLS12-381')
    const bits = bls.Y.toString(2)
    const a = load12(v, 'a')
    let c = bls.compress(a)
    const out = {}
    let k = 0
    const recover = () => {
      const di = bls.f2inv(detOf(c))
      out[`d${k}i0`] = di[0]; out[`d${k}i1`] = di[1]
      k++
      return bls.decompress(c)
    }
    for (let i = 1; i < bits.length; i++) {
      c = bls.compressedSqr(c)
      if (bits[i] === '1') c = bls.compress(bls.f12mulRaw(recover(), a))
    }
    recover()
    return out
  },
  model: (v, { n }) => {
    if (n !== BLS) throw new Error('fp12.powXc: the curve parameter belongs to BLS12-381')
    return store12(bls.f12pow(load12(v, 'a'), bls.Y))
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp12.powXc')
    const bits = bls.Y.toString(2)
    // Compression is a CHOICE OF NAMES: flat1, flat4, flat2, flat5, which in
    // the twelve() layout are B0, A2, A1, B2. It emits nothing at all.
    const compressed = (pre) => [pre + 'B0', pre + 'A2', pre + 'A1', pre + 'B2']
    const droppedBy = (pre) => [pre + 'A0', pre + 'B1']

    let k = 0
    const recover = () => emitDecompress(asm, p, c, [`d${k}i0`, `d${k}i1`])

    let c = compressed('a').map((name) => dup(asm, name))    // the leading bit
    for (let i = 1; i < bits.length; i++) {
      c = emitCompSqr(asm, p, c)
      if (bits[i] !== '1') continue
      const full = recover(); k++
      const copy = twelve('a').map((name) => { const t = fresh(); asm.pick(name, t); return t })
      apply(asm, mul, p, [...full, ...copy], twelve('_m'))
      c = compressed('_m')
      // the two coefficients compression drops are live values and have to go
      for (const pair of droppedBy('_m')) { asm.discard(pair + '0'); asm.discard(pair + '1') }
      // rename so the next round's names do not collide with the round after
      c = c.map((name) => { const t = fresh(); asm.roll(name + '0'); asm.rename(t + '0'); asm.roll(name + '1'); asm.rename(t + '1'); return t })
    }
    const out = recover()
    for (const x of SUF12) asm.discard('a' + x)
    dropModulus(asm, n)
    out.forEach((name, i) => { asm.roll(name); asm.rename(twelve('r')[i]) })
  },
  notes: [
    'correct only on the cyclotomic subgroup, and incomplete where the decompression determinant vanishes',
    'six witnessed Fp2 inversions — one per decompression'
  ],
  fuzz: (rnd) => spread(randomCyclotomic(rnd), 'a'),
  cases: [
    { name: 'cyclotomic', inputs: spread(cyclotomic(2n), 'a'), params: { n: BLS } },
    { name: 'another', inputs: spread(cyclotomic(7n), 'a'), params: { n: BLS } }
  ]
})

module.exports = { mul, sqr, cycSqr, mulLine, conj, frob, inv, powX, powXc, randomCyclotomic,
  emitCompSqr, emitDecompress, twelve, op6, dup6, park6, unpark6, F12mul, spread, cyclotomic }
