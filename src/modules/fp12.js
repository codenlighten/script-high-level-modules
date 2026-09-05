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
const cyclotomic = (k) => {
  const f = bls.millerLoop(bls.g1mul(k), bls.g2mul(k + 1n))
  let e = bls.f12mulRaw(bls.f12conj(f), bls.f12inv(f))
  return bls.f12mulRaw(bls.f12frobN(e, 2), e)
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

module.exports = { mul, sqr, cycSqr, mulLine, twelve, op6, dup6, park6, unpark6, F12mul, spread, cyclotomic }
