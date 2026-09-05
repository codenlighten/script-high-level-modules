'use strict'

const { defineModule, apply } = require('../module')
const fp2 = require('./fp2')
const { mod } = require('../bigint')

// Fp6 = Fp2[v]/(v³ − ξ), ξ = u + 1 — built by CALLING the Fp2 modules.
//
// This layer exists to make one number honest. Costing a pairing by adding up
// Fp2 module bodies gives an arithmetic FLOOR and nothing else: it prices the
// multiplications and silently prices the stack at zero. Real composition is
// not free — operands have to be brought to the top before a module can read
// them, and an Fp6 product touches twelve inputs three times each.
//
// So these are composed with apply(), the same mechanism every other module in
// this repository uses, and measured. The gap between what they cost and what
// their parts cost is the price of moving values about, measured rather than
// assumed. tools/pairing-cost.js reports both.
//
// The modulus is a NAME here, always. Everything inside picks it, and the one
// literal push — 49 bytes for BLS12-381 — happens once at the top.

function numericModulus (params, who) {
  const nn = params.nn !== undefined ? params.nn : params.n
  if (typeof nn === 'bigint' || typeof nn === 'number') return BigInt(nn)
  throw new Error(`${who}: the modulus is '${params.n}', a value on the stack, so its number is not known here — ` +
    'pass nn: <the prime> alongside it, or the contract this module states would quietly mean nothing')
}
const residues = (params, who) => ({ range: { lo: 0n, hi: numericModulus(params, who) } })
const inField = (who, ...names) => (params) => {
  const r = residues(params, who)
  const out = {}
  for (const k of names) out[k] = r
  return out
}
/** The six stack names of an Fp6 value, or the two of an Fp2 one. */
const six = (p) => [p + '00', p + '01', p + '10', p + '11', p + '20', p + '21']
const two = (p) => [p + '0', p + '1']

const PN = '_pn'
const pushModulus = (asm, n) => { if (typeof n !== 'string') asm.num(n, PN) }
const modulusName = (n) => (typeof n === 'string' ? n : PN)
const dropModulus = (asm, n) => { if (typeof n !== 'string') asm.discard(PN) }
/** What the inner Fp2 calls are given: the prime by NAME, its value for contracts. */
const inner = (params, who) => ({ n: modulusName(params.n), nn: numericModulus(params, who) })

let seq = 0
const fresh = () => `_t${seq++}`

/** Call an Fp2 module on Fp2-valued names. Returns the output's Fp2 name. */
function op (asm, m, p, ins, out = fresh()) {
  apply(asm, m, p, ins.flatMap(two), two(out))
  return out
}
/** Copy an Fp2 value to a fresh name — for operands with a use still to come. */
function dup (asm, from, to = fresh()) {
  asm.pick(from + '0', to + '0')
  asm.pick(from + '1', to + '1')
  return to
}
/** Park an Fp2 value on the altstack, and bring it back in the same order. */
const park = (asm) => { asm.toAlt(); asm.toAlt() }
const unpark = (asm) => { asm.fromAlt(); asm.fromAlt() }

// ── the model, in plain BigInt: the DEFINITION, not the schedule the emitter uses
const f2m = (a, b, n) => [mod(a[0] * b[0] - a[1] * b[1], n), mod(a[0] * b[1] + a[1] * b[0], n)]
const f2a = (a, b, n) => [mod(a[0] + b[0], n), mod(a[1] + b[1], n)]
const f2s = (a, b, n) => [mod(a[0] - b[0], n), mod(a[1] - b[1], n)]
const f2xi = (a, n) => [mod(a[0] - a[1], n), mod(a[0] + a[1], n)]
const load = (v, p) => [[v[p + '00'], v[p + '01']], [v[p + '10'], v[p + '11']], [v[p + '20'], v[p + '21']]]
const store = (c) => ({ r00: c[0][0], r01: c[0][1], r10: c[1][0], r11: c[1][1], r20: c[2][0], r21: c[2][1] })

const BLS = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn
const ensures6 = (who) => (p) => {
  const r = residues(p, who)
  return { r00: r, r01: r, r10: r, r11: r, r20: r, r21: r }
}

/**
 * a·b in Fp6 — Karatsuba, six Fp2 multiplications rather than nine.
 *
 *     t0 = a0b0, t1 = a1b1, t2 = a2b2
 *     c0 = t0 + ξ((a1+a2)(b1+b2) − t1 − t2)
 *     c1 = (a0+a1)(b0+b1) − t0 − t1 + ξt2
 *     c2 = (a0+a2)(b0+b2) − t0 − t2 + t1
 *
 * Every input is read three times, so each is copied twice and ROLLED on its
 * last use — the discipline ec.add uses, for the same reason: a value consumed
 * where it is last needed never becomes a temporary that has to be cleaned up.
 * The three results are built in reverse and parked on the altstack, which
 * returns them in the declared order without a single OP_ROLL at the end.
 */
const mul = defineModule({
  name: 'fp6.mul',
  doc: 'r = a·b in Fp6 = Fp2[v]/(v³ − ξ)',
  inputs: [...six('a'), ...six('b')],
  outputs: six('r'),
  requires: inField('fp6.mul', ...six('a'), ...six('b')),
  ensures: ensures6('fp6.mul'),
  model: (v, { n }) => {
    const [a0, a1, a2] = load(v, 'a')
    const [b0, b1, b2] = load(v, 'b')
    return store([
      f2a(f2m(a0, b0, n), f2xi(f2a(f2m(a1, b2, n), f2m(a2, b1, n), n), n), n),
      f2a(f2a(f2m(a0, b1, n), f2m(a1, b0, n), n), f2xi(f2m(a2, b2, n), n), n),
      f2a(f2a(f2m(a0, b2, n), f2m(a1, b1, n), n), f2m(a2, b0, n), n)
    ])
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp6.mul')
    const m12 = op(asm, fp2.mul, p, [
      op(asm, fp2.add, p, [dup(asm, 'a1'), dup(asm, 'a2')]),
      op(asm, fp2.add, p, [dup(asm, 'b1'), dup(asm, 'b2')])
    ])
    const m01 = op(asm, fp2.mul, p, [
      op(asm, fp2.add, p, [dup(asm, 'a0'), dup(asm, 'a1')]),
      op(asm, fp2.add, p, [dup(asm, 'b0'), dup(asm, 'b1')])
    ])
    const m02 = op(asm, fp2.mul, p, [
      op(asm, fp2.add, p, [dup(asm, 'a0'), dup(asm, 'a2')]),
      op(asm, fp2.add, p, [dup(asm, 'b0'), dup(asm, 'b2')])
    ])
    const t0 = op(asm, fp2.mul, p, ['a0', 'b0'])                   // last use of a0, b0
    const t1 = op(asm, fp2.mul, p, ['a1', 'b1'])
    const t2 = op(asm, fp2.mul, p, ['a2', 'b2'])

    // c2 = m02 − t0 − t2 + t1
    op(asm, fp2.add, p, [
      op(asm, fp2.sub, p, [op(asm, fp2.sub, p, [m02, dup(asm, t0)]), dup(asm, t2)]),
      dup(asm, t1)
    ], '_c2')
    park(asm)
    // c1 = m01 − t0 − t1 + ξt2
    op(asm, fp2.add, p, [
      op(asm, fp2.sub, p, [op(asm, fp2.sub, p, [m01, dup(asm, t0)]), dup(asm, t1)]),
      op(asm, fp2.mulXi, p, [dup(asm, t2)])
    ], '_c1')
    park(asm)
    // c0 = t0 + ξ(m12 − t1 − t2) — every t is on its last use, so all three roll
    op(asm, fp2.add, p, [
      t0,
      op(asm, fp2.mulXi, p, [op(asm, fp2.sub, p, [op(asm, fp2.sub, p, [m12, t1]), t2])])
    ], '_c0')

    asm.relabel('_c00', 'r00'); asm.relabel('_c01', 'r01')
    unpark(asm); asm.relabel('_c10', 'r10'); asm.relabel('_c11', 'r11')
    unpark(asm); asm.relabel('_c20', 'r20'); asm.relabel('_c21', 'r21')
    dropModulus(asm, n)
  },
  cases: (() => {
    const c = (o) => ({ a00: o[0], a01: o[1], a10: o[2], a11: o[3], a20: o[4], a21: o[5], b00: o[6], b01: o[7], b10: o[8], b11: o[9], b20: o[10], b21: o[11] })
    return [
      { name: 'small', inputs: c([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 1n, 2n]), params: { n: 11n } },
      { name: 'v·v = v²', inputs: c([0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'v²·v = ξ', inputs: c([0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n, 1n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'by one', inputs: c([3n, 4n, 5n, 6n, 7n, 8n, 1n, 0n, 0n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'by zero', inputs: c([3n, 4n, 5n, 6n, 7n, 8n, 0n, 0n, 0n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'BLS12-381', inputs: c([BLS - 1n, 1n, BLS - 2n, 2n, BLS - 3n, 3n, 5n, BLS - 5n, 7n, BLS - 7n, 11n, BLS - 11n]), params: { n: BLS } }
    ]
  })()
})

/**
 * a² in Fp6 — Chung–Hasan SQR3: three Fp2 squarings and two multiplications.
 *
 *     s0 = a0²    s1 = 2a0a1    s2 = (a0 − a1 + a2)²    s3 = 2a1a2    s4 = a2²
 *     c0 = s0 + ξs3    c1 = s1 + ξs4    c2 = s1 + s2 + s3 − s0 − s4
 *
 * An Fp2 squaring is two OP_MULs where a multiplication is three, so the
 * schedule is worth the extra bookkeeping: five products where the general
 * routine would want six, and three of the five are cheaper.
 */
const sqr = defineModule({
  name: 'fp6.sqr',
  doc: 'r = a² in Fp6',
  inputs: six('a'),
  outputs: six('r'),
  requires: inField('fp6.sqr', ...six('a')),
  ensures: ensures6('fp6.sqr'),
  model: (v, { n }) => {
    const [a0, a1, a2] = load(v, 'a')
    return store([
      f2a(f2m(a0, a0, n), f2xi(f2a(f2m(a1, a2, n), f2m(a2, a1, n), n), n), n),
      f2a(f2a(f2m(a0, a1, n), f2m(a1, a0, n), n), f2xi(f2m(a2, a2, n), n), n),
      f2a(f2a(f2m(a0, a2, n), f2m(a1, a1, n), n), f2m(a2, a0, n), n)
    ])
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp6.sqr')
    const s0 = op(asm, fp2.sqr, p, [dup(asm, 'a0')])
    const ab = op(asm, fp2.mul, p, [dup(asm, 'a0'), dup(asm, 'a1')])
    const s1 = op(asm, fp2.add, p, [ab, dup(asm, ab)])
    const bc = op(asm, fp2.mul, p, [dup(asm, 'a1'), dup(asm, 'a2')])
    const s3 = op(asm, fp2.add, p, [bc, dup(asm, bc)])
    const s4 = op(asm, fp2.sqr, p, [dup(asm, 'a2')])
    // s2 = (a0 − a1 + a2)² — every input on its last use
    const s2v = op(asm, fp2.sqr, p, [op(asm, fp2.add, p, [op(asm, fp2.sub, p, ['a0', 'a1']), 'a2'])])

    // c2 = s1 + s2 + s3 − s0 − s4
    op(asm, fp2.sub, p, [
      op(asm, fp2.sub, p, [
        op(asm, fp2.add, p, [op(asm, fp2.add, p, [dup(asm, s1), s2v]), dup(asm, s3)]),
        dup(asm, s0)
      ]),
      dup(asm, s4)
    ], '_c2')
    park(asm)
    op(asm, fp2.add, p, [s1, op(asm, fp2.mulXi, p, [s4])], '_c1')
    park(asm)
    op(asm, fp2.add, p, [s0, op(asm, fp2.mulXi, p, [s3])], '_c0')

    asm.relabel('_c00', 'r00'); asm.relabel('_c01', 'r01')
    unpark(asm); asm.relabel('_c10', 'r10'); asm.relabel('_c11', 'r11')
    unpark(asm); asm.relabel('_c20', 'r20'); asm.relabel('_c21', 'r21')
    dropModulus(asm, n)
  },
  cases: (() => {
    const c = (o) => ({ a00: o[0], a01: o[1], a10: o[2], a11: o[3], a20: o[4], a21: o[5] })
    return [
      { name: 'small', inputs: c([1n, 2n, 3n, 4n, 5n, 6n]), params: { n: 11n } },
      { name: 'v² ', inputs: c([0n, 0n, 1n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'one', inputs: c([1n, 0n, 0n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'zero', inputs: c([0n, 0n, 0n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'BLS12-381', inputs: c([BLS - 1n, 1n, BLS - 2n, 2n, BLS - 3n, 3n]), params: { n: BLS } }
    ]
  })()
})

const pointwise = (name, doc, m, jsOp) => defineModule({
  name,
  doc,
  inputs: [...six('a'), ...six('b')],
  outputs: six('r'),
  requires: inField(name, ...six('a'), ...six('b')),
  ensures: ensures6(name),
  model: (v, { n }) => {
    const a = load(v, 'a'); const b = load(v, 'b')
    return store([jsOp(a[0], b[0], n), jsOp(a[1], b[1], n), jsOp(a[2], b[2], n)])
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, name)
    op(asm, m, p, ['a2', 'b2'], '_c2'); park(asm)
    op(asm, m, p, ['a1', 'b1'], '_c1'); park(asm)
    op(asm, m, p, ['a0', 'b0'], '_c0')
    asm.relabel('_c00', 'r00'); asm.relabel('_c01', 'r01')
    unpark(asm); asm.relabel('_c10', 'r10'); asm.relabel('_c11', 'r11')
    unpark(asm); asm.relabel('_c20', 'r20'); asm.relabel('_c21', 'r21')
    dropModulus(asm, n)
  },
  cases: (() => {
    const c = (o) => ({ a00: o[0], a01: o[1], a10: o[2], a11: o[3], a20: o[4], a21: o[5], b00: o[6], b01: o[7], b10: o[8], b11: o[9], b20: o[10], b21: o[11] })
    return [
      { name: 'small', inputs: c([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 1n, 2n]), params: { n: 11n } },
      { name: 'wraps', inputs: c([10n, 10n, 10n, 10n, 10n, 10n, 10n, 10n, 10n, 10n, 10n, 10n]), params: { n: 11n } },
      { name: 'BLS12-381', inputs: c([BLS - 1n, 1n, BLS - 2n, 2n, BLS - 3n, 3n, 5n, BLS - 5n, 7n, BLS - 7n, 11n, BLS - 11n]), params: { n: BLS } }
    ]
  })()
})

const addm = pointwise('fp6.add', 'r = a + b in Fp6', fp2.add, (a, b, n) => f2a(a, b, n))
const subm = pointwise('fp6.sub', 'r = a − b in Fp6', fp2.sub, (a, b, n) => f2s(a, b, n))

/**
 * r = a·v — the shift the Fp12 product needs: (a0, a1, a2) → (ξa2, a0, a1).
 *
 * One call to fp2.mulXi and otherwise nothing but OP_ROLL. Multiplying by the
 * generator of the extension is a permutation, and permutations are free in a
 * stack machine as long as you are willing to name the slots.
 */
const mulV = defineModule({
  name: 'fp6.mulV',
  doc: 'r = a·v in Fp6 — (a0, a1, a2) → (ξa2, a0, a1)',
  inputs: six('a'),
  outputs: six('r'),
  requires: inField('fp6.mulV', ...six('a')),
  ensures: ensures6('fp6.mulV'),
  model: (v, { n }) => {
    const [a0, a1, a2] = load(v, 'a')
    return store([f2xi(a2, n), a0, a1])
  },
  prologue: (asm, { n }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const { n } = params
    const p = inner(params, 'fp6.mulV')
    asm.roll('a10'); asm.rename('r20'); asm.roll('a11'); asm.rename('r21')
    park(asm)
    asm.roll('a00'); asm.rename('r10'); asm.roll('a01'); asm.rename('r11')
    park(asm)
    op(asm, fp2.mulXi, p, ['a2'], '_c0')
    asm.relabel('_c00', 'r00'); asm.relabel('_c01', 'r01')
    unpark(asm); unpark(asm)
    dropModulus(asm, n)
  },
  cases: (() => {
    const c = (o) => ({ a00: o[0], a01: o[1], a10: o[2], a11: o[3], a20: o[4], a21: o[5] })
    return [
      { name: 'small', inputs: c([1n, 2n, 3n, 4n, 5n, 6n]), params: { n: 11n } },
      { name: 'one', inputs: c([1n, 0n, 0n, 0n, 0n, 0n]), params: { n: 11n } },
      { name: 'BLS12-381', inputs: c([BLS - 1n, 1n, BLS - 2n, 2n, BLS - 3n, 3n]), params: { n: BLS } }
    ]
  })()
})

module.exports = { mul, sqr, add: addm, sub: subm, mulV, six, two, op, dup, park, unpark, fresh, numericModulus, residues, inField, PN, pushModulus, modulusName, dropModulus, inner, f2m, f2a, f2s, f2xi, load, store }
