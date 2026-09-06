'use strict'

const { defineModule, apply } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')
const fp12 = require('./fp12')
const g2mod = require('./g2')
const bls = require('../bls12381')
const { mod, invmod } = require('../bigint')

// THE MILLER LOOP, emitted.
//
// Everything else in this repository that touches pairings measures a piece and
// multiplies. This one does not measure and multiply: it emits the whole loop,
// hands it to bsv.Script.Interpreter, and the interpreter either accepts it or
// does not. There is no estimate left in it.
//
// The loop is the optimal ate pairing's, over the 63-bit BLS parameter:
//
//     f ← 1,  T ← Q
//     for each bit of |x| after the first:
//         f ← f²                      fp12.sqr
//         f ← f · line(T, T)          g2.stepDouble ▸ fp12.mulLine
//         if the bit is set:
//             f ← f · line(T, Q)      g2.stepAdd    ▸ fp12.mulLine
//     f ← conj(f)                     because x is negative
//
// 63 squarings, 63 tangents, 5 chords, 68 line products. Every inversion the
// loop needs is a WITNESS: 68 of them, each two Fp2 coefficients the spender
// supplies and the script bounds into [0, p) and checks against a·a⁻¹ = 1.
// That is 136 numbers a spender chooses, and every one of them is pinned to
// exactly one value — which is the whole of why this can be trusted at all.
//
// `rounds` exists so the test suite can prove four iterations in a second and a
// tool can prove all sixty-three when asked. A truncated loop is a real object,
// not a stub: it is the loop state after that many bits, and the model computes
// exactly that.

const P381 = bls.P
const BITS = (bls.X < 0n ? -bls.X : bls.X).toString(2)
const FULL = BITS.length - 1                                    // 63

const { two, op, dup, numericModulus, residues, pushModulus, modulusName, inner } = fp6
const { twelve } = fp12

/** a⁻¹ in Fp2, in plain BigInt — for the hints only. */
const f2inv = (a, n) => {
  const d = invmod(mod(a[0] * a[0] + a[1] * a[1], n), n)
  return [mod(a[0] * d, n), mod(-a[1] * d, n)]
}

/** Which steps a given number of rounds performs, in order. */
function schedule (rounds) {
  const plan = []
  for (let i = 1; i <= rounds; i++) {
    plan.push({ kind: 'double', bit: i })
    if (BITS[i] === '1') plan.push({ kind: 'add', bit: i })
  }
  return plan
}

/**
 * Run the loop in JavaScript: the accumulator it ends on, and the inverse each
 * step needed. The witnesses come out in the same order the script consumes
 * them, which is the only reason a 136-value unlocking script can be built by
 * hand at all.
 */
function replay (P, Q, rounds, n) {
  let f = bls.F12_ONE
  let T = Q
  const witnesses = []
  for (let i = 1; i <= rounds; i++) {
    f = bls.f12sqr(f)
    witnesses.push(f2inv([mod(T.y[0] + T.y[0], n), mod(T.y[1] + T.y[1], n)], n))
    const d = bls.lineDouble(T, P)
    T = d.next
    f = bls.f12mulLine(f, d)
    if (BITS[i] === '1') {
      witnesses.push(f2inv([mod(Q.x[0] - T.x[0], n), mod(Q.x[1] - T.x[1], n)], n))
      const a = bls.lineAdd(T, Q, P)
      T = a.next
      f = bls.f12mulLine(f, a)
    }
  }
  return { f, T, witnesses }
}

const unspread = (v, p) => {
  const g = (i) => v[twelve(p)[i]]
  return [[[g(0), g(1)], [g(2), g(3)], [g(4), g(5)]], [[g(6), g(7)], [g(8), g(9)], [g(10), g(11)]]]
}
const spread = (f, p) => {
  const out = {}
  twelve(p).forEach((name, i) => { out[name] = f[i < 6 ? 0 : 1][Math.floor((i % 6) / 2)][i % 2] })
  return out
}

/**
 * @param rounds  how many bits of |x| to run — FULL (63) is the whole loop
 * @param opts.conjugate  whether to take the final conjugate; defaults to
 *                        "yes when the loop is complete", because x is negative
 */
function miller (rounds = FULL, opts = {}) {
  const plan = schedule(rounds)
  const conjugate = opts.conjugate === undefined ? (rounds === FULL && bls.X < 0n) : opts.conjugate
  const wit = plan.flatMap((_, k) => [`w${k}a`, `w${k}b`])

  return defineModule({
    name: `pairing.miller${rounds}`,
    doc: `the Miller loop over ${rounds} bit(s) of the BLS parameter — ${plan.length} lines, ${plan.length} witnessed inverses`,
    inputs: [
      'Px', 'Py', 'Qx0', 'Qx1', 'Qy0', 'Qy1',
      ...wit.map((name) => ({ name, witness: true }))
    ],
    outputs: twelve('f'),
    maxWitnessAttacks: opts.maxWitnessAttacks || 12,
    requires: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of ['Px', 'Py', 'Qx0', 'Qx1', 'Qy0', 'Qy1']) out[k] = r
      return out
    },
    ensures: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of twelve('f')) out[k] = r
      return out
    },
    hint: ({ Px, Py, Qx0, Qx1, Qy0, Qy1 }, { nn = P381 }) => {
      const { witnesses } = replay({ x: Px, y: Py }, { x: [Qx0, Qx1], y: [Qy0, Qy1] }, rounds, nn)
      const out = {}
      witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      return out
    },
    model: ({ Px, Py, Qx0, Qx1, Qy0, Qy1 }, { nn = P381 }) => {
      const { f } = replay({ x: Px, y: Py }, { x: [Qx0, Qx1], y: [Qy0, Qy1] }, rounds, nn)
      return spread(conjugate ? bls.f12conj(f) : f, 'f')
    },
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = inner({ n, nn: params.nn === undefined ? numericModulus({ n }, 'pairing.miller') : params.nn }, 'pairing.miller')

      // ξ·y_P is the line's w⁰ coefficient and does not depend on T, so it is
      // the same value on all 68 iterations. Hoisting it out of the loop is one
      // fp2.mulXi instead of sixty-eight.
      asm.num(0n, '_zero')
      apply(asm, fp2.mulXi, p, ['Py', '_zero'], ['H0', 'H1'])

      // T starts at Q, which the loop also keeps for its chords
      dup(asm, 'Qx', 'Tx'); dup(asm, 'Qy', 'Ty')

      // f starts at one
      for (const name of twelve('f')) asm.num(name === 'fA00' ? 1n : 0n, name)

      plan.forEach((step, k) => {
        // The squaring belongs to the BIT, not to the line. A set bit
        // contributes two lines and still only one square, and squaring again
        // before the chord gives f² where f was wanted — a wrong answer that
        // costs 2,375 extra bytes to arrive at.
        if (step.kind === 'double') apply(asm, fp12.sqr, p, twelve('f'), twelve('f'))
        // Px is a base-field scalar, not an Fp2 pair, so it is picked directly.
        const px = () => { asm.pick('Px', `_px${k}`); return `_px${k}` }
        const args = step.kind === 'double'
          ? ['Tx0', 'Tx1', 'Ty0', 'Ty1', px()]
          : ['Tx0', 'Tx1', 'Ty0', 'Ty1',
              ...two(dup(asm, 'Qx', `_qx${k}`)), ...two(dup(asm, 'Qy', `_qy${k}`)), px()]
        apply(asm, step.kind === 'double' ? g2mod.stepDouble : g2mod.stepAdd, p,
          [...args, `w${k}a`, `w${k}b`],
          ['Tx0', 'Tx1', 'Ty0', 'Ty1', 'L10', 'L11', 'L20', 'L21'])
        apply(asm, fp12.mulLine, p,
          [...twelve('f'), ...two(dup(asm, 'H', `_h${k}`)), 'L10', 'L11', 'L20', 'L21'],
          twelve('f'))
      })

      if (conjugate) {
        for (const c of ['fB0', 'fB1', 'fB2']) apply(asm, fp2.neg, p, two(c), two(c))
      }

      // everything the loop was carrying, gone; then the twelve results rolled
      // into their declared order, which twelve OP_ROLLs guarantee and no
      // amount of reasoning about the altstack does.
      for (const name of ['Tx0', 'Tx1', 'Ty0', 'Ty1', 'Px', 'Qx0', 'Qx1', 'Qy0', 'Qy1', 'H0', 'H1']) asm.discard(name)
      if (typeof n !== 'string') asm.discard('_pn')
      for (const name of twelve('f')) asm.roll(name)
    },
    notes: [
      `${plan.length} witnessed Fp2 inverses, every coefficient bounded into [0, p)`,
      'the G1 point is affine and so is T: in Script a witnessed inverse is cheaper than the extra multiplications projective coordinates would cost to avoid one'
    ],
    cases: (() => {
      const one = (k, j, name) => ({
        name,
        inputs: (() => {
          const P = bls.g1mul(k); const Q = bls.g2mul(j)
          return { Px: P.x, Py: P.y, Qx0: Q.x[0], Qx1: Q.x[1], Qy0: Q.y[0], Qy1: Q.y[1] }
        })(),
        params: { n: P381, nn: P381 }
      })
      return [
        one(1n, 1n, 'the generators'),
        one(2n, 3n, '2G1, 3G2'),
        one(12345n, 6789n, 'a random pair')
      ]
    })()
  })
}

// ── THE FINAL EXPONENTIATION, emitted ───────────────────────────────────────
//
// f ↦ f^(3(p¹² − 1)/r), in two halves.
//
// The EASY part is f^(p⁶ − 1)(p² + 1), which is conj(f)·f⁻¹ followed by
// φ²(·)·(·). One inversion in the whole pairing, and it is a witness. After it
// the value lies in the cyclotomic subgroup, where squaring is half price and
// inversion is conjugation — and every negative digit below becomes free.
//
// The HARD part is λ = 3(p⁴ − p² + 1)/r, written as fifteen terms a·y^j·p^i
// with |a| ≤ 3, y the 63-bit curve parameter and p a Frobenius. Six shared
// ladders — r, r^y, r^y², … r^y⁵ — and the terms are assembled from those.
// The digits are derived in bls12381.js, not transcribed.
//
// The ladder here is MSB-first and unrolled, so it costs 63 squarings and 5
// multiplications for each exponentiation by y. The JavaScript reference runs
// LSB-first from an accumulator of one and pays 64 and 6, the extra multiply
// being by one — which is free to compute and is not free to emit.

const F12SUF = ['A00', 'A01', 'A10', 'A11', 'A20', 'A21', 'B00', 'B01', 'B10', 'B11', 'B20', 'B21']
let uid = 0
const tmp = () => `_e${uid++}`
const copy12 = (asm, from, to = tmp()) => { for (const x of F12SUF) asm.pick(from + x, to + x); return to }
const call12 = (asm, m, p, ins, out = tmp(), flat = []) => {
  apply(asm, m, p, [...ins.flatMap(twelve), ...flat], twelve(out))
  return out
}

/** x^y for the 63-bit curve parameter: unrolled square-and-multiply, x kept. */
function powY (asm, p, base) {
  const bits = bls.Y.toString(2)
  let acc = copy12(asm, base)                                   // the leading 1 bit
  for (let i = 1; i < bits.length; i++) {
    acc = call12(asm, fp12.cycSqr, p, [acc])
    if (bits[i] === '1') acc = call12(asm, fp12.mul, p, [acc, copy12(asm, base)])
  }
  return acc
}

/** x^a for |a| ≤ 3, consuming x. A negative a is a conjugation, not an inverse. */
function smallPow (asm, p, x, a) {
  const mag = a < 0n ? -a : a
  let acc = x
  if (mag === 2n) acc = call12(asm, fp12.cycSqr, p, [acc])
  else if (mag === 3n) acc = call12(asm, fp12.mul, p, [call12(asm, fp12.cycSqr, p, [copy12(asm, acc)]), acc])
  else if (mag !== 1n) throw new Error(`pairing.finalExp: a digit of ${a} is not one of the small ones this was built for`)
  return a < 0n ? call12(asm, fp12.conj, p, [acc]) : acc
}

const finalExp = defineModule({
  name: 'pairing.finalExp',
  doc: 'f ↦ f^(3(p¹² − 1)/r) — the final exponentiation, easy part and hard part',
  inputs: [...twelve('f'), ...twelve('inv').map((name) => ({ name, witness: true }))],
  outputs: twelve('r'),
  maxWitnessAttacks: 4,
  requires: ({ nn = P381 }) => {
    const r = { range: { lo: 0n, hi: nn } }
    const out = {}
    for (const k of twelve('f')) out[k] = r
    return out
  },
  ensures: ({ nn = P381 }) => {
    const r = { range: { lo: 0n, hi: nn } }
    const out = {}
    for (const k of twelve('r')) out[k] = r
    return out
  },
  hint: (v, params) => spread(bls.f12inv(unspread(v, 'f')), 'inv'),
  model: (v, params) => spread(bls.finalExponentiate(unspread(v, 'f')), 'r'),
  prologue: (asm, { n = P381 }) => pushModulus(asm, n),
  emit: (asm, params) => {
    const n = params.n === undefined ? P381 : params.n
    const p = inner({ n, nn: params.nn === undefined ? numericModulus({ n }, 'pairing.finalExp') : params.nn }, 'pairing.finalExp')

    // easy part: conj(f)·f⁻¹, then φ²(·)·(·)
    const fc = call12(asm, fp12.conj, p, [copy12(asm, 'f')])
    const fi = call12(asm, fp12.inv, p, ['f'], undefined, twelve('inv'))
    let r = call12(asm, fp12.mul, p, [fc, fi])
    let rf = call12(asm, fp12.frob, p, [copy12(asm, r)])
    rf = call12(asm, fp12.frob, p, [rf])
    r = call12(asm, fp12.mul, p, [rf, r])

    // the shared ladders r^(y^j)
    const maxJ = bls.HARD_TERMS.reduce((m, t) => Math.max(m, t.j), 0)
    const pow = [r]
    for (let j = 1; j <= maxJ; j++) pow.push(powY(asm, p, pow[j - 1]))

    // λ = Σ a·y^j·p^i, assembled from them
    let acc = null
    for (const t of bls.HARD_TERMS) {
      let v = copy12(asm, pow[t.j])
      for (let k = 0; k < t.i; k++) v = call12(asm, fp12.frob, p, [v])
      v = smallPow(asm, p, v, t.a)
      acc = acc === null ? v : call12(asm, fp12.mul, p, [acc, v])
    }

    for (const base of pow) for (const x of F12SUF) asm.discard(base + x)
    if (typeof n !== 'string') asm.discard('_pn')
    for (const x of F12SUF) asm.relabel(acc + x, 'r' + x)
    for (const name of twelve('r')) asm.roll(name)
  },
  notes: [
    'the one inversion a pairing needs, and it is a witness: twelve numbers the spender supplies, each bounded into [0, p) and checked by a single Fp12 multiplication',
    'correct only because the easy part lands in the cyclotomic subgroup — fp12.cycSqr is wrong anywhere else, and no range says so'
  ],
  cases: [
    { name: 'a real Miller output', inputs: spread(bls.millerLoop(bls.G1, bls.G2), 'f'), params: { n: P381, nn: P381 } },
    { name: 'another', inputs: spread(bls.millerLoop(bls.g1mul(3n), bls.g2mul(5n)), 'f'), params: { n: P381, nn: P381 } }
  ]
})

/**
 * THE PAIRING. e(P, Q), as one locking script.
 *
 * The Miller loop and the final exponentiation, chained: the twelve values the
 * loop leaves on the stack are the twelve the exponentiation reads, so nothing
 * joins them but a rename. 148 witnessed numbers — 136 Fp2 inverse coefficients
 * for the loop's 68 lines, twelve for the single Fp12 inversion — and every one
 * of them is bounded into [0, p) and checked.
 *
 * There is no opcode in Bitcoin Script for any part of this. There is OP_MUL
 * and OP_MOD at arbitrary width, and that is the whole of what it needs.
 */
function full (opts = {}) {
  const loop = miller(FULL)
  const loopWit = loop.inputs.filter((i) => i.witness).map((i) => i.name)

  return defineModule({
    name: 'pairing.e',
    doc: 'e(P, Q) on BLS12-381 — the optimal ate pairing, as one script',
    inputs: [
      'Px', 'Py', 'Qx0', 'Qx1', 'Qy0', 'Qy1',
      ...loopWit.map((name) => ({ name, witness: true })),
      ...twelve('inv').map((name) => ({ name, witness: true }))
    ],
    outputs: twelve('r'),
    maxWitnessAttacks: opts.maxWitnessAttacks || 3,
    requires: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of ['Px', 'Py', 'Qx0', 'Qx1', 'Qy0', 'Qy1']) out[k] = r
      return out
    },
    ensures: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of twelve('r')) out[k] = r
      return out
    },
    hint: (v, params) => {
      const nn = params.nn === undefined ? P381 : params.nn
      const P = { x: v.Px, y: v.Py }
      const Q = { x: [v.Qx0, v.Qx1], y: [v.Qy0, v.Qy1] }
      const { witnesses } = replay(P, Q, FULL, nn)
      const out = {}
      witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      const f = bls.X < 0n ? bls.f12conj(replay(P, Q, FULL, nn).f) : replay(P, Q, FULL, nn).f
      return { ...out, ...spread(bls.f12inv(f), 'inv') }
    },
    model: (v, params) => {
      const P = { x: v.Px, y: v.Py }
      const Q = { x: [v.Qx0, v.Qx1], y: [v.Qy0, v.Qy1] }
      return spread(bls.pairing(P, Q), 'r')
    },
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = { n: modulusName(n), nn: params.nn === undefined ? numericModulus({ n }, 'pairing.e') : params.nn }
      apply(asm, loop, p, ['Px', 'Py', 'Qx0', 'Qx1', 'Qy0', 'Qy1', ...loopWit], twelve('f'))
      apply(asm, finalExp, p, [...twelve('f'), ...twelve('inv')], twelve('r'))
      if (typeof n !== 'string') asm.discard('_pn')
      for (const name of twelve('r')) asm.roll(name)
    },
    cases: [
      {
        name: 'e(G1, G2)',
        inputs: { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] },
        params: { n: P381, nn: P381 }
      }
    ]
  })
}

module.exports = { miller, finalExp, full, schedule, replay, FULL, BITS }
