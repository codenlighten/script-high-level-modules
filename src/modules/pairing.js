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

module.exports = { miller, schedule, replay, FULL, BITS }
