'use strict'

const { defineModule, apply } = require('../module')
const fp2 = require('./fp2')
const fp6 = require('./fp6')
const fp12 = require('./fp12')
const g2mod = require('./g2')
const txmod = require('./tx')
const bls = require('../bls12381')
const { mod, invmod } = require('../bigint')
const { defaultAttacks } = require('../testkit')

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

/**
 * Which steps a given number of rounds performs, in order, for `pairs` pairings
 * run together.
 *
 * The SQUARING BELONGS TO THE BIT. That is a correctness point for one pairing
 * — squaring again before a chord gives f² where f was wanted — and it is the
 * entire economics of a multi-pairing: k pairings sharing one accumulator pay
 * for 63 squarings between them, not 63 each. `first` marks the step a bit
 * opens with, which is the one that squares.
 */
function schedule (rounds, pairs = 1) {
  const plan = []
  for (let i = 1; i <= rounds; i++) {
    for (let j = 0; j < pairs; j++) plan.push({ kind: 'double', bit: i, pair: j, first: j === 0 })
    if (BITS[i] === '1') for (let j = 0; j < pairs; j++) plan.push({ kind: 'add', bit: i, pair: j, first: false })
  }
  return plan
}
/** The name prefix for pair j — empty when there is only one, so a single
 *  pairing's script is byte for byte what it was before multi-pairings existed. */
const pre = (j, pairs) => (pairs === 1 ? '' : `p${j}_`)

/**
 * Run the loop in JavaScript: the accumulator it ends on, and the inverse each
 * step needed. The witnesses come out in the same order the script consumes
 * them, which is the only reason a 136-value unlocking script can be built by
 * hand at all.
 */
function replay (pairsIn, rounds, n) {
  const list = Array.isArray(pairsIn) ? pairsIn : [pairsIn]
  let f = bls.F12_ONE
  const T = list.map((pq) => pq.Q)
  const witnesses = []
  for (let i = 1; i <= rounds; i++) {
    f = bls.f12sqr(f)
    list.forEach((pq, j) => {
      witnesses.push(f2inv([mod(T[j].y[0] + T[j].y[0], n), mod(T[j].y[1] + T[j].y[1], n)], n))
      const d = bls.lineDouble(T[j], pq.P)
      T[j] = d.next
      f = bls.f12mulLine(f, d)
    })
    if (BITS[i] === '1') {
      list.forEach((pq, j) => {
        witnesses.push(f2inv([mod(pq.Q.x[0] - T[j].x[0], n), mod(pq.Q.x[1] - T[j].x[1], n)], n))
        const a = bls.lineAdd(T[j], pq.Q, pq.P)
        T[j] = a.next
        f = bls.f12mulLine(f, a)
      })
    }
  }
  return { f, T, witnesses }
}
/** The old one-pairing signature, kept because tools/targets.js pins scripts built with it. */
const replay1 = (P, Q, rounds, n) => replay([{ P, Q }], rounds, n)

/** Read k (P, Q) pairs out of a flat input object, and write them back. */
function readPairs (v, pairs) {
  return Array.from({ length: pairs }, (_, j) => {
    const q = pre(j, pairs)
    return { P: { x: v[q + 'Px'], y: v[q + 'Py'] }, Q: { x: [v[q + 'Qx0'], v[q + 'Qx1']], y: [v[q + 'Qy0'], v[q + 'Qy1']] } }
  })
}
function writePairs (list, pairs) {
  const out = {}
  list.forEach((pq, j) => {
    const q = pre(j, pairs)
    out[q + 'Px'] = pq.P.x; out[q + 'Py'] = pq.P.y
    out[q + 'Qx0'] = pq.Q.x[0]; out[q + 'Qx1'] = pq.Q.x[1]
    out[q + 'Qy0'] = pq.Q.y[0]; out[q + 'Qy1'] = pq.Q.y[1]
  })
  return out
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
 * The Miller loop for one or several pairings at once.
 *
 * k pairings sharing one accumulator cost 63 squarings BETWEEN them, because
 * the squaring belongs to the bit. Three separate loops would pay 189 and then
 * three separate final exponentiations besides; run together they pay 63 and
 * one. That is the difference between a Groth16 verifier that is 2.5 MB and one
 * that is 1.4 MB, and it is the reason every pairing-based protocol is checked
 * as a PRODUCT of pairings rather than as pairings compared one at a time.
 *
 * With one pair the emitted script is byte for byte what it was before this
 * generalisation existed — `pre()` makes the names identical, and the deployed
 * loops on chain still rebuild exactly (`npm run verify:chain`).
 *
 * @param rounds  how many bits of |x| to run — FULL (63) is the whole loop
 * @param opts.pairs      how many pairings share the accumulator, default 1
 * @param opts.conjugate  whether to take the final conjugate; defaults to
 *                        "yes when the loop is complete", because x is negative
 */
function miller (rounds = FULL, opts = {}) {
  const pairs = opts.pairs || 1
  const plan = schedule(rounds, pairs)
  const at = (j) => pre(j, pairs)
  const ptNames = []
  for (let j = 0; j < pairs; j++) {
    ptNames.push(`${at(j)}Px`, `${at(j)}Py`, `${at(j)}Qx0`, `${at(j)}Qx1`, `${at(j)}Qy0`, `${at(j)}Qy1`)
  }
  const conjugate = opts.conjugate === undefined ? (rounds === FULL && bls.X < 0n) : opts.conjugate
  const wit = plan.flatMap((_, k) => [`w${k}a`, `w${k}b`])

  return defineModule({
    name: pairs === 1 ? `pairing.miller${rounds}` : `pairing.miller${rounds}x${pairs}`,
    doc: pairs === 1
      ? `the Miller loop over ${rounds} bit(s) of the BLS parameter — ${plan.length} lines, ${plan.length} witnessed inverses`
      : `${pairs} Miller loops over ${rounds} bit(s), sharing one accumulator — ${plan.length} lines, ${rounds} squarings between them`,
    inputs: [
      ...ptNames,
      ...wit.map((name) => ({ name, witness: true }))
    ],
    outputs: twelve('f'),
    maxWitnessAttacks: opts.maxWitnessAttacks || 12,
    requires: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of ptNames) out[k] = r
      return out
    },
    ensures: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of twelve('f')) out[k] = r
      return out
    },
    hint: (v, { nn = P381 }) => {
      const { witnesses } = replay(readPairs(v, pairs), rounds, nn)
      const out = {}
      witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      return out
    },
    model: (v, { nn = P381 }) => {
      const { f } = replay(readPairs(v, pairs), rounds, nn)
      return spread(conjugate ? bls.f12conj(f) : f, 'f')
    },
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = inner({ n, nn: params.nn === undefined ? numericModulus({ n }, 'pairing.miller') : params.nn }, 'pairing.miller')

      // ξ·y_P is the line's w⁰ coefficient and does not depend on T, so it is
      // the same value on all 68 iterations. Hoisting it out of the loop is one
      // fp2.mulXi instead of sixty-eight.
      for (let j = 0; j < pairs; j++) {
        asm.num(0n, `_zero${j}`)
        apply(asm, fp2.mulXi, p, [`${at(j)}Py`, `_zero${j}`], [`${at(j)}H0`, `${at(j)}H1`])
      }

      // T starts at Q, which the loop also keeps for its chords
      for (let j = 0; j < pairs; j++) {
        dup(asm, `${at(j)}Qx`, `${at(j)}Tx`); dup(asm, `${at(j)}Qy`, `${at(j)}Ty`)
      }

      // f starts at one
      for (const name of twelve('f')) asm.num(name === 'fA00' ? 1n : 0n, name)

      plan.forEach((step, k) => {
        // The squaring belongs to the BIT, not to the line. A set bit
        // contributes two lines and still only one square, and squaring again
        // before the chord gives f² where f was wanted — a wrong answer that
        // costs 2,375 extra bytes to arrive at.
        if (step.first) apply(asm, fp12.sqr, p, twelve('f'), twelve('f'))
        const q = at(step.pair)
        const T = [`${q}Tx0`, `${q}Tx1`, `${q}Ty0`, `${q}Ty1`]
        // Px is a base-field scalar, not an Fp2 pair, so it is picked directly.
        const px = () => { asm.pick(`${q}Px`, `_px${k}`); return `_px${k}` }
        const args = step.kind === 'double'
          ? [...T, px()]
          : [...T,
              ...two(dup(asm, `${q}Qx`, `_qx${k}`)), ...two(dup(asm, `${q}Qy`, `_qy${k}`)), px()]
        apply(asm, step.kind === 'double' ? g2mod.stepDouble : g2mod.stepAdd, p,
          [...args, `w${k}a`, `w${k}b`],
          [...T, 'L10', 'L11', 'L20', 'L21'])
        apply(asm, fp12.mulLine, p,
          [...twelve('f'), ...two(dup(asm, `${q}H`, `_h${k}`)), 'L10', 'L11', 'L20', 'L21'],
          twelve('f'))
      })

      if (conjugate) {
        for (const c of ['fB0', 'fB1', 'fB2']) apply(asm, fp2.neg, p, two(c), two(c))
      }

      // everything the loop was carrying, gone; then the twelve results rolled
      // into their declared order, which twelve OP_ROLLs guarantee and no
      // amount of reasoning about the altstack does.
      for (let j = 0; j < pairs; j++) {
        for (const suffix of ['Tx0', 'Tx1', 'Ty0', 'Ty1', 'Px', 'Qx0', 'Qx1', 'Qy0', 'Qy1', 'H0', 'H1']) {
          asm.discard(at(j) + suffix)
        }
      }
      if (typeof n !== 'string') asm.discard('_pn')
      for (const name of twelve('f')) asm.roll(name)
    },
    notes: [
      `${plan.length} witnessed Fp2 inverses, every coefficient bounded into [0, p)`,
      'the G1 point is affine and so is T: in Script a witnessed inverse is cheaper than the extra multiplications projective coordinates would cost to avoid one'
    ],
    cases: (() => {
      const one = (scalars, name) => ({
        name,
        inputs: writePairs(scalars.map(([a, b]) => ({ P: bls.g1mul(a), Q: bls.g2mul(b) })), pairs),
        params: { n: P381, nn: P381 }
      })
      const spread1 = [[1n, 1n], [2n, 3n], [12345n, 6789n]]
      if (pairs === 1) {
        return [one([spread1[0]], 'the generators'), one([spread1[1]], '2G1, 3G2'), one([spread1[2]], 'a random pair')]
      }
      const pick = (o) => Array.from({ length: pairs }, (_, j) => spread1[(j + o) % spread1.length])
      return [one(pick(0), `${pairs} pairings at once`), one(pick(1), 'a different set')]
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
const HARD_MAX_J = bls.HARD_TERMS.reduce((m, t) => Math.max(m, t.j), 0)
let uid = 0
const tmp = () => `_e${uid++}`
const copy12 = (asm, from, to = tmp()) => { for (const x of F12SUF) asm.pick(from + x, to + x); return to }
const call12 = (asm, m, p, ins, out = tmp(), flat = []) => {
  apply(asm, m, p, [...ins.flatMap(twelve), ...flat], twelve(out))
  return out
}

/**
 * x^y for the 63-bit curve parameter, by fp12.powXc — the COMPRESSED ladder.
 *
 * The uncompressed version of this was 63 general cyclotomic squarings inline.
 * fp12.powXc does the same exponentiation with four Fp2 coefficients instead of
 * six and one witnessed decompression before each of the five multiplications
 * plus one at the end: 73,674 bytes against 98,902, checked against the literal
 * f^|x| rather than against another copy of itself.
 *
 * Five of these is most of a final exponentiation, so a quarter off each is a
 * sixth off a pairing.
 */
const LADDER_WITNESSES = 6
const ladderNames = (j) => Array.from({ length: LADDER_WITNESSES },
  (_, k) => [`L${j}d${k}i0`, `L${j}d${k}i1`]).flat()

function powY (asm, p, base, j) {
  return call12(asm, fp12.powXc, p, [copy12(asm, base)], undefined, ladderNames(j))
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
  inputs: [
    ...twelve('f'),
    ...twelve('inv').map((name) => ({ name, witness: true })),
    ...Array.from({ length: HARD_MAX_J }, (_, i) => ladderNames(i + 1)).flat().map((name) => ({ name, witness: true }))
  ],
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
  hint: (v, params) => {
    const f = unspread(v, 'f')
    const out = spread(bls.f12inv(f), 'inv')
    // the ladders' decompression witnesses, produced by replaying what the
    // script is about to do — which is what fp12.powXc's own hint does, once
    // per ladder, on the value that ladder will actually see
    let r = bls.f12mulRaw(bls.f12conj(f), bls.f12inv(f))
    r = bls.f12mulRaw(bls.f12frobN(r, 2), r)
    for (let j = 1; j <= HARD_MAX_J; j++) {
      const w = fp12.powXc.hint(spread(r, 'a'), { n: P381 })
      for (const [name, value] of Object.entries(w)) out[`L${j}${name}`] = value
      r = bls.cyclotomicPow(r, bls.Y)
    }
    return out
  },
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
    const pow = [r]
    for (let j = 1; j <= HARD_MAX_J; j++) pow.push(powY(asm, p, pow[j - 1], j))

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
 * A PRODUCT OF PAIRINGS: Π e(Pᵢ, Qᵢ), as one locking script.
 *
 * With one pair this is the pairing. With several it is what pairing-based
 * protocols actually ask for — nobody computes two pairings and compares them,
 * because a product costs one Miller accumulator and ONE final exponentiation
 * instead of two of each. A Groth16 verification is a product of three; a BLS
 * signature check is a product of two.
 *
 * The saving is not small. Three separate pairings are 3 × 333 KB of loop and
 * 3 × 592 KB of exponentiation, 2.8 MB in all. As a product they are 793 KB of
 * loop and one 592 KB exponentiation: 1.39 MB, half the size, and the half that
 * goes is the half that was doing the same 63 squarings three times.
 *
 * 148 witnessed numbers for one pair — 136 Fp2 inverse coefficients for the
 * loop's 68 lines, twelve for the single Fp12 inversion — and 68 more Fp2
 * inverses for every pair after the first. Every one is bounded into [0, p) and
 * checked. A pairing that accepted a second witness for the same input would
 * not be a pairing.
 */
function product (pairs = 1, opts = {}) {
  const loop = miller(FULL, { pairs })
  const loopIn = loop.inputs.map((i) => i.name)
  const loopWit = loop.inputs.filter((i) => i.witness).map((i) => i.name)
  const points = loopIn.filter((name) => !loopWit.includes(name))
  // whatever the exponentiation needs beyond the Fp12 element itself: the one
  // Fp12 inverse, and the decompression inverses its five ladders consume
  const expWit = finalExp.inputs.filter((i) => i.witness).map((i) => i.name)

  return defineModule({
    name: pairs === 1 ? 'pairing.e' : `pairing.product${pairs}`,
    doc: pairs === 1
      ? 'e(P, Q) on BLS12-381 — the optimal ate pairing, as one script'
      : `Π e(Pᵢ, Qᵢ) over ${pairs} pairs on BLS12-381 — one accumulator, one final exponentiation`,
    inputs: [
      ...points,
      ...loopWit.map((name) => ({ name, witness: true })),
      ...expWit.map((name) => ({ name, witness: true }))
    ],
    outputs: twelve('r'),
    maxWitnessAttacks: opts.maxWitnessAttacks || 3,
    requires: ({ nn = P381 }) => {
      const r = { range: { lo: 0n, hi: nn } }
      const out = {}
      for (const k of points) out[k] = r
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
      const { f, witnesses } = replay(readPairs(v, pairs), FULL, nn)
      const out = {}
      witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      const raw = bls.X < 0n ? bls.f12conj(f) : f
      // the exponentiation's own hint, on the value it will actually see
      return { ...out, ...finalExp.hint(spread(raw, 'f'), { n: nn, nn }) }
    },
    model: (v, params) => {
      const nn = params.nn === undefined ? P381 : params.nn
      const { f } = replay(readPairs(v, pairs), FULL, nn)
      return spread(bls.finalExponentiate(bls.X < 0n ? bls.f12conj(f) : f), 'r')
    },
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = { n: modulusName(n), nn: params.nn === undefined ? numericModulus({ n }, 'pairing.product') : params.nn }
      apply(asm, loop, p, loopIn, twelve('f'))
      apply(asm, finalExp, p, [...twelve('f'), ...expWit], twelve('r'))
      if (typeof n !== 'string') asm.discard('_pn')
      for (const name of twelve('r')) asm.roll(name)
    },
    cases: (() => {
      const sets = [
        [[1n, 1n], [2n, 3n], [12345n, 6789n], [7n, 11n]],
        [[3n, 5n], [1n, 1n], [99n, 101n], [2n, 2n]]
      ]
      const one = (set, name) => ({
        name,
        inputs: writePairs(set.slice(0, pairs).map(([a, b]) => ({ P: bls.g1mul(a), Q: bls.g2mul(b) })), pairs),
        params: { n: P381, nn: P381 }
      })
      return pairs === 1
        ? [one(sets[0], 'e(G1, G2)')]
        : [one(sets[0], `a product of ${pairs}`), one(sets[1], 'a different product')]
    })()
  })
}

/** The pairing. Kept as its own name because that is what it is. */
const full = (opts = {}) => product(1, opts)

/**
 * THE PAIRING CHECK, as a predicate: Π e(Pᵢ, Qᵢ) = a constant fixed at compile
 * time. Asserts and returns nothing, so it composes with `all()` and becomes a
 * coin through `predicate()` like anything else here.
 *
 * This is the shape every pairing-based protocol reduces to. A BLS signature is
 * e(H(m), pk)·e(−σ, G2) = 1. A Groth16 verification is
 * e(A,B)·e(−L,γ)·e(−C,δ) = e(α,β), where the right-hand side is fixed by the
 * verifying key and so is exactly the constant this compares against — which is
 * why comparing against a constant, rather than folding e(α,β) in as a fourth
 * pair, is 68 fewer lines and 177 KB cheaper.
 */
function verify (pairs, expected, opts = {}) {
  const prod = product(pairs, opts)
  const want = spread(expected, 'r')

  return defineModule({
    name: `pairing.verify${pairs}`,
    doc: `Π e(Pᵢ, Qᵢ) over ${pairs} pair(s) equals a constant fixed in the script`,
    inputs: prod.inputs,
    outputs: [],
    maxWitnessAttacks: opts.maxWitnessAttacks || 3,
    requires: prod.requires,
    hint: prod.hint,
    model: () => ({}),
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = { n: modulusName(n), nn: params.nn === undefined ? numericModulus({ n }, 'pairing.verify') : params.nn }
      apply(asm, prod, p, prod.inputs.map((i) => i.name), twelve('r'))
      for (const name of twelve('r')) {
        asm.roll(name)
        asm.num(want[name], '_want')
        asm.numEqualVerify()
      }
      if (typeof n !== 'string') asm.discard('_pn')
    },
    notes: [
      'a predicate: it asserts the product and returns nothing, so all() and predicate() take it',
      'the expected value is a compile-time constant — 576 bytes of Fp12 in the locking script'
    ],
    cases: opts.cases || []
  })
}

// ── A PAIRING SPLIT ACROSS ONE TRANSACTION ──────────────────────────────────
//
// e(P, Q) in one script is 817,031 bytes and the default script-size policy is
// 500,000. Both STAGES fit under it individually and both are on chain; what is
// not is the composition, and no amount of shaving gets 817 KB under 500 KB.
//
// So do not put them in one script. Put them in one TRANSACTION.
//
//     input 0  ── the Miller loop ──► publishes f as an OP_RETURN output
//     input 1  ── the final exponentiation ──► consumes that same output
//
// Both inputs of a spend see the same `hashOutputs`. If each requires that
// commitment to be the data output IT constructs, then they constructed the
// same bytes — so input 1's f is input 0's f, enforced by the transaction
// rather than by trust. Neither script contains the other's code, which is the
// whole point: a covenant can only commit to a successor whose bytes it can
// build, and a 333 KB script cannot carry a 474 KB one.
//
// What the network then verifies, in one transaction:
//
//     the Miller loop ran correctly on P and Q          (input 0)
//     its twelve outputs were published                 (input 0's covenant)
//     the same twelve were consumed                     (input 1's covenant)
//     their final exponentiation is e(P, Q)             (input 1)
//
// which is a complete pairing, evaluated by Bitcoin.
//
// The twelve coefficients are serialised at 49 bytes each: p is 381 bits, so
// 392 bits leaves the sign bit clear and OP_NUM2BIN — which writes a SIGNED
// number — cannot produce a value that reads back negative.

const COEFF_BYTES = 49
const STATE_BYTES = 12 * COEFF_BYTES

/** Twelve field elements as one blob, the way both halves agree to write them. */
function serialiseF12 (values, prefix) {
  return Buffer.concat(twelve(prefix).map((name) => {
    const b = Buffer.alloc(COEFF_BYTES)
    let v = values[name]
    for (let i = 0; i < COEFF_BYTES; i++) { b[i] = Number(v & 0xffn); v >>= 8n }
    if (v !== 0n) throw new Error('serialiseF12: a coefficient does not fit in 49 bytes')
    return b
  }))
}

/**
 * Input 0: run the Miller loop and publish what it produced.
 */
function publish (opts = {}) {
  const loop = miller(FULL)
  const loopIn = loop.inputs.map((i) => i.name)
  const commit = txmod.commitData(STATE_BYTES)

  return defineModule({
    name: 'pairing.publish',
    doc: 'run the Miller loop and require the spend to publish its twelve outputs',
    inputs: [...loop.inputs, { name: 'preimage', kind: 'bytes', witness: true }],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: (ctx) => {
      const { tx, lockingScript, satoshis, spend = {} } = ctx
      const P = { x: spend.Px, y: spend.Py }
      const Q = { x: [spend.Qx0, spend.Qx1], y: [spend.Qy0, spend.Qy1] }
      const { f, witnesses } = replay([{ P, Q }], FULL, P381)
      const out = {}
      witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      const data = serialiseF12(spread(bls.X < 0n ? bls.f12conj(f) : f, 'f'), 'f')

      tx.outputs.length = 0
      tx.addOutput(txmod.dataOutput(STATE_BYTES, data))
      tx._outputAmount = undefined
      const g = txmod.PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'sequence' })
      return { ...out, preimage: g.preimage }
    },
    hint: () => ({}),
    model: () => ({}),
    // The preimage is transaction-shaped and gets transaction-shaped forgeries;
    // the other 136 witnesses are Fp2 inverse coefficients and get the kit's
    // field near-misses. Routing every witness through preimageAttacks was the
    // first version, and it fails on the first bigint it meets.
    attacks: (honest, params, name) => (name === 'preimage'
      ? txmod.preimageAttacks(honest, params, name)
      : defaultAttacks(honest[name], { n: P381 })),
    requires: loop.requires,
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = { n: modulusName(n), nn: params.nn === undefined ? numericModulus({ n }, 'pairing.publish') : params.nn }
      apply(asm, loop, p, loopIn, twelve('f'))
      // twelve numbers into one blob, most significant coefficient first
      twelve('f').forEach((name, i) => {
        asm.roll(name); asm.num2bin(COEFF_BYTES, `_b${i}`)
        if (i > 0) asm.cat('_blob')
      })
      asm.rename('data', 'bytes', STATE_BYTES)
      apply(asm, commit, {}, ['preimage', 'data'], ['_published'])
      asm.drop()
      if (typeof n !== 'string') asm.discard('_pn')
    },
    notes: [
      'the transaction is the channel: whatever this publishes, another input of the same spend can require',
      `${STATE_BYTES} bytes of state — twelve coefficients at ${COEFF_BYTES} each, wide enough that OP_NUM2BIN's sign bit stays clear`
    ],
    cases: opts.cases || []
  })
}

/**
 * Input 1: consume a published Miller output and finish the pairing.
 *
 * The twelve coefficients arrive as a witness and are pinned by the same output
 * commitment `pairing.publish` makes. A spender who supplies a different f
 * makes the covenant fail; a spender who supplies the right f but a different
 * expected value fails the comparison at the end.
 */
function consume (expected, opts = {}) {
  const commit = txmod.commitData(STATE_BYTES)
  const want = spread(expected, 'r')
  const expWit = finalExp.inputs.filter((i) => i.witness).map((i) => i.name)

  return defineModule({
    name: 'pairing.consume',
    doc: 'consume a published Miller output and require its final exponentiation to be a fixed value',
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'data', kind: 'bytes', width: STATE_BYTES, witness: true },
      ...expWit.map((name) => ({ name, witness: true }))
    ],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: (ctx) => {
      const { tx, lockingScript, satoshis, spend = {} } = ctx
      const f = spend.f
      const data = serialiseF12(spread(f, 'f'), 'f')
      tx.outputs.length = 0
      tx.addOutput(txmod.dataOutput(STATE_BYTES, data))
      tx._outputAmount = undefined
      const g = txmod.PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'sequence' })
      return { preimage: g.preimage, data, ...finalExp.hint(spread(f, 'f'), { n: P381, nn: P381 }) }
    },
    hint: () => ({}),
    model: () => ({}),
    // Three kinds of witness, three kinds of forgery. The preimage gets the
    // transaction-shaped attacks; `data` gets a byte flipped, which is the
    // attack that matters — a spender substituting a Miller output the
    // transaction did not publish; everything else is a field element and gets
    // the kit's own near-misses, including the same residue plus p.
    attacks: (honest, params, name) => {
      if (name === 'preimage') return txmod.preimageAttacks(honest, params, name)
      if (name === 'data') {
        const b = Buffer.from(honest[name]); b[0] ^= 0x01
        return [{ label: 'a value the transaction did not publish', value: b }]
      }
      return defaultAttacks(honest[name], { n: P381 })
    },
    prologue: (asm, { n = P381 }) => pushModulus(asm, n),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n
      const p = { n: modulusName(n), nn: params.nn === undefined ? numericModulus({ n }, 'pairing.consume') : params.nn }
      apply(asm, commit, {}, ['preimage', 'data'], ['data'])
      // the blob back into twelve numbers, in the order publish() wrote them
      const names = twelve('f')
      for (let i = 0; i < names.length - 1; i++) {
        asm.splitAt(COEFF_BYTES, names[i], '_rest')
        asm.op('OP_SWAP', 2, [{ name: '_rest2', kind: 'bytes' }, { name: names[i], kind: 'bytes' }])
        asm.bin2num(names[i])
        asm.op('OP_SWAP', 2, [{ name: names[i], kind: 'num' }, { name: '_rest', kind: 'bytes' }])
      }
      asm.bin2num(names[names.length - 1])
      apply(asm, finalExp, p, [...names, ...expWit], twelve('r'))
      for (const name of twelve('r')) {
        asm.roll(name); asm.num(want[name], '_want'); asm.numEqualVerify()
      }
      if (typeof n !== 'string') asm.discard('_pn')
    },
    notes: [
      'the data is a witness AND is pinned by the transaction, so it is whatever the other input published',
      'the expected value is a compile-time constant: this coin is a claim about one specific pairing'
    ],
    cases: opts.cases || []
  })
}

module.exports = { miller, finalExp, product, full, verify, publish, consume, serialiseF12, STATE_BYTES, COEFF_BYTES, schedule, replay, replay1, readPairs, writePairs, pre, spread, unspread, FULL, BITS }
