'use strict'

const { defineModule, apply } = require('../module')
const pairing = require('./pairing')
const bls = require('../bls12381')
const ecJs = require('../ec')
const points = require('./points')

// A GROTH16 VERIFIER, for a statement fixed when the coin is locked.
//
// The check is one equation:
//
//     e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)
//
// A, B and C are the proof. α, β, γ, δ are the verifying key. L is the public
// inputs combined into a G1 point, L = IC₀ + Σ xᵢ·ICᵢ.
//
// WHICH OF THOSE THE SPENDER MAY CHOOSE IS THE WHOLE OF THE SOUNDNESS.
//
// Only A, B and C come from the unlocking script. γ, δ and L are PUSHED AS
// CONSTANTS by this module, because a spender who could choose γ could choose a
// γ that makes the equation hold for a proof of nothing. `pairing.verify(3, …)`
// on its own takes all three pairs as inputs and is therefore a check of the
// equation, not a verifier; the difference is 490 bytes of pushed constant and
// it is the difference between a verifier and a hole.
//
// And because the statement is fixed at lock time, L is fixed too: a covenant
// that says "pay out to whoever proves THIS" knows its public inputs when it is
// written, so the ℓ scalar multiplications a general verifier would need are
// done off-chain, once, for free. A verifier whose public inputs are chosen at
// SPEND time is a different object and needs them on chain — about 40 KB each,
// priced in docs/cost.md under ec.mulG.
//
// The right-hand side, e(α, β), is likewise fixed by the verifying key, so it
// is a compile-time Fp12 constant — 576 bytes — and comparing against it rather
// than folding e(α, β) in as a fourth pair saves 68 lines and about 204 KB.

const P381 = bls.P
const G1 = ecJs.bls12381G1

/**
 * L = IC₀ + Σ xᵢ·ICᵢ, off chain, once.
 *
 * This is the only place the public inputs appear. Change one and L changes,
 * the locking script changes, and it is a different coin — which is exactly
 * what "the statement is fixed at lock time" means.
 */
function combine (IC, publicInputs) {
  if (IC.length !== publicInputs.length + 1) {
    throw new Error(`groth16: ${IC.length} IC points needs ${IC.length - 1} public inputs, given ${publicInputs.length}`)
  }
  let L = IC[0]
  publicInputs.forEach((x, i) => { L = G1.add(L, G1.mul(x, IC[i + 1])) })
  return L
}

/**
 * A verifying key is checked once, when the coin is built.
 *
 * α and every ICᵢ must be in G1, β, γ and δ in G2. They are constants in the
 * locking script, so there is nothing to check on chain — but a coin compiled
 * from a key with a point outside its subgroup would carry the defect into
 * every spend, so the build refuses one.
 */
function checkKey (vk) {
  const bad = [
    ...[['α', vk.alpha], ...vk.IC.map((pt, i) => [`IC${i}`, pt])].filter(([, pt]) => !points.isG1(pt)),
    ...[['β', vk.beta], ['γ', vk.gamma], ['δ', vk.delta]].filter(([, q]) => !points.isG2(q))
  ].map(([name]) => name)
  if (bad.length) throw new Error(`groth16: the verifying key's ${bad.join(', ')} ${bad.length === 1 ? 'is' : 'are'} not in the prime-order subgroup`)
  return vk
}

/**
 * @param vk   { alpha, beta, gamma, delta, IC } — alpha and IC on G1, the rest on G2
 * @param publicInputs  the statement, fixed now
 */
function verifier (vk, publicInputs, opts = {}) {
  checkKey(vk)
  // `subgroup: false` builds the verifier as it was before the subgroup
  // checks — curve equations only — so that what they cost is a measurement
  // of two scripts rather than an estimate of one.
  const SUB = opts.subgroup !== false
  const L = combine(vk.IC, publicInputs)
  const negL = G1.neg(L)
  const expected = bls.pairing(vk.alpha, vk.beta)
  const want = pairing.spread(expected, 'r')
  const at = (j) => pairing.pre(j, 3)
  const twelve = (p) => [...['00', '01', '10', '11', '20', '21'].map((s) => `${p}A${s}`),
    ...['00', '01', '10', '11', '20', '21'].map((s) => `${p}B${s}`)]

  // The three Miller loops, emitting their running points as well as the
  // accumulator: pair 0's T ends as [|x|]B, which is what B's subgroup check
  // compares against.
  const loop = pairing.miller(pairing.FULL, { pairs: 3, emitState: true })
  const loopIn = loop.inputs.map((i) => i.name)
  const loopWit = loop.inputs.filter((i) => i.witness).map((i) => i.name)
  const expWit = pairing.finalExp.inputs.filter((i) => i.witness).map((i) => i.name)
  const subA = SUB ? points.g1WitnessNames('g1A') : []
  const subC = SUB ? points.g1WitnessNames('g1C') : []
  const witnesses = [...loopWit, ...expWit, ...subC, ...subA]
  const T0 = ['Tx0', 'Tx1', 'Ty0', 'Ty1'].map((s) => `r${at(0)}${s}`)

  /** The three pairs, as the Miller loop wants them named. */
  const pairsFor = ({ Ax, Ay, Bx0, Bx1, By0, By1, Cx, Cy }) => [
    { P: { x: Ax, y: Ay }, Q: { x: [Bx0, Bx1], y: [By0, By1] } },
    { P: negL, Q: vk.gamma },
    { P: { x: Cx, y: G1.mod(-Cy) }, Q: vk.delta }
  ]

  return defineModule({
    name: 'groth16.verify',
    doc: `a Groth16 proof for a statement of ${publicInputs.length} fixed public input(s)`,
    inputs: [
      'Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy',
      ...witnesses.map((name) => ({ name, witness: true }))
    ],
    outputs: [],
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    requires: () => {
      const r = { range: { lo: 0n, hi: P381 } }
      const out = {}
      for (const k of ['Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy']) out[k] = r
      return out
    },
    hint: (v) => {
      const { witnesses: w, f } = pairing.replay(pairsFor(v), pairing.FULL, P381)
      const out = {}
      w.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      const raw = bls.X < 0n ? bls.f12conj(f) : f
      return {
        ...out,
        ...pairing.finalExp.hint(pairing.spread(raw, 'f'), { n: P381, nn: P381 }),
        ...(SUB ? points.g1LadderWitnesses({ x: v.Ax, y: v.Ay }, 'g1A') : {}),
        ...(SUB ? points.g1LadderWitnesses({ x: v.Cx, y: v.Cy }, 'g1C') : {})
      }
    },
    model: () => ({}),
    emit: (asm, params) => {
      const n = params.n === undefined ? P381 : params.n

      // THE PROOF IS THREE POINTS OF THE RIGHT GROUPS, and a pair of field
      // elements is neither a point nor, if it is one, necessarily in G1.
      //
      // A and C first, before anything else is on the stack: each check's 136
      // inverses are then the top of the stack in exactly the order it reads
      // them, and apply() moves nothing. Each check pushes its own copy of the
      // prime, 49 bytes, which is cheaper than digging 138 values out from
      // under a shared one. g1.inSubgroup includes the curve equation.
      if (SUB) {
        asm.pick('Ax', '_gAx'); asm.pick('Ay', '_gAy')
        apply(asm, points.inG1, { n: P381 }, [...subA, '_gAx', '_gAy'], [])
        asm.pick('Cx', '_gCx'); asm.pick('Cy', '_gCy')
        apply(asm, points.inG1, { n: P381 }, [...subC, '_gCx', '_gCy'], [])
      }

      asm.num(n, '_pn')
      const p = { n: '_pn', nn: P381 }
      if (SUB) {
        // B's check needs B itself after the loop has consumed it.
        for (const nm of ['Bx0', 'Bx1', 'By0', 'By1']) asm.pick(nm, '_s' + nm)
      } else {
        // The construction as it was: the curve equations and nothing more.
        for (const [x, y] of [['Ax', 'Ay'], ['Cx', 'Cy']]) {
          asm.pick(x, '_cx'); asm.pick(y, '_cy')
          apply(asm, points.onCurveG1, p, ['_cx', '_cy'], [])
        }
        for (const nm of ['Bx0', 'Bx1', 'By0', 'By1']) asm.pick(nm, '_q' + nm)
        apply(asm, points.onCurveG2, p, ['_qBx0', '_qBx1', '_qBy0', '_qBy1'], [])
      }

      // −C: the proof gives C, and the equation wants its negation. One
      // subtraction, and it is p − Cy rather than −Cy because OP_MOD is
      // truncated and a downstream comparison would see the difference.
      asm.relabel('Ax', `${at(0)}Px`); asm.relabel('Ay', `${at(0)}Py`)
      asm.relabel('Bx0', `${at(0)}Qx0`); asm.relabel('Bx1', `${at(0)}Qx1`)
      asm.relabel('By0', `${at(0)}Qy0`); asm.relabel('By1', `${at(0)}Qy1`)
      asm.relabel('Cx', `${at(2)}Px`)
      asm.pick('_pn', '_p'); asm.roll('Cy'); asm.sub('_negCy')
      asm.pick('_pn', '_p2'); asm.mod(`${at(2)}Py`)

      // the verifying key: constants, because a spender who could choose these
      // could satisfy the equation without a proof
      asm.num(negL.x, `${at(1)}Px`); asm.num(negL.y, `${at(1)}Py`)
      const g2 = (pt, name) => {
        asm.num(pt.x[0], `${name}x0`); asm.num(pt.x[1], `${name}x1`)
        asm.num(pt.y[0], `${name}y0`); asm.num(pt.y[1], `${name}y1`)
      }
      g2(vk.gamma, `${at(1)}Q`)
      g2(vk.delta, `${at(2)}Q`)

      apply(asm, loop, p, loopIn)

      // B ∈ G2, against the [|x|]B the loop just finished computing. γ and δ
      // are constants of the key and were checked when the coin was built, so
      // their running points are not needed.
      if (SUB) apply(asm, points.inG2, p, ['_sBx0', '_sBx1', '_sBy0', '_sBy1', ...T0], [])
      for (const j of SUB ? [1, 2] : [0, 1, 2]) for (const s of ['Tx0', 'Tx1', 'Ty0', 'Ty1']) asm.discard(`r${at(j)}${s}`)

      for (const name of twelve('r')) asm.relabel(name, name.replace(/^r/, 'f'))
      apply(asm, pairing.finalExp, p, [...twelve('f'), ...expWit], twelve('r'))
      for (const name of twelve('r')) {
        asm.roll(name)
        asm.num(want[name], '_want')
        asm.numEqualVerify()
      }
      asm.discard('_pn')
    },
    notes: [
      SUB
        ? 'A and C are checked to be in G1 and B in G2 — curve equation and subgroup both — so the pairing is the bilinear map Groth16\'s soundness is about'
        : 'BUILT WITHOUT SUBGROUP CHECKS: A, B and C are checked against their curves only, which is less than Groth16 requires — for measurement',
      'B\'s subgroup check reuses the [|x|]B its own Miller loop computes; it costs a comparison, not a ladder',
      'γ, δ and L are pushed constants, not inputs — a spender who could choose them would not need a proof',
      'the verifying key is checked for subgroup membership once, when the coin is built',
      'the public inputs are fixed when the coin is locked; a verifier taking them at spend time needs ℓ on-chain scalar multiplications on G1',
      `${witnesses.length} witnessed numbers, every one bounded into [0, p) and checked`
    ],
    cases: opts.cases || []
  })
}

/**
 * A synthetic verifying key and a proof that satisfies it.
 *
 * Built from the group law, not from a circuit: e(aG₁, bG₂) = e(G₁, G₂)^(ab),
 * so the whole equation collapses to one identity among scalars,
 * a·b = αβ + lγ + cδ (mod r). Choose every scalar but one and solve for the
 * last. What that establishes is that the VERIFIER is right. Whether a proof
 * came from a circuit is Groth16's soundness and is not what is under test.
 */
function fixture (publicInputs = [3n, 5n]) {
  const R = bls.R
  const invR = (a) => {
    let r = 1n; let b = ((a % R) + R) % R; let e = R - 2n
    while (e > 0n) { if (e & 1n) r = r * b % R; b = b * b % R; e >>= 1n }
    return r
  }
  const k = { alpha: 0x2ecdba1cd7a0f9d2n, beta: 0x51a8f0c3d9b26e74n, gamma: 0x1f0538cd2b9e647n, delta: 0xcafebabedeadbeefn }
  const ic = [0x11111111n, 0x22222222n, 0x33333333n].slice(0, publicInputs.length + 1)
  const vk = {
    alpha: bls.g1mul(k.alpha),
    beta: bls.g2mul(k.beta),
    gamma: bls.g2mul(k.gamma),
    delta: bls.g2mul(k.delta),
    IC: ic.map((v) => bls.g1mul(v))
  }
  const l = publicInputs.reduce((s, x, i) => (s + x * ic[i + 1]) % R, ic[0])
  const c = 0xfedcba0987654321n
  const a = 0x777777777777777n
  const b = (k.alpha * k.beta + l * k.gamma + c * k.delta) % R * invR(a) % R
  const A = bls.g1mul(a); const B = bls.g2mul(b); const C = bls.g1mul(c)
  return {
    vk,
    publicInputs,
    scalars: { ...k, l, c, a, b },
    proof: { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
  }
}

module.exports = { verifier, combine, fixture, checkKey }
