'use strict'

const { defineModule, apply } = require('../module')
const bls = require('../bls12381')
const pairing = require('./pairing')
const points = require('./points')
const carry = require('./carry')
const txmod = require('./tx')
const g16 = require('./groth16')
const split = require('./groth16split')

// A GROTH16 VERIFIER AS A CHAIN OF TRANSACTIONS.
//
// groth16split.js cuts the verifier into three stages and spends them as three
// INPUTS of one transaction. That transaction is consensus-valid and was mined,
// but it could not travel: a node bounds how long it will spend validating work
// a peer sends it, and three 400 KB stages exceeded the budget. See §8.3.
//
// So the stages become three TRANSACTIONS, chained through the carrier coin of
// carry.js — the construction pairing.chainMiller/chainExp already put on chain
// for a single pairing:
//
//     tx₁   stage 1                          → carrier(∅,  proof‖S1)
//     tx₂   stage 2 + carrier(∅, proof‖S1)   → carrier(proof‖S1, S2)
//     tx₃   stage 3 + carrier(proof‖S1, S2)  → carrier(S2, e(α, β))
//
// WHAT CHANGES, AND IT IS NOT COSMETIC. In the split, all three stages write the
// SAME output, and sibling-binding forces the spend to consume exactly its three
// siblings. That is what made stage 1's *witnessed* S2 equal stage 2's *computed*
// S2: the two stages had to agree on one blob or the transaction died.
//
// Across transactions there is no such shared output and no sibling to bind. If a
// link merely witnessed its predecessor's state, a spender could hand it any
// state at all, and the chain would prove nothing. So every link after the first
// takes the state as BYTES and SPLITS IT OUT of what the carrier beside it is
// holding — the carrier pins `prev`, the link recomputes from it, and nothing a
// spender chooses enters between. Stage 2 no longer witnesses the proof or S1;
// stage 3 no longer witnesses S2. They are read from the chain or they are not
// used.
//
// THE WIDTH. Link 2 needs the proof and S1 (32 field elements); link 3 needs only
// S2 (12). A carrier's body is a constant of its width, so one width serves the
// whole chain: 32 elements, 1,568 bytes, with link 2's output padded. Carrying
// the full 44-element blob would cost stage 3 — the stage with the least policy
// headroom — an extra 1,176 bytes in its unlocking script for state nothing reads.
//
// WHAT IT STILL DOES NOT ESTABLISH. A stage cannot check that the carrier beside
// it came from this chain rather than another execution of the same verifier: an
// outpoint does not name a script, and the carrier's txid did not exist when the
// stage coin was written. Splicing one run's link into another's produces a valid
// TRANSACTION that is a link of a different CHAIN, and only a reader walking the
// chain can tell which. tools/groth16-chain.js attacks exactly that and says so.

const P381 = bls.P
const COEFF = pairing.COEFF_BYTES
const CUT = split.CUT
const { PROOF_NAMES, S1_NAMES, S2_NAMES } = split

const twelve = (p) => [...['00', '01', '10', '11', '20', '21'].map((s) => `${p}A${s}`),
  ...['00', '01', '10', '11', '20', '21'].map((s) => `${p}B${s}`)]

/** What link 1 hands link 2: the proof it checked, and where the loops stopped. */
const LINK1_NAMES = [...PROOF_NAMES, ...S1_NAMES]
/** The carrier's field width, fixed for the chain by its widest link. */
const STATE_BYTES = LINK1_NAMES.length * COEFF
const S2_BYTES = S2_NAMES.length * COEFF

/** Field elements into bytes, in the order the links agree to read them. */
function pack (names, values) {
  return Buffer.concat(names.map((name) => {
    const b = Buffer.alloc(COEFF)
    let v = values[name]
    if (v === undefined) throw new Error(`groth16chain: no value for ${name}`)
    for (let i = 0; i < COEFF; i++) { b[i] = Number(v & 0xffn); v >>= 8n }
    if (v !== 0n) throw new Error(`groth16chain: ${name} does not fit in ${COEFF} bytes`)
    return b
  }))
}
const padState = (buf) => Buffer.concat([buf, Buffer.alloc(STATE_BYTES - buf.length)])

/** Numbers into one state field — the inverse of emitUnpack. */
function emitPack (asm, names, out) {
  names.forEach((name, i) => {
    asm.roll(name)
    asm.num2bin(COEFF, `_pk${i}`)
    if (i > 0) asm.cat('_acc')
  })
  asm.rename(out, 'bytes', names.length * COEFF)
}

/**
 * One state field back into numbers, reading the bytes on top of the stack.
 *
 * This is the load-bearing difference from the split: these values are not
 * witnesses a spender chose, they are the carrier's own bytes taken apart. Each
 * comes off OP_BIN2NUM without a range fact attached, so any module that needs
 * them reduced emits its own bound — which is the behaviour wanted here, since
 * a 49-byte field can hold a number larger than the prime.
 */
function emitUnpack (asm, names) {
  for (let i = 0; i < names.length - 1; i++) {
    asm.splitAt(COEFF, names[i], '_rest')
    asm.op('OP_SWAP', 2, [{ name: '_rest2', kind: 'bytes' }, { name: names[i], kind: 'bytes' }])
    asm.bin2num(names[i])
    asm.op('OP_SWAP', 2, [{ name: names[i], kind: 'num' }, { name: '_rest', kind: 'bytes' }])
  }
  asm.bin2num(names[names.length - 1])
}

/** Put the verifying key's fixed points where the multi-pairing reads them. */
function pushConstants (asm, vk, L) {
  const G1c = require('../ec').bls12381G1
  const negL = G1c.neg(L)
  asm.num(negL.x, 'p1_Px'); asm.num(negL.y, 'p1_Py')
  const g2 = (pt, name) => {
    asm.num(pt.x[0], `${name}x0`); asm.num(pt.x[1], `${name}x1`)
    asm.num(pt.y[0], `${name}y0`); asm.num(pt.y[1], `${name}y1`)
  }
  g2(vk.gamma, 'p1_Q')
  g2(vk.delta, 'p2_Q')
}

/** Everything the three links agree on, computed once in JavaScript. */
function stateFor (vk, L, proof) {
  const G1c = require('../ec').bls12381G1
  const list = [
    { P: { x: proof.Ax, y: proof.Ay }, Q: { x: [proof.Bx0, proof.Bx1], y: [proof.By0, proof.By1] } },
    { P: G1c.neg(L), Q: vk.gamma },
    { P: { x: proof.Cx, y: G1c.mod(-proof.Cy) }, Q: vk.delta }
  ]
  const a = pairing.replay(list, CUT, P381)
  const b = pairing.replay(list, pairing.FULL, P381, { first: CUT + 1, f: a.f, T: a.T })
  const s2 = bls.X < 0n ? bls.f12conj(b.f) : b.f
  const values = { ...proof }
  twelve('f').forEach((name) => { values[name] = pairing.spread(a.f, 'f')[name] })
  a.T.forEach((t, j) => {
    values[`p${j}_Tx0`] = t.x[0]; values[`p${j}_Tx1`] = t.x[1]
    values[`p${j}_Ty0`] = t.y[0]; values[`p${j}_Ty1`] = t.y[1]
  })
  Object.assign(values, pairing.spread(s2, 'g'))
  return { values, wit1: a.witnesses, wit2: b.witnesses, s2 }
}

/**
 * The three links of a chained Groth16 verifier, for one verifying key and one
 * statement. The public inputs are compiled in, exactly as in the split: a
 * different statement is a different set of coins.
 */
function chained (vk, publicInputs, opts = {}) {
  g16.checkKey(vk)
  const L = g16.combine(vk.IC, publicInputs)
  const expected = bls.pairing(vk.alpha, vk.beta)
  const want = pairing.spread(expected, 'r')
  const RESULT = padState(pack(twelve('r'), want))

  const SUB = opts.subgroup !== false
  const subA = SUB ? points.g1WitnessNames('g1A') : []
  const subC = SUB ? points.g1WitnessNames('g1C') : []

  const loop1 = pairing.miller(CUT, { pairs: 3, emitState: true })
  const loop2 = pairing.miller(pairing.FULL, { pairs: 3, first: CUT + 1, resume: true, emitState: SUB })
  const w1 = loop1.inputs.filter((i) => i.witness).map((i) => i.name)
  const w2 = loop2.inputs.filter((i) => i.witness).map((i) => i.name)
  const expWit = pairing.finalExp.inputs.filter((i) => i.witness).map((i) => i.name)
  const commit = carry.commitCarry(STATE_BYTES, opts.carrier || {})

  const state1 = (proof) => pack(LINK1_NAMES, stateFor(vk, L, proof).values)
  const state2 = (proof) => padState(pack(S2_NAMES, stateFor(vk, L, proof).values))

  /** Every link pays a carrier, and grinding it is the same work each time. */
  const payCarrier = (ctx, prev, cur) => commit.witnessFor({
    tx: ctx.tx,
    lockingScript: ctx.lockingScript,
    satoshis: ctx.satoshis,
    inputIndex: ctx.inputIndex || 0,
    spend: { prev, cur }
  })

  const stateAttack = (honest, name) => {
    const b = Buffer.from(honest[name]); b[0] ^= 0x01
    return [{ label: 'a state the carrier beside it is not holding', value: b }]
  }

  // ── link 1 ────────────────────────────────────────────────────────────────
  const link1 = defineModule({
    name: 'groth16.chain1',
    doc: SUB
      ? 'A and C in G1, rounds 1–31 of three Miller loops, and pay a carrier holding the proof and where they stopped'
      : 'rounds 1–31 of three Miller loops, and pay a carrier holding the proof and where they stopped',
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      ...PROOF_NAMES,
      ...w1.map((n) => ({ name: n, witness: true })),
      // the ladders' inverses last, C's under A's, so each check finds its own
      ...[...subC, ...subA].map((n) => ({ name: n, witness: true }))
    ],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: (ctx) => {
      const st = stateFor(vk, L, ctx.spend.proof)
      const w = payCarrier(ctx, Buffer.alloc(STATE_BYTES), pack(LINK1_NAMES, st.values))
      const out = { preimage: w.preimage }
      for (const nm of PROOF_NAMES) out[nm] = st.values[nm]
      st.wit1.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      if (SUB) Object.assign(out, split.subgroupWitnesses(ctx.spend.proof))
      return out
    },
    hint: () => ({}),
    model: () => ({}),
    attacks: (honest, params, nm) => (nm === 'preimage'
      ? txmod.preimageAttacks(honest, params, nm)
      : require('../testkit').defaultAttacks(honest[nm], { n: P381 })),
    // The proof coordinates are serialised into the carrier as BYTES, where x
    // and x + p are different states, so they are bounded at the door.
    requires: () => Object.fromEntries(PROOF_NAMES.map((n) => [n, { range: { lo: 0n, hi: P381 } }])),
    emit: (asm, params) => {
      if (SUB) {
        // Before the prime goes on the stack, while the inverses are still on top.
        asm.pick('Ax', '_gAx'); asm.pick('Ay', '_gAy')
        apply(asm, points.inG1, { n: P381 }, [...subA, '_gAx', '_gAy'], [])
        asm.pick('Cx', '_gCx'); asm.pick('Cy', '_gCy')
        apply(asm, points.inG1, { n: P381 }, [...subC, '_gCx', '_gCy'], [])
      }
      asm.num(P381, '_pn')
      const p = { n: '_pn', nn: P381 }
      if (!SUB) {
        for (const [x, y] of [['Ax', 'Ay'], ['Cx', 'Cy']]) {
          asm.pick(x, '_cx'); asm.pick(y, '_cy')
          apply(asm, points.onCurveG1, p, ['_cx', '_cy'], [])
        }
        for (const nm of ['Bx0', 'Bx1', 'By0', 'By1']) asm.pick(nm, '_q' + nm)
        apply(asm, points.onCurveG2, p, ['_qBx0', '_qBx1', '_qBy0', '_qBy1'], [])
      }
      for (const nm of PROOF_NAMES) asm.pick(nm, '_keep' + nm)
      asm.relabel('Ax', 'p0_Px'); asm.relabel('Ay', 'p0_Py')
      asm.relabel('Bx0', 'p0_Qx0'); asm.relabel('Bx1', 'p0_Qx1')
      asm.relabel('By0', 'p0_Qy0'); asm.relabel('By1', 'p0_Qy1')
      asm.relabel('Cx', 'p2_Px')
      asm.pick('_pn', '_p'); asm.roll('Cy'); asm.sub('_negCy')
      asm.pick('_pn', '_p2'); asm.mod('p2_Py')
      pushConstants(asm, vk, L)
      apply(asm, loop1, p, loop1.inputs.map((i) => i.name), loop1.outputs.map((o) => o.name))
      for (const [i, nm] of S1_NAMES.entries()) asm.relabel(loop1.outputs[i].name, nm)
      for (const nm of PROOF_NAMES) asm.relabel('_keep' + nm, nm)
      emitPack(asm, LINK1_NAMES, 'cur')
      asm.data(Buffer.alloc(STATE_BYTES), 'prev')
      asm.roll('cur')
      apply(asm, commit, {}, ['preimage', 'prev', 'cur'], [])
      asm.discard('_pn')
    },
    notes: [
      'the first link has no predecessor, so the carrier it pays holds an empty prev',
      'the proof is carried forward because link 2 needs it, and because it is what link 1 checked'
    ],
    cases: (opts.cases && opts.cases[1]) || (opts.proof
      ? [{ name: 'link 1, on a real proof', spend: { proof: opts.proof }, params: {} }]
      : [])
  })

  // ── link 2 ────────────────────────────────────────────────────────────────
  const link2 = defineModule({
    name: 'groth16.chain2',
    doc: SUB
      ? 'rounds 32–63, resuming from the carrier, and B in G2'
      : 'rounds 32–63, resuming from the carrier',
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'prev', kind: 'bytes', width: STATE_BYTES, witness: true },
      ...w2.map((n) => ({ name: n, witness: true }))
    ],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: (ctx) => {
      const st = stateFor(vk, L, ctx.spend.proof)
      const prev = pack(LINK1_NAMES, st.values)
      const w = payCarrier(ctx, prev, padState(pack(S2_NAMES, st.values)))
      const out = { preimage: w.preimage, prev }
      st.wit2.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
      return out
    },
    hint: () => ({}),
    model: () => ({}),
    attacks: (honest, params, nm) => {
      if (nm === 'preimage') return txmod.preimageAttacks(honest, params, nm)
      if (nm === 'prev') return stateAttack(honest, nm)
      return require('../testkit').defaultAttacks(honest[nm], { n: P381 })
    },
    emit: (asm, params) => {
      // The carrier's cur becomes this link's prev, so the whole field survives
      // for the commitment while a COPY is taken apart into the values.
      asm.roll('prev'); asm.rename('_prev')
      asm.pick('_prev', '_split')
      emitUnpack(asm, LINK1_NAMES)

      asm.num(P381, '_pn')
      const p = { n: '_pn', nn: P381 }
      if (SUB) for (const nm of ['Bx0', 'Bx1', 'By0', 'By1']) asm.pick(nm, '_sub' + nm)
      asm.relabel('Ax', 'p0_Px'); asm.relabel('Ay', 'p0_Py')
      asm.relabel('Bx0', 'p0_Qx0'); asm.relabel('Bx1', 'p0_Qx1')
      asm.relabel('By0', 'p0_Qy0'); asm.relabel('By1', 'p0_Qy1')
      asm.relabel('Cx', 'p2_Px')
      asm.pick('_pn', '_p'); asm.roll('Cy'); asm.sub('_negCy')
      asm.pick('_pn', '_p2'); asm.mod('p2_Py')
      pushConstants(asm, vk, L)
      if (SUB) {
        apply(asm, loop2, p, loop2.inputs.map((i) => i.name))
        apply(asm, points.inG2, p, ['_subBx0', '_subBx1', '_subBy0', '_subBy1',
          ...['Tx0', 'Tx1', 'Ty0', 'Ty1'].map((s) => `rp0_${s}`)], [])
        for (const j of [1, 2]) for (const s of ['Tx0', 'Tx1', 'Ty0', 'Ty1']) asm.discard(`rp${j}_${s}`)
        twelve('r').forEach((nm, i) => asm.relabel(nm, S2_NAMES[i]))
      } else {
        apply(asm, loop2, p, loop2.inputs.map((i) => i.name), S2_NAMES)
      }
      emitPack(asm, S2_NAMES, '_s2')
      asm.data(Buffer.alloc(STATE_BYTES - S2_BYTES), '_pad')
      asm.cat('cur')
      asm.rename('cur', 'bytes', STATE_BYTES)
      apply(asm, commit, {}, ['preimage', '_prev', 'cur'], [])
      asm.discard('_pn')
    },
    notes: [
      'the proof and S1 are SPLIT out of the carrier, not witnessed — nothing a spender chooses enters this link',
      'B is checked against pair 0\'s running point, which this link\'s own loop finishes as [|x|]B'
    ],
    cases: (opts.cases && opts.cases[2]) || (opts.proof
      ? [{ name: 'link 2, resuming a real chain', spend: { proof: opts.proof }, params: {} }]
      : [])
  })

  // ── link 3 ────────────────────────────────────────────────────────────────
  const link3 = defineModule({
    name: 'groth16.chain3',
    doc: 'the final exponentiation of what the carrier holds, against e(α, β)',
    inputs: [
      { name: 'preimage', kind: 'bytes', witness: true },
      { name: 'prev', kind: 'bytes', width: STATE_BYTES, witness: true },
      ...expWit.map((n) => ({ name: n, witness: true }))
    ],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: (ctx) => {
      const st = stateFor(vk, L, ctx.spend.proof)
      const prev = padState(pack(S2_NAMES, st.values))
      const w = payCarrier(ctx, prev, RESULT)
      return {
        preimage: w.preimage,
        prev,
        ...pairing.finalExp.hint(pairing.spread(st.s2, 'f'), { n: P381, nn: P381 })
      }
    },
    hint: () => ({}),
    model: () => ({}),
    attacks: (honest, params, nm) => {
      if (nm === 'preimage') return txmod.preimageAttacks(honest, params, nm)
      if (nm === 'prev') return stateAttack(honest, nm)
      return require('../testkit').defaultAttacks(honest[nm], { n: P381 })
    },
    emit: (asm, params) => {
      asm.roll('prev'); asm.rename('_prev')
      asm.pick('_prev', '_split')
      // Only the first twelve elements are S2; the rest is the padding link 2
      // wrote, which nothing reads.
      asm.splitAt(S2_BYTES, '_s2b', '_padIn')
      asm.discard('_padIn')
      asm.roll('_s2b')
      emitUnpack(asm, S2_NAMES)

      asm.num(P381, '_pn')
      const p = { n: '_pn', nn: P381 }
      apply(asm, pairing.finalExp, p, [...S2_NAMES, ...expWit], twelve('r'))
      for (const nm of twelve('r')) {
        asm.roll(nm); asm.num(want[nm], '_want'); asm.numEqualVerify()
      }
      asm.data(RESULT, 'cur')
      apply(asm, commit, {}, ['preimage', '_prev', 'cur'], [])
      asm.discard('_pn')
    },
    notes: [
      'S2 is split out of the carrier, so the value exponentiated is the one link 2 computed',
      'the carrier it pays holds e(α, β), which makes the last coin a receipt anyone can read'
    ],
    cases: (opts.cases && opts.cases[3]) || (opts.proof
      ? [{ name: 'link 3, finishing a real chain', spend: { proof: opts.proof }, params: {} }]
      : [])
  })

  return {
    link1,
    link2,
    link3,
    stateWidth: STATE_BYTES,
    state1,
    state2,
    result: RESULT,
    stateFor: (proof) => stateFor(vk, L, proof),
    L,
    expected,
    CUT,
    subgroup: SUB
  }
}

module.exports = { chained, STATE_BYTES, LINK1_NAMES, pack, padState, twelve }
