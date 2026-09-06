'use strict'

const { defineModule, apply } = require('../module')
const bls = require('../bls12381')
const pairing = require('./pairing')
const txmod = require('./tx')
const points = require('./points')
const g16 = require('./groth16')
const fp6 = require('./fp6')

// A GROTH16 VERIFIER ACROSS THREE INPUTS OF ONE TRANSACTION.
//
// The verifier is 1,241,011 bytes and the script-size policy is 500,000. Its
// three pairings share one Miller accumulator, and even so that loop alone is
// 705,838 — so a two-way cut is not enough and the loop itself has to be cut.
//
//     input 0   rounds 1–31 of three loops     384,240 B lock, 395,669 unlock
//     input 1   rounds 32–63, resuming         372,456 B lock, 383,888 unlock
//     input 2   the final exponentiation       476,147 B lock, 481,994 unlock
//
// Round 31 is not a seam in the mathematics. It is where the halves are each
// small enough, and what makes an arbitrary cut legal is that the state there
// is small. tools/groth16-split.js proves all three stages against the
// interpreter and builds the transaction; test.js checks on every run that no
// stage takes in the state it is supposed to compute.
//
// The state between rounds 31 and 32 is exactly the accumulator and one running
// point per pair — twenty-four field elements — because that is all a Miller
// loop carries. `pairing.miller` takes a `first` bit and a `resume` flag, and
// with the defaults it emits byte for byte what it did before segments existed,
// which the loops already on chain depend on.
//
// HOW THREE INPUTS AGREE, when the earlier construction only had to make two.
//
// Every input of a spend sees the same `hashOutputs`, so there is ONE data
// output and it has to carry everything any stage needs the others to have
// used: the proof, the state after round 31, and the state after round 63.
//
//     blob = A ‖ B ‖ C ‖ S₁ ‖ S₂          44 field elements, 2,156 bytes
//
// Each stage computes its own part and WITNESSES the rest:
//
//     input 0   computes S₁,   witnesses S₂
//     input 1   computes S₂,   witnesses S₁
//     input 2   witnesses both, and exponentiates S₂
//
// All three build the blob and require it to be the committed output, so the
// witnessed halves are the computed ones. Writing it out: input 0 establishes
// S₁ = M₁(A,B,C), input 1 that S₂ = M₂(A,B,C,S₁), input 2 that F(S₂) = e(α,β),
// and the commitment makes the S₁ and S₂ in those three statements the same
// values. The composition is the transaction.
//
// A spender who supplies a proof no stage rejects still has to supply an S₁ its
// own stage 1 computes, and there is only one such S₁.
//
// ONE PRACTICAL CONSEQUENCE OF THREE. About one OP_PUSH_TX preimage in fifty is
// canonical, so a pair lands in ~2,500 tries and a TRIPLE in ~123,000. The
// two-way construction ground `nSequence`; that stops being affordable here,
// because `nSequence` also sits inside `hashSequence` at offset 36, so moving
// it dirties every SHA-256 block of a ~400 KB preimage. `nLockTime` appears
// once, eight bytes from the end, which leaves every block but the last intact
// and lets each input's midstate be computed once and copied per attempt. See
// tools/groth16-split.js.

const P381 = bls.P
const CUT = 31
const COEFF = pairing.COEFF_BYTES
const G1c = require('../ec').bls12381G1

const twelve = (p) => [...['00', '01', '10', '11', '20', '21'].map((s) => `${p}A${s}`),
  ...['00', '01', '10', '11', '20', '21'].map((s) => `${p}B${s}`)]
const PROOF_NAMES = ['Ax', 'Ay', 'Bx0', 'Bx1', 'By0', 'By1', 'Cx', 'Cy']
const T_NAMES = [0, 1, 2].flatMap((j) => [`p${j}_Tx0`, `p${j}_Tx1`, `p${j}_Ty0`, `p${j}_Ty1`])
const S1_NAMES = [...twelve('f'), ...T_NAMES]
const S2_NAMES = twelve('g')
const BLOB_NAMES = [...PROOF_NAMES, ...S1_NAMES, ...S2_NAMES]
const BLOB_BYTES = BLOB_NAMES.length * COEFF

/** Numbers into one blob, in the order every stage agrees to write them. */
function emitBlob (asm, names, out) {
  names.forEach((name, i) => {
    asm.roll(name)
    asm.num2bin(COEFF, `_bb${i}`)
    if (i > 0) asm.cat('_acc')
  })
  asm.rename(out, 'bytes', BLOB_BYTES)
}
const serialise = (values) => Buffer.concat(BLOB_NAMES.map((name) => {
  const b = Buffer.alloc(COEFF)
  let v = values[name]
  for (let i = 0; i < COEFF; i++) { b[i] = Number(v & 0xffn); v >>= 8n }
  if (v !== 0n) throw new Error(`groth16split: ${name} does not fit in ${COEFF} bytes`)
  return b
}))

/** The three pairs, as the multi-pairing names them. */
function pairsFor (vk, L, proof) {
  return [
    { P: { x: proof.Ax, y: proof.Ay }, Q: { x: [proof.Bx0, proof.Bx1], y: [proof.By0, proof.By1] } },
    { P: G1c.neg(L), Q: vk.gamma },
    { P: { x: proof.Cx, y: G1c.mod(-proof.Cy) }, Q: vk.delta }
  ]
}

/** Everything the three stages agree on, computed once in JavaScript. */
function stateFor (vk, L, proof) {
  const list = pairsFor(vk, L, proof)
  const a = pairing.replay(list, CUT, P381)
  const b = pairing.replay(list, pairing.FULL, P381, { first: CUT + 1, f: a.f, T: a.T })
  const s2 = bls.X < 0n ? bls.f12conj(b.f) : b.f
  const values = { ...proof }
  twelve('f').forEach((name, i) => { values[name] = pairing.spread(a.f, 'f')[name] })
  a.T.forEach((t, j) => {
    values[`p${j}_Tx0`] = t.x[0]; values[`p${j}_Tx1`] = t.x[1]
    values[`p${j}_Ty0`] = t.y[0]; values[`p${j}_Ty1`] = t.y[1]
  })
  Object.assign(values, pairing.spread(s2, 'g'))
  return { values, list, wit1: a.witnesses, wit2: b.witnesses, s1f: a.f, s1T: a.T, s2 }
}

/** Put the verifying key's fixed points where the multi-pairing reads them. */
function pushConstants (asm, vk, L) {
  const negL = G1c.neg(L)
  asm.num(negL.x, 'p1_Px'); asm.num(negL.y, 'p1_Py')
  const g2 = (pt, name) => {
    asm.num(pt.x[0], `${name}x0`); asm.num(pt.x[1], `${name}x1`)
    asm.num(pt.y[0], `${name}y0`); asm.num(pt.y[1], `${name}y1`)
  }
  g2(vk.gamma, 'p1_Q')
  g2(vk.delta, 'p2_Q')
}

function verifier (vk, publicInputs, opts = {}) {
  const L = g16.combine(vk.IC, publicInputs)
  const expected = bls.pairing(vk.alpha, vk.beta)
  const want = pairing.spread(expected, 'r')
  const commit = txmod.commitData(BLOB_BYTES)

  const loop1 = pairing.miller(CUT, { pairs: 3, emitState: true })
  const loop2 = pairing.miller(pairing.FULL, { pairs: 3, first: CUT + 1, resume: true })
  const w1 = loop1.inputs.filter((i) => i.witness).map((i) => i.name)
  const w2 = loop2.inputs.filter((i) => i.witness).map((i) => i.name)
  const expWit = pairing.finalExp.inputs.filter((i) => i.witness).map((i) => i.name)

  /** The witness generator every stage shares: build the output, then grind. */
  const witnessFor = (which) => (ctx) => {
    const { tx, lockingScript, satoshis, spend = {} } = ctx
    const st = stateFor(vk, L, spend.proof)
    tx.outputs.length = 0
    tx.addOutput(txmod.dataOutput(BLOB_BYTES, serialise(st.values)))
    tx._outputAmount = undefined
    const g = txmod.PushTx.grind(tx, 0, lockingScript, satoshis, { field: 'sequence' })
    const out = { preimage: g.preimage, ...st.values }
    const tape = which === 1 ? st.wit1 : which === 2 ? st.wit2 : []
    tape.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
    if (which === 3) Object.assign(out, pairing.finalExp.hint(pairing.spread(st.s2, 'f'), { n: P381, nn: P381 }))
    return out
  }

  const shell = (name, doc, inputs, body, which) => defineModule({
    name,
    doc,
    inputs: [{ name: 'preimage', kind: 'bytes', witness: true }, ...inputs],
    outputs: [],
    contextual: true,
    maxWitnessAttacks: opts.maxWitnessAttacks || 2,
    witnessFor: witnessFor(which),
    hint: () => ({}),
    model: () => ({}),
    attacks: (honest, params, nm) => (nm === 'preimage'
      ? txmod.preimageAttacks(honest, params, nm)
      : require('../testkit').defaultAttacks(honest[nm], { n: P381 })),
    requires: () => {
      const r = { range: { lo: 0n, hi: P381 } }
      const out = {}
      for (const i of inputs) out[typeof i === 'string' ? i : i.name] = r
      return out
    },
    emit: (asm, params) => {
      asm.num(P381, '_pn')
      body(asm, { n: '_pn', nn: P381 })
      asm.discard('_pn')
    },
    // Every stage needs the SAME transaction shape, so every case carries the
    // proof and lets witnessFor build the output all three commit to.
    cases: (opts.cases && opts.cases[which]) || (opts.proof
      ? [{ name: `stage ${which}, on a real proof`, spend: { proof: opts.proof }, params: {} }]
      : [])
  })

  const stage1 = shell('groth16.stage1',
    'rounds 1–31 of three Miller loops, and publish what they left',
    [...PROOF_NAMES, ...S2_NAMES.map((n) => ({ name: n, witness: true })),
      ...w1.map((n) => ({ name: n, witness: true }))],
    (asm, p) => {
      // The proof is three points, and a pair of field elements is not a point.
      for (const [x, y] of [['Ax', 'Ay'], ['Cx', 'Cy']]) {
        asm.pick(x, '_cx'); asm.pick(y, '_cy')
        apply(asm, points.onCurveG1, { n: '_pn', nn: P381 }, ['_cx', '_cy'], [])
      }
      for (const nm of ['Bx0', 'Bx1', 'By0', 'By1']) asm.pick(nm, '_q' + nm)
      apply(asm, points.onCurveG2, { n: '_pn', nn: P381 }, ['_qBx0', '_qBx1', '_qBy0', '_qBy1'], [])

      for (const nm of PROOF_NAMES) asm.pick(nm, '_keep' + nm)   // for the blob
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
      emitBlob(asm, BLOB_NAMES, 'data')
      apply(asm, commit, {}, ['preimage', 'data'], ['_p'])
      asm.drop()
    }, 1)

  const stage2 = shell('groth16.stage2',
    'rounds 32–63, resuming from what input 0 published',
    [...PROOF_NAMES.map((n) => ({ name: n, witness: true })),
      ...S1_NAMES.map((n) => ({ name: n, witness: true })),
      ...w2.map((n) => ({ name: n, witness: true }))],
    (asm, p) => {
      for (const nm of PROOF_NAMES) asm.pick(nm, '_keep' + nm)
      for (const nm of S1_NAMES) asm.pick(nm, '_keepS' + nm)
      asm.relabel('Ax', 'p0_Px'); asm.relabel('Ay', 'p0_Py')
      asm.relabel('Bx0', 'p0_Qx0'); asm.relabel('Bx1', 'p0_Qx1')
      asm.relabel('By0', 'p0_Qy0'); asm.relabel('By1', 'p0_Qy1')
      asm.relabel('Cx', 'p2_Px')
      asm.pick('_pn', '_p'); asm.roll('Cy'); asm.sub('_negCy')
      asm.pick('_pn', '_p2'); asm.mod('p2_Py')
      pushConstants(asm, vk, L)
      apply(asm, loop2, p, loop2.inputs.map((i) => i.name), S2_NAMES)
      for (const nm of PROOF_NAMES) asm.relabel('_keep' + nm, nm)
      for (const nm of S1_NAMES) asm.relabel('_keepS' + nm, nm)
      emitBlob(asm, BLOB_NAMES, 'data')
      apply(asm, commit, {}, ['preimage', 'data'], ['_p'])
      asm.drop()
    }, 2)

  const stage3 = shell('groth16.stage3',
    'the final exponentiation of what input 1 published, against e(α, β)',
    [...PROOF_NAMES.map((n) => ({ name: n, witness: true })),
      ...S1_NAMES.map((n) => ({ name: n, witness: true })),
      ...S2_NAMES.map((n) => ({ name: n, witness: true })),
      ...expWit.map((n) => ({ name: n, witness: true }))],
    (asm, p) => {
      for (const nm of S2_NAMES) asm.pick(nm, '_e' + nm)
      emitBlob(asm, BLOB_NAMES, 'data')
      apply(asm, commit, {}, ['preimage', 'data'], ['_p'])
      asm.drop()
      apply(asm, pairing.finalExp, p,
        [...S2_NAMES.map((n) => '_e' + n), ...expWit], twelve('r'))
      for (const nm of twelve('r')) {
        asm.roll(nm); asm.num(want[nm], '_want'); asm.numEqualVerify()
      }
    }, 3)

  return { stage1, stage2, stage3, blobBytes: BLOB_BYTES, blobNames: BLOB_NAMES, stateFor: (proof) => stateFor(vk, L, proof), serialise, L, expected, CUT }
}

module.exports = { verifier, CUT, BLOB_NAMES, BLOB_BYTES, S1_NAMES, S2_NAMES, PROOF_NAMES }
