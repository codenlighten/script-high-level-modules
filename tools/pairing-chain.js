'use strict'

// A PAIRING ACROSS TWO TRANSACTIONS, NOT TWO INPUTS.
//
//   node tools/pairing-chain.js
//
// tools/pairing-split.js puts both stages of a pairing in one transaction. That
// relayed; the three-stage Groth16 version of the same idea did not, and reached
// a block only because a mining pool took it by hand. The limit it met bounds the
// TRANSACTION — how long a node will spend validating work a peer sent it — so
// this puts one stage in each transaction and chains them through a carrier coin.
//
//     funding   two stage coins, and nothing else
//     tx₁       the Miller loop           → carrier(∅, f)
//     tx₂       the final exponentiation
//               + carrier(∅, f)           → carrier(f, e(P, Q))
//
// Four questions, in order:
//
//   1. does each link verify?          every input, through the interpreter
//   2. does the binding bite?          tx₂ against a carrier holding another f
//   3. what would a node be asked?     each transaction timed, against the two
//                                      whose fate on mainnet is known
//   4. what must a READER check?       the part no script can do for itself

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { policyFlags } = require('../src/run')
const { pushNum, pushData } = require('../src/num')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const carry = require('../src/modules/carry')

const n = (x) => x.toLocaleString('en-US')
const P = bls.P
const params = { n: P, nn: P }
const W = pairing.STATE_BYTES

const pts = { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] }
const rawF = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P).f
const f = bls.X < 0n ? bls.f12conj(rawF) : rawF
const expected = bls.pairing(bls.G1, bls.G2)
const fBytes = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')
const eBytes = pairing.serialiseF12(pairing.spread(expected, 'r'), 'r')

const millerStage = pairing.chainMiller({ cases: [{ name: 'x', inputs: pts, spend: pts, params }] })
const expStage = pairing.chainExp(expected, { cases: [{ name: 'x', spend: { f }, params }] })

/** A predicate as a locking script: emit it, then leave TRUE. */
function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return asm.script()
}
const unlockFor = (m, values) => {
  const u = new bsv.Script()
  for (const i of m.inputs) {
    const v = values[i.name]
    if (v === undefined) throw new Error(`${m.name}: no value for ${i.name}`)
    u.add(i.kind === 'bytes' ? pushData(v) : pushNum(v))
  }
  return u
}

const lockMiller = coin(millerStage)
const lockExp = coin(expStage)
const FUNDING = 'c1'.repeat(32)

/** Time every input of a transaction the way a node would have to. */
function verifyAndTime (tx, coins) {
  let ms = 0
  const verdicts = coins.map((c, i) => {
    const interp = new bsv.Script.Interpreter()
    const t0 = process.hrtime.bigint()
    let ok = false
    try { ok = interp.verify(tx.inputs[i].script, c.lock, tx, i, policyFlags(), new bsv.crypto.BN(c.satoshis)) } catch (e) { return { ok: false, err: e.message } }
    ms += Number(process.hrtime.bigint() - t0) / 1e6
    return { ok, err: interp.errstr }
  })
  return { verdicts, ms }
}

// ── tx₁: the Miller loop alone ──────────────────────────────────────────────
const CARRIER = 1
const tx1 = new bsv.Transaction()
tx1.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(FUNDING, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockMiller, 60000)
// The stage's own inputs are the two points; the witness generator supplies the
// loop's inverses and the preimage it ground.
const w1 = millerStage.witnessFor({ tx: tx1, lockingScript: lockMiller, satoshis: 60000, spend: pts, inputIndex: 0 })
tx1.inputs[0].setScript(unlockFor(millerStage, { ...pts, ...w1 }))
const r1 = verifyAndTime(tx1, [{ lock: lockMiller, satoshis: 60000 }])

// ── tx₂: the exponentiation, beside the carrier tx₁ made ────────────────────
//
// The carrier is an output of tx₁, so its script and its txid are known only now
// — which is exactly what no stage coin could have committed to in advance.
const carrier1 = carry.carrierScript(W, { prev: Buffer.alloc(W), cur: fBytes })
if (!tx1.outputs[0].script.toBuffer().equals(carrier1.toBuffer())) throw new Error('tx₁ did not pay the carrier this expects')

function buildTx2 (carrierState, fUsed) {
  const carrierIn = carry.carrierScript(W, carrierState)
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(FUNDING, 'hex'), outputIndex: 1, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockExp, 70000)
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(tx1.hash, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), carrierIn, CARRIER)
  // Both inputs build the same output, from different halves of what they know.
  tx.addOutput(new bsv.Transaction.Output({ script: carry.carrierScript(W, { prev: carrierState.cur, cur: eBytes }), satoshis: CARRIER }))
  tx._outputAmount = undefined

  // Two preimages, ground together: hashSequence covers both inputs.
  const H = require('@smartledger/bsv/lib/covenant/helpers')
  const txmod = require('../src/modules/tx')
  const leU32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b }
  const baseA = Buffer.from(H.rawPreimage(tx, 0, lockExp, 70000, txmod.SIGHASH_ALL_FORKID))
  const baseB = Buffer.from(H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID))
  let found = null
  for (let k = 0; k < 500000 && !found; k++) {
    const s0 = 0xfffffffe - k
    const hs = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(0xfffffffe)]))
    hs.copy(baseA, 36); leU32(s0).copy(baseA, baseA.length - 44)
    if (!txmod.PushTx.sFromPreimage(baseA)) continue
    hs.copy(baseB, 36); leU32(0xfffffffe).copy(baseB, baseB.length - 44)
    if (txmod.PushTx.sFromPreimage(baseB)) { tx.inputs[0].sequenceNumber = s0; found = k }
  }
  if (found === null) throw new Error('the joint grind found nothing')
  const preA = H.rawPreimage(tx, 0, lockExp, 70000, txmod.SIGHASH_ALL_FORKID)
  const preB = H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID)

  const stageValues = { preimage: preA, data: fUsed, ...pairing.finalExp.hint(pairing.spread(f, 'f'), params) }
  tx.inputs[0].setScript(unlockFor(expStage, stageValues))
  tx.inputs[1].setScript(new bsv.Script().add(pushData(preB)).add(pushData(eBytes)))
  return { tx, carrierIn }
}

const honest = buildTx2({ prev: Buffer.alloc(W), cur: fBytes }, fBytes)
const r2 = verifyAndTime(honest.tx, [{ lock: lockExp, satoshis: 70000 }, { lock: honest.carrierIn, satoshis: CARRIER }])

console.log('\n  a pairing across two transactions\n')
console.log(`    tx₁  pairing.chainMiller   ${n(lockMiller.toBuffer().length).padStart(9)} B lock  ${n(tx1.inputs[0].script.toBuffer().length).padStart(9)} B unlock  ${r1.verdicts[0].ok ? 'ACCEPTED' : 'REFUSED — ' + r1.verdicts[0].err}`)
console.log(`         carrier it pays       ${n(carrier1.toBuffer().length).padStart(9)} B — an empty prev, and f as its cur`)
console.log(`    tx₂  pairing.chainExp      ${n(lockExp.toBuffer().length).padStart(9)} B lock  ${n(honest.tx.inputs[0].script.toBuffer().length).padStart(9)} B unlock  ${r2.verdicts[0].ok ? 'ACCEPTED' : 'REFUSED — ' + r2.verdicts[0].err}`)
console.log(`         the carrier, spent    ${n(honest.carrierIn.toBuffer().length).padStart(9)} B lock  ${n(honest.tx.inputs[1].script.toBuffer().length).padStart(9)} B unlock  ${r2.verdicts[1].ok ? 'ACCEPTED' : 'REFUSED — ' + r2.verdicts[1].err}`)
if (r1.verdicts.concat(r2.verdicts).some((v) => !v.ok)) process.exit(1)

// ── 2. does the binding bite? ───────────────────────────────────────────────
//
// Hand tx₂ a carrier holding a different f, with the stage's own data matching
// that carrier. Both halves are internally consistent; what must refuse them is
// the carrier's insistence that the successor's prev is ITS cur.
{
  const otherF = Buffer.from(fBytes); otherF[0] ^= 0x01
  let refused = false
  let why = ''
  try {
    const bad = buildTx2({ prev: Buffer.alloc(W), cur: otherF }, otherF)
    const rb = verifyAndTime(bad.tx, [{ lock: lockExp, satoshis: 70000 }, { lock: bad.carrierIn, satoshis: CARRIER }])
    refused = rb.verdicts.some((v) => !v.ok)
    why = rb.verdicts.map((v) => v.err).filter(Boolean)[0] || ''
  } catch (e) { refused = true; why = e.message }
  console.log(`\n    a carrier holding another f      ${refused ? 'REFUSED — ' + String(why).slice(0, 48) : 'ACCEPTED — the link is not bound'}`)
  if (!refused) process.exit(1)
}

// ── 3. what each transaction asks of a node ─────────────────────────────────
console.log('\n  what a node is asked to validate\n')
const rows = [
  ['tx₁, the Miller loop', tx1.toBuffer().length, r1.ms],
  ['tx₂, the exponentiation and the carrier', honest.tx.toBuffer().length, r2.ms]
]
for (const [what, bytes, ms] of rows) console.log(`    ${what.padEnd(40)} ${n(bytes).padStart(9)} B  ${ms.toFixed(0).padStart(6)} ms`)
console.log(`    ${'—'.padEnd(40)}`)
console.log(`    ${'the two-input spend that relayed'.padEnd(40)} ${n(830928).padStart(9)} B  ${'2,749'.padStart(6)} ms   mainnet`)
console.log(`    ${'the three-input spend relay refused'.padEnd(40)} ${n(1291329).padStart(9)} B  ${'4,219'.padStart(6)} ms   by hand`)
const worst = Math.max(r1.ms, r2.ms)
console.log(`\n    the heaviest link is ${worst.toFixed(0)} ms — ${(worst / 2749).toFixed(2)}× the spend that relayed,`)
console.log(`    ${(worst / 4219).toFixed(2)}× the one that did not.`)

// ── 4. what a reader has to check, because no script can ────────────────────
console.log(`
  WHAT THE CHAIN DOES NOT SAY BY ITSELF

  Each link is enforced by the two scripts in it: the carrier insists the
  successor's prev is its own cur, the stage insists the successor's cur is what
  it computed from that prev. What no stage can insist on is that the carrier
  beside it is genuine — an outpoint does not name a script, and the carrier's
  txid did not exist when the stage coin was written.

  So the claim is about a CHAIN, and a reader establishes it by walking one:

    · the funding transaction's outputs carry the stage scripts, rebuilt from
      source and compared byte for byte
    · tx₁ spends funding output 0, and pays the carrier its script demands
    · tx₂ spends funding output 1 and tx₁'s carrier, and pays a carrier whose
      cur is e(P, Q)

  Three checks over three transactions, against one that ran atomically. That is
  the price of relaying: the single-transaction version binds everything at once
  and cannot be sent; this one travels and asks the reader for the last step.
`)
