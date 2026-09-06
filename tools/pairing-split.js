'use strict'

// A COMPLETE PAIRING, IN ONE TRANSACTION, ACROSS TWO INPUTS.
//
// e(P, Q) in a single script is 817,031 bytes and the default script-size
// policy is 500,000. Both stages fit under it and both are on chain; the
// composition does not, and no amount of shaving gets 817 KB under 500 KB.
//
// So the composition moves out of the script and into the transaction:
//
//     input 0   the Miller loop        publishes f as an OP_RETURN output
//     input 1   the final exponentiation   consumes that same output
//
// Both inputs of a spend see the same `hashOutputs`. Each requires that
// commitment to be the data output IT builds, so they must have built the same
// bytes — input 1's f is input 0's f, enforced by the transaction. Neither
// script contains the other's code, which is the point: a covenant can only
// commit to a successor whose bytes it can construct, and a 344 KB script
// cannot carry a 475 KB one.
//
// JOINT GRINDING is the part that is not obvious. OP_PUSH_TX needs each
// preimage to satisfy a condition, and `grind` finds one by moving that input's
// nSequence. But `hashSequence` covers EVERY input's sequence, so moving
// input 0's changes input 1's preimage and vice versa. Two independent grinds
// therefore invalidate each other. The search has to be over the PAIR, and it
// is: set both sequences, recompute both preimages, accept when both pass.
// About one preimage in fifty is canonical (measured: 2.01%), so a PAIR lands
// about once in 2,500 tries — cheap here, but see tools/groth16-split.js for
// what the same search costs when there are three of them.
//
// What the network verifies, in one transaction:
//
//     the Miller loop ran correctly on P and Q          input 0
//     its twelve outputs were published                 input 0's covenant
//     the same twelve were consumed                     input 1's covenant
//     their final exponentiation is e(P, Q)             input 1

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { policyFlags } = require('../src/run')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const txmod = require('../src/modules/tx')
const { pushNum, pushData } = require('../src/num')

const P = bls.P
const params = { n: P, nn: P }
const H = require('@smartledger/bsv/lib/covenant/helpers')
const PushTx = txmod.PushTx

// ── the two coins ───────────────────────────────────────────────────────────
const pts = { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] }
const raw = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P).f
const f = bls.X < 0n ? bls.f12conj(raw) : raw
const expected = bls.pairing(bls.G1, bls.G2)
const data = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')

const publish = pairing.publish({ cases: [{ name: 'x', inputs: pts, spend: pts, params }] })
const consume = pairing.consume(expected, { cases: [{ name: 'x', spend: { f }, params }] })

/** A module with no outputs, as a locking script: emit it, then leave TRUE. */
function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return asm.script()
}
const lockA = coin(publish)
const lockB = coin(consume)

const SATS = 1
const mockPrev = (n) => Buffer.alloc(32, n)

// ── the transaction: two inputs, one data output ────────────────────────────
const tx = new bsv.Transaction()
tx.addInput(new bsv.Transaction.Input({ prevTxId: mockPrev(0xa1), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockA, SATS)
tx.addInput(new bsv.Transaction.Input({ prevTxId: mockPrev(0xb2), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockB, SATS)
tx.addOutput(txmod.dataOutput(pairing.STATE_BYTES, data))
tx._outputAmount = undefined

// ── joint grinding ──────────────────────────────────────────────────────────
// One knob, not two: hashSequence covers every input, so moving input 0's
// sequence moves BOTH preimages. There is nothing to decouple, and a first
// version of this broke out of the inner loop on the theory that input 1's
// nonce could not affect input 0 — which is exactly backwards, and is why it
// searched 400 points instead of the space.
//
// About one preimage in fifty satisfies OP_PUSH_TX's canonical low-S condition,
// so a PAIR lands about once in 2,500. Rebuilding a preimage that carries a
// 344 KB scriptCode 2,500 times is the slow way to find out; only 36 bytes of
// it change. BIP-143 puts hashSequence at offset 36 and nSequence 44 bytes from
// the end, so each preimage is built ONCE and those two fields are patched in
// place. What is left per try is the double-SHA the condition is about, which
// is the irreducible part.
const HASHSEQ_AT = 36
const seqOffset = (buf) => buf.length - 44
const leU32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b }

const baseA = Buffer.from(H.rawPreimage(tx, 0, lockA, SATS, txmod.SIGHASH_ALL_FORKID))
const baseB = Buffer.from(H.rawPreimage(tx, 1, lockB, SATS, txmod.SIGHASH_ALL_FORKID))

let tries = 0
let built = 0
let preA = null
let preB = null
const started0 = Date.now()
for (let n0 = 0; n0 < 500000 && !preA; n0++) {
  const s0 = 0xfffffffe - n0
  const s1 = 0xfffffffe
  const hashSeq = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(s1)]))
  hashSeq.copy(baseA, HASHSEQ_AT); leU32(s0).copy(baseA, seqOffset(baseA))
  tries++
  if (!PushTx.sFromPreimage(baseA)) continue
  built++
  hashSeq.copy(baseB, HASHSEQ_AT); leU32(s1).copy(baseB, seqOffset(baseB))
  if (PushTx.sFromPreimage(baseB)) {
    tx.inputs[0].sequenceNumber = s0
    tx.inputs[1].sequenceNumber = s1
    preA = Buffer.from(baseA); preB = Buffer.from(baseB)
  }
}
if (!preA) { console.log('\n  joint grind failed'); process.exit(1) }

// Patched by hand, so it is checked against the library that builds them.
{
  const a = H.rawPreimage(tx, 0, lockA, SATS, txmod.SIGHASH_ALL_FORKID)
  const b = H.rawPreimage(tx, 1, lockB, SATS, txmod.SIGHASH_ALL_FORKID)
  if (!a.equals(preA) || !b.equals(preB)) {
    console.log('\n  the patched preimages do not match the ones bsv builds — the offsets are wrong')
    process.exit(1)
  }
}
const grindSeconds = (Date.now() - started0) / 1000

// ── the unlocking scripts ───────────────────────────────────────────────────
const witnessesA = (() => {
  const { witnesses } = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P)
  const out = { ...pts, preimage: preA }
  witnesses.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
  return out
})()
const witnessesB = { preimage: preB, data, ...pairing.finalExp.hint(pairing.spread(f, 'f'), params) }

const unlockFor = (m, values) => {
  const u = new bsv.Script()
  for (const i of m.inputs) {
    const v = values[i.name]
    if (v === undefined) throw new Error(`missing ${i.name}`)
    u.add(i.kind === 'bytes' ? pushData(v) : pushNum(v))
  }
  return u
}
const unlockA = unlockFor(publish, witnessesA)
const unlockB = unlockFor(consume, witnessesB)
tx.inputs[0].setScript(unlockA)
tx.inputs[1].setScript(unlockB)

// ── the verdict, from the interpreter ───────────────────────────────────────
const started = Date.now()
const check = (i, unlock, lock) => {
  const interp = new bsv.Script.Interpreter()
  let ok = false
  let err = null
  try { ok = interp.verify(unlock, lock, tx, i, policyFlags(), new bsv.crypto.BN(SATS)) } catch (e) { err = e.message }
  return { ok, err: err || interp.errstr }
}
const rA = check(0, unlockA, lockA)
const rB = check(1, unlockB, lockB)

const kb = (b) => (b / 1000).toFixed(1) + ' KB'
const n = (x) => x.toLocaleString('en-US')
console.log('\n  e(P, Q) across one transaction, two inputs\n')
console.log(`    input 0   pairing.publish   ${n(lockA.toBuffer().length).padStart(9)} bytes of lock, ${n(unlockA.toBuffer().length)} of unlock   ${rA.ok ? 'ACCEPTED' : 'REFUSED — ' + rA.err}`)
console.log(`    input 1   pairing.consume   ${n(lockB.toBuffer().length).padStart(9)} bytes of lock, ${n(unlockB.toBuffer().length)} of unlock   ${rB.ok ? 'ACCEPTED' : 'REFUSED — ' + rB.err}`)
console.log(`    output    OP_RETURN         ${n(pairing.STATE_BYTES).padStart(9)} bytes — twelve Fp12 coefficients`)
console.log(`\n    joint grind: ${n(tries)} nonces, ${built} of which cleared input 0, one pair clearing both — ${grindSeconds.toFixed(1)} s`)
console.log(`    transaction ${n(tx.toBuffer().length)} bytes (${kb(tx.toBuffer().length)}), both scripts under the 500,000-byte policy`)
console.log(`    ${((Date.now() - started) / 1000).toFixed(1)} s to verify both inputs\n`)

if (!rA.ok || !rB.ok) process.exit(1)
console.log('  A complete BLS12-381 pairing, evaluated by two Bitcoin Script predicates')
console.log('  bound to each other by the transaction they are spent in.\n')

// The constraint this surfaces, which is not the one we went looking for.
//
// OP_PUSH_TX's preimage CONTAINS the locking script, so a covenant's unlocking
// script is as large as the script it unlocks. `pairing.consume` locks in
// 475,017 bytes and unlocks in 479,302 — under the 500,000-byte policy by about
// twenty thousand. The binding limit on this construction is therefore the
// UNLOCKING script, not the locking one, and the final exponentiation has less
// headroom than its own size suggests.
const headroom = 500000 - unlockB.toBuffer().length
console.log(`  One thing this makes visible: OP_PUSH_TX's preimage contains the script it`)
console.log(`  unlocks, so input 1 unlocks in ${n(unlockB.toBuffer().length)} bytes against a ${n(500000)}-byte`)
console.log(`  policy — ${n(headroom)} bytes of headroom. The binding constraint here is the`)
console.log('  UNLOCKING script, not the locking one.\n')
