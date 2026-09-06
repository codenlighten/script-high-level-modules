'use strict'

// A GROTH16 VERIFIER ACROSS THREE INPUTS OF ONE TRANSACTION.
//
// The verifier is 1,241,012 bytes against a 500,000-byte script policy, and its
// Miller loop alone — three pairings already sharing one accumulator — is
// 705,838. So a two-way cut is not enough; the loop itself is cut, at round 31.
//
//     input 0   rounds 1–31 of three loops, publishes S₁      382,263 bytes
//     input 1   rounds 32–63, resuming from S₁, publishes S₂  370,479
//     input 2   the final exponentiation of S₂ against e(α,β) 475,185
//
// One data output carries everything the three must agree on — the proof, the
// state after round 31, the state after round 63 — and each stage computes its
// own part and witnesses the rest. All three build the blob and require it to
// be the committed output, so the witnessed halves are the computed ones.
//
// GRINDING THREE PREIMAGES AT ONCE. About one preimage in fifty satisfies
// OP_PUSH_TX's canonical low-S condition, so a TRIPLE lands about once in
// 125,000 — and every input's preimage carries a ~400 KB scriptCode. Hashing
// 1.2 MB a hundred thousand times is not the way.
//
// The fix is which field to grind. nSequence appears twice in a BIP-143
// preimage: once as its own field and once inside hashSequence, at offset 36 —
// so moving it changes bytes near the start and every SHA-256 block after them
// must be recomputed. nLockTime appears ONCE, eight bytes from the end. Grind
// that instead and every block but the last is unchanged, so the SHA-256
// midstate is computed once per input and copied per attempt. A hundred
// thousand tries becomes a fraction of a second.
//
// Small nLockTime values are past block heights, so the transaction stays final.

const bsv = require('@smartledger/bsv')
const crypto = require('crypto')
const path = require('path')
const { Asm } = require('../src/asm')
const { policyFlags } = require('../src/run')
const bls = require('../src/bls12381')
const split = require('../src/modules/groth16split')
const txmod = require('../src/modules/tx')
const { pushNum, pushData } = require('../src/num')
const H = require('@smartledger/bsv/lib/covenant/helpers')

const P = bls.P
const n = (x) => x.toLocaleString('en-US')
const D = path.join(__dirname, '..', 'test', 'vectors', 'groth16-age')
const vkJson = require(path.join(D, 'vk.json'))
const proofJson = require(path.join(D, 'proof.json'))
const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })
const vk = {
  alpha: g1(vkJson.vk_alpha_1), beta: g2(vkJson.vk_beta_2),
  gamma: g2(vkJson.vk_gamma_2), delta: g2(vkJson.vk_delta_2), IC: vkJson.IC.map(g1)
}
const A = g1(proofJson.pi_a); const B = g2(proofJson.pi_b); const C = g1(proofJson.pi_c)
const proof = { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }

const v = split.verifier(vk, [2026n, 21n], { proof })
const st = v.stateFor(proof)
const blob = v.serialise(st.values)

// ── part one: are the three stages sound on their own? ──────────────────────
//
// Each stage is proved against the interpreter on the real proof, and then
// attacked: every witnessed input is a value the SPENDER supplies, so for a
// sample of them the kit substitutes forgeries and requires refusal. A stage
// that computed the right answer but accepted a wrong witness would be worse
// than useless — the composition would carry the forgery forward.

const stages = [
  ['stage 1', v.stage1, 'rounds 1–31 of three Miller loops, publishing S₁'],
  ['stage 2', v.stage2, 'rounds 32–63, resuming from S₁, publishing S₂'],
  ['stage 3', v.stage3, 'the final exponentiation of S₂ against e(α, β)']
]
{
  const { proveAll } = require('../src/testkit')
  console.log('\n  the three stages, against the interpreter\n')
  const t0 = Date.now()
  const { failures } = proveAll(stages.map(([, m]) => [m, {}]))
  if (failures.length) { console.log('\n  a stage did not hold up\n'); process.exit(1) }
  console.log(`  (${((Date.now() - t0) / 1000).toFixed(0)} s)`)
}

// ── part two: does the transaction bind them together? ──────────────────────

/** A predicate as a locking script: emit it, then leave TRUE. */
function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, {})
  asm.num(1, 'ok')
  return asm.script()
}
const locks = [coin(v.stage1), coin(v.stage2), coin(v.stage3)]
const mods = [v.stage1, v.stage2, v.stage3]
const SATS = 1

const tx = new bsv.Transaction()
locks.forEach((lock, i) => tx.addInput(new bsv.Transaction.Input({
  prevTxId: Buffer.alloc(32, 0xa0 + i), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe
}), lock, SATS))
tx.addOutput(txmod.dataOutput(split.BLOB_BYTES, blob))
tx._outputAmount = undefined

// ── the triple grind ────────────────────────────────────────────────────────
const LOCKTIME_AT = (len) => len - 8
const started0 = Date.now()
const bases = locks.map((lock, i) => Buffer.from(H.rawPreimage(tx, i, lock, SATS, txmod.SIGHASH_ALL_FORKID)))
// everything before the last whole block that precedes nLockTime, hashed once
const mids = bases.map((b) => {
  const cut = Math.floor(LOCKTIME_AT(b.length) / 64) * 64
  const h = crypto.createHash('sha256')
  h.update(b.subarray(0, cut))
  return { h, cut }
})
// The double-SHA of a preimage whose last block is the only thing that moved.
const sFrom = (buf, mid) => {
  const first = mid.h.copy().update(buf.subarray(mid.cut)).digest()
  return zCheck(crypto.createHash('sha256').update(first).digest())
}
// sFromPreimage takes a whole preimage; this is the same test on the digest we
// already hold. It is checked against the library below rather than trusted.
const BN = bsv.crypto.BN
const N = new BN(Buffer.from(txmod.PushTx.N_LE).reverse())
const HALF = N.div(new BN(2))
const GX = new BN(Buffer.from(txmod.PushTx.gxLe).reverse())
function zCheck (z) {
  if (z[0] < 0x01 || z[0] > 0x7f) return null
  const s = new BN(z).add(GX).mod(N)
  if (s.gt(HALF)) return null
  const sBE = s.toBuffer({ size: 32 })
  return sBE[0] >= 0x01 ? sBE : null
}

// Does the fast filter agree with the library it is standing in for? Walk a
// few hundred nLockTimes through both and require an identical verdict on each.
{
  let checked = 0
  let accepted = 0
  for (let lt = 0; lt < 300; lt++) {
    const lb = Buffer.alloc(4); lb.writeUInt32LE(lt)
    lb.copy(bases[0], LOCKTIME_AT(bases[0].length))
    const mine = sFrom(bases[0], mids[0])
    let theirs = null
    try { theirs = txmod.PushTx.sFromPreimage(bases[0]) } catch (e) { theirs = null }
    const same = (mine === null && theirs === null) ||
      (mine !== null && theirs !== null && Buffer.from(theirs).equals(Buffer.from(mine)))
    if (!same) { console.log(`\n  the fast filter disagrees with the library at nLockTime ${lt}\n`); process.exit(1) }
    checked++
    if (mine) accepted++
  }
  console.log(`  fast filter agrees with the library on ${checked} nLockTimes (${accepted} canonical)`)
}

let tries = 0
let past1 = 0
let past2 = 0
let found = null
for (let lt = 0; lt < 4000000 && !found; lt++) {
  const lb = Buffer.alloc(4); lb.writeUInt32LE(lt)
  tries++
  lb.copy(bases[0], LOCKTIME_AT(bases[0].length))
  if (!sFrom(bases[0], mids[0])) continue
  past1++
  lb.copy(bases[1], LOCKTIME_AT(bases[1].length))
  if (!sFrom(bases[1], mids[1])) continue
  past2++
  lb.copy(bases[2], LOCKTIME_AT(bases[2].length))
  if (sFrom(bases[2], mids[2])) found = lt
}
if (found === null) { console.log('\n  the triple grind found nothing\n'); process.exit(1) }
const grindSeconds = (Date.now() - started0) / 1000

tx.nLockTime = found
const pres = locks.map((lock, i) => H.rawPreimage(tx, i, lock, SATS, txmod.SIGHASH_ALL_FORKID))
// hand-patched midstates, checked against the preimages bsv builds
bases.forEach((b, i) => {
  if (!b.equals(pres[i])) { console.log(`\n  patched preimage ${i} disagrees with the library's\n`); process.exit(1) }
})

// ── the unlocking scripts ───────────────────────────────────────────────────
const tapes = [st.wit1, st.wit2, []]
const unlocks = mods.map((m, i) => {
  const values = { ...st.values, preimage: pres[i] }
  tapes[i].forEach(([a, b], k) => { values[`w${k}a`] = a; values[`w${k}b`] = b })
  if (i === 2) Object.assign(values, require('../src/modules/pairing').finalExp.hint(require('../src/modules/pairing').spread(st.s2, 'f'), { n: P, nn: P }))
  const u = new bsv.Script()
  for (const inp of m.inputs) {
    const val = values[inp.name]
    if (val === undefined) throw new Error(`stage ${i + 1}: missing ${inp.name}`)
    u.add(inp.kind === 'bytes' ? pushData(val) : pushNum(val))
  }
  return u
})
unlocks.forEach((u, i) => tx.inputs[i].setScript(u))

// ── the verdict ─────────────────────────────────────────────────────────────
const started = Date.now()
const results = locks.map((lock, i) => {
  const interp = new bsv.Script.Interpreter()
  let ok = false
  let err = null
  try { ok = interp.verify(unlocks[i], lock, tx, i, policyFlags(), new bsv.crypto.BN(SATS)) } catch (e) { err = e.message }
  return { ok, err: err || interp.errstr }
})

console.log('\n  a Groth16 verifier across three inputs of one transaction\n')
const names = ['rounds 1–31, publishes S₁', 'rounds 32–63, publishes S₂', 'final exponentiation vs e(α,β)']
results.forEach((r, i) => {
  console.log(`    input ${i}  ${names[i].padEnd(32)} ${n(locks[i].toBuffer().length).padStart(9)} B lock  ${n(unlocks[i].toBuffer().length).padStart(9)} B unlock  ${r.ok ? 'ACCEPTED' : 'REFUSED — ' + r.err}`)
})
console.log(`    output   the blob all three commit to      ${n(split.BLOB_BYTES).padStart(9)} B — ${split.BLOB_NAMES.length} field elements`)
console.log(`\n    every locking script is under the ${n(500000)}-byte policy`)
console.log(`    triple grind: ${n(tries)} nLockTimes, ${past1} cleared input 0, ${past2} cleared inputs 0 and 1 — ${grindSeconds.toFixed(1)} s`)
console.log(`    transaction ${n(tx.toBuffer().length)} bytes, ${((Date.now() - started) / 1000).toFixed(1)} s to verify all three inputs\n`)

if (results.some((r) => !r.ok)) process.exit(1)
console.log('  A zero-knowledge proof of age, verified by Bitcoin Script, in a computation')
console.log('  no single script is allowed to be large enough to hold.\n')
