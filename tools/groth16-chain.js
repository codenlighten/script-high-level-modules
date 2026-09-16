'use strict'

// A GROTH16 VERIFIER ACROSS THREE TRANSACTIONS.
//
//   node tools/groth16-chain.js
//
// tools/groth16-split.js puts the three stages in one transaction. That
// transaction is on chain and it could not travel: a node gives a peer-relayed
// transaction about a second to validate, and three 400 KB stages wanted more.
// It reached a block only because a pool submitted it to their own node.
//
// So the stages become three transactions, chained through the carrier coin
// (src/modules/carry.js), the way pairing.chainMiller/chainExp already are:
//
//     funding   three stage coins, and nothing else
//     tx₁       link 1                            → carrier(∅, proof‖S1)
//     tx₂       link 2 + carrier(∅, proof‖S1)     → carrier(proof‖S1, S2)
//     tx₃       link 3 + carrier(proof‖S1, S2)    → carrier(S2, e(α, β))
//
// Five questions, in order:
//
//   1. does every link verify?          every input, through the interpreter
//   2. what does each ask of a node?     against the two spends whose fate is known
//   3. does the binding bite?            a state the carrier is not holding
//   4. where does a bad proof die?       and it matters WHERE, so it is reported
//   5. what must a READER check?         the part no script can do for itself

const bsv = require('@smartledger/bsv')
const H = require('@smartledger/bsv/lib/covenant/helpers')
const { Asm } = require('../src/asm')
const { policyFlags } = require('../src/run')
const { pushNum, pushData } = require('../src/num')
const chain = require('../src/modules/groth16chain')
const split = require('../src/modules/groth16split')
const carry = require('../src/modules/carry')
const txmod = require('../src/modules/tx')
const points = require('../src/modules/points')
const bls = require('../src/bls12381')
const age = require('../test/vectors/groth16-age')

const n = (x) => x.toLocaleString('en-US')
const { PROOF_NAMES, S2_NAMES } = split
const W = chain.STATE_BYTES
const CARRIER = 1
const FUNDING = 'd4'.repeat(32)
const STAGE_SATS = [90000, 80000, 110000]

const v = chain.chained(age.vk, age.statement, { proof: age.proof })

/** A predicate as a locking script: emit it, then leave TRUE. */
function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, {})
  asm.num(1, 'ok')
  return asm.script()
}
const unlockFor = (m, values) => {
  const u = new bsv.Script()
  for (const i of m.inputs) {
    const val = values[i.name]
    if (val === undefined) throw new Error(`${m.name}: no value for ${i.name}`)
    u.add(i.kind === 'bytes' ? pushData(val) : pushNum(val))
  }
  return u
}

const locks = [coin(v.link1), coin(v.link2), coin(v.link3)]

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

/** The witness tapes and field values a proof produces, named as the links read them. */
function valuesFor (proof) {
  const st = v.stateFor(proof)
  const tape = (list) => {
    const out = {}
    list.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
    return out
  }
  return {
    st,
    blob1: chain.pack(chain.LINK1_NAMES, st.values),
    blob2: chain.padState(chain.pack(S2_NAMES, st.values)),
    proofValues: Object.fromEntries(PROOF_NAMES.map((nm) => [nm, st.values[nm]])),
    w1: tape(st.wit1),
    w2: tape(st.wit2),
    expHint: require('../src/modules/pairing').finalExp.hint(
      require('../src/modules/pairing').spread(st.s2, 'f'), { n: bls.P, nn: bls.P })
  }
}

// ── tx₁: link 1 alone ───────────────────────────────────────────────────────
function buildTx1 (proof, vals) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(FUNDING, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe
  }), locks[0], STAGE_SATS[0])
  const w = v.link1.witnessFor({ tx, lockingScript: locks[0], satoshis: STAGE_SATS[0], spend: { proof }, inputIndex: 0 })
  tx.inputs[0].setScript(unlockFor(v.link1, w))
  return tx
}

// ── tx₂ and tx₃: a stage coin beside the carrier its predecessor made ───────
//
// Two inputs, so one grind has to satisfy both preimages: hashSequence covers
// every input's sequence, so moving input 0's dirties input 1's preimage too.
const leU32 = (x) => { const b = Buffer.alloc(4); b.writeUInt32LE(x >>> 0); return b }

//
// `opts` exists for the attacks, and every attack is built through THIS
// function so that it is ground exactly like the honest path. The first version
// of the binding test built its transaction without grinding, and OP_PUSH_TX
// refused the preimage before the binding was ever consulted — a refusal that
// would have happened whatever the carrier did. A test that cannot fail for the
// reason it names is not a test; §10.4 of the paper is about the last time this
// repository made that mistake.
//
//   claimedPrev   what the STAGE says the previous state was
//   payPrev       what the transaction's carrier output actually carries as prev
//   payCur        what it carries as cur
function buildLink (which, carrierState, stageValues, nextCur, opts = {}) {
  const lock = locks[which - 1]
  const sats = STAGE_SATS[which - 1]
  const carrierIn = carry.carrierScript(W, carrierState)
  const stagePrev = opts.claimedPrev || carrierState.cur
  const outPrev = opts.payPrev || stagePrev
  const outCur = opts.payCur || nextCur
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(FUNDING, 'hex'), outputIndex: which - 1, script: new bsv.Script(), sequenceNumber: 0xfffffffe
  }), lock, sats)
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(carrierState.txid, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe
  }), carrierIn, CARRIER)
  tx.addOutput(new bsv.Transaction.Output({
    script: carry.carrierScript(W, { prev: outPrev, cur: outCur }), satoshis: CARRIER
  }))
  tx._outputAmount = undefined

  const baseA = Buffer.from(H.rawPreimage(tx, 0, lock, sats, txmod.SIGHASH_ALL_FORKID))
  const baseB = Buffer.from(H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID))
  let found = null
  for (let k = 0; k < 500000 && found === null; k++) {
    const s0 = 0xfffffffe - k
    const hs = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(0xfffffffe)]))
    hs.copy(baseA, 36); leU32(s0).copy(baseA, baseA.length - 44)
    if (!txmod.PushTx.sFromPreimage(baseA)) continue
    hs.copy(baseB, 36); leU32(0xfffffffe).copy(baseB, baseB.length - 44)
    if (txmod.PushTx.sFromPreimage(baseB)) { tx.inputs[0].sequenceNumber = s0; found = k }
  }
  if (found === null) throw new Error('the joint grind found nothing')

  const preA = H.rawPreimage(tx, 0, lock, sats, txmod.SIGHASH_ALL_FORKID)
  const preB = H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID)
  const m = which === 2 ? v.link2 : v.link3
  tx.inputs[0].setScript(unlockFor(m, { preimage: preA, prev: stagePrev, ...stageValues }))
  tx.inputs[1].setScript(new bsv.Script().add(pushData(preB)).add(pushData(outCur)))
  return { tx, carrierIn, grindTries: found + 1 }
}

/** The whole chain for one proof, built and verified. */
function runChain (proof, { quiet = false } = {}) {
  const vals = valuesFor(proof)
  const tx1 = buildTx1(proof, vals)
  const r1 = verifyAndTime(tx1, [{ lock: locks[0], satoshis: STAGE_SATS[0] }])

  const c1 = { prev: Buffer.alloc(W), cur: vals.blob1, txid: tx1.hash }
  const l2 = buildLink(2, c1, vals.w2, vals.blob2)
  const r2 = verifyAndTime(l2.tx, [{ lock: locks[1], satoshis: STAGE_SATS[1] }, { lock: l2.carrierIn, satoshis: CARRIER }])

  const c2 = { prev: vals.blob1, cur: vals.blob2, txid: l2.tx.hash }
  const l3 = buildLink(3, c2, vals.expHint, v.result)
  const r3 = verifyAndTime(l3.tx, [{ lock: locks[2], satoshis: STAGE_SATS[2] }, { lock: l3.carrierIn, satoshis: CARRIER }])

  if (!quiet) {
    const row = (name, lock, unlock, r, i) =>
      console.log(`    ${name.padEnd(34)} ${n(lock).padStart(9)} B lock ${n(unlock).padStart(9)} B unlock  ${r.verdicts[i].ok ? 'ACCEPTED' : 'REFUSED — ' + r.verdicts[i].err}`)
    row('tx₁  groth16.chain1', locks[0].toBuffer().length, tx1.inputs[0].script.toBuffer().length, r1, 0)
    row('tx₂  groth16.chain2', locks[1].toBuffer().length, l2.tx.inputs[0].script.toBuffer().length, r2, 0)
    row('     the carrier it spends', l2.carrierIn.toBuffer().length, l2.tx.inputs[1].script.toBuffer().length, r2, 1)
    row('tx₃  groth16.chain3', locks[2].toBuffer().length, l3.tx.inputs[0].script.toBuffer().length, r3, 0)
    row('     the carrier it spends', l3.carrierIn.toBuffer().length, l3.tx.inputs[1].script.toBuffer().length, r3, 1)
  }
  return { tx1, l2, l3, r1, r2, r3, vals, ok: [r1, r2, r3].every((r) => r.verdicts.every((x) => x.ok)) }
}

console.log('\n  a Groth16 verifier across three transactions\n')
const good = runChain(age.proof)
if (!good.ok) { console.log('\n  the honest chain does not verify\n'); process.exit(1) }

// ── 2. what each transaction asks of a node ─────────────────────────────────
const relay = (() => {
  try { return JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '..', 'relay.json'), 'utf8')) } catch (e) { return null }
})()

console.log('\n  what a node is asked to validate\n')
const rows = [
  ['tx₁, rounds 1–31 and A, C ∈ G1', good.tx1.toBuffer().length, good.r1.ms],
  ['tx₂, rounds 32–63 and B ∈ G2', good.l2.tx.toBuffer().length, good.r2.ms],
  ['tx₃, the final exponentiation', good.l3.tx.toBuffer().length, good.r3.ms]
]
for (const [what, bytes, ms] of rows) console.log(`    ${what.padEnd(34)} ${n(bytes).padStart(11)} B  ${ms.toFixed(0).padStart(6)} ms`)
const worst = Math.max(good.r1.ms, good.r2.ms, good.r3.ms)
if (relay) {
  console.log(`    ${'—'.padEnd(34)}`)
  console.log(`    ${'the two-input spend that relayed'.padEnd(34)} ${''.padStart(11)}    ${n(relay.baseline.ms).padStart(5)} ms   mainnet`)
  console.log(`    ${'the three-input spend refused'.padEnd(34)} ${''.padStart(11)}    ${n(relay.refused.ms).padStart(5)} ms   by hand`)
  console.log(`\n    the heaviest link is ${worst.toFixed(0)} ms — ${(worst / relay.baseline.ms).toFixed(2)}× the spend that relayed,`)
  console.log(`    ${(worst / relay.refused.ms).toFixed(2)}× the one that did not.`)
  console.log(`    (yardsticks from relay.json, ${relay.generated}, ${relay.machine.cpu})`)
}
const POLICY = 500000
const biggest = Math.max(
  good.tx1.inputs[0].script.toBuffer().length,
  good.l2.tx.inputs[0].script.toBuffer().length,
  good.l3.tx.inputs[0].script.toBuffer().length)
console.log(`\n    the largest unlocking script is ${n(biggest)} B — ${n(POLICY - biggest)} under the ${n(POLICY)} policy`)
if (biggest >= POLICY) { console.log('\n  a stage is past the policy: this wants a four-link chain\n'); process.exit(1) }

// ── 3. does the binding bite, and does the RIGHT script bite? ───────────────
//
// Every attack is built through buildLink, so it is ground exactly like the
// honest path. The first version of this section was not, and OP_PUSH_TX threw
// out its preimage before the binding was ever consulted: it "refused" for a
// reason that had nothing to do with what it claimed to test.
//
// So each attack also names the input that must refuse it. The carrier enforces
// `prev` and the stage enforces `cur`; a refusal from the other one would mean
// the mechanism under test was never exercised, and is failed here rather than
// counted.
console.log('\n  the binding, attacked\n')
{
  const A1 = { prev: Buffer.alloc(W), cur: good.vals.blob1, txid: good.tx1.hash }
  const other = valuesFor(age.underage)   // another run, internally consistent
  const tamper = (b) => { const x = Buffer.from(b); x[0] ^= 0x01; return x }

  const attacks = [
    // The stage is happy — it computed honestly from the state it was handed.
    // What must refuse is the CARRIER, whose cur is not that state.
    ['a state the carrier is not holding', 1,
      () => buildLink(2, A1, other.w2, other.blob2, { claimedPrev: other.blob1 })],
    // The carrier is happy — its prev is intact and it constrains nothing else.
    // What must refuse is the STAGE, which computed a different cur.
    ['a cur the stage did not compute', 0,
      () => buildLink(2, A1, good.vals.w2, good.vals.blob2, { payCur: tamper(good.vals.blob2) })]
  ]
  for (const [label, mustRefuse, build] of attacks) {
    let tx, carrierIn
    try { ({ tx, carrierIn } = build()) } catch (e) {
      console.log(`    ${label.padEnd(38)} could not be built — ${e.message.slice(0, 40)}`)
      process.exit(1)
    }
    const rr = verifyAndTime(tx, [{ lock: locks[1], satoshis: STAGE_SATS[1] }, { lock: carrierIn, satoshis: CARRIER }])
    const who = rr.verdicts.findIndex((x) => !x.ok)
    const name = (i) => (i === 0 ? 'the stage' : 'the carrier')
    if (who === -1) {
      console.log(`    ${label.padEnd(38)} ACCEPTED — the link is not bound`)
      process.exit(1)
    }
    if (who !== mustRefuse) {
      console.log(`    ${label.padEnd(38)} refused by ${name(who)}, and ${name(mustRefuse)} is what should have`)
      process.exit(1)
    }
    console.log(`    ${label.padEnd(38)} refused by ${name(who).padEnd(11)} ${rr.verdicts[who].err}`)
  }

  // The limitation, run rather than asserted. A carrier from ANOTHER execution,
  // with a stage consistent with it, is a perfectly valid link — of that run's
  // chain, not this one's. No script can tell; a reader walking the chain can.
  // That run then dies at link 3, which is part 4.
  const tx1b = buildTx1(age.underage, other)
  const B1 = { prev: Buffer.alloc(W), cur: other.blob1, txid: tx1b.hash }
  const spliced = buildLink(2, B1, other.w2, other.blob2)
  const rs = verifyAndTime(spliced.tx, [{ lock: locks[1], satoshis: STAGE_SATS[1] }, { lock: spliced.carrierIn, satoshis: CARRIER }])
  const ok = rs.verdicts.every((x) => x.ok)
  console.log(`    a consistent carrier from another run  ${ok ? 'ACCEPTED — a valid link of THAT chain' : 'refused, which contradicts the note above'}`)
  if (!ok) process.exit(1)
}

// ── 4. where does a bad proof die? ──────────────────────────────────────────
//
// It matters WHERE, and reporting "the chain refuses it" without saying where
// would hide the interesting part. A chain is not atomic: an invalid proof
// produces perfectly valid EARLY links, and dies at the link that checks an
// equation. What must never happen is a chain that reaches its last carrier.
console.log('\n  where a bad proof dies\n')
for (const [label, proof, note] of [
  ['a proof of the wrong statement', age.underage, 'valid Groth16, wrong claim'],
  ['A on the curve, outside G1', { ...age.proof, ...(() => { const s = points.fast.g1add({ x: age.proof.Ax, y: age.proof.Ay }, { x: 0n, y: 2n }); return { Ax: s.x, Ay: s.y } })() }, 'subgroup']
]) {
  let died = 'NOWHERE — the chain produced a receipt'
  try {
    const vals = valuesFor(proof)
    const tx1 = buildTx1(proof, vals)
    const r1 = verifyAndTime(tx1, [{ lock: locks[0], satoshis: STAGE_SATS[0] }])
    if (!r1.verdicts[0].ok) died = `link 1 — ${r1.verdicts[0].err}`
    else {
      const c1 = { prev: Buffer.alloc(W), cur: vals.blob1, txid: tx1.hash }
      const l2 = buildLink(2, c1, vals.w2, vals.blob2)
      const r2 = verifyAndTime(l2.tx, [{ lock: locks[1], satoshis: STAGE_SATS[1] }, { lock: l2.carrierIn, satoshis: CARRIER }])
      if (r2.verdicts.some((x) => !x.ok)) died = `link 2 — ${r2.verdicts.map((x) => x.err).filter(Boolean)[0]}`
      else {
        const c2 = { prev: vals.blob1, cur: vals.blob2, txid: l2.tx.hash }
        const l3 = buildLink(3, c2, vals.expHint, v.result)
        const r3 = verifyAndTime(l3.tx, [{ lock: locks[2], satoshis: STAGE_SATS[2] }, { lock: l3.carrierIn, satoshis: CARRIER }])
        if (r3.verdicts.some((x) => !x.ok)) died = `link 3 — ${r3.verdicts.map((x) => x.err).filter(Boolean)[0]}`
      }
    }
  } catch (e) { died = `could not be built — ${e.message.slice(0, 40)}` }
  console.log(`    ${label.padEnd(34)} ${note.padEnd(26)} ${died.slice(0, 52)}`)
  if (died.startsWith('NOWHERE')) process.exit(1)
}

// ── 5. what a reader has to check ───────────────────────────────────────────
console.log(`
  WHAT THE CHAIN DOES NOT SAY BY ITSELF

  Every link is enforced by the two scripts in it: the carrier insists the
  successor's prev is its own cur, the stage insists the successor's cur is what
  it computed from that prev. No stage can insist the carrier beside it belongs
  to THIS execution — an outpoint does not name a script, and the carrier's txid
  did not exist when the stage coins were written.

  So a spender may run the chain on any proof they like, and the early links of
  a losing run are valid transactions. What they cannot do is reach the last
  carrier: link 3 pays e(α, β) only for a state whose final exponentiation is
  e(α, β), and that state is split out of the carrier rather than witnessed.

  The claim is therefore about a CHAIN, and a reader establishes it by walking
  one: the funding transaction's outputs carry the three stage scripts, tx₁
  spends output 0, tx₂ spends output 1 and tx₁'s carrier, tx₃ spends output 2
  and tx₂'s carrier, and the last carrier holds e(α, β).
`)
