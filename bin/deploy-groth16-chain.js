#!/usr/bin/env node
'use strict'

// DEPLOY A GROTH16 VERIFIER AS A CHAIN: one stage per transaction.
//
//   node bin/deploy-groth16-chain.js              build, verify and price
//   node bin/deploy-groth16-chain.js --broadcast
//
// bin/deploy-groth16.js put the same verifier on chain as THREE INPUTS of one
// transaction. That transaction is consensus-valid, and it could not travel: a
// node gives a peer-relayed transaction about a second to validate, and three
// 400 KB stages wanted more. It reached a block only because a pool submitted it
// to their own node by hand.
//
// So one stage per transaction, carried by the coin of src/modules/carry.js:
//
//   funding   three stage coins, and the satoshi the first carrier carries
//   tx₁       rounds 1–31, A and C ∈ G1     → carrier(∅, proof‖S1)
//   tx₂       rounds 32–63, B ∈ G2
//             + carrier(∅, proof‖S1)        → carrier(proof‖S1, S2)
//   tx₃       the final exponentiation
//             + carrier(proof‖S1, S2)       → carrier(S2, e(α, β))
//
// THE FEES, because this is where the last chain deployment went wrong. A stage
// coin's whole value becomes its transaction's fee, less whatever its outputs
// carry away. tx₁ creates a carrier out of nothing, so its coin needs the fee
// PLUS that satoshi; tx₂ and tx₃ each spend a carrier worth one satoshi and pay
// one out, so the satoshi passes through and their coins need only the fee.
// Funding tx₁'s coin at `fee − 1` underpaid by exactly two satoshis and was
// refused: "minimum expected fee: 35366, actual fee: 35364".
//
// Every transaction is verified against bsv.Script.Interpreter under relay policy
// flags before anything is broadcast, and each is broadcast only after the one it
// depends on has been accepted.

const bsv = require('@smartledger/bsv')
const H = require('@smartledger/bsv/lib/covenant/helpers')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const { policyFlags } = require('../src/run')
const { Asm } = require('../src/asm')
const { pushNum, pushData } = require('../src/num')
const chain = require('../src/modules/groth16chain')
const split = require('../src/modules/groth16split')
const carry = require('../src/modules/carry')
const txmod = require('../src/modules/tx')
const pairing = require('../src/modules/pairing')
const bls = require('../src/bls12381')
const age = require('../test/vectors/groth16-age')

const BROADCAST = process.argv.includes('--broadcast')
const n = (x) => x.toLocaleString('en-US')
const { S2_NAMES, PROOF_NAMES } = split
const W = chain.STATE_BYTES
const CARRIER = 1

const v = chain.chained(age.vk, age.statement, { proof: age.proof })

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

function check (tx, i, lock, satoshis) {
  const interp = new bsv.Script.Interpreter()
  let ok = false
  try { ok = interp.verify(tx.inputs[i].script, lock, tx, i, policyFlags(), new bsv.crypto.BN(satoshis)) } catch (e) { return { ok: false, err: e.message } }
  return { ok, err: interp.errstr }
}

// ── the state every link agrees on, computed once here ──────────────────────
const st = v.stateFor(age.proof)
const tape = (list) => {
  const out = {}
  list.forEach(([a, b], k) => { out[`w${k}a`] = a; out[`w${k}b`] = b })
  return out
}
const blob1 = chain.pack(chain.LINK1_NAMES, st.values)
const blob2 = chain.padState(chain.pack(S2_NAMES, st.values))
const values = {
  proof: Object.fromEntries(PROOF_NAMES.map((nm) => [nm, st.values[nm]])),
  w1: tape(st.wit1),
  w2: tape(st.wit2),
  expHint: pairing.finalExp.hint(pairing.spread(st.s2, 'f'), { n: bls.P, nn: bls.P })
}

/** tx₁: link 1 alone, paying the first carrier. */
function buildFirst (txid, vout, value) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(txid, 'hex'), outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), locks[0], value)
  const w = v.link1.witnessFor({ tx, lockingScript: locks[0], satoshis: value, spend: { proof: age.proof }, inputIndex: 0 })
  tx.inputs[0].setScript(unlockFor(v.link1, w))
  return tx
}

const leU32 = (x) => { const b = Buffer.alloc(4); b.writeUInt32LE(x >>> 0); return b }

/** tx₂ and tx₃: a stage coin beside the carrier its predecessor made. */
function buildLink (which, stageTxid, stageVout, stageValue, carrierTxid, carrierState, stageValues, nextCur) {
  const lock = locks[which - 1]
  const m = which === 2 ? v.link2 : v.link3
  const carrierIn = carry.carrierScript(W, carrierState)
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(stageTxid, 'hex'), outputIndex: stageVout, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lock, stageValue)
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(carrierTxid, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), carrierIn, CARRIER)
  tx.addOutput(new bsv.Transaction.Output({ script: carry.carrierScript(W, { prev: carrierState.cur, cur: nextCur }), satoshis: CARRIER }))
  tx._outputAmount = undefined

  // Both preimages ground together: hashSequence commits to every input, so
  // moving one input's sequence dirties the other's preimage.
  const baseA = Buffer.from(H.rawPreimage(tx, 0, lock, stageValue, txmod.SIGHASH_ALL_FORKID))
  const baseB = Buffer.from(H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID))
  let found = null
  let tries = 0
  for (let k = 0; k < 500000 && found === null; k++) {
    const s0 = 0xfffffffe - k
    tries++
    const hs = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(0xfffffffe)]))
    hs.copy(baseA, 36); leU32(s0).copy(baseA, baseA.length - 44)
    if (!txmod.PushTx.sFromPreimage(baseA)) continue
    hs.copy(baseB, 36); leU32(0xfffffffe).copy(baseB, baseB.length - 44)
    if (txmod.PushTx.sFromPreimage(baseB)) { tx.inputs[0].sequenceNumber = s0; found = k }
  }
  if (found === null) throw new Error(`link ${which}: the joint grind found nothing`)

  const preA = H.rawPreimage(tx, 0, lock, stageValue, txmod.SIGHASH_ALL_FORKID)
  const preB = H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID)
  if (!baseA.equals(Buffer.from(preA)) || !baseB.equals(Buffer.from(preB))) throw new Error(`link ${which}: the patched preimages disagree with the library's`)

  tx.inputs[0].setScript(unlockFor(m, { preimage: preA, prev: carrierState.cur, ...stageValues }))
  tx.inputs[1].setScript(new bsv.Script().add(pushData(preB)).add(pushData(nextCur)))
  return { tx, carrierIn, tries }
}

async function main () {
  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  const have = utxos.reduce((s, u) => s + u.value, 0)

  // 1. size all three spends against placeholders, to fund the coins for them
  const probe1 = buildFirst('00'.repeat(32), 0, 100000)
  const fee1 = onchain.feeFor(probe1.toBuffer().length)
  const probe2 = buildLink(2, '11'.repeat(32), 1, 100000, '22'.repeat(32), { prev: Buffer.alloc(W), cur: blob1 }, values.w2, blob2)
  const fee2 = onchain.feeFor(probe2.tx.toBuffer().length)
  const probe3 = buildLink(3, '33'.repeat(32), 2, 100000, '44'.repeat(32), { prev: blob1, cur: blob2 }, values.expHint, v.result)
  const fee3 = onchain.feeFor(probe3.tx.toBuffer().length)

  // tx₁ mints a carrier out of nothing, so its coin carries the fee AND that
  // satoshi. tx₂ and tx₃ each spend one carrier and pay one out — it passes
  // through, and their coins need the fee alone.
  const stageValues = [fee1 + CARRIER, fee2, fee3]

  const fundBytes = 12 + utxos.length * 148 + locks.reduce((s, l) => s + l.toBuffer().length + 12, 0) + 34
  const fundFee = onchain.feeFor(fundBytes)
  const need = stageValues.reduce((a, b) => a + b, 0) + fundFee

  console.log('\n  a Groth16 verifier as a chain: one stage per transaction\n')
  console.log(`    wallet    ${wallet.address}   ${n(have)} sat`)
  const names = ['groth16.chain1', 'groth16.chain2', 'groth16.chain3']
  locks.forEach((l, i) => console.log(`    coin ${i}    ${names[i].padEnd(16)} ${n(l.toBuffer().length).padStart(9)} B   funded with ${n(stageValues[i])} sat`))
  console.log(`    funding   ${n(fundBytes).padStart(9)} B, fee ~${n(fundFee)} sat`)
  console.log(`    tx₁       ${n(probe1.toBuffer().length).padStart(9)} B, fee ${n(fee1)} sat`)
  console.log(`    tx₂       ${n(probe2.tx.toBuffer().length).padStart(9)} B, fee ${n(fee2)} sat, ${probe2.tries} nonces`)
  console.log(`    tx₃       ${n(probe3.tx.toBuffer().length).padStart(9)} B, fee ${n(fee3)} sat, ${probe3.tries} nonces`)
  console.log(`    needs     ${n(need)} sat all told`)
  if (have < need) { console.log(`\n    short by ${n(need - have)} sat — send it to ${wallet.address} and run again\n`); process.exit(2) }

  const worst = await onchain.deepestAncestry(utxos)
  if (worst.depth >= 25) { console.log(`\n    an input is ${worst.depth} unconfirmed links deep — this wants a block\n`); process.exit(1) }

  // 2. the funding transaction: three stage coins
  const fund = new bsv.Transaction()
  let funded = 0
  const chosen = []
  for (const u of utxos) {
    fund.from({ txId: u.tx_hash, outputIndex: u.tx_pos, script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(), satoshis: u.value })
    chosen.push(u); funded += u.value
    if (funded >= need + 546) break
  }
  locks.forEach((l, i) => fund.addOutput(new bsv.Transaction.Output({ script: l, satoshis: stageValues[i] })))
  fund.change(wallet.address)
  fund.feePerKb(Math.round(onchain.SAT_PER_BYTE * 1000))
  fund.change(wallet.address)
  fund.sign(wallet.key)
  if (!fund.isFullySigned()) throw new Error('the funding transaction is not fully signed')

  // 3. the three links, against the real txids
  const tx1 = buildFirst(fund.hash, 0, stageValues[0])
  const r1 = check(tx1, 0, locks[0], stageValues[0])

  const c1 = { prev: Buffer.alloc(W), cur: blob1 }
  const l2 = buildLink(2, fund.hash, 1, stageValues[1], tx1.hash, c1, values.w2, blob2)
  const r2a = check(l2.tx, 0, locks[1], stageValues[1])
  const r2b = check(l2.tx, 1, l2.carrierIn, CARRIER)

  const c2 = { prev: blob1, cur: blob2 }
  const l3 = buildLink(3, fund.hash, 2, stageValues[2], l2.tx.hash, c2, values.expHint, v.result)
  const r3a = check(l3.tx, 0, locks[2], stageValues[2])
  const r3b = check(l3.tx, 1, l3.carrierIn, CARRIER)

  console.log(`\n    fund      ${n(fund.toBuffer().length).padStart(9)} B, fee ${n(funded - fund.outputs.reduce((s, o) => s + o.satoshis, 0))} sat`)
  console.log(`    tx₁       ${n(tx1.toBuffer().length).padStart(9)} B   rounds 1–31, A, C ∈ G1   ${r1.ok ? 'verified' : 'REFUSED — ' + r1.err}`)
  console.log(`    tx₂       ${n(l2.tx.toBuffer().length).padStart(9)} B   rounds 32–63, B ∈ G2     ${r2a.ok ? 'verified' : 'REFUSED — ' + r2a.err}`)
  console.log(`                          the carrier it spends    ${r2b.ok ? 'verified' : 'REFUSED — ' + r2b.err}`)
  console.log(`    tx₃       ${n(l3.tx.toBuffer().length).padStart(9)} B   the final exponentiation ${r3a.ok ? 'verified' : 'REFUSED — ' + r3a.err}`)
  console.log(`                          the carrier it spends    ${r3b.ok ? 'verified' : 'REFUSED — ' + r3b.err}`)
  if (![r1, r2a, r2b, r3a, r3b].every((r) => r.ok)) process.exit(1)

  // The last carrier is the receipt: it holds e(α, β), and anyone can read it.
  const last = l3.tx.outputs[0].script.toBuffer()
  if (!last.subarray(last.length - W).equals(v.result)) throw new Error('the last carrier does not hold e(α, β)')
  console.log(`\n    the last carrier holds e(α, β) — ${n(W)} B of state, checked here`)

  if (!BROADCAST) { console.log('\n    (dry run — nothing broadcast)\n'); return }

  const fundId = await woc.broadcast(fund.toBuffer().toString('hex'))
  onchain.noteSpend(chosen.map((u) => `${u.tx_hash}:${u.tx_pos}`),
    fund.outputs.length > 3 ? [{ tx_hash: fundId, tx_pos: 3, value: fund.outputs[3].satoshis, height: 0 }] : [])
  console.log(`\n    funded    ${fundId}`)

  const id1 = await woc.broadcast(tx1.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:0`], [])
  console.log(`    tx₁       ${id1}`)

  const id2 = await woc.broadcast(l2.tx.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:1`, `${id1}:0`], [])
  console.log(`    tx₂       ${id2}`)

  const id3 = await woc.broadcast(l3.tx.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:2`, `${id2}:0`], [])
  console.log(`    tx₃       ${id3}`)

  onchain.record({
    target: 'groth16.chain1 ▸ chain2 ▸ chain3',
    key: 'groth16Chain',
    claim: 'a Groth16 proof of age verified across three transactions, each state split out of the carrier beside it',
    lockBytes: locks.reduce((s, l) => s + l.toBuffer().length, 0),
    deploy: fundId,
    spend: id3,
    chain: [
      { name: 'groth16.chain1', txid: id1, lockBytes: locks[0].toBuffer().length, vout: 0 },
      { name: 'groth16.chain2', txid: id2, lockBytes: locks[1].toBuffer().length, vout: 1 },
      { name: 'groth16.chain3', txid: id3, lockBytes: locks[2].toBuffer().length, vout: 2 }
    ]
  })
  console.log('\n    recorded in deployments.json\n')
}

main().catch((e) => { console.error('\n  ' + (e.message || e) + '\n'); process.exit(1) })
