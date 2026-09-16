#!/usr/bin/env node
'use strict'

// DEPLOY A PAIRING AS A CHAIN: one stage per transaction.
//
//   node bin/deploy-chain.js              build, verify and price; broadcast nothing
//   node bin/deploy-chain.js --broadcast
//
// Three transactions, each small enough for a node to pass along:
//
//   funding   two stage coins, and the satoshi the carrier will carry
//   tx₁       the Miller loop            → carrier(∅, f)
//   tx₂       the final exponentiation
//             + carrier(∅, f)            → carrier(f, e(P, Q))
//
// The single-transaction version of this computation (bin/deploy-split.js) is on
// chain and relayed; the three-stage Groth16 version of it was refused for its
// validation time and mined only because a pool took it by hand. Each link here
// asks a node for about two thirds of what the one that relayed did.
//
// Every transaction is built and run through bsv.Script.Interpreter under relay
// policy flags before anything is broadcast, and each is broadcast only after the
// one it depends on has been.

const bsv = require('@smartledger/bsv')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const { policyFlags } = require('../src/run')
const { Asm } = require('../src/asm')
const { minimize } = require('../src/minimize')
const { pushNum, pushData } = require('../src/num')
const H = require('@smartledger/bsv/lib/covenant/helpers')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const carry = require('../src/modules/carry')
const txmod = require('../src/modules/tx')

const BROADCAST = process.argv.includes('--broadcast')
const n = (x) => x.toLocaleString('en-US')
const P = bls.P
const params = { n: P, nn: P }
const W = pairing.STATE_BYTES
const CARRIER = 1

// ── what is being computed ──────────────────────────────────────────────────
const pts = { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] }
const rawF = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P).f
const f = bls.X < 0n ? bls.f12conj(rawF) : rawF
const expected = bls.pairing(bls.G1, bls.G2)
const fBytes = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')
const eBytes = pairing.serialiseF12(pairing.spread(expected, 'r'), 'r')

const millerStage = pairing.chainMiller({ cases: [{ name: 'x', inputs: pts, spend: pts, params }] })
const expStage = pairing.chainExp(expected, { cases: [{ name: 'x', spend: { f }, params }] })

function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return minimize(asm.script(), { label: m.name })
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

function check (tx, i, lock, satoshis) {
  const interp = new bsv.Script.Interpreter()
  let ok = false
  try { ok = interp.verify(tx.inputs[i].script, lock, tx, i, policyFlags(), new bsv.crypto.BN(satoshis)) } catch (e) { return { ok: false, err: e.message } }
  return { ok, err: interp.errstr }
}

/** tx₁: the Miller loop alone, paying the carrier. */
function buildFirst (txid, vout, value) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(txid, 'hex'), outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockMiller, value)
  const w = millerStage.witnessFor({ tx, lockingScript: lockMiller, satoshis: value, spend: pts, inputIndex: 0 })
  tx.inputs[0].setScript(unlockFor(millerStage, { ...pts, ...w }))
  return tx
}

/** tx₂: the exponentiation, beside the carrier tx₁ made. */
function buildSecond (stageTxid, stageVout, stageValue, carrierTxid) {
  const carrierIn = carry.carrierScript(W, { prev: Buffer.alloc(W), cur: fBytes })
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(stageTxid, 'hex'), outputIndex: stageVout, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockExp, stageValue)
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(carrierTxid, 'hex'), outputIndex: 0, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), carrierIn, CARRIER)
  tx.addOutput(new bsv.Transaction.Output({ script: carry.carrierScript(W, { prev: fBytes, cur: eBytes }), satoshis: CARRIER }))
  tx._outputAmount = undefined

  // Two preimages, ground together: hashSequence commits to both inputs, so
  // grinding one invalidates the other.
  const leU32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b }
  const baseA = Buffer.from(H.rawPreimage(tx, 0, lockExp, stageValue, txmod.SIGHASH_ALL_FORKID))
  const baseB = Buffer.from(H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID))
  let tries = 0
  let found = null
  for (let k = 0; k < 500000 && found === null; k++) {
    const s0 = 0xfffffffe - k
    tries++
    const hs = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(0xfffffffe)]))
    hs.copy(baseA, 36); leU32(s0).copy(baseA, baseA.length - 44)
    if (!txmod.PushTx.sFromPreimage(baseA)) continue
    hs.copy(baseB, 36); leU32(0xfffffffe).copy(baseB, baseB.length - 44)
    if (txmod.PushTx.sFromPreimage(baseB)) { tx.inputs[0].sequenceNumber = s0; found = k }
  }
  if (found === null) throw new Error('the joint grind found nothing')

  const preA = H.rawPreimage(tx, 0, lockExp, stageValue, txmod.SIGHASH_ALL_FORKID)
  const preB = H.rawPreimage(tx, 1, carrierIn, CARRIER, txmod.SIGHASH_ALL_FORKID)
  if (!baseA.equals(Buffer.from(preA)) || !baseB.equals(Buffer.from(preB))) throw new Error('the patched preimages disagree with the library\'s')

  tx.inputs[0].setScript(unlockFor(expStage, { preimage: preA, data: fBytes, ...pairing.finalExp.hint(pairing.spread(f, 'f'), params) }))
  tx.inputs[1].setScript(new bsv.Script().add(pushData(preB)).add(pushData(eBytes)))
  return { tx, carrierIn, tries }
}

async function main () {
  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  const have = utxos.reduce((s, u) => s + u.value, 0)

  // 1. size both spends against placeholders, so the coins can be funded for them
  const probe1 = buildFirst('00'.repeat(32), 0, 100000)
  const fee1 = onchain.feeFor(probe1.toBuffer().length)
  const probe2 = buildSecond('11'.repeat(32), 1, 100000, '22'.repeat(32))
  const fee2 = onchain.feeFor(probe2.tx.toBuffer().length)
  // Each stage coin's whole value becomes its transaction's fee, less whatever
  // the carrier output carries away — so the coin has to hold the fee PLUS the
  // carrier's satoshi, not the fee less it. Funding it at `fee − 1` underpays by
  // exactly two satoshis, which is what GorillaPool refused the first time this
  // ran: "minimum expected fee: 35366, actual fee: 35364".
  //
  // tx₂ spends the carrier as well, so that satoshi comes back in and its coin
  // needs only the fee.
  const valueMiller = fee1 + CARRIER
  const valueExp = fee2

  const fundBytes = 12 + utxos.length * 148 + (lockMiller.toBuffer().length + 12) + (lockExp.toBuffer().length + 12) + 34
  const fundFee = onchain.feeFor(fundBytes)
  const need = valueMiller + valueExp + CARRIER + fundFee

  console.log('\n  a pairing as a chain: one stage per transaction\n')
  console.log(`    wallet    ${wallet.address}   ${n(have)} sat`)
  console.log(`    coin 0    pairing.chainMiller ${n(lockMiller.toBuffer().length).padStart(9)} B   funded with ${n(valueMiller)} sat`)
  console.log(`    coin 1    pairing.chainExp    ${n(lockExp.toBuffer().length).padStart(9)} B   funded with ${n(valueExp)} sat`)
  console.log(`    funding   ${n(fundBytes).padStart(9)} B, fee ~${n(fundFee)} sat`)
  console.log(`    tx₁       ${n(probe1.toBuffer().length).padStart(9)} B, fee ${n(fee1)} sat`)
  console.log(`    tx₂       ${n(probe2.tx.toBuffer().length).padStart(9)} B, fee ${n(fee2)} sat, ${probe2.tries} nonces to grind both preimages`)
  console.log(`    needs     ${n(need)} sat all told`)
  if (have < need) { console.log(`\n    short by ${n(need - have)} sat — send it to ${wallet.address} and run again\n`); process.exit(2) }

  const worst = await onchain.deepestAncestry(utxos)
  if (worst.depth >= 25) { console.log(`\n    an input is ${worst.depth} unconfirmed links deep — this wants a block\n`); process.exit(1) }

  // 2. the funding transaction
  const fund = new bsv.Transaction()
  let funded = 0
  const chosen = []
  for (const u of utxos) {
    fund.from({ txId: u.tx_hash, outputIndex: u.tx_pos, script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(), satoshis: u.value })
    chosen.push(u); funded += u.value
    if (funded >= need + 546) break
  }
  fund.addOutput(new bsv.Transaction.Output({ script: lockMiller, satoshis: valueMiller }))
  fund.addOutput(new bsv.Transaction.Output({ script: lockExp, satoshis: valueExp }))
  fund.change(wallet.address)
  fund.feePerKb(Math.round(onchain.SAT_PER_BYTE * 1000))
  fund.change(wallet.address)
  fund.sign(wallet.key)
  if (!fund.isFullySigned()) throw new Error('the funding transaction is not fully signed')

  // 3. both links, against the real txids
  const tx1 = buildFirst(fund.hash, 0, valueMiller)
  const r1 = check(tx1, 0, lockMiller, valueMiller)
  const second = buildSecond(fund.hash, 1, valueExp, tx1.hash)
  const r2a = check(second.tx, 0, lockExp, valueExp)
  const r2b = check(second.tx, 1, second.carrierIn, CARRIER)

  console.log(`\n    fund      ${n(fund.toBuffer().length).padStart(9)} B, fee ${n(funded - fund.outputs.reduce((s, o) => s + o.satoshis, 0))} sat`)
  console.log(`    tx₁       ${n(tx1.toBuffer().length).padStart(9)} B   the Miller loop        ${r1.ok ? 'verified' : 'REFUSED — ' + r1.err}`)
  console.log(`    tx₂       ${n(second.tx.toBuffer().length).padStart(9)} B   the exponentiation     ${r2a.ok ? 'verified' : 'REFUSED — ' + r2a.err}`)
  console.log(`                          the carrier it spends  ${r2b.ok ? 'verified' : 'REFUSED — ' + r2b.err}`)
  if (!r1.ok || !r2a.ok || !r2b.ok) process.exit(1)

  if (!BROADCAST) { console.log('\n    (dry run — nothing broadcast)\n'); return }

  const fundId = await woc.broadcast(fund.toBuffer().toString('hex'))
  onchain.noteSpend(chosen.map((u) => `${u.tx_hash}:${u.tx_pos}`),
    fund.outputs.length > 2 ? [{ tx_hash: fundId, tx_pos: 2, value: fund.outputs[2].satoshis, height: 0 }] : [])
  console.log(`\n    funded    ${fundId}`)

  const id1 = await woc.broadcast(tx1.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:0`], [])
  console.log(`    tx₁       ${id1}`)

  const id2 = await woc.broadcast(second.tx.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:1`, `${id1}:0`], [])
  console.log(`    tx₂       ${id2}`)

  onchain.record({
    target: 'pairing.chainMiller ▸ pairing.chainExp',
    key: 'pairingChain',
    claim: 'a complete BLS12-381 pairing, one stage per transaction, chained through a carrier coin',
    lockBytes: lockMiller.toBuffer().length + lockExp.toBuffer().length,
    deploy: fundId,
    spend: id2,
    chain: [
      { name: 'pairing.chainMiller', txid: id1, lockBytes: lockMiller.toBuffer().length, vout: 0 },
      { name: 'pairing.chainExp', txid: id2, lockBytes: lockExp.toBuffer().length, vout: 1 }
    ]
  })
  console.log('\n    recorded in deployments.json\n')
}

main().catch((e) => { console.error('\n  ' + (e.message || e) + '\n'); process.exit(1) })
