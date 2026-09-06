#!/usr/bin/env node
'use strict'

// DEPLOY A WHOLE PAIRING: two coins, spent together.
//
//   node bin/deploy-split.js              build and verify, broadcast nothing
//   node bin/deploy-split.js --broadcast
//
// One funding transaction creates both coins; one spending transaction consumes
// them together and publishes the Miller output they must agree on. The spend
// carries NO change output — `tx.commitData` requires the output set to be
// exactly the data output — so every satoshi the two coins hold becomes its
// fee, and the funding has to size them for it in advance.
//
// Everything is built and run through bsv.Script.Interpreter before anything is
// broadcast, the same as every other deployment here. The difference is that
// there are two inputs to verify rather than one, and their preimages have to
// be ground together (tools/pairing-split.js explains why).

const bsv = require('@smartledger/bsv')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const { policyFlags } = require('../src/run')
const { Asm } = require('../src/asm')
const { pushNum, pushData } = require('../src/num')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const txmod = require('../src/modules/tx')
const H = require('@smartledger/bsv/lib/covenant/helpers')

const BROADCAST = process.argv.includes('--broadcast')
const P = bls.P
const params = { n: P, nn: P }
const n = (x) => x.toLocaleString('en-US')

// ── the two coins ───────────────────────────────────────────────────────────
const pts = { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] }
const rawF = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P).f
const f = bls.X < 0n ? bls.f12conj(rawF) : rawF
const expected = bls.pairing(bls.G1, bls.G2)
const data = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')

const publish = pairing.publish({ cases: [{ name: 'x', inputs: pts, spend: pts, params }] })
const consume = pairing.consume(expected, { cases: [{ name: 'x', spend: { f }, params }] })

function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return asm.script()
}
const lockA = coin(publish)
const lockB = coin(consume)

const witnessesFor = (preA, preB) => {
  const { witnesses } = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P)
  const a = { ...pts, preimage: preA }
  witnesses.forEach(([x, y], k) => { a[`w${k}a`] = x; a[`w${k}b`] = y })
  const b = { preimage: preB, data, ...pairing.finalExp.hint(pairing.spread(f, 'f'), params) }
  return [a, b]
}
const unlockFor = (m, values) => {
  const u = new bsv.Script()
  for (const i of m.inputs) u.add(i.kind === 'bytes' ? pushData(values[i.name]) : pushNum(values[i.name]))
  return u
}

// ── the spend, built for a given pair of coin values ────────────────────────
//
// The preimage commits to each input's amount, so the values have to be chosen
// before the preimages are ground — and the fee depends on the size, which
// depends on the preimages. It converges in one step because the unlocking
// scripts are a fixed length whatever the amounts are: build once with a guess,
// measure, then build again with the values that measurement implies.
function buildSpend (txidA, voutA, valA, txidB, voutB, valB) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(txidA, 'hex'), outputIndex: voutA, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockA, valA)
  tx.addInput(new bsv.Transaction.Input({ prevTxId: Buffer.from(txidB, 'hex'), outputIndex: voutB, script: new bsv.Script(), sequenceNumber: 0xfffffffe }), lockB, valB)
  tx.addOutput(txmod.dataOutput(pairing.STATE_BYTES, data))
  tx._outputAmount = undefined

  const HASHSEQ_AT = 36
  const seqOffset = (buf) => buf.length - 44
  const leU32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b }
  const baseA = Buffer.from(H.rawPreimage(tx, 0, lockA, valA, txmod.SIGHASH_ALL_FORKID))
  const baseB = Buffer.from(H.rawPreimage(tx, 1, lockB, valB, txmod.SIGHASH_ALL_FORKID))

  let preA = null
  let preB = null
  let tries = 0
  for (let k = 0; k < 500000 && !preA; k++) {
    const s0 = 0xfffffffe - k
    const s1 = 0xfffffffe
    const hs = bsv.crypto.Hash.sha256sha256(Buffer.concat([leU32(s0), leU32(s1)]))
    hs.copy(baseA, HASHSEQ_AT); leU32(s0).copy(baseA, seqOffset(baseA))
    tries++
    if (!txmod.PushTx.sFromPreimage(baseA)) continue
    hs.copy(baseB, HASHSEQ_AT); leU32(s1).copy(baseB, seqOffset(baseB))
    if (txmod.PushTx.sFromPreimage(baseB)) {
      tx.inputs[0].sequenceNumber = s0
      tx.inputs[1].sequenceNumber = s1
      preA = Buffer.from(baseA); preB = Buffer.from(baseB)
    }
  }
  if (!preA) throw new Error('joint grind failed')
  // hand-patched offsets, checked against the ones the library builds
  if (!H.rawPreimage(tx, 0, lockA, valA, txmod.SIGHASH_ALL_FORKID).equals(preA) ||
      !H.rawPreimage(tx, 1, lockB, valB, txmod.SIGHASH_ALL_FORKID).equals(preB)) {
    throw new Error('the patched preimages do not match the ones bsv builds')
  }

  const [wa, wb] = witnessesFor(preA, preB)
  const unlockA = unlockFor(publish, wa)
  const unlockB = unlockFor(consume, wb)
  tx.inputs[0].setScript(unlockA)
  tx.inputs[1].setScript(unlockB)
  return { tx, unlockA, unlockB, tries }
}

async function main () {
  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  const have = utxos.reduce((s, u) => s + u.value, 0)
  console.log(`\n  wallet ${wallet.address}   ${n(have)} sat`)

  // Look before broadcasting. A node limits unconfirmed ancestors to 25 by
  // default, over the whole history behind every input — including history this
  // wallet did not make. A funding output that looks ordinary can be forty
  // links deep in its sender's own chain, and finding that out from the node
  // costs a round trip and a confusing error.
  const worst = await onchain.deepestAncestry(utxos)
  if (worst.depth) {
    console.log(`  deepest unconfirmed ancestry: ${worst.depth}${worst.depth >= 25 ? ' — AT OR PAST the usual limit of 25' : ''}  (${worst.txid.slice(0, 16)}…)`)
    if (worst.depth >= 25) {
      console.log('  a transaction built on that will come back too-long-mempool-chain.')
      console.log('  it wants a block, not a retry.\n')
      if (BROADCAST) process.exit(1)
    }
  }

  // 1. size the spend, so the coins can be funded to pay for it
  const probe = buildSpend('00'.repeat(32), 0, 1, '11'.repeat(32), 0, 100000)
  const spendBytes = probe.tx.toBuffer().length
  const spendFee = onchain.feeFor(spendBytes)
  const valA = 1
  const valB = spendFee - valA

  // 2. the funding transaction: both coins in one
  // COUNT and VALUE are different quantities, and the first version of this
  // used one where it needed the other: `funded * 148` with `funded` holding
  // satoshis rather than inputs, which made the estimated size astronomical,
  // the estimated fee unreachable, and the loop sweep every output the wallet
  // had — including three unconfirmed ones sitting on chains this transaction
  // then inherited. The node called it too-long-mempool-chain, which is true
  // and is not where the mistake was.
  //
  // This is the third funding bug of the same shape here (see src/onchain.js),
  // and all three were invisible until a transaction was large enough that
  // sweeping the wallet mattered.
  const fund = new bsv.Transaction()
  let funded = 0
  let used = 0
  const fundBytes = (nIn) => 12 + nIn * 148 + lockA.toBuffer().length + lockB.toBuffer().length + 40 + 34
  for (const u of utxos) {
    fund.from({ txId: u.tx_hash, outputIndex: u.tx_pos, script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(), satoshis: u.value })
    funded += u.value
    used++
    if (funded >= valA + valB + onchain.feeFor(fundBytes(used)) + 546) break
  }
  if (funded < valA + valB + onchain.feeFor(fundBytes(used))) {
    throw new Error(`the wallet holds ${n(funded)} satoshis across ${used} output(s); this needs ${n(valA + valB + onchain.feeFor(fundBytes(used)))}`)
  }
  console.log(`  funding from ${fund.inputs.length} input(s):`)
  for (const i of fund.inputs) {
    const u = utxos.find((x) => x.tx_hash === i.prevTxId.toString('hex') && x.tx_pos === i.outputIndex)
    console.log(`    ${String(u ? u.value : '?').padStart(9)} sat  ${u && u.height ? 'confirmed at ' + u.height : 'UNCONFIRMED'}  ${i.prevTxId.toString('hex').slice(0, 16)}…`)
  }
  fund.addOutput(new bsv.Transaction.Output({ script: lockA, satoshis: valA }))
  fund.addOutput(new bsv.Transaction.Output({ script: lockB, satoshis: valB }))
  fund.change(wallet.address)
  fund.feePerKb(Math.round(onchain.SAT_PER_BYTE * 1000))
  fund.change(wallet.address)
  fund.sign(wallet.key)
  const fundSize = fund.toBuffer().length
  const fundFee = funded - fund.outputs.reduce((s, o) => s + o.satoshis, 0)
  if (fundFee < 0) throw new Error(`the wallet holds ${n(funded)} satoshis; this needs ${n(valA + valB + onchain.feeFor(fundSize))}`)

  // 3. the spend, against the real funding txid
  const txid = fund.hash
  const { tx, unlockA, unlockB, tries } = buildSpend(txid, 0, valA, txid, 1, valB)

  // 4. verify BOTH inputs before anything goes anywhere
  const check = (i, unlock, lock, sats) => {
    const interp = new bsv.Script.Interpreter()
    let ok = false
    try { ok = interp.verify(unlock, lock, tx, i, policyFlags(), new bsv.crypto.BN(sats)) } catch (e) { return { ok: false, err: e.message } }
    return { ok, err: interp.errstr }
  }
  const rA = check(0, unlockA, lockA, valA)
  const rB = check(1, unlockB, lockB, valB)

  console.log('\n  a complete BLS12-381 pairing, across two inputs of one spend\n')
  console.log(`    fund   ${n(fundSize).padStart(9)} B, fee ${n(fundFee)} sat   two coins: ${n(valA)} and ${n(valB)} sat`)
  console.log(`    spend  ${n(tx.toBuffer().length).padStart(9)} B, fee ${n(valA + valB)} sat   ${tries} nonces to grind both preimages`)
  console.log(`    input 0  pairing.publish  ${n(lockA.toBuffer().length).padStart(9)} B lock  ${rA.ok ? 'verified' : 'REFUSED — ' + rA.err}`)
  console.log(`    input 1  pairing.consume  ${n(lockB.toBuffer().length).padStart(9)} B lock  ${rB.ok ? 'verified' : 'REFUSED — ' + rB.err}`)
  if (!rA.ok || !rB.ok) process.exit(1)

  if (!BROADCAST) { console.log('\n    (dry run — nothing broadcast)\n'); return }

  const fundHex = fund.toBuffer().toString('hex')
  const fundId = await woc.broadcast(fundHex)
  onchain.noteSpend(fund.inputs.map((i) => `${i.prevTxId.toString('hex')}:${i.outputIndex}`),
    fund.outputs.length > 2 ? [{ tx_hash: fundId, tx_pos: 2, value: fund.outputs[2].satoshis, height: 0 }] : [])
  console.log(`\n    funded    ${fundId}`)

  const spendId = await woc.broadcast(tx.toBuffer().toString('hex'))
  onchain.noteSpend([`${fundId}:0`, `${fundId}:1`], [])
  console.log(`    spent     ${spendId}`)

  onchain.record({
    // `target` and `key` are what tools/verify-chain.js reads; recording them
    // as `name` produced a verified deployment called "undefined".
    target: 'pairing.publish ▸ pairing.consume',
    key: 'pairingSplit',
    claim: 'a complete BLS12-381 pairing, evaluated across two inputs of one transaction',
    lockBytes: lockA.toBuffer().length + lockB.toBuffer().length,
    deploy: fundId,
    spend: spendId,
    inputs: [
      { name: 'pairing.publish', lockBytes: lockA.toBuffer().length, vout: 0 },
      { name: 'pairing.consume', lockBytes: lockB.toBuffer().length, vout: 1 }
    ]
  })
  console.log('\n    recorded in deployments.json\n')
}

main().catch((e) => { console.error('\n  ' + (e.message || e) + '\n'); process.exit(1) })
