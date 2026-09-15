#!/usr/bin/env node
'use strict'

// DEPLOY A GROTH16 VERIFIER: three coins, spent together.
//
//   node bin/deploy-groth16.js              build, verify and price; broadcast nothing
//   node bin/deploy-groth16.js --broadcast
//
// The coin moves for a zero-knowledge proof that its spender was at least 21 in
// 2026 — a snarkjs proof over BLS12-381, verified by Bitcoin Script with its
// points checked into their subgroups. The verifier is past the script policy,
// so it is three coins: one funding transaction creates them at outputs 0, 1
// and 2, and one spending transaction consumes all three and publishes the blob
// they must agree on.
//
// The spend carries NO change output. tx.commitData requires the output set to
// be exactly the blob, so every satoshi the three coins hold becomes its fee,
// and the funding sizes them for that in advance.
//
// Nothing is broadcast until both transactions are built and every input of
// the spend has been run through bsv.Script.Interpreter under relay policy
// flags. The spend is built by src/groth16spend.js — the same code
// tools/groth16-split.js proves — against the real funding txid.

const fs = require('fs')
const path = require('path')
const bsv = require('@smartledger/bsv')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const split = require('../src/modules/groth16split')
const spendlib = require('../src/groth16spend')
const age = require('../test/vectors/groth16-age')

const BROADCAST = process.argv.includes('--broadcast')
const n = (x) => x.toLocaleString('en-US')
const coinsAt = (txid, values) => values.map((satoshis, vout) => ({ txid, vout, satoshis }))

async function main () {
  const v = split.verifier(age.vk, age.statement, { proof: age.proof })
  const locks = spendlib.lockingScripts(v)
  const lockBytes = locks.map((s) => s.toBuffer().length)

  // 1. size the spend. Its unlocking scripts are a fixed length whatever the
  //    funding txid and the amounts are, so a placeholder prices it exactly.
  const probe = spendlib.buildSpend(v, age.proof, coinsAt('00'.repeat(32), [1, 1, 1]), { locks })
  const spendBytes = probe.tx.toBuffer().length
  const spendFee = onchain.feeFor(spendBytes)
  // Which coin carries the fee does not matter — all three are spent together
  // and the spend has no change — so two hold a satoshi and the third the rest.
  const values = [1, 1, spendFee - 2]

  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  const have = utxos.reduce((s, u) => s + u.value, 0)

  // 2. price the funding transaction before choosing its inputs
  const fundBytes = (nIn) => 12 + nIn * 148 + lockBytes.reduce((s, b) => s + b + 12, 0) + 34
  let funded = 0
  let used = 0
  const chosen = []
  for (const u of utxos) {
    chosen.push(u); funded += u.value; used++
    if (funded >= spendFee + onchain.feeFor(fundBytes(used)) + 546) break
  }
  const need = spendFee + onchain.feeFor(fundBytes(Math.max(used, 1)))

  console.log('\n  a Groth16 verifier across three inputs of one transaction\n')
  console.log(`    wallet   ${wallet.address}   ${n(have)} sat in ${utxos.length} output(s)`)
  locks.forEach((s, i) => console.log(`    coin ${i}   ${['A, C ∈ G1; rounds 1–31', 'rounds 32–63; B ∈ G2', 'final exponentiation'][i].padEnd(26)} ${n(lockBytes[i]).padStart(9)} B`))
  console.log(`    spend    ${n(spendBytes).padStart(9)} B, fee ${n(spendFee)} sat`)
  console.log(`    funding  ~${n(fundBytes(Math.max(used, 1)))} B, fee ~${n(onchain.feeFor(fundBytes(Math.max(used, 1))))} sat`)
  console.log(`    needs    ${n(need)} sat all told`)

  if (funded < need) {
    console.log(`\n    the wallet is ${n(need - funded)} sat short.`)
    console.log(`    send at least that to ${wallet.address} from a CONFIRMED output, then run this again.`)
    // The construction can still be proven without funds: verify the probe.
    const r = spendlib.verifyInputs(probe.tx, locks, coinsAt('00'.repeat(32), [1, 1, 1]))
    console.log(`    (the spend, against a placeholder funding txid: ${r.every((x) => x.ok) ? 'all three inputs verify' : 'REFUSED — ' + r.map((x) => x.err).join('; ')})\n`)
    process.exit(2)
  }

  const worst = await onchain.deepestAncestry(chosen)
  if (worst.depth >= 25) {
    console.log(`\n    an input is ${worst.depth} unconfirmed links deep (${worst.txid.slice(0, 16)}…) — this wants a block, not a retry\n`)
    process.exit(1)
  }

  // 3. the funding transaction: three coins in one
  const fund = new bsv.Transaction()
  for (const u of chosen) {
    fund.from({ txId: u.tx_hash, outputIndex: u.tx_pos, script: bsv.Script.buildPublicKeyHashOut(wallet.address).toHex(), satoshis: u.value })
  }
  locks.forEach((lock, i) => fund.addOutput(new bsv.Transaction.Output({ script: lock, satoshis: values[i] })))
  fund.change(wallet.address)
  fund.feePerKb(Math.round(onchain.SAT_PER_BYTE * 1000))
  fund.change(wallet.address)
  fund.sign(wallet.key)
  if (!fund.isFullySigned()) throw new Error('the funding transaction is not fully signed')
  const fundSize = fund.toBuffer().length
  const fundFee = funded - fund.outputs.reduce((s, o) => s + o.satoshis, 0)

  // 4. the spend, against the real funding txid
  const coins = coinsAt(fund.hash, values)
  const { tx, unlocks, grind } = spendlib.buildSpend(v, age.proof, coins, { locks })
  const tip = await woc.chainInfo()
  if (tx.nLockTime >= tip.blocks) throw new Error(`the ground nLockTime ${tx.nLockTime} is not below the chain height ${tip.blocks}, so the spend would not be final`)

  // 5. every input, before anything goes anywhere
  const results = spendlib.verifyInputs(tx, locks, coins)
  console.log(`\n    fund     ${n(fundSize).padStart(9)} B, fee ${n(fundFee)} sat, ${chosen.length} input(s)`)
  console.log(`    spend    ${n(tx.toBuffer().length).padStart(9)} B, fee ${n(values.reduce((s, x) => s + x, 0))} sat, nLockTime ${grind.nLockTime} after ${n(grind.tries)} tries`)
  results.forEach((r, i) => console.log(`    input ${i}  ${n(unlocks[i].toBuffer().length).padStart(9)} B unlock  ${r.ok ? 'verified' : 'REFUSED — ' + r.err}`))
  if (results.some((r) => !r.ok)) process.exit(1)

  if (!BROADCAST) { console.log('\n    (dry run — nothing broadcast)\n'); return }

  const fundId = await woc.broadcast(fund.toBuffer().toString('hex'))
  onchain.noteSpend(chosen.map((u) => `${u.tx_hash}:${u.tx_pos}`),
    fund.outputs.length > 3 ? [{ tx_hash: fundId, tx_pos: 3, value: fund.outputs[3].satoshis, height: 0 }] : [])
  console.log(`\n    funded    ${fundId}`)

  // If the spend is refused after the coins exist, they are not lost: the spend
  // is a function of the funding txid, and this rebuilds it. Keep the bytes
  // anyway, so a retry does not depend on anything but a broadcast.
  const spendHex = tx.toBuffer().toString('hex')
  let spendId
  try {
    spendId = await woc.broadcast(spendHex)
  } catch (e) {
    const keep = path.join(__dirname, '..', `.pending-spend-${fundId}.hex`)
    fs.writeFileSync(keep, spendHex + '\n', { mode: 0o600 })
    console.log(`\n    the spend was not accepted: ${e.message}`)
    console.log(`    its bytes are in ${path.basename(keep)}; the coins are at ${fundId}:0..2\n`)
    process.exit(1)
  }
  onchain.noteSpend(coins.map((c) => `${c.txid}:${c.vout}`), [])
  console.log(`    spent     ${spendId}`)

  onchain.record({
    target: 'groth16.stage1 ▸ groth16.stage2 ▸ groth16.stage3',
    key: 'groth16Split',
    claim: 'a zero-knowledge proof of age, verified with its points checked into their subgroups, across three inputs of one transaction',
    lockBytes: lockBytes.reduce((s, b) => s + b, 0),
    deploy: fundId,
    spend: spendId,
    spendBytes: tx.toBuffer().length,
    feeSat: fundFee + values.reduce((s, x) => s + x, 0),
    nLockTime: grind.nLockTime,
    inputs: [
      { name: 'groth16.stage1', lockBytes: lockBytes[0], unlockBytes: unlocks[0].toBuffer().length, vout: 0 },
      { name: 'groth16.stage2', lockBytes: lockBytes[1], unlockBytes: unlocks[1].toBuffer().length, vout: 1 },
      { name: 'groth16.stage3', lockBytes: lockBytes[2], unlockBytes: unlocks[2].toBuffer().length, vout: 2 }
    ]
  })
  console.log('\n    recorded in deployments.json\n')
}

main().catch((e) => { console.error('\n  ' + (e.message || e) + '\n'); process.exit(1) })
