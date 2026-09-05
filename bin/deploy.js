#!/usr/bin/env node
'use strict'

const bsv = require('@smartledger/bsv')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const { targets } = require('../tools/targets')

// Deploy a module's locking script to mainnet and spend it back.
//
// The whole round trip is built and verified BEFORE anything is broadcast. A
// signed transaction's txid is its own hash, so the spend can be constructed
// against the deployment while the deployment is still sitting in memory — and
// run through `bsv.Script.Interpreter` under the same policy flags as every
// test in this repository. Only then does either one go to a node.
//
//   node bin/deploy.js --list
//   node bin/deploy.js rsa                # build and verify, broadcast nothing
//   node bin/deploy.js rsa --broadcast
//   node bin/deploy.js --all --broadcast

const args = process.argv.slice(2)
const BROADCAST = args.includes('--broadcast')
const names = args.filter((a) => !a.startsWith('--'))
const chosen = args.includes('--all') ? Object.keys(targets) : names

if (args.includes('--list') || (!chosen.length && !args.includes('--all'))) {
  console.log('\n  targets\n')
  for (const [k, t] of Object.entries(targets)) {
    console.log(`  ${k.padEnd(10)} ${String(t.lock.toBuffer().length).padStart(7)} B   ${t.claim}`)
  }
  console.log('\n  node bin/deploy.js <target> [--broadcast]   |   --all\n')
  process.exit(0)
}

const sign = (tx, lockingScript, satoshis) => (privateKey) =>
  bsv.Transaction.Sighash.sign(
    tx, privateKey,
    bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID,
    0, lockingScript, new bsv.crypto.BN(satoshis)
  ).toTxFormat()

/** Build the spend of a deployment, sized so its own fee is covered. */
function buildSpend (target, deployTxid, satoshis, fee) {
  return onchain.buildUnlock({
    txid: deployTxid,
    vout: 0,
    lockingScript: target.lock,
    satoshis,
    shape: target.shape || {},
    fee,
    unlock: ({ tx, lockingScript, satoshis: v, shape }) =>
      target.unlock({ tx, lockingScript, satoshis: v, shape, sign: sign(tx, lockingScript, v) })
  })
}

async function run () {
  const wallet = onchain.loadWallet()
  let utxos = await onchain.spendable(wallet.address)
  const held = utxos.reduce((s, u) => s + u.value, 0)
  const pending = onchain.unconfirmed(utxos)
  console.log(`\n  wallet ${wallet.address}   ${held} sat in ${utxos.length} spendable output(s)` +
    (pending ? `, ${pending} unconfirmed` : ''))
  if (BROADCAST && pending === utxos.length && utxos.length) {
    console.log('  every output is unconfirmed — a node limits how deep an unconfirmed')
    console.log('  chain may go, and each deployment adds two links. If a broadcast comes')
    console.log('  back too-long-mempool-chain, it wants a block, not a retry.')
  }
  console.log('')

  const results = []
  for (const key of chosen) {
    const target = targets[key]
    if (!target) { console.log(`  no target '${key}'`); continue }

    // Two passes: the first learns how big the unlocking script is, the second
    // funds the output with exactly the fee that spend will need.
    const probe = buildSpend(target, '00'.repeat(32), 100000, 1)
    const spendFee = onchain.feeFor(probe.size)
    // A covenant that pins its outputs decides what the input must hold: it pays
    // a fixed amount, and the fee is the remainder. Everything else just needs
    // to cover its own spend.
    const value = target.valueFor ? target.valueFor(spendFee) : spendFee + 1

    const dep = await onchain.buildDeploy(target.lock, { satoshis: value, utxos })
    const deployTxid = dep.tx.hash
    const spend = buildSpend(target, deployTxid, value, spendFee)

    const ok = spend.check.ok
    console.log(`  ${target.name}`)
    console.log(`    ${target.claim}`)
    console.log(`    lock ${target.lock.toBuffer().length.toLocaleString()} B | unlock ${spend.tx.inputs[0].script.toBuffer().length.toLocaleString()} B`)
    console.log(`    deploy tx ${dep.size.toLocaleString()} B, fee ${dep.fee} sat | spend tx ${spend.size.toLocaleString()} B, fee ${spendFee} sat`)
    console.log(`    verified against the interpreter under relay policy: ${ok ? 'yes' : 'NO — ' + spend.check.error}`)

    if (!ok) { results.push({ key, ok: false }); continue }

    if (!BROADCAST) {
      console.log('    (dry run — nothing broadcast)\n')
      results.push({ key, ok: true, dry: true })
      // keep chaining locally so --all sizes every target against real change
      utxos = [{ tx_hash: deployTxid, tx_pos: dep.tx.outputs.length - 1, value: dep.tx.outputs[dep.tx.outputs.length - 1].satoshis }]
      continue
    }

    const deployId = await woc.broadcast(dep.tx.toString())
    console.log(`    deployed  ${deployId}`)
    const changeIndex = dep.tx.outputs.length - 1
    onchain.noteSpend(
      dep.tx.inputs.map((i) => `${i.prevTxId.toString('hex')}:${i.outputIndex}`),
      [{ tx_hash: deployId, tx_pos: changeIndex, value: dep.tx.outputs[changeIndex].satoshis }]
    )
    const spendId = await woc.broadcast(spend.tx.toString())
    console.log(`    spent     ${spendId}\n`)
    onchain.noteSpend([`${deployId}:0`], [])
    onchain.record({ target: target.name, key, claim: target.claim, deploy: deployId, spend: spendId, lockBytes: target.lock.toBuffer().length, value, spendFee })
    results.push({ key, ok: true, deploy: deployId, spend: spendId })

    utxos = await onchain.spendable(wallet.address)
  }

  const bad = results.filter((r) => !r.ok)
  console.log(`  ${results.length - bad.length}/${results.length} ${BROADCAST ? 'on chain' : 'verified'}`)
  process.exit(bad.length ? 1 : 0)
}

run().catch((e) => { console.error('  ' + e.message); process.exit(1) })
