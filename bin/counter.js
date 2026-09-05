#!/usr/bin/env node
'use strict'

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { pushData } = require('../src/num')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const recipes = require('../src/recipes')
const txMod = require('../src/modules/tx')
const stateMod = require('../src/modules/state')

// Deploy a counter coin and advance it, on chain, one transaction per step.
//
// Every other deployment here is a coin that moves once. This one is a sequence:
// each spend pays an output carrying the same script with the counter one
// higher, and that output is what the next spend consumes. The state is not
// recorded alongside the chain — the state IS the chain.
//
//   node bin/counter.js            build and verify, broadcast nothing
//   node bin/counter.js --broadcast --steps 3

const args = process.argv.slice(2)
const BROADCAST = args.includes('--broadcast')
const STEPS = Number((args.find((a) => a.startsWith('--steps=')) || '').split('=')[1] || 3)
const W = 8
const FEE = 250
const START = 0n

const m = recipes.counterCoin({ from: START, stateWidth: W, fee: FEE })

function coinAt (v) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ ...i })))
  m.emit(asm, { state: stateMod.le(v, W) })
  asm.num(1, 'true')
  return new bsv.Script(Buffer.concat([asm.script().toBuffer(), m.tail({ state: stateMod.le(v, W) })]))
}

/** One step: spend the coin at `at`, paying the coin at `at + 1`. */
function step (at, txid, vout, value) {
  const lock = coinAt(at)
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(txid, 'hex'), outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), lock, value)

  const w = txMod.recreateWitness({ tx, lockingScript: lock, satoshis: value, spend: { next: stateMod.le(at + 1n, W) } }, W, FEE)
  tx.inputs[0].setScript(new bsv.Script().add(pushData(w.preimage)).add(pushData(w.next)))

  const check = onchain.verifyLocally(tx, lock, value)
  return { tx, lock, check, next: tx.outputs[0].satoshis }
}

async function main () {
  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  console.log(`\n  wallet ${wallet.address}   ${utxos.reduce((s, u) => s + u.value, 0)} sat\n`)

  const funding = FEE * (STEPS + 1) + 500
  const lock0 = coinAt(START)
  const dep = await onchain.buildDeploy(lock0, { satoshis: funding, utxos })
  console.log(`  counter coin       ${lock0.toBuffer().length} bytes, starting at ${START}`)
  console.log(`  funding            ${funding} sat, deploy tx ${dep.size.toLocaleString()} B, fee ${dep.fee} sat`)

  // Every step is built and verified before anything is sent, including the
  // steps that spend outputs which do not exist yet — a signed transaction's
  // txid is its own hash, so the whole sequence is knowable in advance.
  let txid = dep.tx.hash
  let value = funding
  let at = START
  const steps = []
  for (let i = 0; i < STEPS; i++) {
    const s = step(at, txid, 0, value)
    steps.push({ from: at, to: at + 1n, ...s })
    if (!s.check.ok) break
    txid = s.tx.hash; value = s.next; at += 1n
  }

  for (const s of steps) {
    console.log(`  ${String(s.from).padStart(3)} → ${String(s.to).padEnd(3)}  ${s.check.ok ? 'verified' : 'NOT VERIFIED — ' + s.check.error}   ${s.tx.toBuffer().length.toLocaleString()} B`)
  }
  if (!steps.every((s) => s.check.ok)) { console.log('\n  refusing to broadcast a sequence that does not verify\n'); process.exit(1) }

  if (!BROADCAST) { console.log('\n  (dry run — nothing broadcast)\n'); return }

  const depId = await woc.broadcast(dep.tx.toString())
  console.log(`\n  deployed  ${depId}`)
  const change = dep.tx.outputs.length - 1
  onchain.noteSpend(dep.tx.inputs.map((i) => `${i.prevTxId.toString('hex')}:${i.outputIndex}`),
    [{ tx_hash: depId, tx_pos: change, value: dep.tx.outputs[change].satoshis }])

  const ids = []
  for (const s of steps) {
    const id = await woc.broadcast(s.tx.toString())
    console.log(`  ${String(s.from).padStart(3)} → ${String(s.to).padEnd(3)}  ${id}`)
    ids.push({ from: String(s.from), to: String(s.to), txid: id })
  }
  onchain.record({
    target: 'tx.transition ▸ state.counter', key: 'counter',
    claim: `a coin advanced ${STEPS} times on chain, each spend paying the coin the next spend consumed`,
    deploy: depId, spend: ids[ids.length - 1].txid,
    lockBytes: lock0.toBuffer().length, lockHex: lock0.toHex(),
    value: funding, spendFee: FEE, steps: ids
  })
  console.log(`\n  the counter is at ${START + BigInt(STEPS)}, and every step is a transaction\n`)
}

main().catch((e) => { console.error('  ' + e.message); process.exit(1) })
