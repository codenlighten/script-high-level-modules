#!/usr/bin/env node
'use strict'

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { pushData, pushNum } = require('../src/num')
const onchain = require('../src/onchain')
const woc = require('../src/woc')
const recipes = require('../src/recipes')
const txMod = require('../src/modules/tx')
const stateMod = require('../src/modules/state')

// Deploy a stateful coin and run it, on chain, one transaction per step.
//
// Every other deployment here is a coin that moves once. These are sequences:
// each spend pays an output carrying the same script with its state moved on,
// and that output is what the next spend consumes. The state is not recorded
// alongside the chain — the state IS the chain.
//
//   node bin/sequence.js counter --steps=3
//   node bin/sequence.js budget --broadcast
//
// The two differ only in what a step means, so they share everything else.

const args = process.argv.slice(2)
const BROADCAST = args.includes('--broadcast')
const WHICH = args.find((a) => !a.startsWith('--')) || 'counter'
const STEPS = Number((args.find((a) => a.startsWith('--steps=')) || '').split('=')[1] || 3)
const W = 8
const FEE = 250

const PAYEES = [Buffer.alloc(20, 0x11), Buffer.alloc(20, 0x22), Buffer.alloc(20, 0x33)]

const RECIPES = {
  counter: {
    start: 0n,
    describe: (v) => `at ${v}`,
    module: () => recipes.counterCoin({ from: 0n, stateWidth: W, fee: FEE }),
    funding: (steps) => FEE * (steps + 1) + 500,
    // one step: the successor's state is one higher, and nothing is paid out
    step: (at, i) => ({ next: at + 1n, spend: { next: stateMod.le(at + 1n, W) } }),
    witness: (ctx, sp) => txMod.recreateWitness(ctx, W, FEE),
    unlock: (w) => new bsv.Script().add(pushData(w.preimage)).add(pushData(w.next)),
    label: (from, to) => `${from} → ${to}`
  },
  budget: {
    start: 1500n,
    describe: (v) => `${v} satoshis of allowance`,
    module: () => recipes.budgetCoin({ allowance: 1500n, stateWidth: W, fee: FEE }),
    funding: (steps) => 1500 + FEE * (steps + 1),
    // one step: pay somebody, and the allowance falls by exactly that
    step: (at, i) => {
      const amount = [600n, 500n, 400n][i % 3]
      return { next: at - amount, amount, payee: PAYEES[i % PAYEES.length], spend: { next: stateMod.le(at - amount, W), amount, payee: PAYEES[i % PAYEES.length] } }
    },
    witness: (ctx, sp) => txMod.payingWitness({ ...ctx, spend: sp.spend }, W, FEE),
    unlock: (w) => new bsv.Script().add(pushData(w.preimage)).add(pushData(w.next)).add(pushNum(w.amount)).add(pushData(w.payee)),
    label: (from, to) => `pays, ${from} → ${to} left`
  }
}

const R = RECIPES[WHICH]
if (!R) { console.log(`  no sequence '${WHICH}' — try counter or budget`); process.exit(1) }
const START = R.start
const m = R.module()

function coinAt (v) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ ...i })))
  m.emit(asm, { state: stateMod.le(v, W) })
  asm.num(1, 'true')
  return new bsv.Script(Buffer.concat([asm.script().toBuffer(), m.tail({ state: stateMod.le(v, W) })]))
}

/** One step: spend the coin at `at`, paying the coin it becomes. */
function step (at, i, txid, vout, value) {
  const lock = coinAt(at)
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(txid, 'hex'), outputIndex: vout, script: new bsv.Script(), sequenceNumber: 0xffffffff
  }), lock, value)

  const sp = R.step(at, i)
  const w = R.witness({ tx, lockingScript: lock, satoshis: value, spend: sp.spend }, sp)
  tx.inputs[0].setScript(R.unlock(w))

  const check = onchain.verifyLocally(tx, lock, value)
  return { tx, lock, check, next: tx.outputs[0].satoshis, to: sp.next }
}

async function main () {
  const wallet = onchain.loadWallet()
  const utxos = await onchain.spendable(wallet.address)
  console.log(`\n  wallet ${wallet.address}   ${utxos.reduce((s, u) => s + u.value, 0)} sat\n`)

  const funding = R.funding(STEPS)
  const lock0 = coinAt(START)
  const dep = await onchain.buildDeploy(lock0, { satoshis: funding, utxos })
  console.log(`  ${WHICH} coin${' '.repeat(Math.max(0, 12 - WHICH.length))} ${lock0.toBuffer().length} bytes, ${R.describe(START)}`)
  console.log(`  funding            ${funding} sat, deploy tx ${dep.size.toLocaleString()} B, fee ${dep.fee} sat`)

  // Every step is built and verified before anything is sent, including the
  // steps that spend outputs which do not exist yet — a signed transaction's
  // txid is its own hash, so the whole sequence is knowable in advance.
  let txid = dep.tx.hash
  let value = funding
  let at = START
  const steps = []
  for (let i = 0; i < STEPS; i++) {
    const s = step(at, i, txid, 0, value)
    steps.push({ from: at, ...s })
    if (!s.check.ok) break
    txid = s.tx.hash; value = s.next; at = s.to
  }

  for (const s of steps) {
    console.log(`  ${R.label(s.from, s.to).padEnd(28)} ${s.check.ok ? 'verified' : 'NOT VERIFIED — ' + s.check.error}   ${s.tx.toBuffer().length.toLocaleString()} B`)
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
    console.log(`  ${R.label(s.from, s.to).padEnd(28)} ${id}`)
    ids.push({ from: String(s.from), to: String(s.to), txid: id })
  }
  onchain.record({
    target: m.name, key: WHICH,
    claim: `a coin stepped ${STEPS} times on chain, each spend paying the coin the next spend consumed`,
    deploy: depId, spend: ids[ids.length - 1].txid,
    lockBytes: lock0.toBuffer().length, lockHex: lock0.toHex(),
    value: funding, spendFee: FEE, steps: ids
  })
  console.log(`\n  ${R.describe(at)}, and every step is a transaction\n`)
}

main().catch((e) => { console.error('  ' + e.message); process.exit(1) })
