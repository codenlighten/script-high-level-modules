'use strict'

// A COIN THAT CAN ONLY BE SPENT BY ADVANCING ITSELF.
//
// Every other example here is a gate: the coin moves, or it does not. This one
// carries something forward, and it is the difference between a cryptography
// library for Script and a substrate for verifiable state.
//
// Two modules, and neither knows what the other does.
//
//   tx.transition   reads this script's own bytes out of the BIP-143 preimage,
//                   replaces one field, and requires the spend to pay an output
//                   carrying exactly that — the coin's own successor.
//   state.counter   says which replacements are legal: the current value plus
//                   one, and nothing else.
//
// One is about preimages and the other is about numbers. `pipe()` is the whole
// of the joining, and what comes out is a monotonic sequence with a transaction
// for every step: nobody can skip, nobody can go back, and the history is on
// chain because the history IS the chain of spends.

const bsv = require('@smartledger/bsv')
const { buildSpend, evaluatePrepared } = require('../src/run')
const { pushData } = require('../src/num')
const { recipes } = require('../src')
const txMod = require('../src/modules/tx')
const stateMod = require('../src/modules/state')

const W = 8
const FEE = 300
const START = 41n
const STEPS = 4

const m = recipes.counterCoin({ from: START, stateWidth: W, fee: FEE })

/** The locking script for a counter sitting at `v`. */
function coinAt (v) {
  const { Asm } = require('../src/asm')
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ ...i })))
  m.emit(asm, { state: stateMod.le(v, W) })
  asm.num(1, 'true')
  const tail = m.tail({ state: stateMod.le(v, W) })
  return new bsv.Script(Buffer.concat([asm.script().toBuffer(), tail]))
}

let value = 20000
let prevTxId = null
let at = START
const rows = []

for (let i = 0; i < STEPS; i++) {
  const lock = coinAt(at)
  const prepared = buildSpend(lock, { satoshis: value, prevTxId })
  const w = txMod.recreateWitness({ ...prepared, spend: { next: stateMod.le(at + 1n, W) } }, W, FEE)
  const r = evaluatePrepared(prepared, () => new bsv.Script().add(pushData(w.preimage)).add(pushData(w.next)))

  const successor = prepared.tx.outputs[0]
  rows.push({ from: at, to: at + 1n, ok: r.ok, err: r.error, value, next: successor.satoshis, txid: prepared.tx.hash })

  // the successor is the next coin: same script, one field on, one fee lighter
  prevTxId = prepared.tx.hash
  value = successor.satoshis
  at += 1n
}

// And what it refuses: any successor but the one the rule allows.
const lock = coinAt(at)
const prepared = buildSpend(lock, { satoshis: value })
const refusals = [['skipping two', at + 2n], ['standing still', at], ['going back', at - 1n]].map(([label, to]) => {
  const w = txMod.recreateWitness({ ...prepared, spend: { next: stateMod.le(to, W) } }, W, FEE)
  const r = evaluatePrepared(prepared, () => new bsv.Script().add(pushData(w.preimage)).add(pushData(w.next)))
  return [label, r.ok]
})

console.log(`
  A counter that only Bitcoin can advance

  locking script     ${coinAt(START).toBuffer().length} bytes
  state              ${W} bytes, after a top-level OP_RETURN
  fee per step       ${FEE} satoshis
`)
for (const r of rows) {
  console.log(`  ${String(r.from).padStart(3)} → ${String(r.to).padEnd(3)}  ${r.ok ? 'ACCEPTED' : 'refused — ' + r.err}   ${r.value} sat → ${r.next} sat   ${r.txid.slice(0, 16)}…`)
}
console.log('')
for (const [what, ok] of refusals) console.log(`  ${what.padEnd(38)} ${ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

const ok = rows.every((r) => r.ok) && refusals.every(([, a]) => !a)
console.log(`\n  ${ok ? 'Each spend produced the coin that the next spend consumed. The state is the chain.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
