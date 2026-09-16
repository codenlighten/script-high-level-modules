'use strict'

// WILL IT RELAY? — the measurement that would have predicted a refusal.
//
//   node tools/relay-budget.js
//
// A transaction can be valid, and be mined, and still be one a node will not
// pass along. Nodes bound how long they will spend validating work that arrives
// from a peer — `maxnonstdtxvalidationduration`, 1000 ms by default — because a
// transaction that is cheap to send and expensive to check is a denial of
// service otherwise.
//
// This repository learned that the expensive way. A three-input Groth16 spend
// verified locally, funded, broadcast, and then sat unmined for 128 blocks; a
// mining pool's API returned `too-long-validation-time`, and its operator
// explained that their node allows a peer-relayed transaction about a second.
// The spend reached a block only because the pool submitted it to their own node
// directly.
//
// So this times every spend this repository has put on chain, in the same
// interpreter, on whatever machine runs it. The absolute numbers are a property
// of this machine — a node's C++ is far quicker — which is why what it reports
// is a RATIO against the transactions whose fate is known:
//
//     pairing.publish ▸ pairing.consume   relayed and was mined
//     groth16 stage1 ▸ stage2 ▸ stage3    refused by relay, mined by hand
//
// Anything at or above the second is a transaction to expect trouble from.
// Anything near or below the first has relayed in practice.

const bsv = require('@smartledger/bsv')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const { policyFlags } = require('../src/run')

const n = (x) => x.toLocaleString('en-US')
const raw = new Map()
async function rawTx (txid) {
  if (!raw.has(txid)) raw.set(txid, new bsv.Transaction(await woc.rawTx(txid)))
  return raw.get(txid)
}

/** Every input of a spend, verified and timed, the way a node would have to. */
async function timeSpend (spendId) {
  const spend = await rawTx(spendId)
  let total = 0
  for (let i = 0; i < spend.inputs.length; i++) {
    const input = spend.inputs[i]
    const parent = await rawTx(input.prevTxId.toString('hex'))
    const out = parent.outputs[input.outputIndex]
    const interp = new bsv.Script.Interpreter()
    const t0 = process.hrtime.bigint()
    const ok = interp.verify(input.script, out.script, spend, i, policyFlags(), new bsv.crypto.BN(out.satoshis))
    total += Number(process.hrtime.bigint() - t0) / 1e6
    if (!ok) throw new Error(`${spendId} input ${i}: ${interp.errstr}`)
  }
  return { ms: total, inputs: spend.inputs.length, bytes: spend.toBuffer().length }
}

async function main () {
  const entries = onchain.ledger().deployments
  // Deployments whose spend is worth timing: the ones with scripts big enough
  // for the question to arise at all.
  const interesting = entries.filter((e) => (e.lockBytes || 0) > 40000)
  console.log('\n  every large spend this repository has on chain, timed in bsv.Script.Interpreter\n')
  console.log(`    ${'deployment'.padEnd(38)} ${'inputs'.padStart(6)} ${'tx bytes'.padStart(11)} ${'ms'.padStart(8)}   relative`)

  const rows = []
  for (const e of interesting) {
    let r
    try { r = await timeSpend(e.spend) } catch (err) { console.log(`    ${e.target.padEnd(38)} ${err.message.slice(0, 60)}`); continue }
    rows.push({ name: e.target, key: e.key, ...r })
  }
  const pairing = rows.find((r) => r.key === 'pairingSplit')
  const groth = rows.find((r) => r.key === 'groth16Split')
  for (const r of rows.sort((a, b) => a.ms - b.ms)) {
    const rel = pairing ? (r.ms / pairing.ms).toFixed(2) + '×' : '—'
    const note = groth && r.ms >= groth.ms ? '  ← refused by relay' : (pairing && r.key === 'pairingSplit' ? '  ← relayed, mined' : '')
    console.log(`    ${r.name.padEnd(38)} ${String(r.inputs).padStart(6)} ${n(r.bytes).padStart(11)} ${r.ms.toFixed(0).padStart(8)}   ${rel.padStart(6)}${note}`)
  }

  if (pairing && groth) {
    console.log(`\n  The line is somewhere between ${pairing.ms.toFixed(0)} ms and ${groth.ms.toFixed(0)} ms on this machine:`)
    console.log('  the first relayed and was mined, the second was refused for its validation')
    console.log('  time and reached a block only by direct submission to a pool.')
  }
  console.log('\n  These are this machine\'s numbers, not a node\'s. What transfers is the ratio,')
  console.log('  and the rule it implies: keep a spend at or under the one that relayed.\n')
}

main().catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
