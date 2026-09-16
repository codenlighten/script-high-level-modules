'use strict'

// COULD THE ONE-TRANSACTION GROTH16 VERIFIER RELAY AGAIN?
//
//   node tools/relay-scriptmin.js
//
// tools/relay-budget.js established the yardsticks: the two-input pairing split
// relayed and was mined; the three-input Groth16 split was refused by relay for
// its validation time (1.50× the first) and reached a block only by direct
// submission. That is why the verifier became a chain of three transactions.
//
// Stage scripts minimized by scriptmin (SCRIPTMIN=1, src/minimize.js) are about
// 40% smaller, and most of what disappears is executed stack traffic, so they
// also validate faster. This asks whether that is enough to bring the
// single-transaction verifier back under the spend that relayed.
//
// It times, in one process and interleaved so load affects them alike, the two
// on-chain yardstick spends and the Groth16 split rebuilt both ways, and keeps
// the best of three rounds. As with relay-budget, only the RATIO transfers.
// Needs the network (to fetch the yardsticks) and scriptmin installed.

const path = require('path')
const bsv = require('@smartledger/bsv')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const { policyFlags } = require('../src/run')
const split = require('../src/modules/groth16split')
const spendlib = require('../src/groth16spend')

const D = path.join(__dirname, '..', 'test', 'vectors', 'groth16-age')
const vkJson = require(path.join(D, 'vk.json'))
const proofJson = require(path.join(D, 'proof.json'))
const g1 = (p) => ({ x: BigInt(p[0]), y: BigInt(p[1]) })
const g2 = (p) => ({ x: [BigInt(p[0][0]), BigInt(p[0][1])], y: [BigInt(p[1][0]), BigInt(p[1][1])] })
const vk = { alpha: g1(vkJson.vk_alpha_1), beta: g2(vkJson.vk_beta_2), gamma: g2(vkJson.vk_gamma_2), delta: g2(vkJson.vk_delta_2), IC: vkJson.IC.map(g1) }
const A = g1(proofJson.pi_a); const B = g2(proofJson.pi_b); const C = g1(proofJson.pi_c)
const proof = { Ax: A.x, Ay: A.y, Bx0: B.x[0], Bx1: B.x[1], By0: B.y[0], By1: B.y[1], Cx: C.x, Cy: C.y }
const v = split.verifier(vk, [2026n, 21n], { proof })

function timeLocal (tx, locks, coins) {
  let total = 0
  for (let i = 0; i < locks.length; i++) {
    const interp = new bsv.Script.Interpreter()
    const t0 = process.hrtime.bigint()
    const ok = interp.verify(tx.inputs[i].script, locks[i], tx, i, policyFlags(), new bsv.crypto.BN(coins[i].satoshis))
    total += Number(process.hrtime.bigint() - t0) / 1e6
    if (!ok) throw new Error(`input ${i}: ${interp.errstr}`)
  }
  return total
}
async function timeChain (spendId) {
  const spend = new bsv.Transaction(await woc.rawTx(spendId))
  const parents = []
  for (const input of spend.inputs) parents.push(new bsv.Transaction(await woc.rawTx(input.prevTxId.toString('hex'))))
  return () => {
    let total = 0
    spend.inputs.forEach((input, i) => {
      const out = parents[i].outputs[input.outputIndex]
      const interp = new bsv.Script.Interpreter()
      const t0 = process.hrtime.bigint()
      const ok = interp.verify(input.script, out.script, spend, i, policyFlags(), new bsv.crypto.BN(out.satoshis))
      total += Number(process.hrtime.bigint() - t0) / 1e6
      if (!ok) throw new Error(`${spendId} input ${i}: ${interp.errstr}`)
    })
    return { total, bytes: spend.toBuffer().length }
  }
}

async function main () {
  const ledger = onchain.ledger().deployments
  const relayed = await timeChain(ledger.find((d) => d.key === 'pairingSplit').spend)
  const refused = await timeChain(ledger.find((d) => d.key === 'groth16Split').spend)
  const coins = [0, 1, 2].map((vout) => ({ txid: 'a7'.repeat(32), vout, satoshis: 1 }))
  const variants = {}
  for (const mode of ['0', '1']) {
    process.env.SCRIPTMIN = mode
    const { tx, locks } = spendlib.buildSpend(v, proof, coins)
    variants[mode] = { tx, locks, bytes: tx.toBuffer().length }
  }
  const best = { relayed: Infinity, refused: Infinity, local0: Infinity, local1: Infinity }
  for (let round = 0; round < 3; round++) {
    best.relayed = Math.min(best.relayed, relayed().total)
    best.refused = Math.min(best.refused, refused().total)
    best.local0 = Math.min(best.local0, timeLocal(variants['0'].tx, variants['0'].locks, coins))
    best.local1 = Math.min(best.local1, timeLocal(variants['1'].tx, variants['1'].locks, coins))
  }
  const r = (x) => (x / best.relayed).toFixed(2) + '×'
  console.log('\n  validation time, best of three rounds, relative to the spend that relayed\n')
  console.log(`  pairing split on chain (relayed)        ${Math.round(best.relayed)} ms  1.00×  ${relayed().bytes} B`)
  console.log(`  groth16 split on chain (refused)        ${Math.round(best.refused)} ms  ${r(best.refused)}`)
  console.log(`  groth16 split rebuilt, as deployed      ${Math.round(best.local0)} ms  ${r(best.local0)}  ${variants['0'].bytes} B`)
  console.log(`  groth16 split rebuilt, SCRIPTMIN=1      ${Math.round(best.local1)} ms  ${r(best.local1)}  ${variants['1'].bytes} B`)
}
main().catch((e) => { console.error(e); process.exit(1) })
