'use strict'

// WALKING A VERIFIER THAT RUNS ACROSS THREE TRANSACTIONS.
//
//   node tools/verify-groth16-chainwalk.js
//
// When a computation is split across the INPUTS of one transaction, that
// transaction's validity is the whole statement: each stage checks through
// hashPrevouts that it was spent beside its siblings, and a reader has nothing
// left to establish.
//
// Split across TRANSACTIONS, that is no longer true. Each carrier comes from the
// previous transaction, whose txid nothing could know when the stage coins were
// written, so no stage can insist the carrier beside it belongs to this run. Each
// link is enforced by the two scripts in it; that the coins spent were the
// intended ones is a property of the CHAIN, and somebody has to check it.
//
// This is that somebody. It rebuilds all three stage scripts from source, finds
// them in the funding transaction, follows the carrier from link to link, and
// compares the value the last one holds against e(α, β) computed here — so
// "the network verified a Groth16 proof" rests on checks rather than on the word
// of whoever broadcast it.

const bsv = require('@smartledger/bsv')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const { Asm } = require('../src/asm')
const { minimize, packageFor, installHint } = require('../src/minimize')
const chain = require('../src/modules/groth16chain')
const split = require('../src/modules/groth16split')
const carry = require('../src/modules/carry')
const age = require('../test/vectors/groth16-age')

const n = (x) => x.toLocaleString('en-US')
const W = chain.STATE_BYTES
const { S2_NAMES } = split

// A deployment minimized by scriptmin is rebuilt the same way it was built.
function coin (m, minimized, version) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, {})
  asm.num(1, 'ok')
  return minimize(asm.script(), { label: m.name, force: minimized, version })
}

let findings = 0
const say = (ok, what, detail = '') => {
  if (!ok) findings++
  console.log(`    ${ok ? '·' : '✗'} ${what.padEnd(58)} ${detail}`)
}

async function walk (entry) {
  const minimized = !!entry.scriptmin
  if (minimized && !packageFor(entry.scriptmin)) {
    say(false, 'the scriptmin that built these stages is installed', `${String(entry.scriptmin).slice(0, 12)}: ${installHint(entry.scriptmin)}`)
    return
  }
  if (minimized) say(true, 'rebuilt with the scriptmin that built these stages', String(entry.scriptmin).slice(0, 12))

  // What this repository says the coins and the answer should be, computed here.
  const v = chain.chained(age.vk, age.statement, { proof: age.proof })
  const st = v.stateFor(age.proof)
  const blob1 = chain.pack(chain.LINK1_NAMES, st.values)
  const blob2 = chain.padState(chain.pack(S2_NAMES, st.values))
  const locks = [coin(v.link1, minimized, entry.scriptmin), coin(v.link2, minimized, entry.scriptmin), coin(v.link3, minimized, entry.scriptmin)]

  const fund = new bsv.Transaction(await woc.rawTx(entry.deploy))
  const txs = []
  for (const link of entry.chain) txs.push(new bsv.Transaction(await woc.rawTx(link.txid)))
  const meta = await woc.tx(entry.chain[2].txid)

  console.log('\n  a Groth16 proof verified across a chain of transactions\n')
  console.log(`    funding  ${entry.deploy}`)
  entry.chain.forEach((l, i) => console.log(`    tx${i + 1}      ${l.txid}`))
  console.log('')

  // 1. the coins the chain starts from are the scripts this code builds
  locks.forEach((lock, i) => {
    say(fund.outputs[i].script.toBuffer().equals(lock.toBuffer()),
      `funding output ${i} is groth16.chain${i + 1}`, `${n(lock.toBuffer().length)} B, byte for byte`)
  })

  // 2. each link spends its own stage coin, and the carrier its predecessor made
  const carriers = [
    carry.carrierScript(W, { prev: Buffer.alloc(W), cur: blob1 }),
    carry.carrierScript(W, { prev: blob1, cur: blob2 }),
    carry.carrierScript(W, { prev: blob2, cur: v.result })
  ]
  txs.forEach((tx, i) => {
    say(tx.inputs[0].prevTxId.toString('hex') === entry.deploy && tx.inputs[0].outputIndex === i,
      `tx${i + 1} spends its own stage coin`, `funding output ${i}`)
    say(tx.outputs.length === 1 && tx.outputs[0].script.toBuffer().equals(carriers[i].toBuffer()),
      `tx${i + 1} pays exactly the carrier it should`, `${n(carriers[i].toBuffer().length)} B`)
    if (i > 0) {
      say(tx.inputs.length === 2 &&
        tx.inputs[1].prevTxId.toString('hex') === entry.chain[i - 1].txid &&
        tx.inputs[1].outputIndex === 0,
      `tx${i + 1} spends the carrier tx${i} made`, 'and nothing else carries state in')
    }
  })

  // 3. what the last carrier holds is e(α, β), computed here independently
  const last = txs[2].outputs[0].script.toBuffer()
  say(last.subarray(last.length - W).equals(v.result),
    'the last carrier holds e(α, β)', 'twelve Fp12 coefficients, padded')
  say(last.subarray(last.length - 2 * W, last.length - W).equals(blob2),
    'and its prev is the state tx₂ computed', `${n(W)} B`)

  console.log(`\n    mined in block ${meta.blockheight || '(unconfirmed)'}, ${meta.confirmations || 0} confirmation(s)`)
  if (findings) {
    console.log(`\n  ${findings} check(s) did not hold — the chain does not say what it claims to.\n`)
    return findings
  }
  console.log(`
  Every link is enforced by the two scripts in it, and the checks above are what
  a reader adds: that the coins spent were the intended ones, and that the value
  the chain ends on is e(α, β) — the right-hand side of the Groth16 equation for
  this verifying key and this statement.

  What it does NOT establish, because no script can: that the carrier beside each
  stage came from this execution rather than another run of the same verifier. A
  spender may run the chain on any proof; the early links of a losing run are
  valid transactions. What no one reaches is this last carrier, because link 3
  pays e(α, β) only for a state whose final exponentiation is e(α, β).
`)
  return 0
}

async function main () {
  // The deployment as first built, and the scriptmin-minimized one, when recorded.
  const entries = ['groth16Chain', 'groth16ChainScriptmin']
    .map((k) => onchain.ledger().deployments.find((d) => d.key === k))
    .filter(Boolean)
  if (!entries.length) { console.log('\n  no chained verifier recorded yet\n'); return 0 }
  for (const entry of entries) await walk(entry)
  return findings
}

main().then((bad) => process.exit(bad ? 1 : 0)).catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
