'use strict'

// WALKING A CHAINED COMPUTATION, WHICH IS THE PART NO SCRIPT CAN DO.
//
//   node tools/verify-chainwalk.js
//
// When a computation is split across the INPUTS of one transaction, that
// transaction's validity is the whole statement: every stage checks through
// hashPrevouts that it was spent beside its siblings, and there is nothing left
// for a reader to establish.
//
// Split across TRANSACTIONS, that is no longer true. The carrier coin comes from
// the previous transaction, whose txid nothing could know when the stage coins
// were written, so no stage can insist the carrier beside it is genuine. Each
// link is enforced by the two scripts in it; that the coins spent were the
// intended ones is a property of the CHAIN, and somebody has to check it.
//
// This is that somebody. It rebuilds both stage scripts from source, finds them
// in the funding transaction, follows the carrier from one link to the next, and
// compares the value the last carrier holds with the pairing computed here — so
// the claim "the network evaluated e(P, Q)" rests on checks rather than on the
// word of whoever broadcast it.

const bsv = require('@smartledger/bsv')
const woc = require('../src/woc')
const onchain = require('../src/onchain')
const { Asm } = require('../src/asm')
const { minimize, packageFor, installHint } = require('../src/minimize')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const carry = require('../src/modules/carry')

const W = pairing.STATE_BYTES
const params = { n: bls.P, nn: bls.P }
const n = (x) => x.toLocaleString('en-US')

const pts = { Px: bls.G1.x, Py: bls.G1.y, Qx0: bls.G2.x[0], Qx1: bls.G2.x[1], Qy0: bls.G2.y[0], Qy1: bls.G2.y[1] }

// A deployment minimized by scriptmin is rebuilt the same way it was built.
function coin (m, minimized, version) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return minimize(asm.script(), { label: m.name, force: minimized, version })
}

let findings = 0
const say = (ok, what, detail = '') => {
  if (!ok) findings++
  console.log(`    ${ok ? '·' : '✗'} ${what.padEnd(56)} ${detail}`)
}

async function walk (entry) {
  const minimized = !!entry.scriptmin
  if (minimized && !packageFor(entry.scriptmin)) {
    say(false, 'the scriptmin that built these stages is installed', `${String(entry.scriptmin).slice(0, 12)}: ${installHint(entry.scriptmin)}`)
    return
  }
  if (minimized) say(true, 'rebuilt with the scriptmin that built these stages', String(entry.scriptmin).slice(0, 12))

  // What the code says the coins and the answer should be, computed here.
  const rawF = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, bls.P).f
  const f = bls.X < 0n ? bls.f12conj(rawF) : rawF
  const fBytes = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')
  const eBytes = pairing.serialiseF12(pairing.spread(bls.pairing(bls.G1, bls.G2), 'r'), 'r')
  const lockMiller = coin(pairing.chainMiller({ cases: [{ name: 'x', inputs: pts, spend: pts, params }] }), minimized, entry.scriptmin)
  const lockExp = coin(pairing.chainExp(bls.pairing(bls.G1, bls.G2), { cases: [{ name: 'x', spend: { f }, params }] }), minimized, entry.scriptmin)

  const fund = new bsv.Transaction(await woc.rawTx(entry.deploy))
  const tx1 = new bsv.Transaction(await woc.rawTx(entry.chain[0].txid))
  const tx2 = new bsv.Transaction(await woc.rawTx(entry.chain[1].txid))
  const meta = await woc.tx(entry.chain[1].txid)

  console.log('\n  a pairing evaluated across a chain of transactions\n')
  console.log(`    funding  ${entry.deploy}`)
  console.log(`    tx₁      ${entry.chain[0].txid}`)
  console.log(`    tx₂      ${entry.chain[1].txid}\n`)

  // 1. the coins the chain starts from are the scripts this code builds
  say(fund.outputs[0].script.toBuffer().equals(lockMiller.toBuffer()),
    'funding output 0 is pairing.chainMiller', `${n(lockMiller.toBuffer().length)} B, byte for byte`)
  say(fund.outputs[1].script.toBuffer().equals(lockExp.toBuffer()),
    'funding output 1 is pairing.chainExp', `${n(lockExp.toBuffer().length)} B, byte for byte`)

  // 2. each link spends the coin it should, and the carrier its predecessor made
  say(tx1.inputs[0].prevTxId.toString('hex') === entry.deploy && tx1.inputs[0].outputIndex === 0,
    'tx₁ spends the Miller stage coin', 'funding output 0')
  const carrier1 = carry.carrierScript(W, { prev: Buffer.alloc(W), cur: fBytes })
  say(tx1.outputs.length === 1 && tx1.outputs[0].script.toBuffer().equals(carrier1.toBuffer()),
    'tx₁ pays exactly one output: the carrier holding f', `${n(carrier1.toBuffer().length)} B`)
  say(tx2.inputs[0].prevTxId.toString('hex') === entry.deploy && tx2.inputs[0].outputIndex === 1,
    'tx₂ spends the exponentiation stage coin', 'funding output 1')
  say(tx2.inputs[1].prevTxId.toString('hex') === entry.chain[0].txid && tx2.inputs[1].outputIndex === 0,
    'tx₂ spends the carrier tx₁ made', 'and nothing else carries state in')
  say(tx2.inputs.length === 2, 'tx₂ has exactly those two inputs', `${tx2.inputs.length}`)

  // 3. what the last carrier holds is the pairing, computed here independently
  const carrier2 = carry.carrierScript(W, { prev: fBytes, cur: eBytes })
  say(tx2.outputs.length === 1 && tx2.outputs[0].script.toBuffer().equals(carrier2.toBuffer()),
    'tx₂ pays a carrier whose prev is f and whose cur is e(P, Q)', `${n(carrier2.toBuffer().length)} B`)
  say(tx2.outputs[0].script.toBuffer().subarray(-W).equals(eBytes),
    'and that value is the pairing this repository computes', 'twelve Fp12 coefficients')

  console.log(`\n    mined in block ${meta.blockheight || '(unconfirmed)'}, ${meta.confirmations || 0} confirmation(s)`)
  if (findings) {
    console.log(`\n  ${findings} check(s) did not hold — the chain does not say what it claims to.\n`)
    return findings
  }
  console.log(`
  Every link is enforced by the two scripts in it, and the three checks above are
  what a reader adds: that the coins spent were the intended ones, and that the
  value the chain ends on is the pairing. That is the price of splitting a
  computation across transactions rather than inputs — and what buys it is that
  each transaction is small enough for a node to pass along.
`)
  return 0
}

async function main () {
  // The deployment as first built, and the scriptmin-minimized one, when recorded.
  const entries = ['pairingChain', 'pairingChainScriptmin']
    .map((k) => onchain.ledger().deployments.find((d) => d.key === k))
    .filter(Boolean)
  if (!entries.length) { console.log('\n  no chained deployment recorded yet\n'); return 0 }
  for (const entry of entries) await walk(entry)
  return findings
}

main().then((bad) => process.exit(bad ? 1 : 0)).catch((e) => { console.error(`\n  ${e.message}\n`); process.exit(1) })
