'use strict'

const fs = require('fs')
const path = require('path')
const bsv = require('@smartledger/bsv')
const woc = require('./woc')
const { policyFlags } = require('./run')

// PUTTING ONE ON THE CHAIN.
//
// Everything else in this repository is proven against `bsv.Script.Interpreter`
// — the evaluator that validates blocks — which is a strong claim and not the
// same claim as "the network accepted it". Between the two sit relay policy,
// fee rates, and every assumption the harness makes about a transaction that a
// real one might not share.
//
// So: deploy a module's locking script to an output on mainnet, then spend it.
// A spend that confirms is the only proof that leaves no room for the harness to
// have been wrong.
//
// THE ORDER OF OPERATIONS IS NOT NEGOTIABLE. The spending transaction is built,
// its witness produced, and the whole thing run through the SAME interpreter and
// the SAME policy flags as every test — before anything is broadcast. A refused
// broadcast costs nothing but a round trip; a broadcast that succeeds and strands
// the coin costs the coin.

const WALLET = path.join(__dirname, '..', '.wallet.json')
// Public chain data: txids, sizes, and what each one claims. Tracked, so the
// record can be checked against the chain by anyone who clones this.
const LEDGER = path.join(__dirname, '..', 'deployments.json')
const UTXOS = path.join(__dirname, '..', '.wallet.utxos.json')

// BSV relay policy: 0.05 sat/byte is what miners have accepted for years. Fees
// are rounded up, and a floor keeps a tiny transaction above the minimum.
const SAT_PER_BYTE = 0.05
const MIN_FEE = 1

function loadWallet () {
  if (!fs.existsSync(WALLET)) throw new Error('no .wallet.json — run `npm run wallet:new`')
  const w = JSON.parse(fs.readFileSync(WALLET, 'utf8'))
  const key = bsv.PrivateKey.fromWIF(w.wif)
  return { ...w, key, address: key.toAddress().toString() }
}

function ledger () {
  return fs.existsSync(LEDGER) ? JSON.parse(fs.readFileSync(LEDGER, 'utf8')) : { deployments: [] }
}
function record (entry) {
  const l = ledger()
  l.deployments.push({ ...entry, at: new Date().toISOString() })
  fs.writeFileSync(LEDGER, JSON.stringify(l, null, 2) + '\n', { mode: 0o600 })
  return entry
}

const feeFor = (bytes) => Math.max(MIN_FEE, Math.ceil(bytes * SAT_PER_BYTE))

// ── Which outputs are actually spendable ────────────────────────────────────
//
// An indexer does not see a transaction the moment it is broadcast, and it does
// not have to. Deploying several targets in a row spends change that is still in
// the mempool, so asking WhatsOnChain what the wallet holds returns outputs that
// were spent seconds ago — and building on those produces a double spend the
// node correctly refuses.
//
// So the wallet keeps its own note of what it has spent and what it has created.
// The indexer is one source; this file is the other; the truth is the union
// minus what we know is gone.

function utxoCache () {
  return fs.existsSync(UTXOS) ? JSON.parse(fs.readFileSync(UTXOS, 'utf8')) : { spent: [], created: [] }
}
function saveUtxoCache (c) {
  fs.writeFileSync(UTXOS, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 })
}
const outpoint = (u) => `${u.tx_hash}:${u.tx_pos}`

/** Note that a transaction consumed these and created those. */
function noteSpend (inputs, created) {
  const c = utxoCache()
  for (const i of inputs) if (!c.spent.includes(i)) c.spent.push(i)
  for (const o of created) if (!c.created.some((x) => outpoint(x) === outpoint(o))) c.created.push(o)
  saveUtxoCache(c)
}

/**
 * Everything the wallet can spend right now, indexer and local notes combined,
 * CONFIRMED FIRST.
 *
 * A node limits how deep an unconfirmed chain may go — deploying several
 * covenants in a row spends change that is still in the mempool, and each
 * deployment is one link deeper. Somewhere around a dozen the next broadcast
 * comes back `too-long-mempool-chain`, which is not a fee problem and not
 * something to retry: it needs a block, or a confirmed output to start a fresh
 * chain from.
 *
 * So confirmed outputs are offered first, and `chainDepth()` says how deep the
 * unconfirmed run has become before a broadcast finds out the hard way.
 */
async function spendable (address) {
  const c = utxoCache()
  let indexed = []
  try { indexed = await woc.utxos(address) } catch (e) { /* the local note stands alone */ }
  const all = [...indexed]
  for (const o of c.created) if (!all.some((x) => outpoint(x) === outpoint(o))) all.push(o)
  const live = all.filter((u) => !c.spent.includes(outpoint(u)))
  return live.sort((a, b) => (b.height || 0) - (a.height || 0))
}

/** How many of these outputs are still unconfirmed. */
const unconfirmed = (utxos) => utxos.filter((u) => !u.height).length

/** Verify a fully-formed spend the way every test in this repository does. */
function verifyLocally (tx, lockingScript, satoshis, inputIndex = 0) {
  const interp = new bsv.Script.Interpreter()
  const ok = interp.verify(
    tx.inputs[inputIndex].script, lockingScript, tx, inputIndex,
    policyFlags(), new bsv.crypto.BN(satoshis)
  )
  return { ok, error: ok ? null : interp.errstr }
}

/**
 * Fund an output carrying `lockingScript`. Returns the signed funding
 * transaction; does not broadcast.
 */
async function buildDeploy (lockingScript, { satoshis = 1000, utxos } = {}) {
  const w = loadWallet()
  if (!utxos) utxos = await woc.utxos(w.address)
  if (!utxos.length) throw new Error(`${w.address} holds no spendable outputs`)

  const tx = new bsv.Transaction()
  let funded = 0
  for (const u of utxos) {
    tx.from({
      txId: u.tx_hash,
      outputIndex: u.tx_pos,
      script: bsv.Script.buildPublicKeyHashOut(w.address).toHex(),
      satoshis: u.value
    })
    funded += u.value
    if (funded > satoshis + 5000) break
  }

  tx.addOutput(new bsv.Transaction.Output({ script: lockingScript, satoshis }))
  tx.change(w.address)
  // change() sizes the fee from the library's rate; set ours explicitly.
  tx.feePerKb(Math.round(SAT_PER_BYTE * 1000))
  tx.change(w.address)
  tx.sign(w.key)

  const size = tx.toBuffer().length
  return { tx, size, fee: funded - tx.outputs.reduce((s, o) => s + o.satoshis, 0), funded, wallet: w }
}

/**
 * Build the spend of a deployed output, verify it locally, and return it.
 * `unlock({ tx, lockingScript, satoshis })` returns the unlocking script.
 */
function buildUnlock ({ txid, vout, lockingScript, satoshis, unlock, shape = {}, payTo, fee }) {
  const w = loadWallet()
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(txid, 'hex'),
    outputIndex: vout,
    script: new bsv.Script(),
    sequenceNumber: shape.sequence === undefined ? 0xffffffff : shape.sequence
  }), lockingScript, satoshis)

  // The output has to exist before the preimage is computed: it is committed to.
  // A covenant that PINS its outputs supplies them, and then the fee is whatever
  // the input holds minus what the covenant insists on paying — which is why
  // such a target has to say how much to fund, rather than being handed the
  // change.
  if (shape.outputs) {
    shape.outputs.forEach((o) => tx.addOutput(new bsv.Transaction.Output({ script: o.script, satoshis: o.satoshis })))
  } else {
    const provisional = fee === undefined ? 1 : fee
    tx.addOutput(new bsv.Transaction.Output({
      script: bsv.Script.buildPublicKeyHashOut(payTo || w.address),
      satoshis: Math.max(1, satoshis - provisional)
    }))
  }
  if (shape.nLockTime !== undefined) tx.nLockTime = shape.nLockTime

  const script = unlock({ tx, lockingScript, satoshis, shape })
  tx.inputs[0].setScript(script)

  const check = verifyLocally(tx, lockingScript, satoshis)
  return { tx, size: tx.toBuffer().length, check, wallet: w }
}

module.exports = {
  loadWallet, ledger, record, feeFor, verifyLocally, buildDeploy, buildUnlock,
  spendable, unconfirmed, noteSpend, utxoCache, outpoint,
  SAT_PER_BYTE, WALLET, LEDGER, UTXOS, woc
}
