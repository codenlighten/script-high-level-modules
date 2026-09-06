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

// 100 sat/KB — the rate this wallet pays. Fees are rounded up, and a floor keeps
// a tiny transaction above the minimum.
//
// The first eight deployments went out at half this and confirmed, but two
// blocks after broadcast rather than one; whether that was the rate or ordinary
// variance is not something one sample can say. Paying the going rate is cheaper
// than finding out.
const SAT_PER_KB = 100
const SAT_PER_BYTE = SAT_PER_KB / 1000
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
 * CONFIRMED FIRST and LARGEST FIRST.
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
 *
 * Within one confirmation status the LARGEST comes first, and that is not a
 * preference — it is the same mempool-chain problem again. Taking outputs in
 * whatever order an indexer returns them means sweeping up the dust left by
 * previous deployments, and that dust sits at the END of the unconfirmed chain
 * those deployments built. One fresh 50,000-satoshi output funds a 334 KB
 * transaction on its own; the same transaction funded by three satoshis of dust
 * and then that output inherits fourteen links of ancestry and comes back
 * `too-long-mempool-chain`. Measured, on the whole Miller loop.
 */
async function spendable (address) {
  const c = utxoCache()
  let indexed = []
  try { indexed = await woc.utxos(address) } catch (e) { /* the local note stands alone */ }
  const all = [...indexed]
  for (const o of c.created) if (!all.some((x) => outpoint(x) === outpoint(o))) all.push(o)
  const live = all.filter((u) => !c.spent.includes(outpoint(u)))
  return live.sort((a, b) => ((b.height || 0) - (a.height || 0)) || (b.value - a.value))
}

/** How many of these outputs are still unconfirmed. */
const unconfirmed = (utxos) => utxos.filter((u) => !u.height).length

/**
 * How deep an output's UNCONFIRMED ancestry runs.
 *
 * A node limits how many unconfirmed ancestors a transaction may have — 25 by
 * default — and the limit is over the whole chain behind every input, not over
 * what this wallet did. Money arriving from a wallet that has been paying itself
 * carries that history in, and a transaction built on it comes back
 * `too-long-mempool-chain` no matter how carefully the fee was sized.
 *
 * That is how this was found: a 200,000-satoshi funding output looked perfectly
 * ordinary and was forty links deep in its sender's own mempool chain. The node
 * said so; the wallet had not looked. It looks now, before broadcasting rather
 * than after.
 *
 * The indexer's UTXO listing lags a block or two behind its transaction
 * listing, so `height` on an output is not the last word: an output reported
 * unconfirmed is checked against /tx/hash before its ancestry is walked at all.
 */
async function ancestorDepth (txid, limit = 30) {
  let id = txid
  for (let depth = 0; depth < limit; depth++) {
    let info = null
    try { info = await woc.tx(id) } catch (e) { return depth }        // cannot see it: stop counting
    if (info && info.blockheight) return depth                        // confirmed: the chain ends here
    let raw = null
    try { raw = await woc.rawTx(id) } catch (e) { return depth }
    const parent = new bsv.Transaction(raw).inputs[0]
    if (!parent) return depth
    id = parent.prevTxId.toString('hex')
  }
  return limit                                                        // at least this deep
}

/**
 * Refuse to build on inputs whose unconfirmed ancestry is already at the limit.
 *
 * Returns the deepest chain found, so a caller can say what it is rather than
 * only that something is wrong.
 */
async function deepestAncestry (utxos, limit = 25) {
  let worst = { txid: null, depth: 0 }
  for (const u of utxos) {
    if (u.height) continue
    const d = await ancestorDepth(u.tx_hash, limit + 2)
    if (d > worst.depth) worst = { txid: u.tx_hash, depth: d, value: u.value }
  }
  return worst
}

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

  // Take inputs until the fee is actually covered, and know what the fee is.
  //
  // This used to stop at `satoshis + 5000`, which is a fine constant for a
  // 400-byte covenant and nonsense for a 334 KB Miller loop whose fee alone is
  // 33,433 satoshis. It did not underfund — the library's change() would have
  // thrown — it just kept adding inputs until it had swept the whole wallet,
  // dust and deep mempool ancestry included. Sizing the fee from the script
  // that is about to be deployed costs three lines and stops both.
  const TX_OVERHEAD = 12                                 // version, counts, locktime
  const INPUT_BYTES = 148                                // outpoint, P2PKH scriptSig, sequence
  const OUTPUT_BYTES = lockingScript.toBuffer().length + 12
  const CHANGE_BYTES = 34
  const feeFor = (n) => Math.max(MIN_FEE,
    Math.ceil((TX_OVERHEAD + n * INPUT_BYTES + OUTPUT_BYTES + CHANGE_BYTES) * SAT_PER_BYTE))

  const tx = new bsv.Transaction()
  let funded = 0
  let used = 0
  for (const u of utxos) {
    tx.from({
      txId: u.tx_hash,
      outputIndex: u.tx_pos,
      script: bsv.Script.buildPublicKeyHashOut(w.address).toHex(),
      satoshis: u.value
    })
    funded += u.value
    used++
    if (funded >= satoshis + feeFor(used) + 546) break
  }
  if (funded < satoshis + feeFor(used)) {
    throw new Error(`${w.address} holds ${funded} satoshis across ${used} output(s); ` +
      `this deployment needs ${satoshis + feeFor(used)} — ${OUTPUT_BYTES} bytes of locking script ` +
      `at ${SAT_PER_KB} sat/KB is ${feeFor(used)} of fee`)
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
  spendable, unconfirmed, ancestorDepth, deepestAncestry, noteSpend, utxoCache, outpoint,
  SAT_PER_BYTE, SAT_PER_KB, WALLET, LEDGER, UTXOS, woc
}
