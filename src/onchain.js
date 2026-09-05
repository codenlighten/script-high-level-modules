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
const LEDGER = path.join(__dirname, '..', '.deployments.json')

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
async function buildDeploy (lockingScript, { satoshis = 1000 } = {}) {
  const w = loadWallet()
  const utxos = await woc.utxos(w.address)
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
  const provisional = fee === undefined ? 1 : fee
  tx.addOutput(new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(payTo || w.address),
    satoshis: Math.max(1, satoshis - provisional)
  }))
  if (shape.nLockTime !== undefined) tx.nLockTime = shape.nLockTime

  const script = unlock({ tx, lockingScript, satoshis, shape })
  tx.inputs[0].setScript(script)

  const check = verifyLocally(tx, lockingScript, satoshis)
  return { tx, size: tx.toBuffer().length, check, wallet: w }
}

module.exports = {
  loadWallet, ledger, record, feeFor, verifyLocally, buildDeploy, buildUnlock,
  SAT_PER_BYTE, WALLET, LEDGER, woc
}
