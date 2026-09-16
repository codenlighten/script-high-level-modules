'use strict'

// THE SPEND OF A THREE-STAGE GROTH16 VERIFIER.
//
// Built in one place, because two things build it: tools/groth16-split.js,
// which proves the construction against the interpreter, and
// bin/deploy-groth16.js, which puts it on chain. A transaction that the test
// builds one way and the deployment builds another is a transaction the test
// did not test.
//
// THE SHAPE. Three inputs — outputs 0, 1 and 2 of one funding transaction, as
// each stage's sibling check requires — and one output, the OP_RETURN blob all
// three commit to. No change: tx.commitData requires the output set to be
// exactly the blob, so the three coins' values are the fee.
//
// GRINDING THREE PREIMAGES AT ONCE. About one OP_PUSH_TX preimage in fifty
// satisfies the canonical low-S condition, so a TRIPLE lands about once in
// 125,000 — and every input's preimage carries a ~400 KB scriptCode. The field
// ground is what makes that affordable. nSequence appears twice in a BIP-143
// preimage: once as its own field and once inside hashSequence, at offset 36 —
// so moving it changes bytes near the start and every SHA-256 block after them
// must be recomputed. nLockTime appears ONCE, eight bytes from the end. Grind
// that instead and every block but the last is unchanged, so each input's
// SHA-256 midstate is computed once and copied per attempt.
//
// Small nLockTime values are past block heights, so the transaction stays
// final — which is why the search stops well short of the current height rather
// than at 2³².

const bsv = require('@smartledger/bsv')
const crypto = require('crypto')
const H = require('@smartledger/bsv/lib/covenant/helpers')
const { Asm } = require('./asm')
const { minimize } = require('./minimize')
const { policyFlags } = require('./run')
const { pushNum, pushData } = require('./num')
const txmod = require('./modules/tx')
const pairing = require('./modules/pairing')
const split = require('./modules/groth16split')
const P = require('./bls12381').P

/** A predicate as a locking script: emit it, then leave TRUE. */
function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, {})
  asm.num(1, 'ok')
  return minimize(asm.script(), { label: m.name })
}
const lockingScripts = (v) => [coin(v.stage1), coin(v.stage2), coin(v.stage3)]

// ── the canonical-s filter, on a digest already in hand ─────────────────────
const BN = bsv.crypto.BN
const N = new BN(Buffer.from(txmod.PushTx.N_LE).reverse())
const HALF = N.div(new BN(2))
const GX = new BN(Buffer.from(txmod.PushTx.gxLe).reverse())
function sFromDigest (z) {
  if (z[0] < 0x01 || z[0] > 0x7f) return null
  const s = new BN(z).add(GX).mod(N)
  if (s.gt(HALF)) return null
  const sBE = s.toBuffer({ size: 32 })
  return sBE[0] >= 0x01 ? sBE : null
}

/**
 * Find an nLockTime at which all three preimages are canonical.
 *
 * The fast filter stands in for the library's sFromPreimage, so before it is
 * trusted it is walked across a few hundred nLockTimes alongside the library
 * and required to agree on every one. Afterwards the patched preimages are
 * compared with the ones the library builds from the finished transaction.
 */
function grind (tx, locks, amounts, { limit = 900000 } = {}) {
  const started = Date.now()
  const at = (buf) => buf.length - 8
  const bases = locks.map((lock, i) => Buffer.from(H.rawPreimage(tx, i, lock, amounts[i], txmod.SIGHASH_ALL_FORKID)))
  const mids = bases.map((b) => {
    const cut = Math.floor(at(b) / 64) * 64
    return { h: crypto.createHash('sha256').update(b.subarray(0, cut)), cut }
  })
  const s = (buf, mid) => sFromDigest(crypto.createHash('sha256').update(mid.h.copy().update(buf.subarray(mid.cut)).digest()).digest())
  const put = (i, lt) => { bases[i].writeUInt32LE(lt, at(bases[i])) }

  let filterChecked = 0
  let filterCanonical = 0
  for (let lt = 0; lt < 300; lt++) {
    put(0, lt)
    const mine = s(bases[0], mids[0])
    let theirs = null
    try { theirs = txmod.PushTx.sFromPreimage(bases[0]) } catch (e) { theirs = null }
    const same = (mine === null && theirs === null) || (mine !== null && theirs !== null && Buffer.from(theirs).equals(Buffer.from(mine)))
    if (!same) throw new Error(`groth16spend: the fast filter disagrees with the library at nLockTime ${lt}`)
    filterChecked++
    if (mine) filterCanonical++
  }

  let tries = 0; let past1 = 0; let past2 = 0; let found = null
  for (let lt = 0; lt < limit && found === null; lt++) {
    tries++
    put(0, lt); if (!s(bases[0], mids[0])) continue
    past1++
    put(1, lt); if (!s(bases[1], mids[1])) continue
    past2++
    put(2, lt); if (s(bases[2], mids[2])) found = lt
  }
  if (found === null) throw new Error(`groth16spend: no nLockTime below ${limit} makes all three preimages canonical`)

  tx.nLockTime = found
  const preimages = locks.map((lock, i) => H.rawPreimage(tx, i, lock, amounts[i], txmod.SIGHASH_ALL_FORKID))
  bases.forEach((b, i) => {
    if (!b.equals(preimages[i])) throw new Error(`groth16spend: patched preimage ${i} disagrees with the library's`)
  })
  return { preimages, nLockTime: found, tries, past1, past2, seconds: (Date.now() - started) / 1000, filterChecked, filterCanonical }
}

/** Each stage's unlocking script: its witnesses in the order it declares them. */
function unlockingScripts (v, proof, preimages) {
  const st = v.stateFor(proof)
  const mods = [v.stage1, v.stage2, v.stage3]
  const tapes = [st.wit1, st.wit2, []]
  return mods.map((m, i) => {
    const values = { ...st.values, preimage: preimages[i], fundingTxid: Buffer.from(preimages[i]).subarray(68, 100) }
    tapes[i].forEach(([a, b], k) => { values[`w${k}a`] = a; values[`w${k}b`] = b })
    if (i === 0 && v.subgroup) Object.assign(values, split.subgroupWitnesses(proof))
    if (i === 2) Object.assign(values, pairing.finalExp.hint(pairing.spread(st.s2, 'f'), { n: P, nn: P }))
    const u = new bsv.Script()
    for (const inp of m.inputs) {
      const val = values[inp.name]
      if (val === undefined) throw new Error(`groth16spend: stage ${i + 1} has no value for ${inp.name}`)
      u.add(inp.kind === 'bytes' ? pushData(val) : pushNum(val))
    }
    return u
  })
}

/**
 * The whole spend.
 *
 * @param coins  three { txid, vout, satoshis }: outputs 0, 1 and 2 of one
 *               funding transaction, stage 1 at output 0
 */
function buildSpend (v, proof, coins, { locks, limit } = {}) {
  locks = locks || lockingScripts(v)
  if (coins.length !== 3 || coins.some((c, i) => c.txid !== coins[0].txid || c.vout !== i)) {
    throw new Error('groth16spend: the coins must be outputs 0, 1 and 2 of one funding transaction — each stage checks exactly that')
  }
  const st = v.stateFor(proof)
  const tx = new bsv.Transaction()
  coins.forEach((c, i) => tx.addInput(new bsv.Transaction.Input({
    prevTxId: Buffer.from(c.txid, 'hex'), outputIndex: c.vout, script: new bsv.Script(), sequenceNumber: 0xfffffffe
  }), locks[i], c.satoshis))
  tx.addOutput(txmod.dataOutput(split.BLOB_BYTES, v.serialise(st.values)))
  tx._outputAmount = undefined
  const g = grind(tx, locks, coins.map((c) => c.satoshis), { limit })
  const unlocks = unlockingScripts(v, proof, g.preimages)
  unlocks.forEach((u, i) => tx.inputs[i].setScript(u))
  return { tx, locks, unlocks, grind: g }
}

/** Every input through bsv.Script.Interpreter under relay policy flags. */
function verifyInputs (tx, locks, coins) {
  return locks.map((lock, i) => {
    const interp = new bsv.Script.Interpreter()
    let ok = false
    let err = null
    try { ok = interp.verify(tx.inputs[i].script, lock, tx, i, policyFlags(), new BN(coins[i].satoshis)) } catch (e) { err = e.message }
    return { ok, err: err || interp.errstr }
  })
}

module.exports = { coin, lockingScripts, grind, unlockingScripts, buildSpend, verifyInputs }
