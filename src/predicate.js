'use strict'

const bsv = require('@smartledger/bsv')
const { Asm } = require('./asm')
const { pushNum, pushData } = require('./num')
const { evaluateSpend, buildSpend, evaluatePrepared } = require('./run')

// TURNING A MODULE INTO A COIN.
//
// Everything else here proves that a module computes what it claims. This turns
// one into something you can actually deploy: a locking script, and the
// unlocking script that spends it.
//
// It only accepts a module with NO OUTPUTS — a verifier, something that asserts
// and leaves nothing behind. A module that returns a value is a component of a
// predicate, not a predicate: "the coin moves if this equals 7" is a claim
// somebody still has to write down.
//
// OWNERSHIP IS REQUIRED, AND THAT IS DELIBERATE.
//
// Every off-chain signature scheme in this repository — RSA, TOTP, an oracle's
// ECDSA — authorises a MESSAGE. None of them says anything about a TRANSACTION.
// A coin locked to `rsa.verify` alone is a hashlock whose preimage is published
// the first time it is spent: the unlocking script goes into a block where
// anyone can read it, copy the message and the signature, and redirect the next
// such coin to themselves.
//
// So `owner` is not optional. Pass a public key and the predicate is gated on
// OP_CHECKSIG as well; pass `null` and you are stating on purpose that the coin
// is spendable by anyone who can replay a witness. There is no default, because
// a default would be a decision made for someone who did not know they were
// making it.

/**
 * @param m       a module with no outputs
 * @param params  its compile-time parameters
 * @param owner   a bsv.PublicKey to bind the spend to, or null to opt out
 * @returns { lockingScript, unlock, size, module }
 */
function predicate (m, params = {}, { owner } = {}) {
  if (m.outputs.length) {
    throw new Error(`${m.name}: a predicate asserts and returns nothing, but this module returns ${m.outputs.map((o) => o.name).join(', ')} — wrap it in one that checks the value`)
  }
  if (owner === undefined) {
    throw new Error(`${m.name}: pass an owner public key to bind the spend to this transaction, or owner: null to state on purpose that anyone who replays the witness can spend it`)
  }

  const asm = new Asm()
  const slots = m.inputs.map((i) => ({ ...i }))
  if (owner) {
    slots.push({ name: '_ownerSig', kind: 'bytes' }, { name: '_ownerKey', kind: 'bytes' })
  }
  asm.given(slots)

  if (owner) {
    const pkh = bsv.crypto.Hash.sha256ripemd160(owner.toBuffer())
    asm.op('OP_DUP', 0, [{ name: '_key2', kind: 'bytes' }])
    asm.hash160('_pkh')
    asm.data(pkh, '_wantPkh')
    asm.equalVerify()
    asm.op('OP_CHECKSIGVERIFY', 2, [])
  }

  m.emit(asm, params)
  if (asm.stack.length !== 0) {
    throw new Error(`${m.name}: left ${asm.stack.length} value(s) behind (${asm.toString()}) — a predicate must consume everything it was given`)
  }
  asm.num(1, '_true')

  const lockingScript = asm.script()

  /**
   * Build the unlocking script. `values` supplies the module's inputs; the
   * module's own hint() fills in every witness it knows how to compute.
   * `sign` comes from the spend context and signs this transaction.
   */
  function unlock (values, sign) {
    // The hint fills in what the caller did not supply. It must not overrule
    // what they did: a caller passing a deliberately wrong witness — to check
    // that the coin refuses it — would otherwise have it quietly corrected into
    // the right one and watch the spend succeed.
    const full = { ...values }
    if (m.hint) {
      const hinted = m.hint(full, params)
      for (const k of Object.keys(hinted)) if (!(k in full)) full[k] = hinted[k]
    }
    const s = new bsv.Script()
    for (const i of m.inputs) {
      if (!(i.name in full)) throw new Error(`${m.name}: unlock is missing '${i.name}'`)
      const v = full[i.name]
      s.add(i.kind === 'bytes' ? pushData(Buffer.isBuffer(v) ? v : Buffer.from(v)) : pushNum(v))
    }
    if (owner) {
      if (!sign) throw new Error(`${m.name}: this predicate is bound to an owner, so unlock needs the spend's sign()`)
      s.add(sign()).add(owner.toBuffer())
    }
    return s
  }

  return {
    module: m,
    params,
    lockingScript,
    unlock,
    size: lockingScript.toBuffer().length,

    /**
     * Spend it against the real interpreter — the check before broadcasting.
     *
     * `spend` shapes the transaction: its locktime, its sequence, its outputs.
     * It matters for a module that reads its own spending transaction, because
     * such a module produces its own witness FROM that transaction — the
     * preimage has to be the genuine one — and the shape is what it will read.
     */
    test (values, ownerKey, spend = {}) {
      if (!m.contextual) {
        return evaluateSpend(lockingScript, ({ sign }) => unlock(values, () => sign(ownerKey)))
      }
      const prepared = buildSpend(lockingScript, spend)
      // The witness is produced from the transaction, and producing it mutates
      // the transaction — so it happens before anything signs.
      const produced = m.witnessFor({ ...prepared, spend })
      const full = { ...produced, ...values }
      return evaluatePrepared(prepared, ({ sign }) => unlock(full, () => sign(ownerKey)))
    }
  }
}

module.exports = { predicate }
