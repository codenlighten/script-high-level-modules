'use strict'

const bsv = require('@smartledger/bsv')
const Interpreter = bsv.Script.Interpreter
const BN = bsv.crypto.BN

// Running a Script FRAGMENT against the real consensus interpreter.
//
// A module is not proven by a simulator. It is proven the same way a whole
// predicate is: `unlockingScript || lockingScript` is evaluated by
// bsv.Script.Interpreter — the evaluator that validates blocks — under the flags
// a node actually relays with. The difference from a predicate bench is only
// that the "predicate" here is a fragment plus an assertion about the value it
// computed, and that no transaction data is consulted unless the fragment asks.

/** What a node RELAYS, not merely what a block would accept. */
function policyFlags () {
  const I = Interpreter
  return I.currentConsensusFlags() |
    I.SCRIPT_VERIFY_MINIMALDATA |
    I.SCRIPT_VERIFY_CLEANSTACK |
    I.SCRIPT_VERIFY_SIGPUSHONLY |
    I.SCRIPT_VERIFY_LOW_S |
    I.SCRIPT_VERIFY_NULLFAIL |
    I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    I.SCRIPT_VERIFY_NULLDUMMY
}

// Fixed so a failing run reproduces byte-for-byte. A pure-arithmetic fragment
// never reads any of it, but the interpreter still wants a transaction.
const MOCK_PREVOUT = Buffer.from('0'.repeat(63) + '1', 'hex')
const SATOSHIS = 1000

function mockTx (lockingScript) {
  const tx = new bsv.Transaction()
  tx.addInput(new bsv.Transaction.Input({
    prevTxId: MOCK_PREVOUT,
    outputIndex: 0,
    script: new bsv.Script(),
    sequenceNumber: 0xffffffff
  }), lockingScript, SATOSHIS)
  tx.to(bsv.PrivateKey.fromRandom().toAddress(), SATOSHIS)
  return tx
}

/**
 * Evaluate `unlock || lock` and report the verdict, the error, and the size.
 * `lock` and `unlock` may be bsv.Script objects or anything with .script().
 */
function evaluate (unlock, lock, { flags } = {}) {
  const lockingScript = lock.script ? lock.script() : lock
  const unlockingScript = unlock.script ? unlock.script() : (unlock || new bsv.Script())
  const tx = mockTx(lockingScript)
  tx.inputs[0].setScript(unlockingScript)

  const interp = new Interpreter()
  let ok, thrown = null
  try {
    ok = interp.verify(
      unlockingScript, lockingScript, tx, 0,
      flags !== undefined ? flags : policyFlags(),
      new BN(SATOSHIS)
    )
  } catch (err) {
    ok = false
    thrown = err.message
  }
  return {
    ok,
    error: ok ? null : (thrown || interp.errstr || 'unknown'),
    lockSize: lockingScript.toBuffer().length,
    unlockSize: unlockingScript.toBuffer().length,
    opCount: countOps(lockingScript) + countOps(unlockingScript),
    stack: (interp.stack || []).map((b) => b.toString('hex')),
    lockAsm: lockingScript.toASM(),
    unlockAsm: unlockingScript.toASM()
  }
}

/**
 * Evaluate a spend whose unlocking script has to SIGN the spending transaction.
 * `buildUnlock({ tx, sign })` returns the unlocking script; `sign(privateKey)`
 * returns the DER signature with the sighash byte appended — the bytes a script
 * actually pushes, not a Signature object that verifies everywhere but on chain.
 */
function evaluateSpend (lock, buildUnlock, { flags } = {}) {
  const lockingScript = lock.script ? lock.script() : lock
  const tx = mockTx(lockingScript)
  const sighashType = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
  const sign = (privateKey) => bsv.Transaction.Sighash
    .sign(tx, privateKey, sighashType, 0, lockingScript, new BN(SATOSHIS))
    .toTxFormat()

  const unlockingScript = buildUnlock({ tx, sign })
  tx.inputs[0].setScript(unlockingScript)

  const interp = new Interpreter()
  let ok, thrown = null
  try {
    ok = interp.verify(unlockingScript, lockingScript, tx, 0,
      flags !== undefined ? flags : policyFlags(), new BN(SATOSHIS))
  } catch (err) { ok = false; thrown = err.message }
  return {
    ok,
    error: ok ? null : (thrown || interp.errstr || 'unknown'),
    tx,
    lockSize: lockingScript.toBuffer().length,
    unlockSize: unlockingScript.toBuffer().length
  }
}

/** Static opcode count — data pushes excluded, matching the consensus counter. */
function countOps (script) {
  let n = 0
  for (const c of script.chunks) if (c.opcodenum > bsv.Opcode.OP_16) n++
  return n
}

module.exports = { evaluate, evaluateSpend, policyFlags, countOps, mockTx, MOCK_PREVOUT, SATOSHIS }
