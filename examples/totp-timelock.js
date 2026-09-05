'use strict'

// CLOSING A HOLE THIS REPOSITORY DOCUMENTED ABOUT ITSELF.
//
// `totp.verify` has carried a note since it was written:
//
//     time must be bound to nLockTime by the surrounding predicate,
//     or it is the spender's choice
//
// On its own the module proves that a code matches a time. It cannot prove
// anything about WHICH time, because the time arrives as a number the spender
// pushed — so a spender with the secret could present the code for any moment
// they liked and spend whenever they wanted.
//
// `tx.locktime` supplies the missing half. OP_PUSH_TX proves the pushed preimage
// is this transaction; the module reads nLockTime out of it and refuses a final
// sequence, without which consensus ignores nLockTime entirely. Wired together,
// the code must match the time the transaction is LOCKED to.
//
// And what that buys, stated exactly, because it is less than it first looks:
//
//     enforced      this transaction cannot be MINED before the time its
//                   code is valid for
//     not enforced  that the time is the present moment
//
// A spender may still claim a time further in the future and wait for it. What
// they can no longer do is claim one time and spend at another — which is the
// hole, and it is closed.

const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { apply } = require('../src/module')
const { predicate, totp } = require('../src')
const tx = require('../src/modules/tx')

const secret = Buffer.from('12345678901234567890')
const commitment = crypto.createHash('sha256').update(secret).digest()
const owner = bsv.PrivateKey.fromBuffer(Buffer.from('88'.repeat(32), 'hex'))

const STEP = 30
const T = 1600000020                       // a whole TOTP window
const code = totp.totpCode(secret, T, { digits: 6, step: STEP })

// The two modules, wired: one produces the time, the other consumes it. This is
// what apply() is for — all() composes predicates that each stand alone, and
// here the output of one IS the input of the next.
const timelockedTotp = {
  name: 'tx.locktime ▸ totp.verify',
  doc: 'an authenticator code, for the time the transaction is locked to',
  inputs: [
    { name: 'preimage', kind: 'bytes', witness: true },
    { name: 'key', kind: 'bytes', witness: true },
    { name: 'code', witness: true }
  ],
  outputs: [],
  contextual: true,
  witnessFor: (ctx) => tx.locktime.witnessFor(ctx),
  hint: () => ({}),
  model: () => ({}),
  notes: [
    'the code must match the time the transaction is locked to, not one the spender chose',
    'enforces that the spend cannot be mined earlier than that time — not that it is now'
  ],
  emit: (asm, params) => {
    apply(asm, tx.locktime, {}, ['preimage'], ['time'])
    apply(asm, totp.verify, params, ['key', 'time', 'code'], [])
  }
}

const coin = predicate(timelockedTotp, {
  keyLen: secret.length, digits: 6, step: STEP, algo: 'sha1', keyCommitment: commitment
}, { owner: owner.publicKey })

const spendAt = (t) => ({ nLockTime: t })
const honest = coin.test({ key: secret, code }, owner, spendAt(T))

const refusals = [
  ['the code for a LATER window, locked to this one', coin.test(
    { key: secret, code: totp.totpCode(secret, T + STEP, { digits: 6, step: STEP }) }, owner, spendAt(T))],
  ['the right code, but locked to a later time', coin.test(
    { key: secret, code }, owner, spendAt(T + STEP))],
  ['the right code, but the sequence left final', coin.test(
    { key: secret, code }, owner, { nLockTime: T, sequence: 0xffffffff })],
  ['a different secret', coin.test(
    { key: Buffer.from('09876543210987654321'), code }, owner, spendAt(T))],
  ['everything right, a stranger’s key', coin.test(
    { key: secret, code }, bsv.PrivateKey.fromRandom(), spendAt(T))]
]

console.log(`
  An authenticator code bound to the time the coin is locked to

  locking script     ${coin.size} bytes
  unlocking script   ${honest.unlockSize} bytes
  window             ${new Date(T * 1000).toISOString()}  (t=${T})
  code               ${String(code).padStart(6, '0')}

  the owner spends at the locked time with its code  ${honest.ok ? 'ACCEPTED' : 'refused — ' + honest.error}`)
for (const [what, r] of refusals) console.log(`  ${what.padEnd(50)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

console.log('\n  What this still cannot do:')
for (const n of timelockedTotp.notes) console.log(`    · ${n}`)

const ok = honest.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'The code and the transaction now describe the same moment.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
