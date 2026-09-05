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

const bsv = require('@smartledger/bsv')
const { predicate, totp, recipes } = require('../src')

const secret = Buffer.from('12345678901234567890')
const owner = bsv.PrivateKey.fromBuffer(Buffer.from('88'.repeat(32), 'hex'))

const STEP = 30
const T = 1600000020                       // a whole TOTP window
const code = totp.totpCode(secret, T, { digits: 6, step: STEP })

// One module produces the time, the other consumes it. `pipe()` is the linker:
// it walks the parts, wires each input to whatever an earlier part produced,
// and asks the caller only for what nothing upstream supplies. The result is a
// module like any other — inputs `preimage`, `key`, `code`, no outputs, so
// `predicate()` will take it.
const timelockedTotp = recipes.timelockedTotp(secret, { digits: 6, step: STEP, at: T })

const coin = predicate(timelockedTotp, {}, { owner: owner.publicKey })

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
