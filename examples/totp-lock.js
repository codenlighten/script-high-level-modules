'use strict'

// A COIN AN AUTHENTICATOR CODE UNLOCKS — and the whole of it, in five lines.
//
// Everything the other examples do by hand, `predicate()` does: it takes a
// module that asserts and returns nothing, binds the spend to an owner's key,
// and hands back the locking script plus the unlocking script that spends it.
//
// TOTP is the module most worth reading the caveats on, so they are printed
// rather than buried: the shared secret is published in the unlocking script of
// the spending transaction, and `time` is an input that the surrounding
// covenant has to bind to nLockTime or the spender picks whatever time makes
// their code valid.

const crypto = require('crypto')
const bsv = require('@smartledger/bsv')
const { predicate, totp } = require('../src')

const secret = Buffer.from('12345678901234567890')            // the RFC 6238 secret
const owner = bsv.PrivateKey.fromBuffer(Buffer.from('66'.repeat(32), 'hex'))
const commitment = crypto.createHash('sha256').update(secret).digest()

const coin = predicate(totp.verify, {
  keyLen: secret.length, digits: 6, step: 30, algo: 'sha1', keyCommitment: commitment
}, { owner: owner.publicKey })

const time = 1111111109n
const code = totp.totpCode(secret, Number(time), { digits: 6 })

const honest = coin.test({ key: secret, time, code }, owner)
const refusals = [
  ['the code from the previous window', coin.test({ key: secret, time, code: totp.totpCode(secret, Number(time) - 30, { digits: 6 }) }, owner)],
  ['the code from the next window', coin.test({ key: secret, time, code: totp.totpCode(secret, Number(time) + 30, { digits: 6 }) }, owner)],
  ['the right code, a different secret', coin.test({ key: Buffer.from('09876543210987654321'), time, code }, owner)],
  ['the right code, a stranger’s key', coin.test({ key: secret, time, code }, bsv.PrivateKey.fromRandom())]
]

console.log(`
  A coin an authenticator code unlocks

  locking script     ${coin.size} bytes
  unlocking script   ${honest.unlockSize} bytes
  code at t=${time}   ${String(code).padStart(6, '0')}

  the owner spends with the current code             ${honest.ok ? 'ACCEPTED' : 'refused — ' + honest.error}`)
for (const [what, r] of refusals) console.log(`  ${what.padEnd(50)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

console.log('\n  What this module cannot do for you:')
for (const n of coin.module.notes) console.log(`    · ${n}`)

const ok = honest.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'Five lines, and the rules are the ones the test kit already proved.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
