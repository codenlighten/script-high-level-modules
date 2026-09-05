'use strict'

const crypto = require('crypto')
const compose = require('./compose')
const txMod = require('./modules/tx')
const totp = require('./modules/totp')

// COMPOSITIONS WORTH HAVING A NAME FOR.
//
// A recipe is not a new capability — every one of these is `pipe()` or `all()`
// over modules that already exist. It is here because a composition written out
// twice is a composition that will drift, and one of these had already been
// hand-wired in an example and in a deployment target with different names for
// the same value.

/**
 * An authenticator code for the time the transaction is locked to.
 *
 * `totp.verify` proves a code matches a time and can say nothing about WHICH
 * time, because the time arrives as a number the spender pushed. `tx.locktime`
 * produces that number from the transaction itself. Chained, the code must match
 * the time the spend is locked to.
 *
 * What it enforces, exactly: the transaction cannot be MINED before the time its
 * code is valid for. Not that the time is now — a spender may still claim a
 * later window and wait. What they cannot do is claim one time and spend at
 * another.
 */
function timelockedTotp (secret, { digits = 6, step = 30, algo = 'sha1', at, cases } = {}) {
  const keyCommitment = crypto.createHash('sha256').update(secret).digest()
  const code = at === undefined ? null : totp.totpCode(secret, at, { digits, step, algo })

  return compose.pipe('tx.locktime ▸ totp.verify', [
    { module: txMod.locktime, params: {}, as: { locktime: 'time' } },
    { module: totp.verify, params: { keyLen: secret.length, digits, step, algo, keyCommitment } }
  ], {
    doc: 'an authenticator code for the time the transaction is locked to',
    notes: [
      'the code must match the time the transaction is locked to, not one the spender chose',
      'enforces that the spend cannot be mined before that time — not that it is now',
      'single use: the secret is published in the unlocking script of the spend'
    ],
    cases: cases || (at === undefined ? [] : [
      { name: 'the code for the locked time', spend: { nLockTime: at }, inputs: { key: secret, code } },
      {
        name: 'the code for the next window',
        refuse: 'the code must match the time the transaction is locked to',
        spend: { nLockTime: at },
        inputs: { key: secret, code: totp.totpCode(secret, at + step, { digits, step, algo }) }
      },
      {
        name: 'a final sequence',
        refuse: 'consensus ignores nLockTime when the sequence is final, so the time proves nothing',
        spend: { sequence: 0xffffffff },
        inputs: { key: secret, code }
      }
    ])
  })
}

module.exports = { timelockedTotp }
