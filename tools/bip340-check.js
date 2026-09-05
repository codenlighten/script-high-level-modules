'use strict'

// src/schnorr.js against BIP-340's own published test vectors.
//
// The library has no Schnorr, so there is no second implementation here to
// cross-check the way src/ec.js is checked against the library's secp256k1. The
// standard's vectors are that second implementation — and they are the better
// one, because they were written to catch exactly the misreadings that two
// implementations by the same author would share: a public key that is not on
// the curve, an r past the field size, an s past the group order, an odd R.y,
// and the point at infinity.

const fs = require('fs')
const path = require('path')
const schnorr = require('../src/schnorr')

const csv = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'bip340-test-vectors.csv'), 'utf8')
const rows = csv.trim().split('\n').slice(1).map((line) => {
  const [index, secret, pubkey, aux, message, sig, result, comment] = line.split(',')
  return { index, secret, pubkey, aux, message, sig, expect: result.trim().toUpperCase() === 'TRUE', comment: (comment || '').trim() }
})

let bad = 0
for (const v of rows) {
  const pk = Buffer.from(v.pubkey, 'hex')
  const msg = Buffer.from(v.message, 'hex')
  const sig = Buffer.from(v.sig, 'hex')

  let got
  try { got = schnorr.verify(pk, msg, sig) } catch (e) { got = false }
  const ok = got === v.expect
  if (!ok) bad++

  // Where a secret is given, the signature must also be REPRODUCED, not merely
  // accepted: verifying is a weaker claim than agreeing on what to sign.
  let signed = ''
  if (v.secret && v.expect) {
    const mine = schnorr.sign(BigInt('0x' + v.secret), msg, Buffer.from(v.aux, 'hex'))
    const same = mine.toString('hex').toUpperCase() === v.sig.toUpperCase()
    if (!same) { bad++; signed = ' — SIGNATURE DIFFERS' } else signed = ' + signature reproduced'
  }

  console.log(`${ok ? 'ok  ' : 'FAIL'}  vector ${String(v.index).padStart(2)}  verify=${String(got).padEnd(5)} expected=${String(v.expect).padEnd(5)}${signed}${v.comment ? '  (' + v.comment.slice(0, 52) + ')' : ''}`)
}

console.log(`\n${rows.length - bad === rows.length ? rows.length : rows.length - bad}/${rows.length} BIP-340 vectors reproduced`)
process.exit(bad ? 1 : 0)
