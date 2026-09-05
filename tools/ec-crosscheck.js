'use strict'

// src/ec.js against the library's own secp256k1 — the implementation that
// verifies real Bitcoin signatures. The Script modules are checked against
// src/ec.js, so this is the link that stops a shared mistake agreeing with
// itself all the way down.

const bsv = require('@smartledger/bsv')
const ec = require('../src/ec')

const SCALARS = [1n, 2n, 3n, 7n, 12345n, 2n ** 128n + 1n,
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140n]

let bad = 0
const say = (ok, what) => { if (!ok) bad++; console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}`) }

say(ec.isOnCurve(ec.G), 'G is on the curve')

for (const k of SCALARS) {
  const mine = ec.mul(k)
  const theirs = ec.fromBsv(bsv.crypto.Point.getG().mul(new bsv.crypto.BN(k.toString(16), 16)))
  say(mine.x === theirs.x && mine.y === theirs.y, `k·G agrees with the library at k = ${k.toString().slice(0, 24)}`)
  say(ec.isOnCurve(mine), `k·G is on the curve at k = ${k.toString().slice(0, 24)}`)
}

const p1 = ec.mul(7n); const p2 = ec.mul(11n)
const sum = ec.add(p1, p2)
const libSum = ec.fromBsv(ec.toBsv(p1).add(ec.toBsv(p2)))
say(sum.x === libSum.x && sum.y === libSum.y, 'point addition agrees with the library')
say(sum.x === ec.mul(18n).x, '7·G + 11·G = 18·G')

const dbl = ec.double(p1)
const libDbl = ec.fromBsv(ec.toBsv(p1).add(ec.toBsv(p1)))
say(dbl.x === libDbl.x && dbl.y === libDbl.y, 'point doubling agrees with the library')
say(dbl.x === ec.mul(14n).x, '2·(7·G) = 14·G')

console.log(`\n${bad ? bad + ' FAILED' : 'the reference agrees with the library everywhere it was asked'}`)
process.exit(bad ? 1 : 0)
