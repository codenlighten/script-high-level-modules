'use strict'

// Why the range check in rsa.verify is not decoration.
//
// s and s + n are different numbers with the same residue mod n, so both satisfy
// s^e ≡ EM. A verifier that checks only the equation accepts both — and a
// covenant built on it can be spent two ways, with two different txids, by
// anyone who can see the transaction in flight. Adding a signature to the
// unlocking script is not supposed to be a choice the spender gets to make.
//
// This runs the real module's emit(), once with the check and once without.

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { evaluate } = require('../src/run')
const { pushNum, pushData } = require('../src/num')
const rsaMod = require('../src/modules/rsa')
const rsaJs = require('../src/rsa')

const key = rsaMod.fixtureKey()
const params = { n: key.n, e: key.e, emLen: key.emLen }
const msg = Buffer.from('pay the bearer on demand')
const s = rsaJs.encodeSignature(rsaJs.sign(msg, key.privateKey))

function lock (bounded) {
  const asm = new Asm()
  asm.given([{ name: 'msg', kind: 'bytes' }, { name: 'sig', kind: 'num' }])
  rsaMod.emitVerify(asm, params, { bounded })
  asm.num(1, 'true')                     // the predicate's result
  return asm.script()
}
function unlock (sigValue) {
  return new bsv.Script().add(pushData(msg)).add(pushNum(sigValue))
}

const rows = []
for (const bounded of [true, false]) {
  const l = lock(bounded)
  for (const [label, value] of [['the signature', s], ['the signature + n', s + key.n], ['the signature + 2n', s + 2n * key.n]]) {
    const r = evaluate(unlock(value), l)
    rows.push({ check: bounded ? 'with 0 ≤ s < n' : 'WITHOUT the check', spend: label, accepted: r.ok, bytes: l.toBuffer().length })
  }
}

console.log('\n  range check         unlocking script       verdict')
console.log('  ─────────────────────────────────────────────────────────')
for (const r of rows) {
  console.log(`  ${r.check.padEnd(19)} ${r.spend.padEnd(22)} ${r.accepted ? 'ACCEPTED' : 'refused'}`)
}

const withCheck = rows.filter((r) => r.check.startsWith('with '))
const without = rows.filter((r) => !r.check.startsWith('with '))
const ok = withCheck.filter((r) => r.accepted).length === 1 && without.filter((r) => r.accepted).length === 3
console.log(`\n  ${withCheck.filter((r) => r.accepted).length} of 3 spends accepted with the check, ${without.filter((r) => r.accepted).length} of 3 without it.`)
console.log(`  ${ok ? 'The check is the only thing making the signature unique.' : 'UNEXPECTED — the demonstration did not reproduce.'}`)
console.log(`  Cost of the check: ${lock(true).toBuffer().length - lock(false).toBuffer().length} bytes.\n`)
process.exit(ok ? 0 : 1)
