'use strict'

// Two signature schemes, one lesson: verifying the equation is not the same as
// pinning the witness.
//
// Part one — why the range check in rsa.verify is not decoration.
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

function lock (mode) {
  const asm = new Asm()
  asm.given([{ name: 'msg', kind: 'bytes' }, { name: 'sig', kind: 'num' }])
  rsaMod.emitVerify(asm, params, { mode })
  asm.num(1, 'true')                     // the predicate's result
  return asm.script()
}
function unlock (sigValue) {
  return new bsv.Script().add(pushData(msg)).add(pushNum(sigValue))
}

const MODES = [
  ['checked', 'the bound is emitted'],
  ['omitted', 'the line is deleted'],
  ['asserted', 'the fact is claimed, unchecked']
]
const rows = []
for (const [mode, how] of MODES) {
  const l = lock(mode)
  for (const [label, value] of [['the signature', s], ['the signature + n', s + key.n], ['the signature + 2n', s + 2n * key.n]]) {
    rows.push({ mode, how, spend: label, accepted: evaluate(unlock(value), l).ok, bytes: l.toBuffer().length })
  }
}

console.log('\n  what the module does           unlocking script       verdict')
console.log('  ───────────────────────────────────────────────────────────────────')
for (const r of rows) console.log(`  ${r.how.padEnd(30)} ${r.spend.padEnd(22)} ${r.accepted ? 'ACCEPTED' : 'refused'}`)

const accepted = (m) => rows.filter((r) => r.mode === m && r.accepted).length
console.log(`
  Deleting the check changes nothing: int.modexp REQUIRES a base reduced into
  [0, n) and says so, so the framework emits the bound the module stopped
  emitting. ${lock('omitted').toBuffer().length - lock('checked').toBuffer().length >= 0 ? 'It costs the same or more that way' : 'It even costs a little more that way'}, which is the point — the obligation
  belongs to the mathematics, not to the line of code.

  The property is only lost by CLAIMING the bound without checking it, which is
  why asm.assert() will not take a claim without a written reason.`)
const ok = accepted('checked') === 1 && accepted('omitted') === 1 && accepted('asserted') === 3
console.log(`\n  accepted: ${accepted('checked')}/3 checked, ${accepted('omitted')}/3 with the line deleted, ${accepted('asserted')}/3 asserted.`)
console.log(`  ${ok ? 'A signature is unique because something proves it, not because something says so.' : 'UNEXPECTED — the demonstration did not reproduce.'}`)

// ── Part two: ECDSA is malleable by construction ────────────────────────────
//
// If (r, s) verifies then so does (r, n − s): R and −R share an x coordinate,
// and x is all the equation looks at. Both are genuine signatures over the same
// message by the same key. Bitcoin's answer for OP_CHECKSIG is the mandatory
// LOW_S policy rule, and the same rule belongs in a verifier built out of
// arithmetic — this shows what happens without it.

const { build, complete } = require('../src/testkit')
const ecdsaMod = require('../src/modules/ecdsa')
const ecJs = require('../src/ec')

const sigCase = ecdsaMod.signCase('22'.repeat(32), 'the reference rate is 3.75%')
const rows2 = []
for (const lowS of [true, false]) {
  const m = ecdsaMod.verifier([sigCase], { lowS })
  const honest = complete(m, { lowS }, sigCase.inputs)
  for (const [label, s] of [['s, as signed', honest.s], ['n − s', ecJs.N - honest.s]]) {
    // The witness follows the signature: u₁ and u₂ change with s, so the
    // malleated spend is a properly built one, not a corrupted push.
    const forged = { ...sigCase.inputs, s }
    const w = ecdsaMod.witness({ z: forged.z, r: forged.r, s, q: { x: forged.qx, y: forged.qy } })
    const b = build(m, { lowS }, { ...forged, ...w })
    rows2.push({ lowS, label, accepted: evaluate(b.unlock, b.lock).ok })
  }
}

console.log('\n  low-S rule          signature               verdict')
console.log('  ─────────────────────────────────────────────────────────')
for (const r of rows2) console.log(`  ${(r.lowS ? 'enforced' : 'NOT enforced').padEnd(19)} ${r.label.padEnd(23)} ${r.accepted ? 'ACCEPTED' : 'refused'}`)

const ecdsaOk = rows2.filter((r) => r.lowS && r.accepted).length === 1 &&
  rows2.filter((r) => !r.lowS && r.accepted).length === 2
console.log(`\n  ${ecdsaOk ? 'Both are valid signatures. Only the low-S rule makes one of them the only one.' : 'UNEXPECTED — the demonstration did not reproduce.'}\n`)

process.exit(ok && ecdsaOk ? 0 : 1)
