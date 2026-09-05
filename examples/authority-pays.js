'use strict'

// THE AUTHORITY NAMES THE DESTINATION, AND THE CHAIN PAYS WHOEVER THEY NAMED.
//
// Every other example here gates a coin: the signature says *whether* it may
// move. This one directs it. The authority signs an instruction — twenty bytes
// of public-key hash and eight of amount — and the locking script builds the
// transaction output that instruction describes and requires the spend to match
// it. Nothing about the destination is in the locking script.
//
// AND THIS ONE NEEDS NO OWNER, WHICH IS THE POINT.
//
// `predicate()` refuses to build without an owner key, because every off-chain
// signature scheme here authorises a MESSAGE and not a TRANSACTION: publish the
// witness once and anyone can replay it to redirect the next such coin to
// themselves. `owner: null` says you meant it.
//
// Here it is meant. Replaying this witness produces the same payment to the same
// address, because the destination is inside the thing that was signed. Output
// binding removes the reason the owner check existed — which is worth seeing,
// because it shows that check was a thought rather than a ritual.

const bsv = require('@smartledger/bsv')
const { predicate, recipes } = require('../src')
const rsaMod = require('../src/modules/rsa')

const authority = rsaMod.fixtureKey()
const payee = bsv.PrivateKey.fromBuffer(Buffer.from('55'.repeat(32), 'hex')).toAddress()
const elsewhere = bsv.PrivateKey.fromBuffer(Buffer.from('66'.repeat(32), 'hex')).toAddress()
const AMOUNT = 700

const msg = recipes.instruction(payee, AMOUNT)
const m = recipes.authorityPays(authority, { cases: recipes.authorityPaysCases(payee, AMOUNT, elsewhere) })
const coin = predicate(m, {}, { owner: null })

const paying = (to, sats, extra) => ({
  outputs: [recipes.instructedOutput(to, sats), ...(extra ? [recipes.instructedOutput(elsewhere, extra)] : [])]
})

const honest = coin.test({ msg }, null, paying(payee, AMOUNT))
const refusals = [
  ['the right amount, a different address', coin.test({ msg }, null, paying(elsewhere, AMOUNT))],
  ['the right address, a different amount', coin.test({ msg }, null, paying(payee, AMOUNT - 1))],
  ['what was named, and a second output', coin.test({ msg }, null, paying(payee, AMOUNT, 1))],
  ['an instruction the authority did not sign', coin.test(
    { msg: recipes.instruction(elsewhere, AMOUNT), rsaSig: 0n }, null, paying(elsewhere, AMOUNT))]
]

console.log(`
  A payment directed by an authority's signature

  locking script     ${coin.size.toLocaleString()} bytes
  unlocking script   ${honest.unlockSize.toLocaleString()} bytes
  instruction        pay ${AMOUNT} to ${payee}
  signed by          an RSA-2048 key, over 28 bytes

  the spend pays exactly what was named               ${honest.ok ? 'ACCEPTED' : 'refused — ' + honest.error}`)
for (const [what, r] of refusals) console.log(`  ${what.padEnd(51)} ${r.ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

console.log('\n  What this costs you:')
for (const n of m.notes) console.log(`    · ${n}`)

const ok = honest.ok && refusals.every(([, r]) => !r.ok)
console.log(`\n  ${ok ? 'The signature does not permit a spend. It directs one.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
