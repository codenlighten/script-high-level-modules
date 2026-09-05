'use strict'

// A COIN WITH A CEILING NOBODY CAN RAISE.
//
// The counter carries a number forward. This carries an AUTHORITY: whoever can
// satisfy the predicate may pay whatever they like, to whomever they like, up to
// a total fixed at the moment the coin was funded.
//
//   tx.transitionPaying   commits to BOTH of the spend's outputs — the successor
//                         and one payment — and does the value arithmetic
//                         itself, so nothing is left over to be redirected.
//   state.limit           requires the successor's allowance to be lower by
//                         exactly what was paid.
//
// Overspending is not refused by a comparison. `next + amount = state` with
// `next` an unsigned field and `amount` at least one leaves no successor that
// balances the equation, so there is no spend to refuse.
//
// WHAT IT COSTS TO SAY IT THIS WAY. The allowance is denominated in the coin's
// own satoshis — the payment comes out of its value — so the coin must be funded
// with the allowance plus a fee for every step it might take. And the rule says
// nothing about WHO may spend or to WHOM: an owner key, a payee allowlist, a time
// window are more rules alongside, and `all()` is how they join.

const bsv = require('@smartledger/bsv')
const { Asm } = require('../src/asm')
const { buildSpend, evaluatePrepared } = require('../src/run')
const { pushData, pushNum } = require('../src/num')
const { recipes } = require('../src')
const txMod = require('../src/modules/tx')
const stateMod = require('../src/modules/state')

const W = 8
const FEE = 300
const ALLOWANCE = 2000n

const m = recipes.budgetCoin({ allowance: ALLOWANCE, stateWidth: W, fee: FEE })

function coinAt (remaining) {
  const asm = new Asm()
  asm.given(m.inputs.map((i) => ({ ...i })))
  m.emit(asm, { state: stateMod.le(remaining, W) })
  asm.num(1, 'true')
  return new bsv.Script(Buffer.concat([asm.script().toBuffer(), m.tail({ state: stateMod.le(remaining, W) })]))
}

const payees = [
  ['a supplier', Buffer.alloc(20, 0x11)],
  ['a contractor', Buffer.alloc(20, 0x22)],
  ['the same supplier again', Buffer.alloc(20, 0x11)]
]
const amounts = [700n, 500n, 800n]

// funded with the allowance, plus a fee for every step it may take
let value = Number(ALLOWANCE) + FEE * (payees.length + 1)
let remaining = ALLOWANCE
let prevTxId = null
const rows = []

for (let i = 0; i < payees.length; i++) {
  const [who, pkh] = payees[i]
  const amount = amounts[i]
  const lock = coinAt(remaining)
  const prepared = buildSpend(lock, { satoshis: value, prevTxId })
  const w = txMod.payingWitness({ ...prepared, spend: { next: stateMod.le(remaining - amount, W), amount, payee: pkh } }, W, FEE)
  const r = evaluatePrepared(prepared, () => new bsv.Script()
    .add(pushData(w.preimage)).add(pushData(w.next)).add(pushNum(w.amount)).add(pushData(w.payee)))

  rows.push({ who, amount, ok: r.ok, err: r.error, from: remaining, to: remaining - amount, left: prepared.tx.outputs[0].satoshis })
  prevTxId = prepared.tx.hash
  value = prepared.tx.outputs[0].satoshis
  remaining -= amount
}

// and what it will not do
const lock = coinAt(remaining)
const prepared = buildSpend(lock, { satoshis: value })
function attempt (amount, next, label) {
  try {
    const w = txMod.payingWitness({ ...prepared, spend: { next: stateMod.le(next, W), amount, payee: Buffer.alloc(20, 0x33) } }, W, FEE)
    const r = evaluatePrepared(prepared, () => new bsv.Script()
      .add(pushData(w.preimage)).add(pushData(w.next)).add(pushNum(w.amount)).add(pushData(w.payee)))
    return [label, r.ok]
  } catch (e) {
    // A successor with a negative value cannot even be serialised — the coin
    // holds less than the payment would take out of it.
    return [label, false]
  }
}
const refusals = [
  attempt(remaining + 1n, 0n, 'paying one more than remains'),
  attempt(100n, remaining, 'paying without decrementing'),
  attempt(0n, remaining, 'paying nothing at all')
]

console.log(`
  A spending allowance the coin enforces on itself

  locking script     ${coinAt(ALLOWANCE).toBuffer().length} bytes
  allowance          ${ALLOWANCE} satoshis, fixed when it was funded
  fee per step       ${FEE} satoshis
`)
for (const r of rows) {
  console.log(`  pays ${String(r.amount).padStart(4)} to ${r.who.padEnd(24)} ${r.ok ? 'ACCEPTED' : 'refused — ' + r.err}   allowance ${r.from} → ${r.to}`)
}
console.log(`\n  ${remaining} satoshis of allowance left\n`)
for (const [what, ok] of refusals) console.log(`  ${what.padEnd(38)} ${ok ? 'ACCEPTED — BROKEN' : 'refused'}`)

const ok = rows.every((r) => r.ok) && refusals.every(([, a]) => !a)
console.log(`\n  ${ok ? 'A ceiling fixed at funding, that no later transaction can raise.' : 'UNEXPECTED — the example did not behave as described.'}\n`)
process.exit(ok ? 0 : 1)
