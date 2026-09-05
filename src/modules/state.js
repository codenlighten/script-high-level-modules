'use strict'

const { defineModule } = require('../module')

// RULES ABOUT SUCCESSION.
//
// `tx.transition` enforces the mechanics — that the spend recreates this exact
// script with one field replaced, carrying the value that came in less a fee. It
// deliberately does not decide WHICH successor is legal, because that is the
// part that differs between a counter, a licence, a ledger and a game.
//
// These are that second half. Each takes the current state and the proposed one
// and says whether the step is allowed. Piped after `tx.transition` they make a
// coin that can only move by advancing its own state in a particular way.
//
// The split is the point. Everything below is about what a state may become;
// nothing below knows what a preimage is.

const leNum = (asm, name, out) => {
  asm.pick(name, out + '_b')
  asm.data(Buffer.from([0]), out + '_z')     // keep the top bit from meaning a sign
  asm.cat(out + '_p')
  asm.bin2num(out)
}

const toNum = (b) => {
  let v = 0n
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i])
  return v
}

/**
 * The state is a counter, and it may only go up by one.
 *
 * The smallest rule there is, and it makes a coin that is a monotonic sequence:
 * every spend advances it, nobody can skip, nobody can go back, and the history
 * is the chain of transactions that did it.
 */
function counter ({ stateWidth = 8, step = 1n, cases } = {}) {
  const W = stateWidth
  return defineModule({
    name: 'state.counter',
    doc: `the successor is the current state plus ${step}`,
    inputs: [
      { name: 'state', kind: 'bytes', width: W },
      { name: 'next', kind: 'bytes', width: W, witness: true }
    ],
    outputs: [],
    hint: ({ state }) => (state === undefined ? {} : { next: bump(state, step) }),
    model: () => ({}),
    emit: (asm) => {
      leNum(asm, 'state', '_cur')
      asm.num(step, '_step'); asm.add('_want')
      leNum(asm, 'next', '_got')
      asm.numEqualVerify()
      asm.discard('state'); asm.discard('next')
    },
    attacks: (honest) => [
      { label: 'skipping ahead', value: bump(honest.state, step + step) },
      { label: 'standing still', value: Buffer.from(honest.state) },
      { label: 'going back', value: bump(honest.state, -step) }
    ],
    cases: cases || [
      { name: 'from zero', inputs: { state: le(0n, W) } },
      { name: 'from forty-one', inputs: { state: le(41n, W) } },
      {
        name: 'skipping a step',
        refuse: 'the successor is the current state plus one, and nothing else',
        inputs: { state: le(41n, W), next: le(43n, W) }
      },
      {
        name: 'standing still',
        refuse: 'a spend has to advance it',
        inputs: { state: le(41n, W), next: le(41n, W) }
      },
      {
        name: 'going backwards',
        refuse: 'the sequence is monotonic',
        inputs: { state: le(41n, W), next: le(40n, W) }
      }
    ],
    notes: ['says nothing about how the state is carried — tx.transition does that']
  })
}

/**
 * The state is a spending allowance, and every payment takes it down by exactly
 * what was paid.
 *
 * `next + amount = state`, and that single equation does more than it looks.
 * `next` is an unsigned field — it is read out of the script's bytes with a
 * sign byte appended, so it cannot be negative — and `amount` is required to be
 * at least one. Together those force `amount ≤ state`: overspending is not
 * refused by a comparison, it is unrepresentable, because there is no successor
 * that would balance the equation.
 *
 * What the coin becomes is an authority with a ceiling. Whoever can satisfy the
 * rest of the predicate may pay whatever they like, to whomever they like, up to
 * a total nobody can raise — not the holder, and not whoever wrote the spend.
 */
function limit ({ stateWidth = 8, cases } = {}) {
  const W = stateWidth
  return defineModule({
    name: 'state.limit',
    doc: 'the allowance falls by exactly what the spend pays out',
    inputs: [
      { name: 'state', kind: 'bytes', width: W },
      { name: 'next', kind: 'bytes', width: W, witness: true },
      { name: 'amount', witness: true }
    ],
    outputs: [],
    hint: ({ state, amount }) => (state === undefined || amount === undefined
      ? {}
      : { next: le(toNum(state) - BigInt(amount), W) }),
    model: () => ({}),
    emit: (asm) => {
      asm.pick('amount', '_a0'); asm.num(1, '_one'); asm.geVerify()   // a payment, not a nudge
      leNum(asm, 'next', '_nx')
      asm.pick('amount', '_a1'); asm.add('_sum')
      leNum(asm, 'state', '_st')
      asm.numEqualVerify()
      asm.discard('state'); asm.discard('next'); asm.discard('amount')
    },
    attacks: (honest, params, name) => {
      const remaining = toNum(honest.state)
      if (name === 'amount') {
        return [
          { label: 'paying more than the successor accounts for', value: BigInt(honest.amount) + 1n },
          { label: 'paying the whole allowance while keeping it', value: remaining },
          { label: 'paying nothing', value: 0n }
        ]
      }
      return [
        { label: 'an allowance that did not fall', value: Buffer.from(honest.state) },
        { label: 'an allowance that rose', value: le(remaining + 1n, W) }
      ]
    },
    cases: cases || [
      { name: 'spending 400 of 1000', inputs: { state: le(1000n, W), amount: 400n } },
      { name: 'spending the last satoshi of it', inputs: { state: le(1n, W), amount: 1n } },
      { name: 'spending all of it at once', inputs: { state: le(1000n, W), amount: 1000n } },
      {
        name: 'spending more than remains',
        refuse: 'there is no successor that balances the equation',
        inputs: { state: le(10n, W), amount: 11n, next: le(0n, W) }
      },
      {
        name: 'paying without decrementing',
        refuse: 'the allowance falls by exactly what was paid',
        inputs: { state: le(1000n, W), amount: 400n, next: le(1000n, W) }
      },
      {
        name: 'a payment of nothing',
        refuse: 'a spend has to pay something',
        inputs: { state: le(1000n, W), amount: 0n, next: le(1000n, W) }
      }
    ],
    notes: [
      'overspending is unrepresentable rather than refused: no successor balances the equation',
      'says nothing about WHO may spend or to whom — compose that alongside'
    ]
  })
}

function le (v, w) {
  // A counter is an unsigned field, and a forgery that would take it below zero
  // is still a forgery — it just wraps, the way the bytes would.
  const span = 1n << BigInt(8 * w)
  const x = ((BigInt(v) % span) + span) % span
  const b = Buffer.alloc(w)
  b.writeBigUInt64LE(x)
  return b
}
function bump (state, by) { return le(toNum(state) + BigInt(by), state.length) }

module.exports = { counter, limit, le, toNum }
