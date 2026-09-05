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

module.exports = { counter, le, toNum }
