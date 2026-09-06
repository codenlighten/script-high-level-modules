'use strict'

// WHAT IS KNOWN ABOUT A VALUE.
//
// Three modules in this repository documented a precondition and did not
// enforce it, and all three were green: `schnorr.liftX` did not bound x below
// the field size, `ecdsa.verify` did not bound its public key's coordinates, and
// `ec.add` said its inputs were in [0, p) and took whatever it was given. The
// third produced a NEGATIVE x₃ — congruent to the right answer, and not the
// canonical representative of it.
//
// The fix each time was a bound. The interesting part was WHERE to put it:
// inside a ladder every coordinate is a reduction the module itself produced, so
// the check would cost 7 KB to learn nothing; standalone, the caller is whoever
// wrote the unlocking script and the check is the only thing standing between
// the module and its documentation. That distinction was a hand-written
// `if (N.pushed)` sitting on my judgement about which callers were safe.
//
// This makes it mechanical. A value carries FACTS; a module states what it
// REQUIRES of each input and what it ENSURES of each output. At the call, each
// requirement is either
//
//   DISCHARGED   an upstream fact already implies it — nothing is emitted;
//   EMITTED      the framework knows a check for it and inserts one;
//   REFUSED      neither, and the build fails naming the obligation.
//
// The third case is the point. Some obligations cannot be checked in Script at
// all — that a preimage is authenticated is established by OP_PUSH_TX or not at
// all — and for those, silence is the only wrong answer.

const bsv = require('@smartledger/bsv')
const Op = bsv.Opcode

/** A value is in [lo, hi). */
const range = (lo, hi) => ({ range: { lo: BigInt(lo), hi: BigInt(hi) } })
/** A preimage has been proven to be this spending transaction. */
const authenticated = () => ({ authenticated: true })

/** Does what is known about a value imply what a module needs of it? */
function implies (have = {}, need = {}) {
  if (need.range) {
    if (!have.range) return false
    if (have.range.lo < need.range.lo || have.range.hi > need.range.hi) return false
  }
  if (need.authenticated && !have.authenticated) return false
  return true
}

/** Everything two fact sets both say. */
function meet (a = {}, b = {}) {
  const out = {}
  if (a.range && b.range) {
    out.range = { lo: a.range.lo > b.range.lo ? a.range.lo : b.range.lo, hi: a.range.hi < b.range.hi ? a.range.hi : b.range.hi }
  } else if (a.range || b.range) out.range = a.range || b.range
  if (a.authenticated || b.authenticated) out.authenticated = true
  return out
}

/**
 * Emit the check that establishes `need` for the value named `name`, or return
 * the reason it cannot be emitted.
 *
 * A range is checkable: OP_WITHIN, seven bytes. Authentication is not — it is
 * established by proving a preimage IS this transaction, which no bound can
 * substitute for. Saying so is better than emitting something that looks like a
 * check and is not one.
 */
function discharge (asm, name, need) {
  if (need.authenticated) {
    return `'${name}' must be an authenticated preimage, and no check can establish that here — it comes from tx.locktime or tx.hashOutputs, or it does not come at all`
  }
  if (need.range) {
    const { lo, hi } = need.range
    asm.pick(name, '_fk')
    pushBound(asm, lo, '_flo')
    pushBound(asm, hi, '_fhi')
    asm.withinVerify()
    // Record which INPUT this bound landed on, so that "is every witness
    // bounded" is answerable by structure rather than by sampling attacks.
    // tools/audit-soundness.js reads it; without this line a bound emitted by
    // the framework is invisible to the audit and reports as a hole.
    const slot = asm.slot(name)
    if (slot && slot.origin) asm.boundedOrigins.add(slot.origin)
    return null
  }
  return `'${name}' carries a requirement this framework does not know how to check`
}

/**
 * Put a bound where OP_WITHIN can read it, copying one that is already on the
 * stack in preference to pushing it again.
 *
 * A 256-bit modulus is a 33-byte push and a point operation needs its bounds
 * four times. The module has that value live already — it is about to reduce
 * with it — and the fact system is what makes it findable: a literal carries its
 * own exact range, so a slot whose range is [v, v+1) IS v.
 */
function pushBound (asm, v, temp) {
  const found = findExact(asm, v)
  return found ? asm.pick(found, temp) : asm.num(v, temp)
}

/** How many bytes it takes to push this value as a literal. */
function pushCost (v) {
  const { pushNum } = require('./num')
  const p = pushNum(v)
  if (typeof p === 'number') return 1                    // a dedicated opcode
  return p.length + (p.length < 76 ? 1 : p.length < 256 ? 2 : 3)
}

/** The name of a live value known to be exactly `v`, if there is one. */
function findExact (asm, v) {
  for (let i = asm.stack.length - 1; i >= 0; i--) {
    const f = asm.stack[i].facts
    if (f && f.range && f.range.lo === v && f.range.hi === v + 1n) return asm.stack[i].name
  }
  return null
}

/** A short, readable form, for an error that has to explain itself. */
function describe (f = {}) {
  const parts = []
  if (f.range) parts.push(`in [${short(f.range.lo)}, ${short(f.range.hi)})`)
  if (f.authenticated) parts.push('an authenticated preimage')
  return parts.length ? parts.join(' and ') : 'nothing in particular'
}
const short = (v) => (v > 0xffffffffn ? '2^' + (v.toString(2).length - 1) + '…' : v.toString())

module.exports = { range, authenticated, implies, meet, discharge, pushBound, findExact, pushCost, describe, Op }
