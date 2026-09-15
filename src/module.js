'use strict'

// A MODULE is one mathematical operation, in two forms that must agree:
//
//   model()   the operation in JavaScript — the specification, readable by
//             anyone who knows the maths and nothing about Script
//   emit()    the same operation as Script, appended to a stack-tracking
//             assembler
//
// Nothing asserts they agree except the test kit, which runs the emitted Script
// on the real consensus interpreter and compares it with the model over a set of
// cases including the awkward ones. A module with no cases is not a module.
//
// THE CALLING CONVENTION. On entry the module's declared inputs are the top of
// the stack, in declared order (last declared = top). On exit those are gone and
// the declared outputs are on top, in declared order. Everything beneath is
// untouched — the test kit proves this with a sentinel rather than trusting it.
//
// WITNESSED INPUTS. Some operations are far cheaper to CHECK than to COMPUTE.
// Modular inverse is the standard example: computing it in Script means the
// extended Euclidean algorithm; checking it means one multiplication. A module
// may therefore declare an input `witness: true`, supplied by whoever spends the
// coin, and verify it instead of computing it.
//
// This is where a module can be quietly, dangerously wrong, so the discipline is
// not optional:
//
//   SOUNDNESS   no wrong witness may be accepted.
//   CANONICITY  exactly ONE witness may be accepted. A module that accepts two
//               different witnesses is a function of the spender's choice, not
//               of its inputs — and a covenant built on it is malleable.
//
// The test kit attacks every witnessed module with both in mind, and a module
// that names a witness without a `hint()` that produces the honest one cannot be
// tested and is rejected at definition time.

const F = require('./facts')

/** `requires`/`ensures` may be a plain object or a function of the params. */
function factsFor (spec, params) {
  return typeof spec === 'function' ? spec(params || {}) : (spec || {})
}

function defineModule (spec) {
  const m = {
    name: spec.name,
    doc: spec.doc || '',
    params: spec.params || {},
    inputs: (spec.inputs || []).map(normSlot),
    outputs: (spec.outputs || []).map(normSlot),
    model: spec.model,
    prologue: spec.prologue || null,
    // How to generate a random, valid input — for modules whose inputs have
    // structure a range cannot describe: a signature, a Merkle proof, a padded
    // block. Without one, tools/fuzz.js says so rather than skipping quietly.
    fuzz: spec.fuzz || null,
    // Bytes appended after everything else in the locking script. A covenant
    // that reads its own script needs that script to have a particular shape —
    // tx.transition's state lives after a top-level OP_RETURN, where it is inert
    // data at a constant offset from the end — and the harness has to build the
    // script it will actually be deployed in, not a convenient stand-in.
    tail: spec.tail || null,
    requires: spec.requires || null,
    ensures: spec.ensures || null,
    emit: spec.emit,
    hint: spec.hint || null,
    cases: spec.cases || [],
    attacks: spec.attacks || null,
    notes: spec.notes || [],
    // A module that reads its own spending transaction cannot be handed a
    // stand-in witness: it produces one from the spend itself.
    contextual: !!spec.contextual,
    witnessFor: spec.witnessFor || null,
    maxWitnessAttacks: spec.maxWitnessAttacks || null,
    alwaysAttack: spec.alwaysAttack || null
  }
  if (!m.name) throw new Error('module: needs a name')
  if (typeof m.model !== 'function') throw new Error(`${m.name}: needs a model()`)
  if (typeof m.emit !== 'function') throw new Error(`${m.name}: needs an emit()`)
  if (!m.cases.length) throw new Error(`${m.name}: needs cases — an untested module is not a module`)
  if (m.contextual && typeof m.witnessFor !== 'function') {
    throw new Error(`${m.name}: reads its own spending transaction, so it needs witnessFor(context) to produce the witness from it`)
  }
  if (!m.contextual && m.witnessFor) {
    throw new Error(`${m.name}: has witnessFor() but is not marked contextual — the kit would never call it`)
  }
  const witnessed = m.inputs.filter((i) => i.witness)
  if (witnessed.length && !m.hint) {
    throw new Error(`${m.name}: declares witnessed input(s) ${witnessed.map((w) => w.name).join(', ')} but no hint() to produce the honest value`)
  }
  m.witnessed = witnessed

  // Every call goes through here, whoever makes it. A requirement stated in
  // `requires` is discharged from what is already known about the value,
  // emitted as a check, or refused — and the third is not an inconvenience, it
  // is the whole reason the mechanism exists.
  const rawEmit = m.emit
  m.emit = (asm, params = {}) => {
    // A module may put its own constants on the stack before its requirements
    // are checked: the bounds are usually among them, and a bound that is
    // already live costs two bytes to reference instead of thirty-four to push.
    const beforePrologue = asm.stack.length
    if (typeof m.prologue === 'function') m.prologue(asm, params)
    enforceRequires(asm, m, params, beforePrologue)
    rawEmit(asm, params)
    attachEnsures(asm, m, params)
  }
  return m
}

/** Check the module's inputs, which the calling convention puts on top. */
function enforceRequires (asm, m, params, depthBeforePrologue) {
  const need = factsFor(m.requires, params)
  if (!Object.keys(need).length) return
  // The inputs sit where the calling convention put them, which is BELOW
  // anything the prologue has since pushed on top of them.
  const top = depthBeforePrologue === undefined ? asm.stack.length : depthBeforePrologue
  const base = top - m.inputs.length

  // First decide what is still owed. A requirement an upstream fact already
  // implies costs nothing, and most of them do.
  const owed = []
  m.inputs.forEach((slot, i) => {
    const want = need[slot.name]
    if (!want) return
    const live = asm.stack[base + i]
    if (!live) throw new Error(`${m.name}: '${slot.name}' is not on the stack where the calling convention says it is`)
    if (F.implies(live.facts, want)) return
    if (want.authenticated) {
      throw new Error(`${m.name} requires '${slot.name}' to be ${F.describe(want)}; ` +
        `what is known of '${live.name}' is ${F.describe(live.facts)}. ` +
        `'${live.name}' must be an authenticated preimage, and no check can establish that here — ` +
        'it comes from tx.locktime or tx.hashOutputs, or it does not come at all')
    }
    if (!want.range) {
      throw new Error(`${m.name} requires '${slot.name}' to be ${F.describe(want)}, ` +
        'which this framework does not know how to check')
    }
    owed.push({ live, want })
  })
  if (!owed.length) return

  // Several inputs usually share one bound — four coordinates and one prime.
  // Pushing a 256-bit modulus once and picking it four times is 40 bytes to
  // pushing it four times' 136. A SMALL bound is the other way round: a pick
  // costs two bytes and OP_0 costs one, so hoisting it would lose. Which is why
  // this asks how big the push actually is rather than assuming.
  const hoisted = []
  const bounds = new Map()
  const boundFor = (v) => {
    if (bounds.has(v)) return bounds.get(v)
    const found = F.findExact(asm, v)
    if (found) { bounds.set(v, found); return found }
    if (F.pushCost(v) <= 2) { bounds.set(v, null); return null }   // cheaper inline
    const temp = `_rq${hoisted.length}`
    asm.num(v, temp)
    hoisted.push(temp)
    bounds.set(v, temp)
    return temp
  }

  const place = (v, name, temp) => (name ? asm.pick(name, temp) : asm.num(v, temp))

  for (const { live, want } of owed) {
    const lo = boundFor(want.range.lo)
    const hi = boundFor(want.range.hi)
    asm.pick(live.name, '_rqv')
    place(want.range.lo, lo, '_rqlo')
    place(want.range.hi, hi, '_rqhi')
    asm.withinVerify()
    live.facts = F.meet(live.facts, want)
    // The check is in the script now, so the bound is established rather than
    // claimed — and an audit that asks which witnesses were bounded should be
    // able to see it, the same as a bound written with asm.bound().
    if (live.origin) asm.boundedOrigins.add(live.origin)
  }
  for (const t of hoisted.reverse()) asm.discard(t)
}

/** Record what the module says its outputs are, for whoever consumes them. */
function attachEnsures (asm, m, params) {
  const gives = factsFor(m.ensures, params)
  if (!Object.keys(gives).length) return
  const base = asm.stack.length - m.outputs.length
  m.outputs.forEach((slot, i) => {
    const f = gives[slot.name]
    const live = asm.stack[base + i]
    if (f && live) live.facts = F.meet(live.facts, f)
  })
}

function normSlot (s) {
  const v = typeof s === 'string' ? { name: s } : { ...s }
  v.kind = v.kind || 'num'
  if (!v.name) throw new Error('module: a slot needs a name')
  return v
}

/**
 * Instantiate a module for a given set of compile-time parameters: the concrete
 * Script it emits, its inputs and its cost. Modules compose by calling each
 * other's emit() on the same assembler, so a composite pays no wrapping cost.
 */
function instantiate (m, params = {}) {
  return {
    module: m,
    params,
    emit: (asm) => m.emit(asm, params),
    inputs: m.inputs,
    outputs: m.outputs
  }
}

/**
 * CALL one module from another.
 *
 * A module names its inputs, and its emit() reaches for them by those names. So
 * composing is not "concatenate the two scripts": the caller's values have to be
 * moved into the callee's declared order and renamed to what the callee expects.
 * That is all this does — and doing it in one place is what stops composition
 * from being the thing that reintroduces stack bugs.
 *
 *   apply(asm, int.modexp, { n, e }, ['sig'], ['r'])
 *
 * `args` are existing stack names, in the callee's input order; they are
 * CONSUMED. `outs` renames the callee's outputs for the caller. A value needed
 * afterwards must be copied first (asm.pick).
 */
function apply (asm, m, params, args, outs) {
  if (args.length !== m.inputs.length) {
    throw new Error(`${m.name}: takes ${m.inputs.length} input(s) (${m.inputs.map((i) => i.name).join(', ')}), given ${args.length}`)
  }
  // If the arguments are already the top of the stack, in order, the calling
  // convention is satisfied and there is nothing to emit — renaming the slots is
  // enough. Rolling them anyway costs two bytes each, and a ladder makes this
  // call 512 times.
  const top = asm.stack.slice(-args.length).map((v) => v.name)
  const inPlace = args.length > 0 && top.length === args.length &&
    top.every((n, k) => n === args[k])

  if (inPlace) {
    args.forEach((a, k) => {
      const slot = asm.stack[asm.stack.length - args.length + k]
      const want = m.inputs[k]
      if (slot.kind !== want.kind) {
        throw new Error(`${m.name}: input '${want.name}' is ${want.kind}, but '${a}' is ${slot.kind}`)
      }
      slot.name = want.name
    })
  } else {
    args.forEach((a, k) => {
      asm.roll(a)
      const want = m.inputs[k]
      const have = asm.top()
      if (have.kind !== want.kind) {
        throw new Error(`${m.name}: input '${want.name}' is ${want.kind}, but '${a}' is ${have.kind}`)
      }
      asm.rename(want.name, want.kind, have.width)
    })
  }
  m.emit(asm, params)
  if (outs) {
    if (outs.length !== m.outputs.length) {
      throw new Error(`${m.name}: produces ${m.outputs.length} output(s), ${outs.length} name(s) given`)
    }
    // Rename bottom-up so the callee's declared output order is preserved.
    for (let k = 0; k < outs.length; k++) {
      asm.roll(m.outputs[k].name)
      asm.rename(outs[k], m.outputs[k].kind)
    }
  }
  return asm
}

module.exports = { defineModule, instantiate, apply, factsFor, enforceRequires, attachEnsures }
