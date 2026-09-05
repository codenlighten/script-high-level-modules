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

function defineModule (spec) {
  const m = {
    name: spec.name,
    doc: spec.doc || '',
    params: spec.params || {},
    inputs: (spec.inputs || []).map(normSlot),
    outputs: (spec.outputs || []).map(normSlot),
    model: spec.model,
    emit: spec.emit,
    hint: spec.hint || null,
    cases: spec.cases || [],
    attacks: spec.attacks || null,
    notes: spec.notes || []
  }
  if (!m.name) throw new Error('module: needs a name')
  if (typeof m.model !== 'function') throw new Error(`${m.name}: needs a model()`)
  if (typeof m.emit !== 'function') throw new Error(`${m.name}: needs an emit()`)
  if (!m.cases.length) throw new Error(`${m.name}: needs cases — an untested module is not a module`)
  const witnessed = m.inputs.filter((i) => i.witness)
  if (witnessed.length && !m.hint) {
    throw new Error(`${m.name}: declares witnessed input(s) ${witnessed.map((w) => w.name).join(', ')} but no hint() to produce the honest value`)
  }
  m.witnessed = witnessed
  return m
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
  args.forEach((a, k) => {
    asm.roll(a)
    const want = m.inputs[k]
    const have = asm.top()
    if (have.kind !== want.kind) {
      throw new Error(`${m.name}: input '${want.name}' is ${want.kind}, but '${a}' is ${have.kind}`)
    }
    asm.rename(want.name, want.kind, have.width)
  })
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

module.exports = { defineModule, instantiate, apply }
