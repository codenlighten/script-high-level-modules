'use strict'

const { defineModule, apply } = require('./module')

// AND.
//
// A coin's rules are almost never one condition. "The oracle attested it AND
// the holder is on the whitelist AND the owner signed" is three modules, and
// the interesting question is what happens where they meet.
//
// The answer here is deliberately boring: `all()` builds ONE module out of
// several predicates. Its inputs are theirs, prefixed so two modules that both
// call something `msg` do not collide; its emit runs each in turn through
// apply(), which is the same mechanism any module uses to call another; its
// hint merges theirs. The result is a module like any other, so the test kit
// attacks the composition, not just the parts.
//
// That last point is why this exists as a module rather than as a helper that
// concatenates scripts. A composition can be broken in ways its parts are not —
// one module leaving a value where the next reads a depth, two modules sharing
// a witness that only one of them constrains — and the only way to find that is
// to put the composed thing in front of the interpreter and attack it.
//
// Every part must be a PREDICATE: no outputs, asserting and returning nothing.
// A conjunction of things that return values is not a conjunction.

/**
 * @param name   what to call the composed module
 * @param parts  [{ module, params, prefix }] — prefix defaults to the module's
 *               own short name, so `totp.verify` contributes `totp_key`, `totp_time`…
 * @param opts   { doc, cases, notes, maxWitnessAttacks, alwaysAttack }
 */
function all (name, parts, opts = {}) {
  const norm = parts.map((p, i) => {
    if (p.module.outputs.length) {
      throw new Error(`${name}: '${p.module.name}' returns ${p.module.outputs.map((o) => o.name).join(', ')} — all() composes predicates, which assert and return nothing`)
    }
    const prefix = p.prefix || (p.module.name.split('.')[0] + '_')
    return { ...p, prefix, index: i }
  })

  const seen = new Set()
  for (const p of norm) {
    if (seen.has(p.prefix)) throw new Error(`${name}: two parts share the prefix '${p.prefix}' — give one an explicit prefix`)
    seen.add(p.prefix)
  }

  const inputs = norm.flatMap((p) => p.module.inputs.map((i) => ({ ...i, name: p.prefix + i.name })))

  return defineModule({
    name,
    doc: opts.doc || norm.map((p) => p.module.name).join(' ∧ '),
    inputs,
    outputs: [],
    maxWitnessAttacks: opts.maxWitnessAttacks || null,
    alwaysAttack: opts.alwaysAttack || null,
    hint: (values, params) => {
      const out = {}
      for (const p of norm) {
        if (!p.module.hint) continue
        // Each part sees its own inputs under their own names, which is what its
        // hint was written against.
        const local = {}
        for (const i of p.module.inputs) if (p.prefix + i.name in values) local[i.name] = values[p.prefix + i.name]
        const hinted = p.module.hint(local, { ...p.params, ...params })
        for (const k of Object.keys(hinted)) if (!(p.prefix + k in values)) out[p.prefix + k] = hinted[k]
      }
      return out
    },
    model: () => ({}),
    emit: (asm, params) => {
      for (const p of norm) {
        apply(asm, p.module, { ...p.params, ...params }, p.module.inputs.map((i) => p.prefix + i.name), [])
      }
    },
    attacks: (honest, params, fullName) => {
      const p = norm.find((q) => fullName.startsWith(q.prefix))
      if (!p || !p.module.attacks) return null
      const short = fullName.slice(p.prefix.length)
      const local = {}
      for (const i of p.module.inputs) local[i.name] = honest[p.prefix + i.name]
      const list = p.module.attacks(local, { ...p.params, ...params }, short)
      return list && list.map((a) => ({ ...a, label: `${p.module.name}: ${a.label}` }))
    },
    cases: opts.cases || [],
    notes: [
      'composed by all(): every part must hold, and the kit attacks the composition rather than the parts',
      ...(opts.notes || [])
    ]
  })
}

/** The inputs one part of a composition contributes, for building a case. */
function forPart (prefix, values) {
  const out = {}
  for (const k of Object.keys(values)) out[prefix + k] = values[k]
  return out
}

module.exports = { all, forPart }
