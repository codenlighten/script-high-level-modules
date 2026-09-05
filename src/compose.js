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

// ── PIPE: one module's output is the next one's input ───────────────────────
//
// `all()` composes predicates that each stand alone — every part must hold, and
// none of them talks to another. The other shape is a chain: `tx.locktime`
// produces the transaction's locktime and `totp.verify` consumes it as the time
// its code must match. Neither is a conjunction; the second cannot run without
// the first.
//
// That was written by hand twice before this existed, in an example and in a
// deployment target, which is the usual sign that it should not have been
// written by hand at all. The two copies had already drifted in their naming.
//
// The wiring is a small linker. Walk the parts in order keeping track of what
// has been produced; a part's input is either taken from something an earlier
// part produced, or it becomes an input of the composed module. Whatever is
// still unconsumed at the end is the composed module's output — so a chain that
// consumes everything is a predicate, and `predicate()` will take it.

/**
 * @param name  what to call the result
 * @param parts [{ module, params, as }] — `as` renames a part's outputs so a
 *              later part can name them, e.g. `{ locktime: 'time' }`
 * @param opts  { doc, cases, notes, prefix }
 */
function pipe (name, parts, opts = {}) {
  const produced = new Map()          // name -> the part that produced it
  const consumed = new Set()
  const inputs = []
  const wiring = []

  parts.forEach((part, i) => {
    const where = `${name}: part ${i} (${part.module.name})`
    const args = part.module.inputs.map((slot) => {
      if (produced.has(slot.name)) {
        if (consumed.has(slot.name)) {
          throw new Error(`${where} wants '${slot.name}', which an earlier part produced and another part already consumed — a piped value has exactly one reader`)
        }
        consumed.add(slot.name)
        return slot.name
      }
      // not produced upstream, so the composition asks for it
      const outer = inputs.some((x) => x.name === slot.name) ? `${part.module.name.split('.')[0]}_${slot.name}` : slot.name
      if (inputs.some((x) => x.name === outer)) throw new Error(`${where}: two parts both want '${slot.name}' from the caller; give one an explicit prefix`)
      inputs.push({ ...slot, name: outer })
      return outer
    })

    const outs = part.module.outputs.map((o) => {
      const renamed = (part.as && part.as[o.name]) || o.name
      if (produced.has(renamed) && !consumed.has(renamed)) {
        throw new Error(`${where} produces '${renamed}', which is already live and unread`)
      }
      produced.set(renamed, i)
      return renamed
    })

    wiring.push({ part, args, outs })
  })

  const leftover = [...produced.keys()].filter((k) => !consumed.has(k))
  const outputs = leftover.map((k) => {
    const w = wiring.find((x) => x.outs.includes(k))
    const o = w.part.module.outputs[w.outs.indexOf(k)]
    return { ...o, name: k }
  })

  // A chain is contextual if any link is: the witness comes from the spend.
  const ctx = parts.find((p) => p.module.contextual)

  return defineModule({
    name,
    doc: opts.doc || parts.map((p) => p.module.name).join(' ▸ '),
    inputs,
    outputs,
    contextual: !!ctx,
    witnessFor: ctx ? ((c) => ctx.module.witnessFor(c)) : null,
    // A hint works out an honest witness off chain from the module's own
    // inputs. In a chain, some of those inputs do not exist off chain — they are
    // produced at spend time by an earlier part — so a part whose inputs are not
    // all available is SKIPPED rather than called with an undefined. Its witness
    // has to come from the case, which is the honest position: nothing off chain
    // knows what the transaction will say.
    hint: (values, params) => {
      const out = {}
      for (const { part, args } of wiring) {
        if (!part.module.hint) continue
        const merged = { ...values, ...out }
        const local = {}
        let ready = true
        part.module.inputs.forEach((slot, k) => {
          if (!(args[k] in merged)) { ready = false; return }
          local[slot.name] = merged[args[k]]
        })
        if (!ready) continue
        const hinted = part.module.hint(local, { ...part.params, ...params })
        for (const [k, v] of Object.entries(hinted)) {
          const idx = part.module.inputs.findIndex((s) => s.name === k)
          const outer = idx >= 0 ? args[idx] : k
          if (!(outer in merged)) out[outer] = v
        }
      }
      return out
    },
    model: opts.model || (() => ({})),
    emit: (asm, params) => {
      for (const { part, args, outs } of wiring) {
        apply(asm, part.module, { ...part.params, ...params }, args, outs)
      }
    },
    // A part's own forgeries are the best ones — the previous window's code, a
    // residue of the same class — but they are computed from that part's
    // inputs, and in a chain some of those only exist at spend time. When they
    // are not all available the composition falls back to near-misses of the
    // value itself. That is a weaker attack, not an absent one: the kit's rule
    // that an unattackable witness is UNPROVEN still holds, and still bites.
    attacks: (honest, params, fullName) => {
      for (const { part, args } of wiring) {
        const idx = args.indexOf(fullName)
        if (idx < 0) continue
        const local = {}
        let ready = true
        part.module.inputs.forEach((slot, k) => {
          if (!(args[k] in honest)) ready = false
          local[slot.name] = honest[args[k]]
        })
        if (part.module.attacks && ready) {
          const list = part.module.attacks(local, { ...part.params, ...params }, part.module.inputs[idx].name)
          if (list) return list.map((a) => ({ ...a, label: `${part.module.name}: ${a.label}` }))
        }
        return nearMisses(honest[fullName], `${part.module.name}: ${fullName}`)
      }
      return null
    },
    cases: opts.cases || [],
    notes: [
      'composed by pipe(): each part reads what the one before it produced',
      ...(opts.notes || [])
    ]
  })
}

/** Generic forgeries of a value, for when a part's own generator cannot run. */
function nearMisses (v, label) {
  if (typeof v === 'bigint') {
    return [
      { label: `${label} off by one`, value: v + 1n },
      { label: `${label} off by one the other way`, value: v - 1n },
      { label: `${label} zeroed`, value: 0n }
    ]
  }
  if (Buffer.isBuffer(v) && v.length) {
    const flipped = Buffer.from(v); flipped[0] ^= 0x01
    return [
      { label: `${label}: first byte changed`, value: flipped },
      { label: `${label}: truncated`, value: v.subarray(0, v.length - 1) },
      { label: `${label}: a byte appended`, value: Buffer.concat([v, Buffer.from([0])]) }
    ]
  }
  return null
}

/** The inputs one part of a composition contributes, for building a case. */
function forPart (prefix, values) {
  const out = {}
  for (const k of Object.keys(values)) out[prefix + k] = values[k]
  return out
}

module.exports = { all, pipe, forPart, nearMisses }
