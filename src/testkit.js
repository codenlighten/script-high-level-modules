'use strict'

const bsv = require('@smartledger/bsv')
const { Asm } = require('./asm')
const { evaluate, countOps } = require('./run')
const { pushNum, pushData, toNum } = require('./num')

// Proving a module. Three questions, in order of how often they are skipped:
//
//   1. does the Script compute what the model says?      (over real cases)
//   2. does it leave the stack the way it promised?      (a sentinel beneath)
//   3. what does it REFUSE?                              (every witnessed input,
//      attacked — including the attacks that look like the honest answer)
//
// Only the first is usually asked. The third is the one that decides whether a
// module can be trusted inside someone else's covenant.

const SENTINEL = Buffer.from('5ec0ffee', 'hex')

/** Push a value onto an unlocking script in the encoding its kind implies. */
function push (script, value, kind) {
  if (kind === 'bytes') return script.add(pushData(Buffer.isBuffer(value) ? value : Buffer.from(value)))
  return script.add(pushNum(value))
}

/**
 * Build `unlock || lock` for one case: the module's Script, followed by an
 * assertion that each output equals what the model predicted.
 */
function build (m, params, values) {
  const expected = m.model(values, params)

  const unlock = new bsv.Script()
  push(unlock, SENTINEL, 'bytes')
  for (const i of m.inputs) {
    if (!(i.name in values)) throw new Error(`${m.name}: case is missing input '${i.name}'`)
    push(unlock, values[i.name], i.kind)
  }

  const asm = new Asm()
  asm.given([{ name: '_sentinel', kind: 'bytes', width: SENTINEL.length }, ...m.inputs])
  m.emit(asm, params)

  // Everything after this point is the TEST, not the module: compare each
  // declared output with the model, then prove the sentinel is untouched.
  for (let k = m.outputs.length - 1; k >= 0; k--) {
    const o = m.outputs[k]
    if (asm.top().name !== o.name) {
      throw new Error(`${m.name}: emit() promised output '${o.name}' at depth ${m.outputs.length - 1 - k}, but the stack has '${asm.top().name}' (${asm.toString()})`)
    }
    const want = expected[o.name]
    if (want === undefined) throw new Error(`${m.name}: model() produced no '${o.name}'`)
    if (o.kind === 'bytes') { asm.data(Buffer.isBuffer(want) ? want : Buffer.from(want), 'want'); asm.equalVerify() } else { asm.num(want, 'want'); asm.numEqualVerify() }
  }
  if (asm.stack.length !== 1 || asm.stack[0].name !== '_sentinel') {
    throw new Error(`${m.name}: left ${asm.stack.length} value(s) on the stack — expected only the caller's [${asm.toString()}]`)
  }
  asm.data(SENTINEL, 'sentinel*')
  asm.equal('ok')

  return { unlock, lock: asm.script(), expected }
}

/**
 * The ACCEPTANCE script: the module, with its outputs dropped and nothing
 * asserted about them.
 *
 * This is the only correct way to attack a witnessed module. Reusing the
 * correctness script instead hides malleability behind the test's own output
 * comparison: a forged witness that the module happily accepts still fails the
 * comparison against the honest answer, and the run is reported as a refusal
 * that never happened. Asking `did the module accept?` separates the two.
 */
function buildAccept (m, params) {
  const asm = new Asm()
  asm.given([{ name: '_sentinel', kind: 'bytes', width: SENTINEL.length }, ...m.inputs])
  m.emit(asm, params)
  for (let k = 0; k < m.outputs.length; k++) asm.drop()
  asm.data(SENTINEL, 'sentinel*')
  asm.equal('ok')
  return asm.script()
}

/**
 * The module's OWN cost: the Script it emits, with none of the test's
 * assertion bytes. Reporting the built script instead would charge a module for
 * the constant it is being compared against — which is often larger than the
 * module.
 */
function moduleSize (m, params) {
  const asm = new Asm()
  asm.given([{ name: '_sentinel', kind: 'bytes', width: SENTINEL.length }, ...m.inputs])
  m.emit(asm, params)
  return { bytes: asm.script().toBuffer().length, ops: countOps(asm.script()) }
}

/** The honest inputs for a case: what the case gives, plus the module's hints. */
function complete (m, params, caseValues) {
  const values = { ...caseValues }
  if (m.hint) Object.assign(values, m.hint(values, params))
  return values
}

/** Two supplied values are the same value — Buffers included. */
function sameValue (a, b) {
  if (Buffer.isBuffer(a) || Buffer.isBuffer(b)) {
    return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b)
  }
  return a === b
}

/**
 * Default attacks on a witnessed value — the near-misses, not random noise.
 *
 * Returns null when the near-misses cannot be constructed. A witnessed module
 * whose CANONICITY cannot be attacked has not been proven canonical, and the kit
 * says so rather than reporting a green run it did not earn.
 */
function defaultAttacks (honest, params) {
  const n = params && params.n
  if (typeof honest !== 'bigint') return null
  const out = [
    { label: 'off by one (+1)', value: honest + 1n },
    { label: 'off by one (−1)', value: honest - 1n },
    { label: 'zero', value: 0n },
    { label: 'one', value: 1n },
    { label: 'negated', value: -honest }
  ]
  // The attack that looks right: another representative of the same residue
  // class. A check written as a congruence accepts it; a canonical module does not.
  if (typeof n !== 'bigint') return null
  out.push({ label: 'same residue (+n)', value: honest + n })
  out.push({ label: 'same residue (−n)', value: honest - n })
  return out.filter((a) => a.value !== honest)
}

/**
 * Run every case of a module, then attack it. Returns a report; prints as it goes.
 */
function proveModule (m, { params = {}, quiet = false } = {}) {
  const report = { name: m.name, params, cases: [], attacks: [], sizes: [], failures: [] }
  const say = (s) => { if (!quiet) console.log(s) }
  say(`\n── ${m.name}${Object.keys(params).length ? '  ' + describeParams(params) : ''} ──  ${m.doc}`)

  for (const c of m.cases) {
    const p = { ...params, ...(c.params || {}) }
    const label = c.name || JSON.stringify(c.inputs)

    // A case marked `refuse` asserts the other half of the module: an input it
    // must not accept, whatever the spender supplies. The honest hint is not
    // available for such a case (there IS no honest witness), so the case
    // supplies the witness values itself.
    if (c.refuse) {
      let rr
      try {
        const unlock = new bsv.Script()
        push(unlock, SENTINEL, 'bytes')
        for (const i of m.inputs) push(unlock, c.inputs[i.name], i.kind)
        rr = evaluate(unlock, buildAccept(m, p))
      } catch (err) { rr = { ok: false, error: err.message } }
      report.cases.push({ label, ok: !rr.ok, refuse: true })
      if (rr.ok) {
        report.failures.push(`${m.name} / ${label}: ACCEPTED what it must refuse — ${c.refuse}`)
        say(`  BROKEN  ${label} was ACCEPTED (${c.refuse})`)
      } else say(`  ok    ${label.padEnd(40)} refused — ${c.refuse}`)
      continue
    }

    let built, r
    try {
      built = build(m, p, complete(m, p, c.inputs))
      r = evaluate(built.unlock, built.lock)
      r.own = moduleSize(m, p)
    } catch (err) {
      report.failures.push(`${m.name} / ${label}: ${err.message}`)
      say(`  FAIL  ${label} — ${err.message}`)
      continue
    }
    report.cases.push({ label, ok: r.ok, bytes: r.own.bytes, ops: r.own.ops })
    report.sizes.push(r.own.bytes)
    if (r.ok) say(`  ok    ${label.padEnd(40)} ${r.own.bytes} B, ${r.own.ops} ops`)
    else { report.failures.push(`${m.name} / ${label}: ${r.error}`); say(`  FAIL  ${label} — ${r.error}`) }
  }

  // ── refusal: every witnessed input, attacked ──────────────────────────────
  for (const c of m.cases) {
    if (c.skipAttacks || c.refuse) continue
    const p = { ...params, ...(c.params || {}) }
    let honest
    try { honest = complete(m, p, c.inputs) } catch { continue }
    for (const w of m.witnessed) {
      let attacks = (m.attacks ? m.attacks(honest, p, w.name) : null) || defaultAttacks(honest[w.name], p)
      // An "attack" that reproduces the honest value tests nothing, and being
      // accepted is the correct behaviour — counting it as a refusal, or as a
      // break, would both be lies. Drop it, and say so if none survive.
      if (attacks) attacks = attacks.filter((a) => !sameValue(a.value, honest[w.name]))
      if (attacks && !attacks.length) attacks = null
      if (!attacks) {
        const why = `${m.name}: no usable attack on the witness '${w.name}'${c.name ? ` for case ${c.name}` : ''} — declare attacks() that differ from the honest value, or the module is not proven sound`
        report.failures.push(why)
        say(`  UNPROVEN  ${why}`)
        continue
      }
      for (const a of attacks) {
        const forged = { ...honest, [w.name]: a.value }
        let r
        try {
          const unlock = new bsv.Script()
          push(unlock, SENTINEL, 'bytes')
          for (const i of m.inputs) push(unlock, forged[i.name], i.kind)
          r = evaluate(unlock, buildAccept(m, p))
        } catch (err) {
          r = { ok: false, error: err.message }
        }
        const refused = !r.ok
        report.attacks.push({ witness: w.name, label: a.label, refused })
        if (!refused) {
          report.failures.push(`${m.name}: ACCEPTED a forged '${w.name}' — ${a.label}. The witness is not unique, so the module's output is the spender's choice.`)
          say(`  BROKEN  forged ${w.name}: ${a.label} was ACCEPTED`)
        }
      }
    }
  }
  const atk = report.attacks.length
  if (atk) say(`  ok    refused all ${atk} forged witnesses`)
  return report
}

function describeParams (p) {
  return '{' + Object.entries(p).map(([k, v]) => `${k}=${typeof v === 'bigint' ? (v > 0xffffffffn ? bits(v) + 'b' : v) : v}`).join(' ') + '}'
}
function bits (v) { return v.toString(2).length }

/** Run many modules and exit non-zero if any failed. */
function proveAll (entries) {
  const reports = entries.map(([m, opts]) => proveModule(m, opts))
  const failures = reports.flatMap((r) => r.failures)
  const cases = reports.reduce((s, r) => s + r.cases.length, 0)
  const attacks = reports.reduce((s, r) => s + r.attacks.length, 0)
  console.log(`\n${reports.length} modules, ${cases} cases, ${attacks} forgery attempts — ${failures.length ? failures.length + ' FAILED' : 'all green'}`)
  for (const f of failures) console.log(`  ${f}`)
  return { reports, failures }
}

module.exports = { sameValue, build, buildAccept, moduleSize, proveModule, proveAll, complete, SENTINEL, defaultAttacks }
