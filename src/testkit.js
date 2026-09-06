'use strict'

const bsv = require('@smartledger/bsv')
const { Asm } = require('./asm')
const { evaluate, countOps, buildSpend, evaluatePrepared } = require('./run')
const F = require('./facts')
const { factsFor } = require('./module')
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
  return withTail(m, params, asm.script())
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

// ── MODULES THAT READ THEIR OWN SPENDING TRANSACTION ────────────────────────
//
// A module holding an OP_PUSH_TX preimage cannot be handed a stand-in: the
// bytes have to be the genuine BIP-143 preimage of the very transaction being
// verified. So the case describes the SHAPE of that transaction and the module
// produces its own witness from it.
//
// That makes the build circular — the locking script contains the constant the
// test compares against, the transaction commits to the locking script, and the
// witness comes from the transaction. It is broken by building twice: once with
// nothing asserted, to obtain a witness and learn what the module computes, and
// again with that value asserted.
//
// The second pass is not a formality. If what the module computes CHANGES when
// its own script bytes change, the two passes disagree, and the kit says so —
// a module whose output depends on its own length is not a function of its
// inputs, and no amount of testing would pin it.

function buildFor (m, params, expected) {
  const asm = new Asm()
  asm.given([{ name: '_sentinel', kind: 'bytes', width: SENTINEL.length }, ...m.inputs])
  m.emit(asm, params)
  if (expected === null) {
    for (let k = 0; k < m.outputs.length; k++) asm.drop()
  } else {
    for (let k = m.outputs.length - 1; k >= 0; k--) {
      const o = m.outputs[k]
      if (asm.top().name !== o.name) throw new Error(`${m.name}: emit() promised '${o.name}' on top, found '${asm.top().name}' (${asm.toString()})`)
      const want = expected[o.name]
      if (want === undefined) throw new Error(`${m.name}: model() produced no '${o.name}'`)
      if (o.kind === 'bytes') { asm.data(Buffer.isBuffer(want) ? want : Buffer.from(want), 'want'); asm.equalVerify() } else { asm.num(want, 'want'); asm.numEqualVerify() }
    }
  }
  if (asm.stack.length !== 1 || asm.stack[0].name !== '_sentinel') {
    throw new Error(`${m.name}: left ${asm.stack.length} value(s) on the stack — expected only the caller's [${asm.toString()}]`)
  }
  asm.data(SENTINEL, 'sentinel*')
  asm.equal('ok')
  return withTail(m, params, asm.script())
}

/** A module that must live in a particular shape of script says so. */
function withTail (m, params, script) {
  if (!m.tail) return script
  const extra = typeof m.tail === 'function' ? m.tail(params) : m.tail
  return extra ? new bsv.Script(Buffer.concat([script.toBuffer(), extra])) : script
}

function sameOutputs (a, b) {
  const ks = new Set([...Object.keys(a), ...Object.keys(b)])
  for (const k of ks) if (!sameValue(a[k], b[k])) return false
  return true
}

/**
 * One pass: lock, transaction, witness, and what the module says it computed.
 *
 * Producing the witness generally MUTATES the transaction — an OP_PUSH_TX
 * preimage has to be ground, and grinding varies a field. So the shape the case
 * asked for is checked afterwards. Without that, a case pinning a final
 * sequence and a witness generator that grinds the sequence quietly agree to
 * test something else: the case reads as a refusal that never happened.
 */
function onePass (m, params, spend, expected, caseValues = {}) {
  const lock = buildFor(m, params, expected)
  const prepared = buildSpend(lock, spend)

  // Three sources, in falling precedence: what the case pinned, what only the
  // spend can produce, and what the module can work out for itself. A case that
  // states a value keeps it — otherwise a deliberately wrong one would be
  // quietly corrected, which is the bug this rule already caught once.
  const values = { ...caseValues }
  const produced = m.witnessFor({ ...prepared, spend })
  for (const k of Object.keys(produced)) if (!(k in values)) values[k] = produced[k]
  if (m.hint) {
    const hinted = m.hint(values, params)
    for (const k of Object.keys(hinted)) if (!(k in values)) values[k] = hinted[k]
  }

  const actual = { nLockTime: prepared.tx.nLockTime, sequence: prepared.tx.inputs[prepared.inputIndex || 0].sequenceNumber }
  for (const field of ['nLockTime', 'sequence']) {
    if (spend[field] !== undefined && spend[field] !== actual[field]) {
      throw new Error(`${m.name}: the case asked for ${field}=${spend[field]} and witnessFor() left ${actual[field]} — ` +
        'the witness generator changed the transaction the case was describing, so the case tests something else')
    }
  }
  return { lock, prepared, values, computed: expected === null ? m.model(values, params) : expected }
}

function buildContextual (m, params, c) {
  const spend = c.spend || {}
  const probe = onePass(m, params, spend, null, c.inputs)          // nothing asserted
  const real = onePass(m, params, spend, probe.computed, c.inputs) // the value asserted
  const after = m.model(real.values, params)
  if (!sameOutputs(probe.computed, after)) {
    throw new Error(`${m.name}: what it computes changed when its own script did (${JSON.stringify(probe.computed, bigints)} then ${JSON.stringify(after, bigints)}) — the output is not a function of the inputs`)
  }
  return { ...real, expected: probe.computed, spend }
}

const bigints = (k, v) => (typeof v === 'bigint' ? v.toString() : v)

/** Push the module's values as an unlocking script, sentinel first. */
function unlockFor (m, values) {
  const s = new bsv.Script()
  push(s, SENTINEL, 'bytes')
  for (const i of m.inputs) {
    if (!(i.name in values)) throw new Error(`${m.name}: no value for '${i.name}'`)
    push(s, values[i.name], i.kind)
  }
  return s
}

/**
 * A module's `ensures` is a claim about its outputs that nothing in the build
 * can check — the framework derives what it can from the arithmetic, and where
 * it cannot, the author states it and downstream modules rely on it.
 *
 * So it is checked here, against the model, on every case. A module that
 * promises its result is in [0, p) and returns p − 3 + p has said something
 * false, and the case that shows it is the same case that was already being run.
 */
function checkEnsures (m, params, expected) {
  const gives = factsFor(m.ensures, params)
  const bad = []
  for (const [name, need] of Object.entries(gives)) {
    const v = expected[name]
    if (v === undefined) { bad.push(`${name}: the model produced no such output`); continue }
    if (!need.range) continue
    const n = typeof v === 'bigint' ? v : (Buffer.isBuffer(v) ? null : BigInt(v))
    if (n === null) continue
    if (n < need.range.lo || n >= need.range.hi) {
      bad.push(`${name} = ${n} is not ${F.describe(need)}, which the module promises`)
    }
  }
  return bad
}

/** The honest inputs for a case: what the case gives, plus the module's hints. */
function complete (m, params, caseValues) {
  const values = { ...caseValues }
  if (m.hint) {
    // Fill in what the case did not give; never overrule what it did. A case
    // that pins a witness on purpose must keep the value it pinned.
    const hinted = m.hint(values, params)
    for (const k of Object.keys(hinted)) if (!(k in values)) values[k] = hinted[k]
  }
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
  // The modulus is called `n` by the integer modules and `p` by the curve ones,
  // and this only looked for `n`. So the same-residue attacks — the ones that
  // test CANONICITY rather than soundness, and the ones the last four bugs
  // needed — were silently skipped for every ec.* module. They passed their
  // attack suites without ever being asked the question.
  const params2 = params || {}
  const n = typeof params2.n === 'bigint' ? params2.n
    : typeof params2.nn === 'bigint' ? params2.nn
      : typeof params2.p === 'bigint' ? params2.p
        : typeof params2.pn === 'bigint' ? params2.pn : undefined
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

    if (m.contextual) {
      let r, own
      try {
        if (c.refuse) {
          const probe = onePass(m, p, c.spend || {}, null, c.inputs)
          own = moduleSize(m, p)
          r = evaluatePrepared(probe.prepared, () => unlockFor(m, probe.values))
        } else {
          const built = buildContextual(m, p, c)
          const broken = checkEnsures(m, p, built.expected)
          if (broken.length) throw new Error(`${m.name}: its own promise does not hold — ${broken[0]}`)
          own = moduleSize(m, p)
          r = evaluatePrepared(built.prepared, () => unlockFor(m, built.values))
        }
      } catch (err) { r = { ok: false, error: err.message } }
      const passed = c.refuse ? !r.ok : r.ok
      report.cases.push({ label, ok: passed, bytes: own && own.bytes, ops: own && own.ops })
      if (passed) say(`  ok    ${label.padEnd(40)} ${c.refuse ? 'refused — ' + c.refuse : `${own.bytes} B, ${own.ops} ops`}`)
      else {
        report.failures.push(`${m.name} / ${label}: ${c.refuse ? 'ACCEPTED what it must refuse — ' + c.refuse : r.error}`)
        say(`  FAIL  ${label} — ${c.refuse ? 'ACCEPTED' : r.error}`)
      }
      continue
    }

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
      const broken = checkEnsures(m, p, built.expected)
      if (broken.length) throw new Error(`${m.name}: its own promise does not hold — ${broken[0]}`)
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
    let honest, contextual = null
    if (m.contextual) {
      try {
        const probe = onePass(m, p, c.spend || {}, null, c.inputs)
        honest = probe.values
        contextual = probe.prepared
      } catch { continue }
    } else {
      try { honest = complete(m, p, c.inputs) } catch { continue }
    }
    // A module with hundreds of witnessed inputs (a 256-step ladder has one per
    // step) cannot be attacked exhaustively in a test suite. Sampling is
    // honest as long as it is SAID: the report carries how many of how many.
    const witnesses = sampleWitnesses(m, c)
    for (const w of witnesses) {
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
          if (contextual) {
            r = evaluatePrepared(contextual, () => unlockFor(m, forged))
          } else {
            r = evaluate(unlockFor(m, forged), buildAccept(m, p))
          }
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
  if (atk) {
    const total = m.witnessed.length
    const tried = new Set(report.attacks.map((a) => a.witness)).size
    const how = tried < total ? ` (a sample of ${tried} of the ${total} witnessed inputs)` : ''
    say(`  ok    refused all ${atk} forged witnesses${how}`)
    report.sampled = tried < total ? { tried, total } : null
  }
  return report
}

function describeParams (p) {
  return '{' + Object.entries(p).map(([k, v]) => `${k}=${typeof v === 'bigint' ? (v > 0xffffffffn ? bits(v) + 'b' : v) : v}`).join(' ') + '}'
}
function bits (v) { return v.toString(2).length }

/**
 * Which witnessed inputs to attack. All of them, unless the module declares
 * `maxWitnessAttacks` — then a deterministic spread across the list, so the
 * first, the last and the middle are always covered rather than a prefix.
 */
function sampleWitnesses (m, c) {
  const all = m.witnessed
  const cap = c.maxWitnessAttacks || m.maxWitnessAttacks
  if (!cap || all.length <= cap) return all
  // Some witnesses are the point of the module — a signature's own r and s —
  // and must never be left to a sample. Those are always attacked; the budget
  // that remains is spread evenly across the rest, so the first, the last and
  // the middle are covered rather than a prefix.
  const always = new Set(m.alwaysAttack || [])
  const must = all.filter((w) => always.has(w.name))
  const rest = all.filter((w) => !always.has(w.name))
  const budget = Math.max(0, cap - must.length)
  const picked = []
  for (let i = 0; i < budget && rest.length; i++) picked.push(rest[Math.round((i * (rest.length - 1)) / Math.max(1, budget - 1))])
  return [...new Set([...must, ...picked])]
}

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

module.exports = { sameValue, checkEnsures, sampleWitnesses, buildContextual, onePass, unlockFor, build, buildAccept, moduleSize, proveModule, proveAll, complete, SENTINEL, defaultAttacks }
