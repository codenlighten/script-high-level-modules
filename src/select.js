'use strict'

const { Asm } = require('./asm')
const F = require('./facts')
const { pushNum } = require('./num')
const { complete, build } = require('./testkit')
const { evaluate } = require('./run')

// CHOOSING BETWEEN IMPLEMENTATIONS OF THE SAME MATHEMATICS.
//
// Several things here compute the same function by different schedules:
// fp12.sqr and fp12.cycSqr, fp12.powX and fp12.powXc. Which is cheaper is not
// a fact about the algorithm, it is a fact about the target — and this target
// has a cost model that inverts received wisdom more than once, so it is a
// question that has to be measured rather than reasoned about.
//
// This is the smallest honest version of an instruction-selection pass:
//
//     candidates ──► PROVE THEY AGREE ──► measure ──► choose by an objective
//
// The first arrow is the one that matters. A selector that picks the cheaper of
// two modules without first establishing that they compute the same thing is a
// bug generator with a benchmark attached, so agreement comes first and
// disagreement is a REFUSAL rather than a preference.
//
// And agreement is always agreement ON A DOMAIN. fp12.cycSqr is a squaring only
// on the cyclotomic subgroup; outside it the two candidates genuinely differ and
// the right answer is that they are not interchangeable. Every contest names the
// domain its vectors came from, and that name is reported with the result,
// because "cheaper" without "and equivalent, here" is not a finding.

const SAT_PER_KB = 100

/** Emit a module and take the whole cost vector, not just its size. */
function measure (m, params, prime) {
  const asm = new Asm()
  const reduced = F.range(0n, prime)
  asm.given([{ name: '_s', kind: 'bytes', width: 1 },
    ...m.inputs.map((i) => ({ name: i.name, kind: i.kind || 'num', facts: reduced }))])
  m.emit(asm, params)
  const script = asm.script()
  const { countOps } = require('./run')
  return {
    bytes: script.toBuffer().length,
    opcodes: countOps(script),
    maxStack: asm.maxStack,
    maxAlt: asm.maxAlt,
    witnessValues: m.inputs.filter((i) => i.witness).length
  }
}

/** What the spender actually has to push, in bytes, for one set of inputs. */
function unlockingBytes (m, params, inputs) {
  const values = complete(m, params, inputs)
  let n = 0
  for (const slot of m.inputs) {
    const v = values[slot.name]
    if (v === undefined) continue
    const p = pushNum(typeof v === 'bigint' ? v : BigInt(v))
    n += typeof p === 'number' ? 1 : p.length + (p.length < 76 ? 1 : p.length < 256 ? 2 : 3)
  }
  return n
}

const OBJECTIVES = {
  bytes: (c) => c.bytes,
  total: (c) => c.bytes + c.unlockBytes,
  opcodes: (c) => c.opcodes,
  stack: (c) => c.maxStack,
  witness: (c) => c.unlockBytes
}

/**
 * @param what        the mathematical function, as a name
 * @param domain      where the candidates are claimed to agree, as a sentence
 * @param candidates  [{ name, module, params }]
 * @param vectors     input objects, all from `domain`
 * @param objective   which coordinate of the cost vector to minimise
 */
function select (what, { domain, candidates, vectors, objective = 'bytes', prime }) {
  if (!OBJECTIVES[objective]) throw new Error(`select: no objective '${objective}'`)
  if (candidates.length < 2) throw new Error(`select(${what}): needs at least two candidates to choose between`)
  if (!vectors.length) throw new Error(`select(${what}): no vectors, so nothing establishes that these agree`)

  // ── agreement, first, and in TWO parts ──────────────────────────────────
  //
  // Comparing models is not enough, and finding that out was the point of
  // trying. fp12.cycSqr's model is the general square — correct everywhere —
  // and only its EMIT is confined to the cyclotomic subgroup. Two candidates
  // whose models agree can therefore have scripts that do not, which is exactly
  // the case a selector must refuse and exactly the one a model comparison
  // cannot see.
  //
  // So: every candidate's SCRIPT is checked against its OWN model on every
  // vector, and the models are checked against each other. Together those give
  // script_i = model_i = model_j = script_j, which is the thing being claimed.
  const outputs = candidates[0].module.outputs.map((o) => o.name)
  const disagreements = []
  vectors.forEach((inputs, vi) => {
    // part one: does each candidate do what it says, here?
    for (const c of candidates) {
      let ok = false
      let why = null
      try {
        const built = build(c.module, c.params, complete(c.module, c.params, inputs))
        const r = evaluate(built.unlock, built.lock)
        ok = r.ok
        why = r.error || r.thrown
      } catch (e) { why = e.message }
      if (!ok) disagreements.push(`${c.name}'s script does not match its own model at vector ${vi}${why ? ` (${why})` : ''} — it is outside its domain here`)
    }
    // part two: do the models say the same thing?
    const answers = candidates.map((c) => {
      try { return c.module.model(complete(c.module, c.params, inputs), c.params) } catch (e) { return { _error: e.message } }
    })
    for (let i = 1; i < answers.length; i++) {
      for (const name of outputs) {
        if (answers[0][name] !== answers[i][name]) {
          disagreements.push(`${candidates[0].name} and ${candidates[i].name} differ on '${name}' at vector ${vi}`)
        }
      }
    }
  })
  if (disagreements.length) {
    return { what, domain, agreed: false, disagreements, chosen: null, table: [] }
  }

  // ── then measurement ────────────────────────────────────────────────────
  const table = candidates.map((c) => {
    const cost = measure(c.module, c.params, prime)
    cost.unlockBytes = unlockingBytes(c.module, c.params, vectors[0])
    cost.name = c.name
    cost.total = cost.bytes + cost.unlockBytes
    cost.feeSat = Math.ceil((cost.total / 1000) * SAT_PER_KB)
    return cost
  })
  const key = OBJECTIVES[objective]
  const chosen = table.reduce((best, c) => (key(c) < key(best) ? c : best), table[0])
  return { what, domain, agreed: true, vectors: vectors.length, objective, chosen: chosen.name, table }
}

module.exports = { select, measure, unlockingBytes, OBJECTIVES, SAT_PER_KB }
